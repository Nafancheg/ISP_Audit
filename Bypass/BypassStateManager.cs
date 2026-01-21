using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Immutable;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;

namespace IspAudit.Bypass
{
    /// <summary>
    /// AsyncLocal-контекст операции для корреляции логов между UI/apply и низким уровнем (TrafficEngine).
    /// Best-effort: не влияет на функционал, только на наблюдаемость.
    /// </summary>
    internal static class BypassOperationContext
    {
        internal sealed record Context(string CorrelationId, string Operation, string HostKey, string GroupKey);

        private static readonly AsyncLocal<Context?> Current = new();

        private sealed class Scope : IDisposable
        {
            private readonly Context? _previous;

            public Scope(Context? previous)
            {
                _previous = previous;
            }

            public void Dispose()
            {
                Current.Value = _previous;
            }
        }

        internal static Context? Snapshot() => Current.Value;

        internal static IDisposable Enter(string correlationId, string operation, string? hostKey = null, string? groupKey = null)
        {
            var prev = Current.Value;
            Current.Value = new Context(
                CorrelationId: (correlationId ?? string.Empty).Trim(),
                Operation: string.IsNullOrWhiteSpace(operation) ? "unknown" : operation.Trim(),
                HostKey: (hostKey ?? string.Empty).Trim(),
                GroupKey: (groupKey ?? string.Empty).Trim());

            return new Scope(prev);
        }

        internal static IDisposable EnterIfNone(string operation, string? hostKey = null, string? groupKey = null)
        {
            if (Current.Value != null)
            {
                return new Scope(Current.Value);
            }

            return Enter(Guid.NewGuid().ToString("N"), operation, hostKey, groupKey);
        }
    }

    /// <summary>
    /// Внутренний guard: позволяет логировать попытки управлять bypass/TrafficEngine
    /// в обход единого менеджера состояния.
    /// </summary>
    internal static class BypassStateManagerGuard
    {
        internal static bool EnforceManagerUsage;

        private sealed class GuardState
        {
            public int ManagerDepth;
            public int StrictDepth;
        }

        private static readonly AsyncLocal<GuardState?> State = new();

        private static GuardState GetOrCreateState()
        {
            var s = State.Value;
            if (s != null) return s;
            s = new GuardState();
            State.Value = s;
            return s;
        }

        internal static bool IsInManagerScope => State.Value?.ManagerDepth > 0;
        internal static bool IsStrictMode => State.Value?.StrictDepth > 0;

        internal static IDisposable EnterScope()
        {
            var s = GetOrCreateState();
            s.ManagerDepth++;
            return new Scope(isStrict: false);
        }

        /// <summary>
        /// Smoke-хук: включает строгий режим guard для текущего async-потока.
        /// В этом режиме любые вызовы TrafficEngine/TlsBypassService вне manager-scope приводят к исключению.
        /// </summary>
        internal static IDisposable EnterStrictModeForSmoke()
        {
            var s = GetOrCreateState();
            s.StrictDepth++;
            return new Scope(isStrict: true);
        }

        internal static void WarnIfBypassed(Action<string>? log, string action)
        {
            if (!EnforceManagerUsage) return;
            if (IsInManagerScope) return;

            var message = $"[Bypass][ERROR] {action}: вызов в обход BypassStateManager";
            if (IsStrictMode)
            {
                throw new InvalidOperationException(message);
            }

            log?.Invoke(message);
        }

        internal static void WarnIfBypassed(IProgress<string>? progress, string action)
        {
            if (!EnforceManagerUsage) return;
            if (IsInManagerScope) return;

            var message = $"[TrafficEngine][ERROR] {action}: вызов в обход BypassStateManager";
            if (IsStrictMode)
            {
                throw new InvalidOperationException(message);
            }

            progress?.Report(message);
        }

        private sealed class Scope(bool isStrict) : IDisposable
        {
            public void Dispose()
            {
                var s = State.Value;
                if (s == null) return;

                if (isStrict)
                {
                    s.StrictDepth = s.StrictDepth > 0 ? s.StrictDepth - 1 : 0;
                }
                else
                {
                    s.ManagerDepth = s.ManagerDepth > 0 ? s.ManagerDepth - 1 : 0;
                }

                if (s.ManagerDepth == 0 && s.StrictDepth == 0)
                {
                    // Не удерживаем state в AsyncLocal без необходимости.
                    State.Value = null;
                }
            }
        }
    }

    /// <summary>
    /// Единый владелец состояния bypass и операций над TrafficEngine.
    /// Все изменения фильтров/старт/стоп движка, а также Apply/Disable TLS-bypass
    /// должны проходить через этот менеджер.
    /// </summary>
    public sealed partial class BypassStateManager : IDisposable
    {
        private static readonly ConditionalWeakTable<TrafficEngine, BypassStateManager> Instances = new();
        private static readonly object InstancesSync = new();

        public static BypassStateManager GetOrCreate(
            TrafficEngine trafficEngine,
            BypassProfile? baseProfile = null,
            Action<string>? log = null)
        {
            if (trafficEngine == null) throw new ArgumentNullException(nameof(trafficEngine));

            lock (InstancesSync)
            {
                if (Instances.TryGetValue(trafficEngine, out var existing))
                {
                    return existing;
                }

                var created = new BypassStateManager(
                    trafficEngine,
                    baseProfile ?? BypassProfile.CreateDefault(),
                    log);

                Instances.Add(trafficEngine, created);
                return created;
            }
        }

        internal static BypassStateManager GetOrCreateFromService(
            TlsBypassService tlsService,
            BypassProfile baseProfile,
            Action<string>? log = null)
        {
            if (tlsService == null) throw new ArgumentNullException(nameof(tlsService));
            if (baseProfile == null) throw new ArgumentNullException(nameof(baseProfile));

            var engine = tlsService.TrafficEngineForManager;
            lock (InstancesSync)
            {
                if (Instances.TryGetValue(engine, out var existing))
                {
                    return existing;
                }

                var created = new BypassStateManager(engine, tlsService, baseProfile, log);
                Instances.Add(engine, created);
                return created;
            }
        }

        private readonly TrafficEngine _trafficEngine;
        private readonly TlsBypassService _tlsService;
        private readonly Action<string>? _log;
        private readonly SemaphoreSlim _applyGate = new(1, 1);

        private readonly BypassSessionJournal _journal;

        public TrafficEngine TrafficEngine => _trafficEngine;
        public BypassProfile BaseProfile { get; }

        public TlsBypassService TlsService => _tlsService;

        public IReadOnlyList<TlsFragmentPreset> FragmentPresets => _tlsService.FragmentPresets;

        public event Action<TlsBypassMetrics>? MetricsUpdated
        {
            add => _tlsService.MetricsUpdated += value;
            remove => _tlsService.MetricsUpdated -= value;
        }

        public event Action<TlsBypassVerdict>? VerdictChanged
        {
            add => _tlsService.VerdictChanged += value;
            remove => _tlsService.VerdictChanged -= value;
        }

        public event Action<TlsBypassState>? StateChanged
        {
            add => _tlsService.StateChanged += value;
            remove => _tlsService.StateChanged -= value;
        }

        private BypassStateManager(TrafficEngine trafficEngine, BypassProfile baseProfile, Action<string>? log)
        {
            _trafficEngine = trafficEngine;
            BaseProfile = baseProfile;
            _log = log;

            _journal = new BypassSessionJournal(BypassSessionJournal.GetDefaultPath(), _log);

            // Важно: лог прокидываем на самый нижний уровень, чтобы любые проблемы
            // в обходе (метрики/вердикт/движок) были видны пользователю.
            _tlsService = new TlsBypassService(_trafficEngine, BaseProfile, _log);

            // Heartbeat для watchdog.
            _tlsService.MetricsUpdated += metrics =>
            {
                var nowUtc = DateTime.UtcNow;
                _lastMetricsSnapshot = metrics;
                _lastMetricsSnapshotUtc = nowUtc;

                var snapshot = _tlsService.GetOptionsSnapshot();
                if (snapshot.IsAnyEnabled())
                {
                    _lastMetricsEventUtc = nowUtc;
                    _journal.TouchHeartbeat("metrics");
                }
            };

            // Включаем guard: все последующие вызовы к TrafficEngine/TlsBypassService,
            // сделанные не из менеджера, будут логироваться как ошибка.
            BypassStateManagerGuard.EnforceManagerUsage = true;
        }

        private BypassStateManager(TrafficEngine trafficEngine, TlsBypassService tlsService, BypassProfile baseProfile, Action<string>? log)
        {
            _trafficEngine = trafficEngine;
            _tlsService = tlsService;
            BaseProfile = baseProfile;
            _log = log;

            _journal = new BypassSessionJournal(BypassSessionJournal.GetDefaultPath(), _log);

            _tlsService.MetricsUpdated += _ =>
            {
                var nowUtc = DateTime.UtcNow;
                _lastMetricsSnapshot = _;
                _lastMetricsSnapshotUtc = nowUtc;

                var snapshot = _tlsService.GetOptionsSnapshot();
                if (snapshot.IsAnyEnabled())
                {
                    _lastMetricsEventUtc = nowUtc;
                    _journal.TouchHeartbeat("metrics");
                }
            };

            BypassStateManagerGuard.EnforceManagerUsage = true;
        }

        public TlsBypassOptions GetOptionsSnapshot() => _tlsService.GetOptionsSnapshot();

        /// <summary>
        /// Задать цель для outcome-check (обычно — hostKey последнего v2 плана/диагноза).
        /// Если цель не задана, outcome остаётся UNKNOWN.
        /// </summary>
        public int GetUdp443DropTargetIpCountSnapshot()
        {
            try
            {
                using var scope = BypassStateManagerGuard.EnterScope();
                var list = _tlsService.GetUdp443DropTargetIpsSnapshot();
                return list?.Length ?? 0;
            }
            catch
            {
                return 0;
            }
        }

        // Outcome/Activation вынесены в partial-файлы.

        public void RegisterEngineFilter(IspAudit.Core.Traffic.IPacketFilter filter)
        {
            using var scope = BypassStateManagerGuard.EnterScope();

            if (filter == null)
            {
                _log?.Invoke("[Bypass][WARN] RegisterEngineFilter: filter is null");
                return;
            }

            // P0.1 observability: фиксируем последнюю «мутацию» движка при регистрации фильтров.
            // Важно для расследования редких падений loop (например, "Collection was modified").
            try
            {
                var op = BypassOperationContext.Snapshot();
                if (op != null)
                {
                    var safeName = (filter.Name ?? string.Empty).Trim();
                    var details = string.IsNullOrWhiteSpace(safeName)
                        ? "engine:RegisterFilter"
                        : $"engine:RegisterFilter name={safeName}";
                    _trafficEngine.SetLastMutationContext(op.CorrelationId, op.Operation, details);
                }
            }
            catch
            {
                // best-effort
            }

            _trafficEngine.RegisterFilter(filter);
        }

        public void RemoveEngineFilter(string filterName)
        {
            using var scope = BypassStateManagerGuard.EnterScope();

            if (string.IsNullOrWhiteSpace(filterName))
            {
                _log?.Invoke("[Bypass][WARN] RemoveEngineFilter: filterName пуст");
                return;
            }

            // P0.1 observability: фиксируем последнюю «мутацию» движка при удалении фильтров.
            try
            {
                var op = BypassOperationContext.Snapshot();
                if (op != null)
                {
                    var safeName = filterName.Trim();
                    var details = string.IsNullOrWhiteSpace(safeName)
                        ? "engine:RemoveFilter"
                        : $"engine:RemoveFilter name={safeName}";
                    _trafficEngine.SetLastMutationContext(op.CorrelationId, op.Operation, details);
                }
            }
            catch
            {
                // best-effort
            }

            _trafficEngine.RemoveFilter(filterName);
        }

        public Task StartEngineAsync(CancellationToken cancellationToken = default)
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            return _trafficEngine.StartAsync(cancellationToken);
        }

        public Task StopEngineAsync()
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            return _trafficEngine.StopAsync();
        }

        public async Task ApplyTlsOptionsAsync(TlsBypassOptions options, CancellationToken cancellationToken = default)
        {
            await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var normalized = options.Normalize();

                // P0.1 Step 1: поддержка нескольких активных целей одновременно.
                // Пользователь может применить разные v2 планы для разных hostKey; рантайм должен
                // держать нужные «capabilities» включёнными (union), а decision graph выбирать действие по пакету.
                var preferredHost = _outcomeTargetHost;
                var activeTargetPolicies = GetActiveTargetPoliciesSnapshot(preferredHost);

                var effective = normalized;
                if (activeTargetPolicies.Length > 0)
                {
                    // OR по assist-флагам.
                    var needDropUdp443 = activeTargetPolicies.Any(p => p.DropUdp443);
                    var needAllowNoSni = activeTargetPolicies.Any(p => p.AllowNoSni);
                    var needHttpHostTricks = activeTargetPolicies.Any(p => p.HttpHostTricksEnabled);

                    // OR по TLS стратегиям (capabilities): разрешаем всем стратегиям существовать одновременно,
                    // а выбор конкретной стратегии переносим на decision graph.
                    var needFragment = activeTargetPolicies.Any(p => p.TlsStrategy == TlsBypassStrategy.Fragment
                        || p.TlsStrategy == TlsBypassStrategy.FakeFragment);
                    var needDisorder = activeTargetPolicies.Any(p => p.TlsStrategy == TlsBypassStrategy.Disorder
                        || p.TlsStrategy == TlsBypassStrategy.FakeDisorder);
                    var needFake = activeTargetPolicies.Any(p => p.TlsStrategy == TlsBypassStrategy.Fake
                        || p.TlsStrategy == TlsBypassStrategy.FakeFragment
                        || p.TlsStrategy == TlsBypassStrategy.FakeDisorder);

                    effective = effective with
                    {
                        DropUdp443 = effective.DropUdp443 || needDropUdp443,
                        AllowNoSni = effective.AllowNoSni || needAllowNoSni,
                        HttpHostTricksEnabled = effective.HttpHostTricksEnabled || needHttpHostTricks,
                        FragmentEnabled = effective.FragmentEnabled || needFragment,
                        DisorderEnabled = effective.DisorderEnabled || needDisorder,
                        FakeEnabled = effective.FakeEnabled || needFake
                    };
                }

                // Если пользователь явно выключил bypass полностью — очищаем remembered активные цели,
                // чтобы при следующем apply они не «воскресли» сами.
                if (!effective.IsAnyEnabled())
                {
                    ClearActiveTargetPolicies();
                    activeTargetPolicies = Array.Empty<ActiveTargetPolicy>();
                }

                // DROP UDP/443:
                // - global: глушим весь UDP/443 (цель не нужна)
                // - selective: перед Apply подготавливаем observed IP цели
                // Важно: вычисляем вне manager-scope (нет доступа к TrafficEngine), чтобы не держать guard дольше.
                uint[] udp443Targets = Array.Empty<uint>();
                if (effective.DropUdp443)
                {
                    if (effective.DropUdp443Global)
                    {
                        _log?.Invoke("[Bypass] DROP UDP/443 включён (GLOBAL) — глушим весь UDP/443");
                    }
                    else
                    {
                        // P0.1 Step 1: поддерживаем несколько активных целей одновременно.
                        // Поэтому в селективном режиме собираем union по нескольким активным host.
                        var host = preferredHost;
                        if (!string.IsNullOrWhiteSpace(host))
                        {
                            RememberUdp443ActiveHost(host);
                        }

                        var hosts = GetActiveUdp443HostsSnapshot(host);
                        if (hosts.Length == 0)
                        {
                            _log?.Invoke("[Bypass] DROP UDP/443 включён, но цель (host) не задана — UDP/443 не будет глушиться (селективный режим)");
                        }
                        else
                        {
                            // union observed IP по активным host (cap)
                            var union = new HashSet<uint>();
                            foreach (var h in hosts)
                            {
                                if (string.IsNullOrWhiteSpace(h)) continue;
                                var ips = await GetOrSeedUdp443DropTargetsAsync(h, cancellationToken).ConfigureAwait(false);
                                foreach (var ip in ips)
                                {
                                    if (ip == 0) continue;
                                    union.Add(ip);
                                    if (union.Count >= 32) break;
                                }
                                if (union.Count >= 32) break;
                            }

                            udp443Targets = union.Count == 0 ? Array.Empty<uint>() : union.Take(32).ToArray();
                            if (udp443Targets.Length == 0)
                            {
                                _log?.Invoke("[Bypass] DROP UDP/443 включён, но IP цели не определены — UDP/443 не будет глушиться (селективный режим)");
                            }
                            else if (hosts.Length > 1)
                            {
                                _log?.Invoke($"[Bypass] DROP UDP/443 (селективно): активных целей={hosts.Length}; IPv4 targets={udp443Targets.Length}");
                            }
                        }
                    }
                }

                // Policy-driven execution plane (P0.2): компилируем snapshot только при включённых gate.
                // При gate=off не меняем runtime-поведение: фильтр использует legacy ветки.
                DecisionGraphSnapshot? decisionSnapshot = null;

                var shouldCompileSnapshot =
                    (PolicyDrivenExecutionGates.PolicyDrivenUdp443Enabled() && effective.DropUdp443)
                    || (PolicyDrivenExecutionGates.PolicyDrivenTcp80HostTricksEnabled() && effective.HttpHostTricksEnabled)
                    || (PolicyDrivenExecutionGates.PolicyDrivenTcp443TlsStrategyEnabled() && (effective.FragmentEnabled || effective.DisorderEnabled || effective.FakeEnabled));

                if (shouldCompileSnapshot)
                {
                    try
                    {
                        var policies = new List<FlowPolicy>();

                        // P0.2 Stage 1: UDP/443 (QUIC fallback)
                        if (PolicyDrivenExecutionGates.PolicyDrivenUdp443Enabled() && effective.DropUdp443)
                        {
                            if (effective.DropUdp443Global)
                            {
                                policies.Add(new FlowPolicy
                                {
                                    Id = "udp443_quic_fallback_global",
                                    Priority = 100,
                                    Match = new MatchCondition
                                    {
                                        Proto = FlowTransportProtocol.Udp,
                                        Port = 443
                                    },
                                    Action = PolicyAction.DropUdp443,
                                    Scope = PolicyScope.Global
                                });
                            }
                            else
                            {
                                // Селективный режим: если targets пусты — не создаём политику (IPv4 не дропаем).
                                if (udp443Targets.Length > 0)
                                {
                                    policies.Add(new FlowPolicy
                                    {
                                        Id = "udp443_quic_fallback_selective",
                                        Priority = 100,
                                        Match = new MatchCondition
                                        {
                                            Proto = FlowTransportProtocol.Udp,
                                            Port = 443,
                                            DstIpv4Set = udp443Targets.ToImmutableHashSet()
                                        },
                                        Action = PolicyAction.DropUdp443,
                                        Scope = PolicyScope.Local
                                    });
                                }
                            }
                        }

                        // P0.2 Stage 3: TCP/80 HTTP Host tricks
                        if (PolicyDrivenExecutionGates.PolicyDrivenTcp80HostTricksEnabled() && effective.HttpHostTricksEnabled)
                        {
                            // P0.1 Step 1: в multi-group режиме стараемся ограничить blast radius.
                            // Если есть remembered активные цели, компилируем per-target политики (match по dst_ip).
                            var addedPerTarget = false;

                            foreach (var tp in activeTargetPolicies)
                            {
                                if (!tp.HttpHostTricksEnabled) continue;
                                if (string.IsNullOrWhiteSpace(tp.HostKey)) continue;

                                // Практическая стабилизация: если у цели уже есть candidate endpoints,
                                // используем их как seed observed IPv4, чтобы per-target политики могли
                                // собраться без DNS resolve.
                                SeedObservedIpv4TargetsFromCandidateEndpointsBestEffort(tp.HostKey, tp.CandidateIpEndpoints);

                                var ips = await GetOrSeedUdp443DropTargetsAsync(tp.HostKey, cancellationToken).ConfigureAwait(false);
                                if (ips.Length == 0) continue;

                                policies.Add(new FlowPolicy
                                {
                                    Id = $"tcp80_http_host_tricks_{NormalizeHostKeyForPolicyId(tp.HostKey)}",
                                    Priority = 110,
                                    Match = new MatchCondition
                                    {
                                        Proto = FlowTransportProtocol.Tcp,
                                        Port = 80,
                                        DstIpv4Set = ips.Take(32).ToImmutableHashSet()
                                    },
                                    Action = PolicyAction.HttpHostTricks,
                                    Scope = PolicyScope.Local
                                });

                                addedPerTarget = true;
                            }

                            // Fallback: если per-target политики не добавились (нет активных целей или не смогли получить IP),
                            // сохраняем прежнее поведение (глобальная политика).
                            if (!addedPerTarget)
                            {
                                policies.Add(new FlowPolicy
                                {
                                    Id = "tcp80_http_host_tricks",
                                    Priority = 100,
                                    Match = new MatchCondition
                                    {
                                        Proto = FlowTransportProtocol.Tcp,
                                        Port = 80
                                    },
                                    Action = PolicyAction.HttpHostTricks,
                                    Scope = PolicyScope.Global
                                });
                            }
                        }

                        // P0.2 Stage 4: TCP/443 TLS ClientHello strategy selection
                        if (PolicyDrivenExecutionGates.PolicyDrivenTcp443TlsStrategyEnabled()
                            && (effective.FragmentEnabled || effective.DisorderEnabled || effective.FakeEnabled))
                        {
                            // Per-target политики (DstIpv4Set) — позволяют держать одновременно разные стратегии
                            // для разных целей (Steam + YouTube).
                            foreach (var tp in activeTargetPolicies)
                            {
                                if (tp.TlsStrategy == TlsBypassStrategy.None) continue;
                                if (string.IsNullOrWhiteSpace(tp.HostKey)) continue;

                                // Практическая стабилизация: candidate endpoints → seed observed IPv4,
                                // чтобы DstIpv4Set не зависел только от DNS resolve.
                                SeedObservedIpv4TargetsFromCandidateEndpointsBestEffort(tp.HostKey, tp.CandidateIpEndpoints);

                                var ips = await GetOrSeedUdp443DropTargetsAsync(tp.HostKey, cancellationToken).ConfigureAwait(false);
                                if (ips.Length == 0) continue;

                                policies.Add(new FlowPolicy
                                {
                                    Id = $"tcp443_tls_{NormalizeHostKeyForPolicyId(tp.HostKey)}",
                                    Priority = 110,
                                    Match = new MatchCondition
                                    {
                                        Proto = FlowTransportProtocol.Tcp,
                                        Port = 443,
                                        TlsStage = TlsStage.ClientHello,
                                        DstIpv4Set = ips.Take(32).ToImmutableHashSet()
                                    },
                                    Action = PolicyAction.TlsBypassStrategy(tp.TlsStrategy.ToString()),
                                    Scope = PolicyScope.Local
                                });
                            }

                            // Fallback глобальная политика: если per-target мэтча нет (IP неизвестен/IPv6),
                            // используем стратегию, выведенную из effective опций.
                            var fallback = TlsBypassStrategy.None;
                            if (effective.DisorderEnabled && effective.FakeEnabled)
                                fallback = TlsBypassStrategy.FakeDisorder;
                            else if (effective.FragmentEnabled && effective.FakeEnabled)
                                fallback = TlsBypassStrategy.FakeFragment;
                            else if (effective.DisorderEnabled)
                                fallback = TlsBypassStrategy.Disorder;
                            else if (effective.FakeEnabled)
                                fallback = TlsBypassStrategy.Fake;
                            else if (effective.FragmentEnabled)
                                fallback = TlsBypassStrategy.Fragment;

                            if (fallback != TlsBypassStrategy.None)
                            {
                                policies.Add(new FlowPolicy
                                {
                                    Id = "tcp443_tls_clienthello_strategy",
                                    Priority = 100,
                                    Match = new MatchCondition
                                    {
                                        Proto = FlowTransportProtocol.Tcp,
                                        Port = 443,
                                        TlsStage = TlsStage.ClientHello
                                    },
                                    Action = PolicyAction.TlsBypassStrategy(fallback.ToString()),
                                    Scope = PolicyScope.Global
                                });
                            }
                        }

                        decisionSnapshot = policies.Count == 0 ? null : PolicySetCompiler.CompileOrThrow(policies);
                    }
                    catch (Exception ex)
                    {
                        // Gate включён, но компиляция не удалась — откатываемся на legacy путь.
                        _log?.Invoke($"[Bypass] Policy-driven snapshot: ошибка компиляции, fallback на legacy. {ex.Message}");
                        decisionSnapshot = null;
                    }
                }

                using var scope = BypassStateManagerGuard.EnterScope();
                _tlsService.SetUdp443DropTargetIpsForManager(udp443Targets);
                _tlsService.SetDecisionGraphSnapshotForManager(decisionSnapshot);
                await _tlsService.ApplyAsync(effective, cancellationToken).ConfigureAwait(false);

                if (effective.IsAnyEnabled())
                {
                    _lastBypassActivatedUtc = DateTime.UtcNow;
                    _lastMetricsEventUtc = DateTime.UtcNow;
                    _journal.SetBypassActive(true, "apply");

                    ScheduleOutcomeProbeIfPossible();
                }
                else
                {
                    _journal.SetBypassActive(false, "apply_disable");

                    CancelOutcomeProbe();
                    _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "bypass отключён");
                }
            }
            finally
            {
                _applyGate.Release();
            }
        }

        public Task DisableTlsAsync(CancellationToken cancellationToken = default)
            => DisableTlsAsync("manual_disable", cancellationToken);

        public async Task DisableTlsAsync(string reason, CancellationToken cancellationToken = default)
        {
            await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var scope = BypassStateManagerGuard.EnterScope();
                await _tlsService.DisableAsync(cancellationToken).ConfigureAwait(false);

                _lastBypassActivatedUtc = DateTime.MinValue;
                _journal.SetBypassActive(false, reason);

                CancelOutcomeProbe();
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "bypass отключён");
            }
            finally
            {
                _applyGate.Release();
            }
        }

        public async Task ApplyPreemptiveAsync(CancellationToken cancellationToken = default)
        {
            await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var scope = BypassStateManagerGuard.EnterScope();
                await _tlsService.ApplyPreemptiveAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _applyGate.Release();
            }
        }

        private static string NormalizeHostKeyForPolicyId(string hostKey)
        {
            if (string.IsNullOrWhiteSpace(hostKey)) return "unknown";

            var trimmed = hostKey.Trim();
            if (trimmed.Length == 0) return "unknown";

            // policy-id используется только как ключ метрик/наблюдаемости, поэтому безопасно нормализуем.
            // Ограничиваем длину, чтобы не раздувать snapshot.
            var chars = trimmed
                .Select(ch => char.IsLetterOrDigit(ch) ? char.ToLowerInvariant(ch) : '_')
                .ToArray();

            var s = new string(chars);
            while (s.Contains("__", StringComparison.Ordinal))
            {
                s = s.Replace("__", "_", StringComparison.Ordinal);
            }

            s = s.Trim('_');
            if (s.Length == 0) s = "unknown";
            if (s.Length > 32) s = s.Substring(0, 32);
            return s;
        }

        public void Dispose()
        {
            try
            {
                _watchdogTimer?.Dispose();
            }
            catch
            {
                // ignore
            }

            CancelOutcomeProbe();

            _tlsService.Dispose();
            _applyGate.Dispose();
        }
    }
}
