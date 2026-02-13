using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Immutable;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;
using IspAudit.Core.RuntimeAdaptation;

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

        // Явное согласие на системные изменения DNS/DoH (включение/отключение DoH через FixService).
        // По умолчанию: false. Управляется из UI (Operator/Engineer) и используется как gate в apply executor.
        private volatile bool _allowDnsDohSystemChanges;

        public bool AllowDnsDohSystemChanges
        {
            get => _allowDnsDohSystemChanges;
            set => _allowDnsDohSystemChanges = value;
        }

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

        // P1.12: пользовательские политики (CRUD в settings). Держим как массив-снимок,
        // чтобы можно было безопасно читать/писать без аллокаций/локов в hot-path.
        private FlowPolicy[] _userPolicies = Array.Empty<FlowPolicy>();

        public void SetUserFlowPoliciesForManager(System.Collections.Generic.IEnumerable<FlowPolicy>? policies)
        {
            try
            {
                var arr = (policies ?? Enumerable.Empty<FlowPolicy>())
                    .Where(p => p != null)
                    .ToArray();

                Volatile.Write(ref _userPolicies, arr);
                _log?.Invoke($"[Bypass] UserFlowPolicies: set count={arr.Length}");
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass] UserFlowPolicies: set failed. {ex.Message}");
            }
        }

        private FlowPolicy[] GetUserFlowPoliciesSnapshot()
        {
            try
            {
                return Volatile.Read(ref _userPolicies) ?? Array.Empty<FlowPolicy>();
            }
            catch
            {
                return Array.Empty<FlowPolicy>();
            }
        }

        // Runtime Adaptation Layer: inbound очередь + retry-until-delivered для доставки runtime-сигналов.
        public ReactiveTargetSyncService ReactiveTargetSync { get; }

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

            // Важно: очередь привязана к lifecycle engine и не очищается на restart.
            // Устаревшие события отбрасываются по TTL внутри ReactiveTargetSyncService.
            ReactiveTargetSync = new ReactiveTargetSyncService(this, _log);

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

            ReactiveTargetSync = new ReactiveTargetSyncService(this, _log);

            BypassStateManagerGuard.EnforceManagerUsage = true;
        }

        public TlsBypassOptions GetOptionsSnapshot() => _tlsService.GetOptionsSnapshot();

        /// <summary>
        /// Получить количество observed IPv4 адресов цели для QUIC fallback (DROP UDP/443).
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

        /// <summary>
        /// Получить observed IPv4 адреса цели для QUIC fallback (DROP UDP/443).
        /// Возвращает массив uint (network byte order, как в PacketParser/PacketHelper).
        /// </summary>
        public uint[] GetUdp443DropTargetIpsSnapshot()
        {
            try
            {
                using var scope = BypassStateManagerGuard.EnterScope();
                var list = _tlsService.GetUdp443DropTargetIpsSnapshot();
                return list == null || list.Length == 0 ? Array.Empty<uint>() : list;
            }
            catch
            {
                return Array.Empty<uint>();
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
            return StartEngineWithNudgeAsync(cancellationToken);
        }

        private async Task StartEngineWithNudgeAsync(CancellationToken cancellationToken)
        {
            await _trafficEngine.StartAsync(cancellationToken).ConfigureAwait(false);

            // Lifecycle hook: после старта движка «дожимаем» pending runtime-события.
            try
            {
                ReactiveTargetSync.Nudge();
            }
            catch
            {
                // best-effort
            }
        }

        public Task StopEngineAsync()
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            return _trafficEngine.StopAsync();
        }

        public async Task ApplyTlsOptionsAsync(TlsBypassOptions options, CancellationToken cancellationToken = default)
        {
            await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            Stopwatch? totalSw = null;
            var currentPhase = "enter";
            var corrText = "-";

            const long WarnNormalizeMs = 100;
            const long WarnUdpTargetsMs = 1500;
            const long WarnPolicyCompileMs = 300;
            const long WarnTlsApplyMs = 2500;
            const long WarnPostApplyMs = 500;
            const long WarnTotalMs = 3000;

            void LogPhase(string phase, long elapsedMs, long warnThresholdMs, string details = "")
            {
                try
                {
                    var warn = elapsedMs >= warnThresholdMs ? "WARN" : "OK";
                    var safeDetails = string.IsNullOrWhiteSpace(details) ? string.Empty : "; " + details;
                    _log?.Invoke($"[Bypass][ApplyTlsOptions] {warn}: phase={phase}; ms={elapsedMs}; corr={corrText}{safeDetails}");
                }
                catch
                {
                    // best-effort
                }
            }

            try
            {
                totalSw = Stopwatch.StartNew();

                var op = BypassOperationContext.Snapshot();
                var corr = op?.CorrelationId;
                corrText = string.IsNullOrWhiteSpace(corr) ? "-" : corr;

                currentPhase = "normalize";
                var normalizeSw = Stopwatch.StartNew();
                var normalized = options.Normalize();
                normalizeSw.Stop();

                // P0.1 Step 1: поддержка нескольких активных целей одновременно.
                // Пользователь может применить разные INTEL-планы для разных hostKey; рантайм должен
                // держать нужные «capabilities» включёнными (union), а decision graph выбирать действие по пакету.
                var preferredHost = _outcomeTargetHost;
                var activeTargetPolicies = GetActiveTargetPoliciesSnapshot(preferredHost);

                LogPhase("normalize", normalizeSw.ElapsedMilliseconds, WarnNormalizeMs, $"anyEnabled={(normalized.IsAnyEnabled() ? "yes" : "no")}; activeTargets={activeTargetPolicies.Length}");

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

                currentPhase = "udp443_targets";
                var udpTargetsSw = Stopwatch.StartNew();

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

                udpTargetsSw.Stop();
                LogPhase(
                    "udp443_targets",
                    udpTargetsSw.ElapsedMilliseconds,
                    WarnUdpTargetsMs,
                    $"enabled={(effective.DropUdp443 ? "yes" : "no")}; global={(effective.DropUdp443Global ? "yes" : "no")}; targets={udp443Targets.Length}");

                // Policy-driven execution plane (P0.2): компилируем snapshot только при включённых gate.
                // При gate=off не меняем runtime-поведение: фильтр использует legacy ветки.
                currentPhase = "policy_compile";
                var policySw = Stopwatch.StartNew();
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

                        // P1.12: подмешиваем пользовательские политики в конец списка.
                        // Порядок не влияет на выбор, так как DecisionGraph сортирует по Priority desc.
                        // Важно: ошибки компиляции (hard-conflict) приведут к fallback на legacy.
                        var userPolicies = GetUserFlowPoliciesSnapshot();
                        if (userPolicies.Length > 0)
                        {
                            policies.AddRange(userPolicies);
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

                policySw.Stop();
                LogPhase(
                    "policy_compile",
                    policySw.ElapsedMilliseconds,
                    WarnPolicyCompileMs,
                    $"shouldCompile={(shouldCompileSnapshot ? "yes" : "no")}; hasSnapshot={(decisionSnapshot != null ? "yes" : "no")}");

                currentPhase = "tls_service_apply";
                var tlsApplySw = Stopwatch.StartNew();
                using var scope = BypassStateManagerGuard.EnterScope();
                _tlsService.SetUdp443DropTargetIpsForManager(udp443Targets);
                _tlsService.SetDecisionGraphSnapshotForManager(decisionSnapshot);
                await _tlsService.ApplyAsync(effective, cancellationToken).ConfigureAwait(false);
                tlsApplySw.Stop();
                LogPhase("tls_service_apply", tlsApplySw.ElapsedMilliseconds, WarnTlsApplyMs, $"effective={effective.ToReadableStrategy()}");

                currentPhase = "post_apply";
                var postSw = Stopwatch.StartNew();
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

                postSw.Stop();
                LogPhase("post_apply", postSw.ElapsedMilliseconds, WarnPostApplyMs);

                totalSw?.Stop();
                LogPhase("total", totalSw?.ElapsedMilliseconds ?? 0, WarnTotalMs);
            }
            catch (OperationCanceledException)
            {
                totalSw?.Stop();
                LogPhase("canceled", totalSw?.ElapsedMilliseconds ?? 0, warnThresholdMs: 0, $"at={currentPhase}");
                throw;
            }
            catch (Exception ex)
            {
                totalSw?.Stop();
                LogPhase("failed", totalSw?.ElapsedMilliseconds ?? 0, warnThresholdMs: 0, $"at={currentPhase}; error={ex.Message}");
                _log?.Invoke($"[Bypass][ApplyTlsOptions] FAILED; corr={corrText}; ex={ex}");
                throw;
            }
            finally
            {
                _applyGate.Release();

                // Lifecycle hook: Apply завершён (успех/rollback/fail) — пробуем доставить накопленные runtime-события.
                try
                {
                    ReactiveTargetSync.Nudge();
                }
                catch
                {
                    // best-effort
                }
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
                _lastEngineNotRunningUtc = DateTime.MinValue;
                ClearActiveTargetPolicies();
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

            try
            {
                ReactiveTargetSync.Dispose();
            }
            catch
            {
                // best-effort
            }

            _tlsService.Dispose();
            _applyGate.Dispose();
        }
    }
}
