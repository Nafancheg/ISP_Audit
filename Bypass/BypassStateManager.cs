using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Net;
using IspAudit.Core.Traffic;

namespace IspAudit.Bypass
{
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
    public sealed class BypassStateManager : IDisposable
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
        private System.Threading.Timer? _watchdogTimer;
        private volatile bool _watchdogInitialized;
        private DateTime _lastMetricsEventUtc = DateTime.MinValue;
        private DateTime _lastBypassActivatedUtc = DateTime.MinValue;
        private DateTime _lastMetricsSnapshotUtc = DateTime.MinValue;
        private TlsBypassMetrics? _lastMetricsSnapshot;

        private string _outcomeTargetHost = string.Empty;
        private OutcomeStatusSnapshot _lastOutcomeSnapshot = new(OutcomeStatus.Unknown, "UNKNOWN", "нет данных");
        private CancellationTokenSource? _outcomeCts;
        private Func<string, CancellationToken, Task<OutcomeStatusSnapshot>>? _outcomeProbeOverrideForSmoke;

        // 2.V2.17: селективный QUIC fallback (DROP UDP/443) — храним observed IPv4 адреса цели по host.
        // TTL/cap нужны, чтобы:
        // - не раздувать состояние
        // - автоматически обновляться при смене IP у цели
        private static readonly TimeSpan Udp443DropTargetIpTtl = TimeSpan.FromMinutes(10);
        private const int Udp443DropTargetIpCap = 16;
        private readonly ConcurrentDictionary<string, ObservedIpsEntry> _udp443DropObservedIpsByHost = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan WatchdogDefaultTick = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan WatchdogDefaultStale = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan WatchdogEngineGrace = TimeSpan.FromSeconds(15);

        private static readonly TimeSpan ActivationDefaultWarmup = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan ActivationDefaultNoTraffic = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan ActivationDefaultStale = TimeSpan.FromSeconds(120);

        private static readonly TimeSpan OutcomeDefaultDelay = TimeSpan.FromSeconds(12);
        private static readonly TimeSpan OutcomeDefaultTimeout = TimeSpan.FromSeconds(6);
        private static readonly TimeSpan OutcomeProbeFlowTtl = TimeSpan.FromSeconds(30);

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

        public async Task InitializeOnStartupAsync(CancellationToken cancellationToken = default)
        {
            if (_watchdogInitialized) return;
            _watchdogInitialized = true;

            _journal.MarkSessionStarted();

            // Crash recovery: если в прошлой сессии bypass был активен и не было clean shutdown — принудительно выключаем.
            if (_journal.StartupWasUncleanAndBypassActive)
            {
                _log?.Invoke("[Bypass][Watchdog] crash_recovery: обнаружена некорректно завершённая сессия при активном bypass — выполняем Disable");
                try
                {
                    await DisableTlsAsync("crash_recovery", cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _log?.Invoke($"[Bypass][Watchdog] crash_recovery: ошибка Disable: {ex.Message}");
                }
            }

            StartWatchdogTimer();
        }

        public void MarkCleanShutdown()
        {
            // Важно: отмечаем clean shutdown независимо от прав администратора.
            _journal.MarkCleanShutdown("clean_shutdown");
        }

        private void StartWatchdogTimer()
        {
            if (_watchdogTimer != null) return;

            var tick = ReadMsEnv("ISP_AUDIT_WATCHDOG_TICK_MS", (int)WatchdogDefaultTick.TotalMilliseconds);
            _watchdogTimer = new System.Threading.Timer(_ => _ = WatchdogTickAsync(), null, dueTime: tick, period: tick);
        }

        private static int ReadMsEnv(string name, int fallback)
        {
            try
            {
                var raw = Environment.GetEnvironmentVariable(name);
                if (string.IsNullOrWhiteSpace(raw)) return fallback;
                return int.TryParse(raw, out var v) && v > 0 ? v : fallback;
            }
            catch
            {
                return fallback;
            }
        }

        private static int ReadMsEnvAllowZero(string name, int fallback)
        {
            try
            {
                var raw = Environment.GetEnvironmentVariable(name);
                if (string.IsNullOrWhiteSpace(raw)) return fallback;
                return int.TryParse(raw, out var v) && v >= 0 ? v : fallback;
            }
            catch
            {
                return fallback;
            }
        }

        private async Task WatchdogTickAsync()
        {
            try
            {
                var snapshot = _tlsService.GetOptionsSnapshot();
                if (!snapshot.IsAnyEnabled())
                {
                    return;
                }

                // Отмечаем, что bypass активен в текущей сессии (важно для crash recovery).
                _journal.SetBypassActive(true, "bypass_active");

                var nowUtc = DateTime.UtcNow;
                var staleMs = ReadMsEnv("ISP_AUDIT_WATCHDOG_STALE_MS", (int)WatchdogDefaultStale.TotalMilliseconds);
                var stale = TimeSpan.FromMilliseconds(staleMs);

                // Если bypass активен, но метрики/heartbeat не обновлялись слишком долго — fail-safe отключаем.
                if (_lastMetricsEventUtc != DateTime.MinValue && (nowUtc - _lastMetricsEventUtc) > stale)
                {
                    _log?.Invoke($"[Bypass][Watchdog] watchdog_timeout: нет heartbeat/метрик {(nowUtc - _lastMetricsEventUtc).TotalSeconds:F0}с — выполняем Disable");
                    await DisableTlsAsync("watchdog_timeout", CancellationToken.None).ConfigureAwait(false);
                    return;
                }

                // Если движок не запущен после активации bypass — отключаем (обычно означает проблему с WinDivert/правами).
                if (!_trafficEngine.IsRunning)
                {
                    if (_lastBypassActivatedUtc == DateTime.MinValue)
                    {
                        _lastBypassActivatedUtc = nowUtc;
                        return;
                    }

                    if ((nowUtc - _lastBypassActivatedUtc) > WatchdogEngineGrace)
                    {
                        _log?.Invoke("[Bypass][Watchdog] engine_dead: bypass активен, но TrafficEngine не запущен — выполняем Disable");
                        await DisableTlsAsync("engine_dead", CancellationToken.None).ConfigureAwait(false);
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass][Watchdog] Ошибка watchdog: {ex.Message}");
            }
        }

        public TlsBypassOptions GetOptionsSnapshot() => _tlsService.GetOptionsSnapshot();

        /// <summary>
        /// Задать цель для outcome-check (обычно — hostKey последнего v2 плана/диагноза).
        /// Если цель не задана, outcome остаётся UNKNOWN.
        /// </summary>
        public void SetOutcomeTargetHost(string? host)
        {
            _outcomeTargetHost = (host ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(_outcomeTargetHost))
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "нет цели для outcome-check");
            }
        }

        public string GetOutcomeTargetHost() => _outcomeTargetHost;

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

        public OutcomeStatusSnapshot GetOutcomeStatusSnapshot()
        {
            var options = _tlsService.GetOptionsSnapshot();
            if (!options.IsAnyEnabled())
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "bypass отключён");
            }

            return _lastOutcomeSnapshot;
        }

        /// <summary>
        /// Немедленно выполняет outcome-probe (без delay), чтобы переоценить доступность цели.
        /// Используется для staged revalidation при смене сети.
        /// </summary>
        public async Task<OutcomeStatusSnapshot> RunOutcomeProbeNowAsync(
            string? hostOverride = null,
            TimeSpan? timeoutOverride = null,
            CancellationToken cancellationToken = default)
        {
            var options = _tlsService.GetOptionsSnapshot();
            if (!options.IsAnyEnabled())
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "bypass отключён");
                return _lastOutcomeSnapshot;
            }

            var host = string.IsNullOrWhiteSpace(hostOverride)
                ? _outcomeTargetHost
                : (hostOverride ?? string.Empty).Trim();

            if (string.IsNullOrWhiteSpace(host))
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "нет цели для outcome-check");
                return _lastOutcomeSnapshot;
            }

            // Отменяем отложенную проверку (если была запланирована), и выполняем probe прямо сейчас.
            CancelOutcomeProbe();

            var timeoutMs = ReadMsEnvAllowZero("ISP_AUDIT_OUTCOME_TIMEOUT_MS", (int)OutcomeDefaultTimeout.TotalMilliseconds);
            var timeout = timeoutOverride ?? TimeSpan.FromMilliseconds(timeoutMs);

            _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "выполняю outcome-probe");

            try
            {
                var snapshot = await RunOutcomeProbeAsync(host, timeout, cancellationToken).ConfigureAwait(false);
                _lastOutcomeSnapshot = snapshot;
                return snapshot;
            }
            catch (OperationCanceledException)
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "outcome-probe отменён");
                return _lastOutcomeSnapshot;
            }
            catch (Exception ex)
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"outcome-probe error: {ex.Message}");
                return _lastOutcomeSnapshot;
            }
        }

        internal void SetOutcomeProbeForSmoke(Func<string, CancellationToken, Task<OutcomeStatusSnapshot>> probe)
        {
            _outcomeProbeOverrideForSmoke = probe;
        }

        public ActivationStatusSnapshot GetActivationStatusSnapshot()
        {
            var options = _tlsService.GetOptionsSnapshot();
            if (!options.IsAnyEnabled())
            {
                return new ActivationStatusSnapshot(ActivationStatus.Unknown, "BYPASS OFF", "bypass отключён");
            }

            var nowUtc = DateTime.UtcNow;

            var engineGraceMs = ReadMsEnvAllowZero("ISP_AUDIT_ACTIVATION_ENGINE_GRACE_MS", (int)ActivationDefaultWarmup.TotalMilliseconds);
            var warmupMs = ReadMsEnvAllowZero("ISP_AUDIT_ACTIVATION_WARMUP_MS", (int)ActivationDefaultWarmup.TotalMilliseconds);
            var noTrafficMs = ReadMsEnvAllowZero("ISP_AUDIT_ACTIVATION_NO_TRAFFIC_MS", (int)ActivationDefaultNoTraffic.TotalMilliseconds);
            var staleMs = ReadMsEnvAllowZero("ISP_AUDIT_ACTIVATION_STALE_MS", (int)ActivationDefaultStale.TotalMilliseconds);

            var engineGrace = TimeSpan.FromMilliseconds(engineGraceMs);
            var warmup = TimeSpan.FromMilliseconds(warmupMs);
            var noTraffic = TimeSpan.FromMilliseconds(noTrafficMs);
            var stale = TimeSpan.FromMilliseconds(staleMs);

            // ENGINE_DEAD: движок не запущен после grace.
            if (!_trafficEngine.IsRunning && _lastBypassActivatedUtc != DateTime.MinValue && (nowUtc - _lastBypassActivatedUtc) >= engineGrace)
            {
                return new ActivationStatusSnapshot(ActivationStatus.EngineDead, "ENGINE_DEAD", "TrafficEngine не запущен");
            }

            // Если метрики не обновлялись слишком долго — считаем, что движок/фильтр не жив.
            if (_lastMetricsSnapshotUtc != DateTime.MinValue && (nowUtc - _lastMetricsSnapshotUtc) >= stale)
            {
                return new ActivationStatusSnapshot(ActivationStatus.EngineDead, "ENGINE_DEAD", $"нет обновлений метрик {(nowUtc - _lastMetricsSnapshotUtc).TotalSeconds:F0}с");
            }

            var metrics = _lastMetricsSnapshot;
            if (metrics == null)
            {
                return new ActivationStatusSnapshot(ActivationStatus.Unknown, "UNKNOWN", "нет снимка метрик");
            }

            // NO_TRAFFIC: пользователь не генерирует релевантный трафик (TLS@443).
            if (metrics.ClientHellosObserved == 0)
            {
                if (_lastBypassActivatedUtc != DateTime.MinValue && (nowUtc - _lastBypassActivatedUtc) >= noTraffic)
                {
                    return new ActivationStatusSnapshot(ActivationStatus.NoTraffic, "NO_TRAFFIC", "нет ClientHello@443 — откройте HTTPS/игру");
                }

                return new ActivationStatusSnapshot(ActivationStatus.Unknown, "UNKNOWN", "нет TLS@443 (ожидание трафика)");
            }

            // ACTIVATED: видим любые признаки работы фильтра на релевантном трафике.
            var hasEffect =
                metrics.TlsHandled > 0 ||
                metrics.ClientHellosFragmented > 0 ||
                metrics.Udp443Dropped > 0 ||
                metrics.RstDroppedRelevant > 0 ||
                metrics.RstDropped > 0;

            if (hasEffect)
            {
                return new ActivationStatusSnapshot(ActivationStatus.Activated, "ACTIVATED",
                    $"tlsHandled={metrics.TlsHandled}, fragmented={metrics.ClientHellosFragmented}, udp443Drop={metrics.Udp443Dropped}, rst443={metrics.RstDroppedRelevant}");
            }

            // NOT_ACTIVATED: трафик есть, но эффекта нет после warmup.
            if (_lastBypassActivatedUtc != DateTime.MinValue && (nowUtc - _lastBypassActivatedUtc) >= warmup)
            {
                return new ActivationStatusSnapshot(ActivationStatus.NotActivated, "NOT_ACTIVATED", "трафик есть, но нет эффекта по метрикам");
            }

            return new ActivationStatusSnapshot(ActivationStatus.Unknown, "UNKNOWN", "ожидание эффекта (warmup)" );
        }

        internal void SetMetricsSnapshotForSmoke(TlsBypassMetrics metrics, DateTime? atUtc = null)
        {
            _lastMetricsSnapshot = metrics;
            _lastMetricsSnapshotUtc = atUtc ?? DateTime.UtcNow;
        }

        public void RegisterEngineFilter(IspAudit.Core.Traffic.IPacketFilter filter)
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            _trafficEngine.RegisterFilter(filter);
        }

        public void RemoveEngineFilter(string filterName)
        {
            using var scope = BypassStateManagerGuard.EnterScope();
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

                // DROP UDP/443:
                // - global: глушим весь UDP/443 (цель не нужна)
                // - selective: перед Apply подготавливаем observed IP цели
                // Важно: вычисляем вне manager-scope (нет доступа к TrafficEngine), чтобы не держать guard дольше.
                uint[] udp443Targets = Array.Empty<uint>();
                if (normalized.DropUdp443)
                {
                    if (normalized.DropUdp443Global)
                    {
                        _log?.Invoke("[Bypass] DROP UDP/443 включён (GLOBAL) — глушим весь UDP/443");
                    }
                    else
                    {
                        var host = _outcomeTargetHost;
                        if (!string.IsNullOrWhiteSpace(host))
                        {
                            udp443Targets = await GetOrSeedUdp443DropTargetsAsync(host, cancellationToken).ConfigureAwait(false);
                            if (udp443Targets.Length == 0)
                            {
                                _log?.Invoke("[Bypass] DROP UDP/443 включён, но IP цели не определены — UDP/443 не будет глушиться (селективный режим)");
                            }
                        }
                        else
                        {
                            _log?.Invoke("[Bypass] DROP UDP/443 включён, но цель (host) не задана — UDP/443 не будет глушиться (селективный режим)");
                        }
                    }
                }

                using var scope = BypassStateManagerGuard.EnterScope();
                _tlsService.SetUdp443DropTargetIpsForManager(udp443Targets);
                await _tlsService.ApplyAsync(normalized, cancellationToken).ConfigureAwait(false);

                if (normalized.IsAnyEnabled())
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

        private sealed class ObservedIpsEntry
        {
            public readonly object Sync = new();
            public readonly Dictionary<uint, long> UntilTickByIp = new();
        }

        private static long NowTick() => Environment.TickCount64;

        private static uint? TryToIpv4Int(IPAddress ip)
        {
            try
            {
                if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
                var bytes = ip.GetAddressBytes();
                if (bytes.Length != 4) return null;
                return BinaryPrimitives.ReadUInt32BigEndian(bytes);
            }
            catch
            {
                return null;
            }
        }

        private static void PruneExpired(ObservedIpsEntry entry, long nowTick)
        {
            if (entry.UntilTickByIp.Count == 0) return;

            List<uint>? toRemove = null;
            foreach (var kv in entry.UntilTickByIp)
            {
                if (nowTick > kv.Value)
                {
                    toRemove ??= new List<uint>();
                    toRemove.Add(kv.Key);
                }
            }

            if (toRemove == null) return;
            foreach (var ip in toRemove)
            {
                entry.UntilTickByIp.Remove(ip);
            }
        }

        private async Task<uint[]> GetOrSeedUdp443DropTargetsAsync(string host, CancellationToken cancellationToken)
        {
            host = (host ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(host)) return Array.Empty<uint>();

            var entry = _udp443DropObservedIpsByHost.GetOrAdd(host, _ => new ObservedIpsEntry());
            var now = NowTick();

            lock (entry.Sync)
            {
                PruneExpired(entry, now);
                if (entry.UntilTickByIp.Count > 0)
                {
                    var list = new List<uint>(entry.UntilTickByIp.Count);
                    foreach (var ip in entry.UntilTickByIp.Keys)
                    {
                        if (ip != 0) list.Add(ip);
                    }
                    return list.ToArray();
                }
            }

            // Cold-start seed: DNS resolve цели.
            IPAddress[] resolved;
            try
            {
                resolved = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return Array.Empty<uint>();
            }

            var found = new List<uint>();
            foreach (var ip in resolved)
            {
                var v4 = TryToIpv4Int(ip);
                if (v4 == null) continue;
                var value = v4.Value;
                if (value == 0) continue;
                if (found.Contains(value)) continue;
                found.Add(value);
                if (found.Count >= Udp443DropTargetIpCap) break;
            }

            if (found.Count == 0) return Array.Empty<uint>();

            var until = now + (long)Udp443DropTargetIpTtl.TotalMilliseconds;
            lock (entry.Sync)
            {
                PruneExpired(entry, now);

                foreach (var ip in found)
                {
                    entry.UntilTickByIp[ip] = until;
                }

                // Cap: если каким-то образом разрослось — урежем.
                if (entry.UntilTickByIp.Count > Udp443DropTargetIpCap)
                {
                    // Удаляем самые "старые" (раньше истекающие).
                    var ordered = new List<KeyValuePair<uint, long>>(entry.UntilTickByIp);
                    ordered.Sort((a, b) => a.Value.CompareTo(b.Value));
                    var extra = ordered.Count - Udp443DropTargetIpCap;
                    for (var i = 0; i < extra; i++)
                    {
                        entry.UntilTickByIp.Remove(ordered[i].Key);
                    }
                }

                var result = new List<uint>(entry.UntilTickByIp.Count);
                foreach (var ip in entry.UntilTickByIp.Keys)
                {
                    if (ip != 0) result.Add(ip);
                }
                return result.ToArray();
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

        private void CancelOutcomeProbe()
        {
            try
            {
                _outcomeCts?.Cancel();
                _outcomeCts?.Dispose();
            }
            catch
            {
                // ignore
            }
            finally
            {
                _outcomeCts = null;
            }
        }

        private void ScheduleOutcomeProbeIfPossible()
        {
            var host = _outcomeTargetHost;
            if (string.IsNullOrWhiteSpace(host))
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "нет цели для outcome-check");
                return;
            }

            CancelOutcomeProbe();
            _outcomeCts = new CancellationTokenSource();
            var ct = _outcomeCts.Token;

            var delayMs = ReadMsEnvAllowZero("ISP_AUDIT_OUTCOME_DELAY_MS", (int)OutcomeDefaultDelay.TotalMilliseconds);
            var timeoutMs = ReadMsEnvAllowZero("ISP_AUDIT_OUTCOME_TIMEOUT_MS", (int)OutcomeDefaultTimeout.TotalMilliseconds);

            var delay = TimeSpan.FromMilliseconds(delayMs);
            var timeout = TimeSpan.FromMilliseconds(timeoutMs);

            _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "ожидание outcome-probe");

            _ = Task.Run(async () =>
            {
                try
                {
                    if (delay > TimeSpan.Zero)
                    {
                        await Task.Delay(delay, ct).ConfigureAwait(false);
                    }

                    var snapshot = await RunOutcomeProbeAsync(host, timeout, ct).ConfigureAwait(false);
                    _lastOutcomeSnapshot = snapshot;
                }
                catch (OperationCanceledException)
                {
                    _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "outcome-probe отменён");
                }
                catch (Exception ex)
                {
                    _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"outcome-probe error: {ex.Message}");
                }
            }, CancellationToken.None);
        }

        private async Task<OutcomeStatusSnapshot> RunOutcomeProbeAsync(string host, TimeSpan timeout, CancellationToken cancellationToken)
        {
            // Smoke-хук: детерминированная подмена, без реальной сети.
            if (_outcomeProbeOverrideForSmoke != null)
            {
                return await _outcomeProbeOverrideForSmoke(host, cancellationToken).ConfigureAwait(false);
            }

            return await HttpsOutcomeProbe.RunAsync(
                host,
                onConnected: (local, remote) =>
                {
                    // Регистрируем flow в фильтре, чтобы probe не попадал в пользовательские метрики.
                    _tlsService.RegisterOutcomeProbeFlow(local, remote, OutcomeProbeFlowTtl);
                },
                timeout: timeout,
                cancellationToken: cancellationToken).ConfigureAwait(false);
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
