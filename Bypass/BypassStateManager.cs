using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
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
