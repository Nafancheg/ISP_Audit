using System;
using System.Collections.Generic;
using System.Threading;
using System.IO;
using System.Runtime.CompilerServices;
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

        private static readonly TimeSpan WatchdogDefaultTick = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan WatchdogDefaultStale = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan WatchdogEngineGrace = TimeSpan.FromSeconds(15);

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
            _tlsService.MetricsUpdated += _ =>
            {
                var snapshot = _tlsService.GetOptionsSnapshot();
                if (snapshot.IsAnyEnabled())
                {
                    _lastMetricsEventUtc = DateTime.UtcNow;
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
                var snapshot = _tlsService.GetOptionsSnapshot();
                if (snapshot.IsAnyEnabled())
                {
                    _lastMetricsEventUtc = DateTime.UtcNow;
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
                using var scope = BypassStateManagerGuard.EnterScope();
                var normalized = options.Normalize();
                await _tlsService.ApplyAsync(normalized, cancellationToken).ConfigureAwait(false);

                if (normalized.IsAnyEnabled())
                {
                    _lastBypassActivatedUtc = DateTime.UtcNow;
                    _lastMetricsEventUtc = DateTime.UtcNow;
                    _journal.SetBypassActive(true, "apply");
                }
                else
                {
                    _journal.SetBypassActive(false, "apply_disable");
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

            _tlsService.Dispose();
            _applyGate.Dispose();
        }
    }
}
