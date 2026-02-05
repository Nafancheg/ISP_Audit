using System;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
        private System.Threading.Timer? _watchdogTimer;
        private volatile bool _watchdogInitialized;
        private DateTime _lastMetricsEventUtc = DateTime.MinValue;
        private DateTime _lastBypassActivatedUtc = DateTime.MinValue;
        private DateTime _lastEngineNotRunningUtc = DateTime.MinValue;
        private DateTime _lastMetricsSnapshotUtc = DateTime.MinValue;
        private TlsBypassMetrics? _lastMetricsSnapshot;

        private static readonly TimeSpan WatchdogDefaultTick = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan WatchdogDefaultStale = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan WatchdogEngineGrace = TimeSpan.FromSeconds(15);

        private static int ReadMsEnv(string name, int fallback)
        {
            try
            {
                if (!IspAudit.Utils.EnvVar.TryReadInt32(name, out var v)) return fallback;
                return v > 0 ? v : fallback;
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
                if (!IspAudit.Utils.EnvVar.TryReadInt32(name, out var v)) return fallback;
                return v >= 0 ? v : fallback;
            }
            catch
            {
                return fallback;
            }
        }

        private void StartWatchdogTimer()
        {
            if (_watchdogTimer != null) return;

            var tick = ReadMsEnv("ISP_AUDIT_WATCHDOG_TICK_MS", (int)WatchdogDefaultTick.TotalMilliseconds);
            _watchdogTimer = new System.Threading.Timer(_ => _ = WatchdogTickAsync(), null, dueTime: tick, period: tick);
        }

        private async Task WatchdogTickAsync()
        {
            try
            {
                var snapshot = _tlsService.GetOptionsSnapshot();
                if (!snapshot.IsAnyEnabled())
                {
                    _lastEngineNotRunningUtc = DateTime.MinValue;
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

                // Если движок не запущен слишком долго при активном bypass — отключаем (обычно означает проблему с WinDivert/правами).
                if (_trafficEngine.IsRunning)
                {
                    _lastEngineNotRunningUtc = DateTime.MinValue;
                    return;
                }

                if (_lastEngineNotRunningUtc == DateTime.MinValue)
                {
                    _lastEngineNotRunningUtc = nowUtc;
                    return;
                }

                if ((nowUtc - _lastEngineNotRunningUtc) > WatchdogEngineGrace)
                {
                    _log?.Invoke("[Bypass][Watchdog] engine_dead: bypass активен, но TrafficEngine не запущен — выполняем Disable");
                    await DisableTlsAsync("engine_dead", CancellationToken.None).ConfigureAwait(false);
                    return;
                }
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass][Watchdog] Ошибка watchdog: {ex.Message}");
            }
        }
    }
}
