using System;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
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
    }
}
