using System;
using System.Threading.Tasks;
using IspAudit.Core.Traffic;
using IspAudit.Utils;
using IspAudit.Wpf;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        /// <summary>
        /// Инициализация bypass и DoH при запуске приложения
        /// </summary>
        public async Task InitializeOnStartupAsync()
        {
            // Проверка VPN
            CheckVpnStatus();

            // Crash recovery + watchdog инициализируем всегда (даже без admin),
            // чтобы корректно обработать некорректно завершённую прошлую сессию.
            try
            {
                await _stateManager.InitializeOnStartupAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log($"[Bypass][Watchdog] Init failed: {ex.Message}");
            }

            // Crash-recovery (P0): если предыдущая сессия меняла DNS/DoH и не успела откатиться,
            // пытаемся восстановить настройки сразу при старте.
            try
            {
                if (FixService.HasBackupFile)
                {
                    if (TrafficEngine.HasAdministratorRights)
                    {
                        Log("[DoH] Detected leftover DNS backup from previous session. Restoring...");
                        var (success, error) = await FixService.RestoreDnsAsync(reason: "startup_crash_recovery").ConfigureAwait(false);
                        Log(success ? "[DoH] DNS restored on startup (crash recovery)." : $"[DoH] Startup restore failed: {error}");
                    }
                    else
                    {
                        Log("[DoH] Detected leftover DNS backup, but no admin rights to restore.");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[DoH] Startup restore exception: {ex.Message}");
            }

            if (!TrafficEngine.HasAdministratorRights)
            {
                Log("[Bypass] No admin rights - bypass not available");
                return;
            }

            try
            {
                Log("[Bypass] Initializing bypass on application startup...");

                // Автоматическое включение отключено по результатам аудита (риск скрытого поведения)
                // _isDisorderEnabled = true;
                // _isFragmentEnabled = false;
                // _isDropRstEnabled = true;

                // Не включаем DoH автоматически по наличию backup.
                // Backup может означать незавершённую прошлую сессию (мы уже попытались восстановить выше).

                // Проверяем текущее состояние DNS (в фоновом потоке, чтобы не фризить UI)
                var activePreset = await Task.Run(() => FixService.DetectActivePreset());

                if (activePreset != null)
                {
                    // Меняем выбранный пресет ТОЛЬКО если есть backup (то есть это состояние выставляло приложение).
                    // Если backup нет, совпадение DNS может быть «чужим» или результатом старой/нечистой сессии,
                    // и мы не должны автоматически переключать выбор пользователя на Cloudflare/Google и т.п.
                    if (FixService.HasBackupFile)
                    {
                        _selectedDnsPreset = activePreset;
                        OnPropertyChanged(nameof(SelectedDnsPreset));
                        _isDoHEnabled = true;
                        OnPropertyChanged(nameof(IsDoHEnabled));
                        Log($"[Bypass] Detected active DoH preset (restorable): {activePreset}");
                    }
                    else
                    {
                        // Если бэкапа нет — просто логируем факт, но не меняем preset и не включаем DoH.
                        if (_isDoHEnabled)
                        {
                            _isDoHEnabled = false;
                            OnPropertyChanged(nameof(IsDoHEnabled));
                        }
                        Log($"[Bypass] Detected active DNS provider: {activePreset} (DoH not confirmed)");
                    }
                }
                else
                {
                    // Если пресет не обнаружен, снимаем галочку (даже если был бэкап, значит состояние рассинхронизировано)
                    if (_isDoHEnabled)
                    {
                        _isDoHEnabled = false;
                        OnPropertyChanged(nameof(IsDoHEnabled));
                    }
                }

                OnPropertyChanged(nameof(IsDisorderEnabled));
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                // IsDoHEnabled уже обновлен выше

                // Проверяем совместимость после включения опций
                CheckCompatibility();

                // Применяем WinDivert bypass
                await ApplyBypassOptionsAsync().ConfigureAwait(false);

                Log($"[Bypass] Startup complete: {_currentOptions.ToReadableStrategy()}");
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Failed to initialize bypass on startup: {ex.Message}");
            }
        }
    }
}
