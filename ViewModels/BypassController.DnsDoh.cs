using System;
using System.Threading.Tasks;
using IspAudit.Utils;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        /// <summary>
        /// Применить DoH (DNS-over-HTTPS)
        /// </summary>
        public async Task ApplyDoHAsync()
        {
            try
            {
                string presetName = SelectedDnsPreset;
                Log($"[DoH] Applying DNS-over-HTTPS ({presetName})...");

                var (success, error) = await FixService.ApplyDnsFixAsync(presetName, reason: "ui_toggle_doh_enable").ConfigureAwait(false);

                SafeUiInvoke(() =>
                {
                    if (success)
                    {
                        Log($"[DoH] DoH enabled: {presetName}");
                    }
                    else
                    {
                        Log($"[DoH] Failed: {error}");
                        _isDoHEnabled = false;
                        OnPropertyChanged(nameof(IsDoHEnabled));
                        OnPropertyChanged(nameof(IsDoHActive));
                    }
                });
            }
            catch (Exception ex)
            {
                Log($"[DoH] Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Восстановить исходные настройки DNS
        /// </summary>
        public async Task RestoreDoHAsync()
        {
            try
            {
                Log("[DoH] Restoring original DNS settings...");
                var (success, error) = await FixService.RestoreDnsAsync(reason: "ui_toggle_doh_restore").ConfigureAwait(false);

                SafeUiInvoke(() =>
                {
                    if (success)
                    {
                        Log("[DoH] DNS settings restored.");
                    }
                    else
                    {
                        Log($"[DoH] Restore failed: {error}");
                    }
                    OnPropertyChanged(nameof(IsDoHActive));
                });
            }
            catch (Exception ex)
            {
                Log($"[DoH] Error restoring DNS: {ex.Message}");
            }
        }

        /// <summary>
        /// Отключить DoH и восстановить исходные DNS настройки.
        /// </summary>
        public async Task DisableDoHAsync()
        {
            if (!_isDoHEnabled)
            {
                return;
            }

            _isDoHEnabled = false;

            SafeUiInvoke(() =>
            {
                OnPropertyChanged(nameof(IsDoHEnabled));
                OnPropertyChanged(nameof(IsDoHActive));
            });

            await RestoreDoHAsync().ConfigureAwait(false);
        }
    }
}
