using System;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        private sealed record BypassStateSnapshot(TlsBypassOptions Options, bool DoHEnabled, string SelectedDnsPreset);

        private BypassStateSnapshot CaptureStateSnapshot()
        {
            return new BypassStateSnapshot(_currentOptions, _isDoHEnabled, SelectedDnsPreset);
        }

        private async Task RestoreSnapshotAsync(BypassStateSnapshot snapshot)
        {
            _currentOptions = snapshot.Options;
            _isDoHEnabled = snapshot.DoHEnabled;
            _selectedDnsPreset = snapshot.SelectedDnsPreset;

            Application.Current?.Dispatcher.Invoke(() =>
            {
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDisorderEnabled));
                OnPropertyChanged(nameof(IsFakeEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                OnPropertyChanged(nameof(IsDoHEnabled));
                OnPropertyChanged(nameof(IsDoHActive));
                OnPropertyChanged(nameof(SelectedDnsPreset));
                NotifyActiveStatesChanged();
                CheckCompatibility();
            });

            await ApplyBypassOptionsAsync(CancellationToken.None).ConfigureAwait(false);

            if (_isDoHEnabled)
            {
                await ApplyDoHAsync().ConfigureAwait(false);
            }
            else
            {
                await DisableDoHAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Применить текущие настройки bypass
        /// </summary>
        public Task ApplyBypassOptionsAsync()
        {
            return ApplyBypassOptionsAsync(CancellationToken.None);
        }

        /// <summary>
        /// Применить текущие настройки bypass (с поддержкой отмены)
        /// </summary>
        public async Task ApplyBypassOptionsAsync(CancellationToken cancellationToken)
        {
            try
            {
                using var op = BypassOperationContext.EnterIfNone("manual_apply");
                var normalized = _currentOptions.Normalize();
                _currentOptions = normalized;
                await _stateManager.ApplyTlsOptionsAsync(normalized, cancellationToken).ConfigureAwait(false);

                SafeUiInvoke(NotifyActiveStatesChanged);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Error applying options: {ex.Message}");
            }
        }

        private static void SafeUiInvoke(Action action)
        {
            try
            {
                var dispatcher = Application.Current?.Dispatcher;
                if (dispatcher == null || dispatcher.HasShutdownStarted || dispatcher.HasShutdownFinished)
                {
                    action();
                    return;
                }

                if (dispatcher.CheckAccess())
                {
                    action();
                }
                else
                {
                    dispatcher.BeginInvoke(action);
                }
            }
            catch
            {
                // ignore
            }
        }

        /// <summary>
        /// Отключить все опции bypass
        /// </summary>
        public Task DisableAllAsync()
        {
            return DisableAllAsync(CancellationToken.None);
        }

        /// <summary>
        /// Отключить все опции bypass (с поддержкой отмены)
        /// </summary>
        public async Task DisableAllAsync(CancellationToken cancellationToken)
        {
            _currentOptions = _currentOptions with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false,
                DropUdp443 = false,
                AllowNoSni = false
            };

            OnPropertyChanged(nameof(IsFragmentEnabled));
            OnPropertyChanged(nameof(IsDisorderEnabled));
            OnPropertyChanged(nameof(IsFakeEnabled));
            OnPropertyChanged(nameof(IsDropRstEnabled));
            OnPropertyChanged(nameof(IsQuicFallbackEnabled));
            OnPropertyChanged(nameof(IsAllowNoSniEnabled));
            NotifyActiveStatesChanged();
            CheckCompatibility();

            using var op = BypassOperationContext.EnterIfNone("manual_disable_all");
            await ApplyBypassOptionsAsync(cancellationToken).ConfigureAwait(false);
        }

        public string GetOutcomeTargetHost() => _stateManager.GetOutcomeTargetHost();

        public string OutcomeTargetHost => _stateManager.GetOutcomeTargetHost();

        public void SetOutcomeTargetHost(string? host)
        {
            _stateManager.SetOutcomeTargetHost(host);
            SafeUiInvoke(() => OnPropertyChanged(nameof(OutcomeTargetHost)));
        }
    }
}
