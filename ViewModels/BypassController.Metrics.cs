using System;
using System.Windows.Media;
using IspAudit.Bypass;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        private void OnMetricsUpdated(TlsBypassMetrics metrics)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                _currentOptions = _stateManager.GetOptionsSnapshot();
                OnPropertyChanged(nameof(SelectedFragmentPresetLabel));

                var plan = string.IsNullOrWhiteSpace(metrics.Plan) ? "-" : metrics.Plan;
                var planWithPreset = string.IsNullOrWhiteSpace(metrics.PresetName) ? plan : $"{plan} · {metrics.PresetName}";
                BypassPlanText = string.IsNullOrWhiteSpace(planWithPreset) ? "-" : planWithPreset;
                BypassMetricsSince = metrics.Since;

                var activation = _stateManager.GetActivationStatusSnapshot();
                var outcome = _stateManager.GetOutcomeStatusSnapshot();
                BypassMetricsText =
                    $"ACT: {activation.Text}; OUT: {outcome.Text}; TLS: {metrics.TlsHandled}; thr: {metrics.FragmentThreshold}; min: {metrics.MinChunk}; Hello@443: {metrics.ClientHellosObserved}; <thr: {metrics.ClientHellosShort}; !=443: {metrics.ClientHellosNon443}; фрагм.: {metrics.ClientHellosFragmented}; UDP443 drop: {metrics.Udp443Dropped}; RST(443,bypass): {metrics.RstDroppedRelevant}; RST(всего): {metrics.RstDropped}";

                BypassSemanticGroupsText = metrics.SemanticGroupsStatusText ?? string.Empty;
                BypassSemanticGroupsSummaryText = metrics.SemanticGroupsSummaryText ?? string.Empty;

                RefreshQuicObservability(metrics);
            });
        }

        private void OnVerdictChanged(TlsBypassVerdict verdict)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                BypassVerdictText = verdict.Text;
                BypassVerdictReason = verdict.Reason;
                BypassVerdictBrush = verdict.Color switch
                {
                    VerdictColor.Green => new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 252, 231)),
                    VerdictColor.Yellow => new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 249, 195)),
                    VerdictColor.Red => new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 226, 226)),
                    _ => new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246))
                };
            });
        }

        private void OnStateChanged(TlsBypassState state)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                var oldOptions = _currentOptions;
                _currentOptions = _stateManager.GetOptionsSnapshot();
                IsBypassActive = state.IsActive;

                var planWithPreset = string.IsNullOrWhiteSpace(state.Plan)
                    ? _currentOptions.PresetName
                    : $"{state.Plan} · {_currentOptions.PresetName}";
                BypassPlanText = string.IsNullOrWhiteSpace(planWithPreset) ? "-" : planWithPreset;
                BypassMetricsSince = state.Since;

                if (oldOptions.FragmentEnabled != _currentOptions.FragmentEnabled) OnPropertyChanged(nameof(IsFragmentEnabled));
                if (oldOptions.DisorderEnabled != _currentOptions.DisorderEnabled) OnPropertyChanged(nameof(IsDisorderEnabled));
                if (oldOptions.FakeEnabled != _currentOptions.FakeEnabled) OnPropertyChanged(nameof(IsFakeEnabled));
                if (oldOptions.DropRstEnabled != _currentOptions.DropRstEnabled) OnPropertyChanged(nameof(IsDropRstEnabled));
                if (oldOptions.DropUdp443 != _currentOptions.DropUdp443) OnPropertyChanged(nameof(IsQuicFallbackEnabled));
                if (oldOptions.DropUdp443Global != _currentOptions.DropUdp443Global) OnPropertyChanged(nameof(IsQuicFallbackGlobal));
                if (oldOptions.AllowNoSni != _currentOptions.AllowNoSni) OnPropertyChanged(nameof(IsAllowNoSniEnabled));

                OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                CheckCompatibility();
                NotifyActiveStatesChanged();

                RefreshQuicObservability(null);
            });
        }
    }
}
