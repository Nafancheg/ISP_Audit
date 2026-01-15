using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Windows;
using IspAudit;
using System.Windows.Media;
using System.Net;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Оркестратор диагностики.
    /// Координирует TrafficCollector и LiveTestingPipeline.
    /// Управляет жизненным циклом мониторинговых сервисов.
    /// </summary>
    public partial class DiagnosticOrchestrator : INotifyPropertyChanged
    {
        #region Private Methods

        private void AttachAutoBypassTelemetry(BypassController bypassController)
        {
            DetachAutoBypassTelemetry();
            _observedTlsService = bypassController.TlsService;
            _observedTlsService.MetricsUpdated += HandleAutoBypassMetrics;
            _observedTlsService.VerdictChanged += HandleAutoBypassVerdict;
            _observedTlsService.StateChanged += HandleAutoBypassState;
        }

        private void DetachAutoBypassTelemetry()
        {
            if (_observedTlsService == null) return;

            _observedTlsService.MetricsUpdated -= HandleAutoBypassMetrics;
            _observedTlsService.VerdictChanged -= HandleAutoBypassVerdict;
            _observedTlsService.StateChanged -= HandleAutoBypassState;
            _observedTlsService = null;
        }

        private void ResetAutoBypassUi(bool autoBypassEnabled)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                if (!autoBypassEnabled)
                {
                    UpdateAutoBypassStatus("Auto-bypass выключен", CreateBrush(243, 244, 246));
                    AutoBypassVerdict = "";
                    AutoBypassMetrics = "";
                    return;
                }

                UpdateAutoBypassStatus("Auto-bypass включается...", CreateBrush(254, 249, 195));
                AutoBypassVerdict = "";
                AutoBypassMetrics = "";
            });
        }

        private void HandleAutoBypassMetrics(TlsBypassMetrics metrics)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                AutoBypassMetrics =
                    $"Hello@443: {metrics.ClientHellosObserved}; <thr: {metrics.ClientHellosShort}; !=443: {metrics.ClientHellosNon443}; Frag: {metrics.ClientHellosFragmented}; RST: {metrics.RstDroppedRelevant}; План: {metrics.Plan}; Пресет: {metrics.PresetName}; с {metrics.Since}";
                // Для v2 дополнительно выводим, что QUIC реально глушится.
                if (metrics.Udp443Dropped > 0)
                {
                    AutoBypassMetrics += $"; UDP443 drop: {metrics.Udp443Dropped}";
                }
            });
        }

        private void HandleAutoBypassVerdict(TlsBypassVerdict verdict)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                AutoBypassVerdict = verdict.Text;
                AutoBypassStatusBrush = verdict.Color switch
                {
                    VerdictColor.Green => CreateBrush(220, 252, 231),
                    VerdictColor.Yellow => CreateBrush(254, 249, 195),
                    VerdictColor.Red => CreateBrush(254, 226, 226),
                    _ => CreateBrush(243, 244, 246)
                };
            });
        }

        private void HandleAutoBypassState(TlsBypassState state)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                var planText = string.IsNullOrWhiteSpace(state.Plan) ? "-" : state.Plan;
                var statusText = state.IsActive
                    ? $"Auto-bypass активен (план: {planText})"
                    : "Auto-bypass выключен";

                UpdateAutoBypassStatus(statusText, state.IsActive ? CreateBrush(220, 252, 231) : CreateBrush(243, 244, 246));
            });
        }

        private void UpdateAutoBypassStatus(string status, System.Windows.Media.Brush brush)
        {
            AutoBypassStatus = status;
            AutoBypassStatusBrush = brush;
        }

        private static System.Windows.Media.Brush CreateBrush(byte r, byte g, byte b)
        {
            return new SolidColorBrush(System.Windows.Media.Color.FromRgb(r, g, b));
        }

        #endregion
    }
}
