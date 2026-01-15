using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using IspAudit.Bypass;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        private void RefreshQuicObservability(TlsBypassMetrics? latestMetrics)
        {
            try
            {
                var host = _stateManager.GetOutcomeTargetHost();
                var ipCount = _stateManager.GetUdp443DropTargetIpCountSnapshot();

                if (!IsQuicFallbackEnabled)
                {
                    QuicModeText = "QUIC→TCP: выключен";
                    QuicRuntimeStatusText = "UDP/443 не глушится";
                    QuicRuntimeStatusBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246));
                    return;
                }

                if (IsQuicFallbackGlobal)
                {
                    QuicModeText = "QUIC→TCP: ВКЛ (GLOBAL) — глушим весь UDP/443";
                }
                else
                {
                    var targetText = string.IsNullOrWhiteSpace(host) ? "цель не задана" : host;
                    QuicModeText = $"QUIC→TCP: ВКЛ (селективно) — цель: {targetText}; IPv4 IPs: {ipCount}";
                }

                if (latestMetrics == null)
                {
                    QuicRuntimeStatusText = "Ожидаю метрики…";
                    QuicRuntimeStatusBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246));
                    return;
                }

                var nowUtc = DateTime.UtcNow;
                var totalDropped = latestMetrics.Udp443Dropped;
                var delta = totalDropped - _lastUdp443Dropped;
                if (delta < 0) delta = 0;

                if (delta > 0)
                {
                    _lastUdp443DroppedUtc = nowUtc;
                    QuicRuntimeStatusText = $"UDP/443 глушится: +{delta} (всего {totalDropped})";
                    QuicRuntimeStatusBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 252, 231));
                }
                else
                {
                    var age = _lastUdp443DroppedUtc == DateTime.MinValue ? TimeSpan.MaxValue : (nowUtc - _lastUdp443DroppedUtc);
                    if (age <= TimeSpan.FromSeconds(15))
                    {
                        QuicRuntimeStatusText = $"UDP/443 глушится (недавно), всего {totalDropped}";
                        QuicRuntimeStatusBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 252, 231));
                    }
                    else
                    {
                        var hint = IsQuicFallbackGlobal
                            ? "нет QUIC трафика или браузер уже на TCP"
                            : "нет QUIC трафика или не та цель (селективный режим)";
                        QuicRuntimeStatusText = $"Нет эффекта по UDP/443 (всего {totalDropped}) — {hint}";
                        QuicRuntimeStatusBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 249, 195));
                    }
                }

                _lastUdp443Dropped = totalDropped;
            }
            catch
            {
                // Наблюдаемость не должна ломать UI
            }
        }

        private async Task RunOutcomeProbeNowUiAsync()
        {
            if (IsOutcomeProbeRunning) return;

            IsOutcomeProbeRunning = true;
            try
            {
                var host = _stateManager.GetOutcomeTargetHost();
                if (string.IsNullOrWhiteSpace(host))
                {
                    OutcomeProbeStatusText = "OUT: нет цели (OutcomeTargetHost пуст)";
                    return;
                }

                OutcomeProbeStatusText = $"OUT: проверяю {host}…";

                var snapshot = await _stateManager.RunOutcomeProbeNowAsync(cancellationToken: CancellationToken.None).ConfigureAwait(false);
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OutcomeProbeStatusText = $"OUT: {snapshot.Text} — {snapshot.Details}";
                });
            }
            catch (Exception ex)
            {
                OutcomeProbeStatusText = $"OUT: ошибка — {ex.Message}";
            }
            finally
            {
                IsOutcomeProbeRunning = false;
            }
        }
    }
}
