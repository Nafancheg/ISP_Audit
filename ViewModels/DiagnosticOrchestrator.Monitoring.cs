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
using IspAudit.Core.RuntimeAdaptation;

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
        #region Monitoring

        private async Task StartMonitoringServicesAsync(IProgress<string> progress, OverlayWindow? overlay)
        {
            Log("[Services] Запуск мониторинговых сервисов...");

            // Connection Monitor
            _connectionMonitor = new ConnectionMonitorService(progress)
            {
                // Временно используем fallback-режим polling через IP Helper API,
                // чтобы видеть попытки соединения даже без успешного Socket Layer.
                UsePollingMode = true
            };

            _connectionMonitor.OnConnectionEvent += (count, pid, proto, remoteIp, remotePort, localPort) =>
            {
                // Обновляем сопоставление remote endpoint -> pid, чтобы потом гейтить SNI-триггеры
                TrackRemoteEndpoint(pid, proto, remoteIp, remotePort);

                // Если раньше прилетел SNI, а PID появился позже (polling/attach) — попробуем добрать из буфера
                TryFlushPendingSniForEndpoint(pid, proto, remoteIp, remotePort);

                if (count % 10 == 0)
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        FlowEventsCount = count;
                        overlay?.UpdateStats(ConnectionsDiscovered, FlowEventsCount);
                    });
                }
            };
            FlowModeText = _connectionMonitor.UsePollingMode ? "IP Helper (polling)" : "Socket Layer";
            Log($"[Services] ConnectionMonitor: {( _connectionMonitor.UsePollingMode ? "Polling (IP Helper)" : "Socket Layer" )} активен");

            await _connectionMonitor.StartAsync(_cts!.Token).ConfigureAwait(false);

            // Traffic Engine (замена NetworkMonitorService)
            _trafficMonitorFilter = new TrafficMonitorFilter();
            _stateManager.RegisterEngineFilter(_trafficMonitorFilter);

            await _stateManager.StartEngineAsync(_cts.Token).ConfigureAwait(false);

            // TCP Retransmission Tracker — подписываем на TrafficMonitorFilter
            _tcpRetransmissionTracker = new TcpRetransmissionTracker();
            _tcpRetransmissionTracker.Attach(_trafficMonitorFilter);

            // HTTP Redirect Detector — минимальный детектор HTTP 3xx Location
            _httpRedirectDetector = new HttpRedirectDetector();
            _httpRedirectDetector.Attach(_trafficMonitorFilter);

            // RST Inspection Service — анализ TTL входящих RST пакетов
            _rstInspectionService = new RstInspectionService();
            _rstInspectionService.Attach(_trafficMonitorFilter);

            // UDP Inspection Service — анализ DTLS/QUIC блокировок
            _udpInspectionService = new UdpInspectionService();
            _udpInspectionService.Attach(_trafficMonitorFilter);

            // Runtime Adaptation Layer (без UI/без политики)
            _reactiveTargetSync ??= new ReactiveTargetSyncService(_stateManager, Log);

            // DNS Parser (теперь умеет и SNI)
            _dnsParser = new DnsParserService(_trafficMonitorFilter, progress);
            _dnsParser.OnDnsLookupFailed += (hostname, error) =>
            {
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OnPipelineMessage?.Invoke($"DNS сбой: {hostname} - {error}");
                });
            };
            _dnsParser.OnSniDetected += HandleSniDetected;
            await _dnsParser.StartAsync().ConfigureAwait(false);

            // Очистка буфера SNI (на случай, если PID так и не появился)
            _pendingSniCleanupTask = Task.Run(() => CleanupPendingSniLoop(_cts!.Token), _cts.Token);

            Log("[Services] ✓ Все сервисы запущены");
        }

        private static string BuildRemoteEndpointKey(byte proto, System.Net.IPAddress remoteIp, ushort remotePort)
            => $"{proto}:{remoteIp}:{remotePort}";

        private void TrackRemoteEndpoint(int pid, byte proto, System.Net.IPAddress remoteIp, ushort remotePort)
        {
            var key = BuildRemoteEndpointKey(proto, remoteIp, remotePort);
            _remoteEndpointPid[key] = (pid, DateTime.UtcNow);
        }

        private bool IsTrackedPid(int pid)
        {
            if (_pidTracker == null) return false;
            try
            {
                return _pidTracker.IsPidTracked(pid);
            }
            catch
            {
                return false;
            }
        }

        private bool TryResolveTrackedPidForEndpoint(byte proto, System.Net.IPAddress remoteIp, ushort remotePort, out int pid)
        {
            pid = 0;
            var key = BuildRemoteEndpointKey(proto, remoteIp, remotePort);
            if (_remoteEndpointPid.TryGetValue(key, out var entry) && IsTrackedPid(entry.Pid))
            {
                pid = entry.Pid;
                return true;
            }
            return false;
        }

        private void TryFlushPendingSniForEndpoint(int pid, byte proto, System.Net.IPAddress remoteIp, ushort remotePort)
        {
            if (!IsTrackedPid(pid)) return;

            var key = BuildRemoteEndpointKey(proto, remoteIp, remotePort);
            if (_pendingSniByEndpoint.TryRemove(key, out var pending))
            {
                EnqueueSniHost(remoteIp, pending.Port, pending.Hostname);
            }
        }

        private async Task CleanupPendingSniLoop(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(1000, token).ConfigureAwait(false);

                    var cutoff = DateTime.UtcNow - PendingSniTtl;
                    foreach (var kv in _pendingSniByEndpoint)
                    {
                        if (kv.Value.SeenUtc < cutoff)
                        {
                            _pendingSniByEndpoint.TryRemove(kv.Key, out _);
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
            }
            catch
            {
                // Не валим оркестратор из-за фоновой очистки
            }
        }

        private void HandleSniDetected(System.Net.IPAddress ip, int port, string hostname)
        {
            try
            {
                // Важно: SNI — это исходные данные.
                // Не фильтруем «шум» на входе, иначе можем потерять сигнал (в т.ч. для CDN/браузерных потоков и любых распределённых сервисов).
                // Фильтрация по шуму применяется только на этапе отображения успешных результатов.
                if (NoiseHostFilter.Instance.IsNoiseHost(hostname))
                {
                    Log($"[SNI] Шумовой хост (не блокируем): {hostname}");
                }

                // Гейт по PID: пропускаем SNI только если есть недавнее событие соединения от отслеживаемого PID.
                // Если PID/endpoint ещё не известны (polling лаг, Steam attach), буферим коротко.
                var proto = (byte)6; // TCP
                if (TryResolveTrackedPidForEndpoint(proto, ip, (ushort)port, out _))
                {
                    EnqueueSniHost(ip, port, hostname);
                }
                else
                {
                    var key = BuildRemoteEndpointKey(proto, ip, (ushort)port);
                    _pendingSniByEndpoint[key] = new PendingSni(ip, hostname, port, DateTime.UtcNow);
                }
            }
            catch (Exception ex)
            {
                Log($"[SNI] Ошибка обработки: {ex.Message}");
            }
        }

        private void FlushPendingSniForTrackedPids()
        {
            // Вызываем после старта PID-tracker и/или после создания pipeline,
            // чтобы не потерять ранний SNI в Steam/attach.
            foreach (var kv in _pendingSniByEndpoint)
            {
                if (!_remoteEndpointPid.TryGetValue(kv.Key, out var entry))
                {
                    continue;
                }

                if (!IsTrackedPid(entry.Pid))
                {
                    continue;
                }

                if (_pendingSniByEndpoint.TryRemove(kv.Key, out var pending))
                {
                    EnqueueSniHost(pending.RemoteIp, pending.Port, pending.Hostname);
                }
            }
        }

        private void EnqueueSniHost(System.Net.IPAddress ip, int port, string hostname)
        {
            var host = new HostDiscovered(
                Key: $"{ip}:{port}:TCP",
                RemoteIp: ip,
                RemotePort: port,
                Protocol: IspAudit.Bypass.TransportProtocol.Tcp,
                DiscoveredAt: DateTime.UtcNow)
            {
                Hostname = hostname,
                SniHostname = hostname
            };

            if (_testingPipeline != null)
            {
                // ValueTask нельзя просто "потерять" (CA2012). Конвертируем в Task и отпускаем.
                // Поздние SNI-события после остановки пайплайна считаем нормой: LiveTestingPipeline enqueue безопасен.
                _ = _testingPipeline.EnqueueHostAsync(host).AsTask();
            }
            else
            {
                _pendingSniHosts.Enqueue(host);
            }
        }

        private async Task StopMonitoringServicesAsync()
        {
            try
            {
                Log("[Services] Остановка сервисов...");
                if (_pidTracker != null) await _pidTracker.StopAsync().ConfigureAwait(false);
                if (_dnsParser != null) await _dnsParser.StopAsync().ConfigureAwait(false);

                // Don't stop TrafficEngine, just remove filter
                if (_trafficMonitorFilter != null)
                {
                    _stateManager.RemoveEngineFilter(_trafficMonitorFilter.Name);
                }

                if (_connectionMonitor != null) await _connectionMonitor.StopAsync().ConfigureAwait(false);

                _pidTracker?.Dispose();
                if (_dnsParser != null)
                {
                    _dnsParser.OnSniDetected -= HandleSniDetected;
                    _dnsParser.Dispose();
                }
                // _trafficEngine is shared, do not dispose
                _connectionMonitor?.Dispose();

                _pidTracker = null;
                _dnsParser = null;
                // _trafficEngine = null; // Cannot assign to readonly
                _connectionMonitor = null;
                _tcpRetransmissionTracker = null;
                _httpRedirectDetector = null;
                _rstInspectionService = null;
            }
            catch (Exception ex)
            {
                Log($"[Services] Ошибка остановки: {ex.Message}");
            }
        }

        private void UpdateOverlayStatus(OverlayWindow? overlay, string msg)
        {
            if (overlay == null) return;

            if (msg.Contains("Захват активен"))
                overlay.UpdateStatus("Мониторинг активности...");
            else if (msg.Contains("Обнаружено соединение") || msg.Contains("Новое соединение"))
                overlay.UpdateStatus("Анализ нового соединения...");
            else if (msg.StartsWith("✓ "))
                overlay.UpdateStatus("Соединение успешно проверено");
            else if (msg.StartsWith("❌ "))
                overlay.UpdateStatus("Обнаружена проблема соединения!");
            else if (msg.Contains("Запуск приложения") || msg.Contains("Запуск целевого"))
                overlay.UpdateStatus("Запуск целевого приложения...");
            else if (msg.Contains("Анализ трафика"))
                overlay.UpdateStatus("Анализ сетевого трафика...");
        }

        #endregion
    }
}
