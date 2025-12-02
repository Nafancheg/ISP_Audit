using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Utils;
using ISPAudit.Windows;
using IspAudit;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace ISPAudit.ViewModels
{
    /// <summary>
    /// Оркестратор диагностики.
    /// Управляет жизненным циклом мониторинговых сервисов,
    /// запуском процесса, сбором трафика.
    /// </summary>
    public class DiagnosticOrchestrator : INotifyPropertyChanged
    {
        private CancellationTokenSource? _cts;
        
        // Мониторинговые сервисы
        private FlowMonitorService? _flowMonitor;
        private NetworkMonitorService? _networkMonitor;
        private DnsParserService? _dnsParser;
        private PidTrackerService? _pidTracker;

        private bool _isDiagnosticRunning;
        private string _diagnosticStatus = "";
        private int _flowEventsCount;
        private int _connectionsDiscovered;
        private string _flowModeText = "WinDivert";

        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<string>? OnLog;
        public event Action<string>? OnPipelineMessage;
        public event Action? OnDiagnosticComplete;

        #region Properties

        public bool IsDiagnosticRunning
        {
            get => _isDiagnosticRunning;
            private set 
            { 
                _isDiagnosticRunning = value; 
                OnPropertyChanged(nameof(IsDiagnosticRunning)); 
            }
        }

        public string DiagnosticStatus
        {
            get => _diagnosticStatus;
            private set 
            { 
                _diagnosticStatus = value; 
                OnPropertyChanged(nameof(DiagnosticStatus)); 
            }
        }

        public int FlowEventsCount
        {
            get => _flowEventsCount;
            private set 
            { 
                _flowEventsCount = value; 
                OnPropertyChanged(nameof(FlowEventsCount)); 
            }
        }

        public int ConnectionsDiscovered
        {
            get => _connectionsDiscovered;
            private set 
            { 
                _connectionsDiscovered = value; 
                OnPropertyChanged(nameof(ConnectionsDiscovered)); 
            }
        }

        public string FlowModeText
        {
            get => _flowModeText;
            private set 
            { 
                _flowModeText = value; 
                OnPropertyChanged(nameof(FlowModeText)); 
            }
        }

        #endregion

        #region Core Methods

        /// <summary>
        /// Запуск диагностики
        /// </summary>
        public async Task RunAsync(
            string targetExePath, 
            BypassController bypassController,
            TestResultsManager resultsManager,
            bool enableAutoBypass = true)
        {
            if (IsDiagnosticRunning)
            {
                Log("[Orchestrator] Diagnostic already running");
                return;
            }

            try
            {
                Log($"[Orchestrator] Starting diagnostic for: {targetExePath}");
                
                if (!OperatingSystem.IsWindows() || !IsAdministrator())
                {
                    MessageBox.Show(
                        "Для захвата трафика требуются права администратора.\n\n" +
                        "Запустите приложение от имени администратора", 
                        "Требуются права администратора", 
                        MessageBoxButton.OK, 
                        MessageBoxImage.Warning);
                    return;
                }

                IsDiagnosticRunning = true;
                DiagnosticStatus = "Запуск приложения...";
                FlowEventsCount = 0;
                ConnectionsDiscovered = 0;
                
                _cts = new CancellationTokenSource();

                // Сброс DNS кеша
                Log("[Pipeline] Flushing DNS cache...");
                await RunFlushDnsAsync();

                // Создаём оверлей
                OverlayWindow? overlay = null;
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    overlay = new OverlayWindow();
                    overlay.Show();
                    overlay.StopRequested += Cancel;
                });

                var progress = new Progress<string>(msg => 
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        DiagnosticStatus = msg;
                        Log($"[Pipeline] {msg}");
                        OnPipelineMessage?.Invoke(msg);
                        UpdateOverlayStatus(overlay, msg);
                    });
                });

                // Запуск мониторинговых сервисов
                await StartMonitoringServicesAsync(progress, overlay);

                // Запуск целевого процесса
                DiagnosticStatus = "Запуск целевого приложения...";
                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = targetExePath,
                        UseShellExecute = true
                    }
                };
                
                if (!process.Start())
                {
                    throw new Exception("Не удалось запустить процесс");
                }
                
                var pid = process.Id;
                Log($"[Pipeline] Process started: PID={pid}");
                
                // PID Tracker
                _pidTracker = new PidTrackerService(pid, progress);
                await _pidTracker.StartAsync(_cts.Token).ConfigureAwait(false);
                
                // Pre-resolve целей
                _ = resultsManager.PreResolveTargetsAsync();
                
                DiagnosticStatus = "Анализ трафика...";

                // Преимптивный bypass
                if (enableAutoBypass)
                {
                    await bypassController.EnablePreemptiveBypassAsync();
                    ((IProgress<string>?)progress)?.Report("✓ Bypass активирован (TLS-фрагментация + DROP_RST)");
                }

                // Запуск анализатора
                var profile = await TrafficAnalyzer.AnalyzeProcessTrafficAsync(
                    pid,
                    TimeSpan.FromMinutes(10),
                    _flowMonitor!,
                    _pidTracker!,
                    _dnsParser!,
                    progress,
                    _cts.Token,
                    enableLiveTesting: true,
                    enableAutoBypass: enableAutoBypass,
                    bypassManager: bypassController.BypassManager,
                    onSilenceDetected: async () => 
                    {
                        var task = Application.Current!.Dispatcher.Invoke(() => 
                            overlay!.ShowSilencePromptAsync(60));
                        return await task;
                    }
                );
                
                Log($"[Pipeline] Finished. Captured {profile?.Targets?.Count ?? 0} targets.");
                
                // Закрываем оверлей
                Application.Current?.Dispatcher.Invoke(() => overlay?.Close());
                
                // Сохранение профиля
                if (profile != null && profile.Targets.Count > 0)
                {
                    await SaveProfileAsync(targetExePath, profile);
                }
                
                DiagnosticStatus = "Диагностика завершена";
            }
            catch (OperationCanceledException)
            {
                Log("[Pipeline] Cancelled by user");
                DiagnosticStatus = "Диагностика отменена";
            }
            catch (Exception ex)
            {
                Log($"[Pipeline] Error: {ex.Message}");
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка Pipeline", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
                DiagnosticStatus = $"Ошибка: {ex.Message}";
            }
            finally
            {
                await StopMonitoringServicesAsync();
                IsDiagnosticRunning = false;
                _cts?.Dispose();
                _cts = null;
                OnDiagnosticComplete?.Invoke();
            }
        }

        /// <summary>
        /// Отмена диагностики
        /// </summary>
        public void Cancel()
        {
            if (_cts == null || _cts.IsCancellationRequested)
            {
                Log("[Orchestrator] Already cancelled or not running");
                return;
            }
            
            Log("[Orchestrator] Cancelling...");
            _cts.Cancel();
            DiagnosticStatus = "Остановка...";
        }

        #endregion

        #region Private Methods

        private async Task StartMonitoringServicesAsync(IProgress<string> progress, OverlayWindow? overlay)
        {
            Log("[Services] Starting monitoring services...");
            
            // Flow Monitor
            _flowMonitor = new FlowMonitorService(progress);
            
            var uniqueConnections = new System.Collections.Concurrent.ConcurrentDictionary<string, bool>();
            _flowMonitor.OnFlowEvent += (count, pid, proto, remoteIp, remotePort, localPort) => 
            {
                var key = $"{remoteIp}:{remotePort}:{proto}";
                if (uniqueConnections.TryAdd(key, true))
                {
                    Application.Current?.Dispatcher.Invoke(() => 
                    {
                        ConnectionsDiscovered = uniqueConnections.Count;
                        overlay?.UpdateStats(ConnectionsDiscovered, FlowEventsCount);
                    });
                }

                if (count % 10 == 0)
                {
                    Application.Current?.Dispatcher.Invoke(() => 
                    {
                        FlowEventsCount = count;
                        overlay?.UpdateStats(ConnectionsDiscovered, FlowEventsCount);
                    });
                }
            };

            _flowMonitor.UseWatcherMode = false;
            FlowModeText = "Socket Layer";
            Log("[Pipeline] FlowMonitor: Socket Layer only");
            
            await _flowMonitor.StartAsync(_cts!.Token).ConfigureAwait(false);
            
            // Network Monitor (для DNS)
            _networkMonitor = new NetworkMonitorService("udp.DstPort == 53 or udp.SrcPort == 53", progress);
            await _networkMonitor.StartAsync(_cts.Token).ConfigureAwait(false);
            
            // DNS Parser
            _dnsParser = new DnsParserService(_networkMonitor, progress);
            _dnsParser.OnDnsLookupFailed += (hostname, error) => 
            {
                Application.Current?.Dispatcher.Invoke(() => 
                {
                    OnPipelineMessage?.Invoke($"DNS сбой: {hostname} - {error}");
                });
            };
            await _dnsParser.StartAsync().ConfigureAwait(false);
        }

        private async Task StopMonitoringServicesAsync()
        {
            try
            {
                Log("[Services] Stopping monitoring services...");
                if (_pidTracker != null) await _pidTracker.StopAsync().ConfigureAwait(false);
                if (_dnsParser != null) await _dnsParser.StopAsync().ConfigureAwait(false);
                if (_networkMonitor != null) await _networkMonitor.StopAsync().ConfigureAwait(false);
                if (_flowMonitor != null) await _flowMonitor.StopAsync().ConfigureAwait(false);
                
                _pidTracker?.Dispose();
                _dnsParser?.Dispose();
                _networkMonitor?.Dispose();
                _flowMonitor?.Dispose();
                
                _pidTracker = null;
                _dnsParser = null;
                _networkMonitor = null;
                _flowMonitor = null;
            }
            catch (Exception ex)
            {
                Log($"[Services] Error stopping: {ex.Message}");
            }
        }

        private void UpdateOverlayStatus(OverlayWindow? overlay, string msg)
        {
            if (overlay == null) return;
            
            if (msg.Contains("Захват активен"))
                overlay.UpdateStatus("Мониторинг активности...");
            else if (msg.Contains("Обнаружено соединение"))
                overlay.UpdateStatus("Анализ нового соединения...");
            else if (msg.StartsWith("✓ "))
                overlay.UpdateStatus("Соединение успешно проверено");
            else if (msg.StartsWith("❌ "))
                overlay.UpdateStatus("Обнаружена проблема соединения!");
            else if (msg.Contains("Запуск приложения"))
                overlay.UpdateStatus("Запуск целевого приложения...");
            else if (msg.Contains("Анализ трафика"))
                overlay.UpdateStatus("Анализ сетевого трафика...");
        }

        private async Task SaveProfileAsync(string targetExePath, GameProfile profile)
        {
            try 
            {
                var profilesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Profiles");
                Directory.CreateDirectory(profilesDir);
                
                var exeName = Path.GetFileNameWithoutExtension(targetExePath);
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var profilePath = Path.Combine(profilesDir, $"{exeName}_{timestamp}.json");
                
                profile.ExePath = targetExePath;
                profile.Name = $"{exeName} (Captured {DateTime.Now:g})";
                
                var jsonOptions = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
                var json = System.Text.Json.JsonSerializer.Serialize(profile, jsonOptions);
                
                await File.WriteAllTextAsync(profilePath, json);
                Log($"[Pipeline] Profile saved: {profilePath}");
                
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    DiagnosticStatus = $"Профиль сохранен: {Path.GetFileName(profilePath)}";
                });
            }
            catch (Exception ex)
            {
                Log($"[Pipeline] Error saving profile: {ex.Message}");
            }
        }

        private async Task RunFlushDnsAsync()
        {
            try
            {
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };

                using var process = System.Diagnostics.Process.Start(startInfo);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    var output = await process.StandardOutput.ReadToEndAsync();
                    Log($"[DNS] Flush result: {output.Trim()}");
                }
            }
            catch (Exception ex)
            {
                Log($"[DNS] Flush failed: {ex.Message}");
            }
        }

        [SupportedOSPlatform("windows")] 
        private static bool IsAdministrator()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void Log(string message)
        {
            OnLog?.Invoke(message);
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
