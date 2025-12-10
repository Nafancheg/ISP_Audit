using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Windows;
using IspAudit;

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
    public class DiagnosticOrchestrator : INotifyPropertyChanged
    {
        private CancellationTokenSource? _cts;
        
        // Мониторинговые сервисы
        private ConnectionMonitorService? _connectionMonitor;
        private readonly TrafficEngine _trafficEngine;
        private TrafficMonitorFilter? _trafficMonitorFilter;
        private TcpRetransmissionTracker? _tcpRetransmissionTracker;
        private HttpRedirectDetector? _httpRedirectDetector;
        private RstInspectionService? _rstInspectionService;
        private UdpInspectionService? _udpInspectionService;
        private DnsParserService? _dnsParser;
        private PidTrackerService? _pidTracker;
        
        // Новые компоненты (после рефакторинга)
        private TrafficCollector? _trafficCollector;
        private LiveTestingPipeline? _testingPipeline;

        private bool _isDiagnosticRunning;
        private string _diagnosticStatus = "";
        private int _flowEventsCount;
        private int _connectionsDiscovered;
        private string _flowModeText = "WinDivert";
        private string? _stopReason;
        
        // Настройки
        public int SilenceTimeoutSeconds { get; set; } = 60;
        public bool EnableSilenceTimeout { get; set; } = true;
        private const int WarmupSeconds = 15;

        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<string>? OnLog;
        public event Action<string>? OnPipelineMessage;
        public event Action? OnDiagnosticComplete;

        public DiagnosticOrchestrator(TrafficEngine trafficEngine)
        {
            _trafficEngine = trafficEngine;
        }

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
        /// Запуск диагностики с новой архитектурой:
        /// TrafficCollector собирает хосты → LiveTestingPipeline тестирует и применяет bypass
        /// </summary>
        public async Task RunAsync(
            string targetExePath, 
            BypassController bypassController,
            TestResultsManager resultsManager,
            bool enableAutoBypass = true,
            bool isSteamMode = false)
        {
            if (IsDiagnosticRunning)
            {
                Log("[Orchestrator] Диагностика уже запущена");
                return;
            }

            try
            {
                Log($"[Orchestrator] Старт диагностики: {targetExePath}");
                
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
                DiagnosticStatus = "Инициализация...";
                FlowEventsCount = 0;
                ConnectionsDiscovered = 0;
                
                _cts = new CancellationTokenSource();

                // Инициализируем фильтр шумных хостов
                var noiseFilterPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "noise_hosts.json");
                NoiseHostFilter.Initialize(noiseFilterPath, new Progress<string>(Log));
                
                // Создаем единый фильтр трафика (для дедупликации и фильтрации)
                var trafficFilter = new UnifiedTrafficFilter();

                // Сброс DNS кеша
                Log("[Orchestrator] Сброс DNS кеша...");
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

                // 1. Запуск мониторинговых сервисов
                await StartMonitoringServicesAsync(progress, overlay);

                // 2. Запуск целевого процесса или ожидание
                int pid = 0;
                
                if (isSteamMode)
                {
                    var processName = Path.GetFileNameWithoutExtension(targetExePath);
                    DiagnosticStatus = $"Ожидание запуска {processName}...";
                    Log($"[Orchestrator] Режим Steam: ожидание процесса {processName}");
                    
                    while (!_cts.Token.IsCancellationRequested)
                    {
                        var found = System.Diagnostics.Process.GetProcessesByName(processName).FirstOrDefault();
                        if (found != null)
                        {
                            pid = found.Id;
                            Log($"[Orchestrator] Процесс обнаружен: {processName} (PID={pid})");
                            break;
                        }
                        await Task.Delay(1000, _cts.Token);
                    }
                }
                else
                {
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
                    pid = process.Id;
                    Log($"[Orchestrator] Процесс запущен: PID={pid}");
                }
                
                // 3. PID Tracker
                _pidTracker = new PidTrackerService(pid, progress);
                await _pidTracker.StartAsync(_cts.Token).ConfigureAwait(false);
                
                // 4. Pre-resolve целей (параллельно)
                _ = resultsManager.PreResolveTargetsAsync();
                
                DiagnosticStatus = "Анализ трафика...";

                // 5. Преимптивный bypass
                if (enableAutoBypass)
                {
                    await bypassController.EnablePreemptiveBypassAsync();
                    ((IProgress<string>?)progress)?.Report("✓ Bypass активирован (TLS_DISORDER + DROP_RST)");
                }

                // 6. Создание TrafficCollector (чистый сборщик)
                _trafficCollector = new TrafficCollector(
                    _connectionMonitor!,
                    _pidTracker!,
                    _dnsParser!,
                    progress,
                    trafficFilter);
                
                // 7. Создание LiveTestingPipeline (тестирование + bypass)
                var pipelineConfig = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = enableAutoBypass,
                    MaxConcurrentTests = 5,
                    TestTimeout = TimeSpan.FromSeconds(3)
                };
                _testingPipeline = new LiveTestingPipeline(
                    pipelineConfig, 
                    progress, 
                    _trafficEngine, 
                    _dnsParser,
                    trafficFilter,
                    _tcpRetransmissionTracker != null
                        ? new InMemoryBlockageStateStore(_tcpRetransmissionTracker, _httpRedirectDetector, _rstInspectionService, _udpInspectionService)
                        : null);
                Log("[Orchestrator] ✓ TrafficCollector + LiveTestingPipeline созданы");

                // Подписываемся на события UDP блокировок для ретеста
                if (_udpInspectionService != null)
                {
                    _udpInspectionService.OnBlockageDetected += (ip) => 
                    {
                        Log($"[Orchestrator] UDP Blockage detected for {ip}. Forcing retest.");
                        _testingPipeline.ForceRetest(ip);
                    };
                }

                // 8. Запуск сбора и тестирования параллельно
                var collectorTask = RunCollectorWithPipelineAsync(overlay, progress!);
                var silenceMonitorTask = RunSilenceMonitorAsync(overlay);
                var processMonitorTask = RunProcessMonitorAsync();
                
                // Ждём завершения (любой таск может завершить диагностику)
                try
                {
                    await Task.WhenAny(collectorTask, silenceMonitorTask, processMonitorTask);
                }
                catch (OperationCanceledException)
                {
                    // Игнорируем здесь, обработка ниже
                }
                
                // 9. Закрываем оверлей
                Application.Current?.Dispatcher.Invoke(() => overlay?.Close());

                // 10. Обработка завершения
                if (_stopReason == "UserCancel")
                {
                    Log("[Orchestrator] Отменено пользователем");
                    DiagnosticStatus = "Диагностика отменена";
                }
                else
                {
                    // ProcessExited, SilenceTimeout или другое
                    Log($"[Orchestrator] Завершение диагностики ({_stopReason ?? "Unknown"})...");
                    
                    // Ждём завершения всех тестов в pipeline (до 30 секунд)
                    if (_testingPipeline != null)
                    {
                        Log("[Orchestrator] Ожидание завершения тестов в pipeline...");
                        await _testingPipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                    }
                    
                    Log($"[Orchestrator] Завершено. Соединений: {_trafficCollector?.ConnectionsCount ?? 0}");
                    
                    // Генерация и сохранение профиля (используем CancellationToken.None, чтобы сохранить даже при отмене)
                    if (_trafficCollector != null && _trafficCollector.ConnectionsCount > 0)
                    {
                        var profile = await _trafficCollector.BuildProfileAsync(
                            Path.GetFileNameWithoutExtension(targetExePath),
                            CancellationToken.None);
                        await SaveProfileAsync(targetExePath, profile);
                    }
                    
                    DiagnosticStatus = "Диагностика завершена";
                }
            }
            catch (OperationCanceledException)
            {
                // Этот блок может быть достигнут, если исключение возникло до Task.WhenAny
                Log("[Orchestrator] Отменено пользователем (до запуска задач)");
                DiagnosticStatus = "Диагностика отменена";
            }
            catch (Exception ex)
            {
                Log($"[Orchestrator] Ошибка: {ex.Message}");
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка диагностики", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
                DiagnosticStatus = $"Ошибка: {ex.Message}";
            }
            finally
            {
                _testingPipeline?.Dispose();
                _trafficCollector?.Dispose();
                await StopMonitoringServicesAsync();
                IsDiagnosticRunning = false;
                _cts?.Dispose();
                _cts = null;
                OnDiagnosticComplete?.Invoke();
            }
        }

        /// <summary>
        /// Повторная диагностика списка целей (для проверки эффективности bypass)
        /// </summary>
        public async Task RetestTargetsAsync(
            System.Collections.Generic.IEnumerable<IspAudit.Models.Target> targets,
            BypassController bypassController)
        {
            if (IsDiagnosticRunning)
            {
                Log("[Orchestrator] Нельзя запустить ретест во время активной диагностики");
                return;
            }

            try
            {
                Log("[Orchestrator] Запуск ретеста проблемных целей...");
                IsDiagnosticRunning = true;
                DiagnosticStatus = "Ретест...";
                _cts = new CancellationTokenSource();

                var progress = new Progress<string>(msg => 
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        DiagnosticStatus = msg;
                        Log($"[Retest] {msg}");
                        OnPipelineMessage?.Invoke(msg);
                    });
                });

                // Создаем pipeline только для тестирования (без сниффера)
                var pipelineConfig = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false, // Bypass уже настроен контроллером
                    MaxConcurrentTests = 5,
                    TestTimeout = TimeSpan.FromSeconds(3)
                };

                // Собираем активные стратегии для исключения их из рекомендаций
                var activeStrategies = new System.Collections.Generic.List<string>();
                if (bypassController.IsFragmentEnabled) activeStrategies.Add("TLS_FRAGMENT");
                if (bypassController.IsDisorderEnabled) activeStrategies.Add("TLS_DISORDER");
                if (bypassController.IsFakeEnabled) activeStrategies.Add("TLS_FAKE");
                if (bypassController.IsFragmentEnabled && bypassController.IsFakeEnabled) activeStrategies.Add("TLS_FAKE_FRAGMENT");
                if (bypassController.IsDropRstEnabled) activeStrategies.Add("DROP_RST");
                if (bypassController.IsDoHEnabled) activeStrategies.Add("DOH");

                // Используем существующий bypass manager из контроллера
                _testingPipeline = new LiveTestingPipeline(
                    pipelineConfig, 
                    progress, 
                    _trafficEngine, 
                    null, // DNS parser не нужен для ретеста (уже есть IP)
                    new UnifiedTrafficFilter(),
                    null, // State store новый
                    activeStrategies);

                // Запускаем цели в pipeline
                foreach (var target in targets)
                {
                    // Пытаемся извлечь порт из Service, если там число
                    int port = 443;
                    if (int.TryParse(target.Service, out var p)) port = p;

                    if (System.Net.IPAddress.TryParse(target.Host, out var ip))
                    {
                        var key = $"{ip}:{port}:TCP";
                        var host = new HostDiscovered(key, ip, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                        {
                            Hostname = target.Name != target.Host ? target.Name : null // Если имя отличается от IP, передаем его
                        };
                        await _testingPipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                    }
                    else
                    {
                        // Если Host - это доменное имя, нужно его разрешить
                        try 
                        {
                            var ips = await System.Net.Dns.GetHostAddressesAsync(target.Host);
                            if (ips.Length > 0)
                            {
                                var ipAddr = ips[0];
                                var key = $"{ipAddr}:{port}:TCP";
                                var host = new HostDiscovered(key, ipAddr, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                                {
                                    Hostname = target.Host // Передаем оригинальный hostname
                                };
                                await _testingPipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                            }
                        }
                        catch { }
                    }
                }

                // Ждем завершения
                await _testingPipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                
                Log("[Orchestrator] Ретест завершен");
                DiagnosticStatus = "Ретест завершен";
            }
            catch (Exception ex)
            {
                Log($"[Orchestrator] Ошибка ретеста: {ex.Message}");
            }
            finally
            {
                _testingPipeline?.Dispose();
                _testingPipeline = null;
                IsDiagnosticRunning = false;
                _cts?.Dispose();
                _cts = null;
                OnDiagnosticComplete?.Invoke();
            }
        }

        /// <summary>
        /// Сбор трафика и передача хостов в pipeline
        /// </summary>
        private async Task RunCollectorWithPipelineAsync(OverlayWindow? overlay, IProgress<string> progress)
        {
            if (_trafficCollector == null || _testingPipeline == null || _cts == null) return;
            
            try
            {
                // Если включен таймаут тишины, то ставим и глобальный лимит 10 минут.
                // Если "Без лимита времени", то глобальный лимит тоже отключаем (null).
                var captureTimeout = EnableSilenceTimeout ? TimeSpan.FromMinutes(10) : (TimeSpan?)null;

                await foreach (var host in _trafficCollector.CollectAsync(
                    captureTimeout, 
                    _cts.Token).ConfigureAwait(false))
                {
                    // Обновляем UI счётчик
                    Application.Current?.Dispatcher.Invoke(() => 
                    {
                        ConnectionsDiscovered = _trafficCollector.ConnectionsCount;
                        overlay?.UpdateStats(ConnectionsDiscovered, FlowEventsCount);
                    });
                    
                    // Отправляем в pipeline на тестирование
                    await _testingPipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
        }

        /// <summary>
        /// Мониторинг тишины (отсутствие новых соединений)
        /// </summary>
        private async Task RunSilenceMonitorAsync(OverlayWindow? overlay)
        {
            if (_trafficCollector == null || _connectionMonitor == null || _cts == null) return;
            
            bool silenceWarningShown = false;
            
            try
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(1000, _cts.Token).ConfigureAwait(false);
                    
                    // Проверяем время с момента запуска мониторинга (warmup)
                    var totalElapsed = _connectionMonitor.MonitorStartedUtc.HasValue 
                        ? (DateTime.UtcNow - _connectionMonitor.MonitorStartedUtc.Value).TotalSeconds 
                        : 0;

                    if (totalElapsed < WarmupSeconds || silenceWarningShown)
                        continue;

                    var silenceDuration = (DateTime.UtcNow - _trafficCollector.LastNewConnectionTime).TotalSeconds;
                    
                    if (EnableSilenceTimeout && silenceDuration > SilenceTimeoutSeconds && overlay != null)
                    {
                        silenceWarningShown = true;
                        Log($"[Silence] Нет новых соединений более {SilenceTimeoutSeconds}с");
                        
                        // Показываем запрос пользователю
                        var extend = await Application.Current!.Dispatcher.Invoke(async () => 
                            await overlay.ShowSilencePromptAsync(SilenceTimeoutSeconds));
                        
                        if (extend)
                        {
                            Log("[Silence] Пользователь продлил диагностику");
                            silenceWarningShown = false;
                            // Сбрасываем время последнего соединения на текущее
                            _trafficCollector.ResetSilenceTimer();
                        }
                        else
                        {
                            Log("[Silence] Авто-завершение диагностики");
                            _stopReason = "SilenceTimeout";
                            _cts.Cancel();
                            break;
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
        }

        /// <summary>
        /// Мониторинг жизни целевых процессов
        /// </summary>
        private async Task RunProcessMonitorAsync()
        {
            if (_pidTracker == null || _cts == null) return;
            
            try
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(2000, _cts.Token).ConfigureAwait(false);
                    
                    bool anyAlive = false;
                    foreach (var pid in _pidTracker.TrackedPids.ToArray())
                    {
                        try
                        {
                            using var proc = System.Diagnostics.Process.GetProcessById(pid);
                            if (!proc.HasExited)
                            {
                                anyAlive = true;
                                break;
                            }
                        }
                        catch { }
                    }
                    
                    if (!anyAlive && _pidTracker.TrackedPids.Count > 0)
                    {
                        Log("[Orchestrator] Все отслеживаемые процессы завершились");
                        _stopReason = "ProcessExited";
                        
                        // Закрываем входящий поток данных (это разблокирует collectorTask)
                        // DrainAndCompleteAsync будет вызван в основном потоке после WhenAny
                        _trafficCollector?.StopCollecting();
                        
                        // НЕ отменяем и НЕ ждём здесь — основной поток сам вызовет DrainAndCompleteAsync
                        break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
        }

        /// <summary>
        /// Отмена диагностики
        /// </summary>
        public void Cancel()
        {
            if (_cts == null || _cts.IsCancellationRequested)
            {
                Log("[Orchestrator] Уже отменено или не запущено");
                return;
            }
            
            Log("[Orchestrator] Отмена...");
            DiagnosticStatus = "Остановка...";
            _stopReason = "UserCancel";
            
            // Сначала отменяем токен — это прервёт await foreach в CollectAsync
            _cts.Cancel();
            
            // Потом останавливаем компоненты
            _testingPipeline?.Dispose();
            _trafficCollector?.Dispose();
        }

        #endregion

        #region Private Methods

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
            _trafficEngine.RegisterFilter(_trafficMonitorFilter);
            
            await _trafficEngine.StartAsync(_cts.Token).ConfigureAwait(false);

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
            
            // DNS Parser (теперь умеет и SNI)
            _dnsParser = new DnsParserService(_trafficMonitorFilter, progress);
            _dnsParser.OnDnsLookupFailed += (hostname, error) => 
            {
                Application.Current?.Dispatcher.Invoke(() => 
                {
                    OnPipelineMessage?.Invoke($"DNS сбой: {hostname} - {error}");
                });
            };
            await _dnsParser.StartAsync().ConfigureAwait(false);
            
            Log("[Services] ✓ Все сервисы запущены");
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
                    _trafficEngine.RemoveFilter(_trafficMonitorFilter.Name);
                }

                if (_connectionMonitor != null) await _connectionMonitor.StopAsync().ConfigureAwait(false);
                
                _pidTracker?.Dispose();
                _dnsParser?.Dispose();
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

        private async Task SaveProfileAsync(string targetExePath, DiagnosticProfile profile)
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
                Log($"[Orchestrator] Профиль сохранен: {profilePath}");
                
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    DiagnosticStatus = $"Профиль сохранен: {Path.GetFileName(profilePath)}";
                });
            }
            catch (Exception ex)
            {
                Log($"[Orchestrator] Ошибка сохранения профиля: {ex.Message}");
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
