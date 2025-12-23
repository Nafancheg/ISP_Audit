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
        private CancellationTokenSource? _applyCts;

        // Последняя цель (hostKey), извлечённая из v2-диагноза в UI сообщениях.
        // Нужна, чтобы не применять v2-план «не к той цели», когда рекомендации обновились.
        private string _lastV2DiagnosisHostKey = "";
        
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
        private readonly ConcurrentQueue<HostDiscovered> _pendingSniHosts = new();

        // Гейтинг SNI-триггеров по PID:
        // WinDivert Network Layer не даёт PID, поэтому сопоставляем SNI с событиями соединений (remote endpoint -> pid)
        // из ConnectionMonitor (IP Helper / Socket Layer) и пропускаем только то, что относится к отслеживаемым PID.
        private readonly ConcurrentDictionary<string, (int Pid, DateTime LastSeenUtc)> _remoteEndpointPid = new();
        private readonly ConcurrentDictionary<string, PendingSni> _pendingSniByEndpoint = new();
        private static readonly TimeSpan PendingSniTtl = TimeSpan.FromSeconds(5);
        private Task? _pendingSniCleanupTask;

        private bool _isDiagnosticRunning;
        private string _diagnosticStatus = "";
        private int _flowEventsCount;
        private int _connectionsDiscovered;
        private string _flowModeText = "WinDivert";
        private string? _stopReason;

        private readonly record struct PendingSni(System.Net.IPAddress RemoteIp, string Hostname, int Port, DateTime SeenUtc);

        // Статус авто-bypass (показываем в UI во время диагностики)
        private string _autoBypassStatus = "";
        private string _autoBypassVerdict = "";
        private string _autoBypassMetrics = "";
        private System.Windows.Media.Brush _autoBypassStatusBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246));
        private TlsBypassService? _observedTlsService;

        // Рекомендации от классификатора/тестера (агрегируем без дублей)
        private readonly HashSet<string> _recommendedStrategies = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _manualRecommendations = new(StringComparer.OrdinalIgnoreCase);
        private string _recommendedStrategiesText = "Нет рекомендаций";
        private string _manualRecommendationsText = "";

        // Legacy (справочно): не влияет на основную рекомендацию v2
        private readonly HashSet<string> _legacyRecommendedStrategies = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _legacyManualRecommendations = new(StringComparer.OrdinalIgnoreCase);

        // Последний v2 диагноз (для панели рекомендаций)
        private string _lastV2DiagnosisSummary = "";

        // Последний v2 план (объектно, без парсинга строк) для ручного применения.
        private BypassPlan? _lastV2Plan;
        private string _lastV2PlanHostKey = "";
        private static readonly TimeSpan V2ApplyTimeout = TimeSpan.FromSeconds(8);

        private static readonly HashSet<string> ServiceStrategies = new(StringComparer.OrdinalIgnoreCase)
        {
            "TLS_FRAGMENT",
            "TLS_DISORDER",
            "TLS_FAKE",
            "TLS_FAKE_FRAGMENT",
            "DROP_RST",
            "DOH"
        };
        
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

        public string AutoBypassStatus
        {
            get => _autoBypassStatus;
            private set
            {
                _autoBypassStatus = value;
                OnPropertyChanged(nameof(AutoBypassStatus));
            }
        }

        public string AutoBypassVerdict
        {
            get => _autoBypassVerdict;
            private set
            {
                _autoBypassVerdict = value;
                OnPropertyChanged(nameof(AutoBypassVerdict));
            }
        }

        public string AutoBypassMetrics
        {
            get => _autoBypassMetrics;
            private set
            {
                _autoBypassMetrics = value;
                OnPropertyChanged(nameof(AutoBypassMetrics));
            }
        }

        public System.Windows.Media.Brush AutoBypassStatusBrush
        {
            get => _autoBypassStatusBrush;
            private set
            {
                _autoBypassStatusBrush = value;
                OnPropertyChanged(nameof(AutoBypassStatusBrush));
            }
        }

        public bool HasRecommendations => _lastV2Plan != null && _recommendedStrategies.Count > 0;

        public bool HasAnyRecommendations => HasRecommendations || _manualRecommendations.Count > 0;

        public string RecommendedStrategiesText
        {
            get => _recommendedStrategiesText;
            private set
            {
                _recommendedStrategiesText = value;
                OnPropertyChanged(nameof(RecommendedStrategiesText));
            }
        }

        public string ManualRecommendationsText
        {
            get => _manualRecommendationsText;
            private set
            {
                _manualRecommendationsText = value;
                OnPropertyChanged(nameof(ManualRecommendationsText));
            }
        }

        public string RecommendationHintText =>
            "TLS обход применяет только ClientHello с hostname (SNI) на порту 443; для IP без имени сначала откройте сайт/игру, чтобы появился SNI.";

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

                ResetRecommendations();
                
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
                        TrackV2DiagnosisSummary(msg);
                        TrackRecommendation(msg, bypassController);
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

                    // ВАЖНО: если приложение уже запущено, мы подключаемся "поздно".
                    // В этом случае ранние TLS ClientHello могли пройти до старта перехвата,
                    // поэтому SNI может не определиться для уже существующих соединений.
                    var alreadyRunning = System.Diagnostics.Process.GetProcessesByName(processName).FirstOrDefault();
                    if (alreadyRunning != null)
                    {
                        pid = alreadyRunning.Id;
                        var warning = $"⚠ Приложение уже запущено (Steam/attach). Ранний TLS (SNI) мог пройти до старта перехвата — колонка SNI может быть пустой для части соединений. Для полного захвата запустите диагностику ДО запуска приложения или перезапустите приложение.";
                        DiagnosticStatus = warning;
                        Log($"[Orchestrator] ⚠ Процесс уже запущен: {processName} (PID={pid}). {warning}");
                    }
                    
                    while (!_cts.Token.IsCancellationRequested)
                    {
                        if (pid != 0) break;

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

                // Если SNI пришёл до того, как PID-tracker успел подняться (Steam/attach),
                // пытаемся добрать из буфера по уже известным remote endpoint -> pid.
                FlushPendingSniForTrackedPids();
                
                // 4. Pre-resolve целей (параллельно)
                _ = resultsManager.PreResolveTargetsAsync();
                
                DiagnosticStatus = "Анализ трафика...";

                // 5. Преимптивный bypass (через сервис, с телеметрией в UI)
                // Важно: в текущем MVP auto-apply запрещён. Даже если флаг включён в UI,
                // мы не применяем техники автоматически.
                if (enableAutoBypass)
                {
                    Log("[Orchestrator] ⚠ Auto-bypass запрошен, но отключён политикой (auto-apply запрещён)");
                    ((IProgress<string>?)progress)?.Report("⚠ Auto-bypass отключён: авто-применение обхода запрещено");
                }

                enableAutoBypass = false;
                ResetAutoBypassUi(enableAutoBypass);

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
                        : null,
                    bypassController.AutoHostlist);

                // v2: принимаем объектный план напрямую из pipeline (auto-apply запрещён).
                _testingPipeline.OnV2PlanBuilt += (hostKey, plan) =>
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        StoreV2Plan(hostKey, plan, bypassController);
                    });
                };

                // Повторно флешим pending SNI — на случай, если endpoint->pid уже есть, а событий соединения больше не будет.
                FlushPendingSniForTrackedPids();
                while (_pendingSniHosts.TryDequeue(out var sniHost))
                {
                    await _testingPipeline.EnqueueHostAsync(sniHost).ConfigureAwait(false);
                }
                Log("[Orchestrator] ✓ TrafficCollector + LiveTestingPipeline созданы");

                // Подписываемся на события UDP блокировок для ретеста
                if (_udpInspectionService != null)
                {
                    _udpInspectionService.OnBlockageDetected += (ip) => 
                    {
                        // UDP/QUIC блокировки часто не означают, что HTTPS по TCP не работает.
                        // Авто-ретест по каждому событию приводит к лавине перетестов и ухудшает UX.
                        Log($"[Orchestrator] UDP Blockage detected for {ip}. (no auto-retest)");
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
                DetachAutoBypassTelemetry();
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
                DetachAutoBypassTelemetry();
                ResetAutoBypassUi(false);

                var progress = new Progress<string>(msg => 
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        DiagnosticStatus = msg;
                        TrackV2DiagnosisSummary(msg);
                        TrackRecommendation(msg, bypassController);
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

                // Используем существующий bypass manager из контроллера
                _testingPipeline = new LiveTestingPipeline(
                    pipelineConfig, 
                    progress, 
                    _trafficEngine, 
                    _dnsParser, // Нужен для кеша SNI/DNS имён (стабильнее подписи в UI и авто-hostlist)
                    new UnifiedTrafficFilter(),
                    null, // State store новый
                    bypassController.AutoHostlist);

                _testingPipeline.OnV2PlanBuilt += (hostKey, plan) =>
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        StoreV2Plan(hostKey, plan, bypassController);
                    });
                };

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
            var cancelledAnything = false;

            // Отмена ручного apply (может выполняться даже когда диагностика уже закончилась)
            if (_applyCts != null && !_applyCts.IsCancellationRequested)
            {
                Log("[Orchestrator] Отмена применения рекомендаций...");
                _applyCts.Cancel();
                cancelledAnything = true;
            }

            // Отмена диагностики
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                Log("[Orchestrator] Отмена...");
                DiagnosticStatus = "Остановка...";
                _stopReason = "UserCancel";

                // Сначала отменяем токен — это прервёт await foreach в CollectAsync
                _cts.Cancel();

                // Потом останавливаем компоненты
                _testingPipeline?.Dispose();
                _trafficCollector?.Dispose();
                cancelledAnything = true;
            }

            if (!cancelledAnything)
            {
                Log("[Orchestrator] Уже отменено или не запущено");
            }
        }

        #endregion

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
                _ = _testingPipeline.EnqueueHostAsync(host);
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
                    _trafficEngine.RemoveFilter(_trafficMonitorFilter.Name);
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

        #region Recommendations

        private void TrackRecommendation(string msg, BypassController bypassController)
        {
            if (string.IsNullOrWhiteSpace(msg)) return;

            // v2 — главный источник рекомендаций. Legacy сохраняем только как справочное.
            var isV2 = msg.TrimStart().StartsWith("[V2]", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("v2:", StringComparison.OrdinalIgnoreCase);

            // Нас интересуют строки вида "💡 Рекомендация: TLS_FRAGMENT" или "→ Стратегия: DROP_RST".
            // Не используем Split(':'), потому что в сообщении может быть host:port или другие двоеточия.
            var raw = TryExtractAfterMarker(msg, "Рекомендация:")
                ?? TryExtractAfterMarker(msg, "Стратегия:");

            if (string.IsNullOrWhiteSpace(raw)) return;

            raw = raw.Trim();
            var paren = raw.IndexOf('(');
            if (paren > 0)
            {
                raw = raw.Substring(0, paren).Trim();
            }

            if (string.IsNullOrWhiteSpace(raw)) return;

            // Поддержка списка стратегий в одной строке (v2 формат, чтобы не убивать UI шумом).
            // Пример: "[V2] 💡 Рекомендация: TLS_FRAGMENT, DROP_RST"
            // Пример: "💡 Рекомендация: v2:TlsFragment + DropRst (conf=78)"
            var normalized = raw;
            if (normalized.StartsWith("v2:", StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized.Substring(3);
            }

            var tokens = normalized
                .Split(new[] { ',', '+', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(MapStrategyToken)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (tokens.Count == 0) return;

            foreach (var token in tokens)
            {
                if (IsStrategyActive(token, bypassController))
                {
                    // Уже включено — удаляем из списка, чтобы не спамить UI
                    _recommendedStrategies.Remove(token);
                    _legacyRecommendedStrategies.Remove(token);
                    continue;
                }

                if (ServiceStrategies.Contains(token))
                {
                    if (isV2)
                    {
                        _recommendedStrategies.Add(token);
                    }
                    else
                    {
                        _legacyRecommendedStrategies.Add(token);
                    }
                }
                else
                {
                    if (isV2)
                    {
                        _manualRecommendations.Add(token);
                    }
                    else
                    {
                        _legacyManualRecommendations.Add(token);
                    }
                }
            }

            UpdateRecommendationTexts(bypassController);
        }

        private void StoreV2Plan(string hostKey, BypassPlan plan, BypassController bypassController)
        {
            _lastV2Plan = plan;
            _lastV2PlanHostKey = hostKey;

            // Токены нужны только для текста панели. Реальное применение идёт по объектному plan.
            _recommendedStrategies.Clear();

            foreach (var strategy in plan.Strategies)
            {
                var token = strategy.Id switch
                {
                    StrategyId.TlsFragment => "TLS_FRAGMENT",
                    StrategyId.TlsDisorder => "TLS_DISORDER",
                    StrategyId.TlsFakeTtl => "TLS_FAKE",
                    StrategyId.DropRst => "DROP_RST",
                    StrategyId.UseDoh => "DOH",
                    _ => string.Empty
                };

                if (string.IsNullOrWhiteSpace(token))
                {
                    continue;
                }

                if (!IsStrategyActive(token, bypassController))
                {
                    _recommendedStrategies.Add(token);
                }
            }

            _lastV2DiagnosisSummary = $"([V2] диагноз={plan.ForDiagnosis} уверенность={plan.PlanConfidence}%: {plan.Reasoning})";

            UpdateRecommendationTexts(bypassController);
        }

        private static string? TryExtractAfterMarker(string msg, string marker)
        {
            var idx = msg.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            idx += marker.Length;
            if (idx >= msg.Length) return null;

            return msg.Substring(idx);
        }

        private void TrackV2DiagnosisSummary(string msg)
        {
            // Берём v2 диагноз из строки карточки: "❌ ... ( [V2] диагноз=SilentDrop уверенность=78%: ... )"
            if (string.IsNullOrWhiteSpace(msg)) return;
            if (!msg.StartsWith("❌ ", StringComparison.Ordinal)) return;
            if (!msg.Contains("[V2]", StringComparison.OrdinalIgnoreCase) && !msg.Contains("v2:", StringComparison.OrdinalIgnoreCase)) return;

            try
            {
                // Хост:port в начале строки
                var host = "";
                var afterPrefix = msg.Substring(2).TrimStart();
                var firstToken = afterPrefix.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(firstToken))
                {
                    host = firstToken.Split(':').FirstOrDefault() ?? "";
                }

                if (!string.IsNullOrWhiteSpace(host))
                {
                    _lastV2DiagnosisHostKey = host;
                }

                // Вытаскиваем компактный текст v2 в скобках (он уже пользовательский)
                var m = Regex.Match(msg, @"\(\s*\[V2\][^\)]*\)", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var tail = m.Value.Trim();
                    _lastV2DiagnosisSummary = string.IsNullOrWhiteSpace(host)
                        ? $"{tail}"
                        : $"{tail} (цель: {host})";
                }
            }
            catch
            {
                // Игнорируем ошибки парсинга
            }
        }

        private static string MapStrategyToken(string token)
        {
            var t = token.Trim();
            if (string.IsNullOrWhiteSpace(t)) return string.Empty;

            // Поддерживаем как legacy-строки, так и enum-названия v2.
            return t switch
            {
                "TlsFragment" => "TLS_FRAGMENT",
                "TlsDisorder" => "TLS_DISORDER",
                "TlsFakeTtl" => "TLS_FAKE",
                "DropRst" => "DROP_RST",
                "UseDoh" => "DOH",
                _ => t.ToUpperInvariant()
            };
        }

        public async Task ApplyRecommendationsAsync(BypassController bypassController)
        {
            if (_lastV2Plan == null || _lastV2Plan.Strategies.Count == 0)
            {
                return;
            }

            if (_recommendedStrategies.Count == 0)
            {
                return;
            }

            // Защита от «устаревшего» плана: применяем только если план относится
            // к последней цели, для которой был показан v2-диагноз.
            if (!string.IsNullOrWhiteSpace(_lastV2DiagnosisHostKey)
                && !string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                && !string.Equals(_lastV2PlanHostKey, _lastV2DiagnosisHostKey, StringComparison.OrdinalIgnoreCase))
            {
                Log($"[V2][APPLY] SKIP: planHost={_lastV2PlanHostKey}; lastDiagHost={_lastV2DiagnosisHostKey} (план устарел)");
                return;
            }

            _applyCts?.Dispose();
            _applyCts = new CancellationTokenSource();

            using var linked = _cts != null
                ? CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, _applyCts.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(_applyCts.Token);

            var ct = linked.Token;

            var hostKey = _lastV2PlanHostKey;
            var planStrategies = string.Join(", ", _lastV2Plan.Strategies.Select(s => MapStrategyToken(s.Id.ToString())));
            var beforeState = BuildBypassStateSummary(bypassController);

            try
            {
                Log($"[V2][APPLY] host={hostKey}; plan={planStrategies}; before={beforeState}");
                await bypassController.ApplyV2PlanAsync(_lastV2Plan, V2ApplyTimeout, ct).ConfigureAwait(false);

                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[V2][APPLY] OK; after={afterState}");
                ResetRecommendations();
            }
            catch (OperationCanceledException)
            {
                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[V2][APPLY] ROLLBACK (cancel/timeout); after={afterState}");
            }
            catch (Exception ex)
            {
                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[V2][APPLY] ROLLBACK (error); after={afterState}; error={ex.Message}");
            }
            finally
            {
                _applyCts?.Dispose();
                _applyCts = null;
            }
        }

        private static string BuildBypassStateSummary(BypassController bypassController)
        {
            // Коротко и стабильно: только ключевые флаги.
            return $"Frag={(bypassController.IsFragmentEnabled ? 1 : 0)},Dis={(bypassController.IsDisorderEnabled ? 1 : 0)},Fake={(bypassController.IsFakeEnabled ? 1 : 0)},DropRst={(bypassController.IsDropRstEnabled ? 1 : 0)},DoH={(bypassController.IsDoHEnabled ? 1 : 0)}";
        }

        private void ResetRecommendations()
        {
            _recommendedStrategies.Clear();
            _manualRecommendations.Clear();
            _legacyRecommendedStrategies.Clear();
            _legacyManualRecommendations.Clear();
            _lastV2DiagnosisSummary = "";
            _lastV2DiagnosisHostKey = "";
            _lastV2Plan = null;
            _lastV2PlanHostKey = "";
            RecommendedStrategiesText = "Нет рекомендаций";
            ManualRecommendationsText = "";
            OnPropertyChanged(nameof(HasRecommendations));
            OnPropertyChanged(nameof(HasAnyRecommendations));
        }

        private void UpdateRecommendationTexts(BypassController bypassController)
        {
            // Убираем рекомендации, если всё уже включено (актуально при ручном переключении)
            _recommendedStrategies.RemoveWhere(s => IsStrategyActive(s, bypassController));

            var hasAny = _recommendedStrategies.Count > 0 || _manualRecommendations.Count > 0;

            if (!hasAny)
            {
                RecommendedStrategiesText = "Нет рекомендаций";
            }
            else if (_recommendedStrategies.Count == 0)
            {
                var header = string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary)
                    ? "[V2] Диагноз определён"
                    : _lastV2DiagnosisSummary;

                RecommendedStrategiesText = $"{header}\nАвтоматических рекомендаций нет";
            }
            else
            {
                RecommendedStrategiesText = BuildRecommendationPanelText();
            }

            // Ручные рекомендации показываем отдельной строкой в UI.
            var legacyManualTokens = _legacyManualRecommendations
                .Where(t => !_manualRecommendations.Contains(t))
                .ToList();

            var manualText = _manualRecommendations.Count == 0
                ? null
                : $"Ручные действия: {string.Join(", ", _manualRecommendations)}";

            var legacyManualText = legacyManualTokens.Count == 0
                ? null
                : $"Legacy (справочно): {string.Join(", ", legacyManualTokens)}";

            ManualRecommendationsText = manualText == null
                ? (legacyManualText ?? "")
                : (legacyManualText == null ? manualText : $"{manualText}\n{legacyManualText}");

            OnPropertyChanged(nameof(HasRecommendations));
            OnPropertyChanged(nameof(HasAnyRecommendations));

            // Подсказка остаётся статичной, но триггерим обновление, чтобы UI мог показать tooltip
            OnPropertyChanged(nameof(RecommendationHintText));
        }

        private string BuildRecommendationPanelText()
        {
            // Пишем текст так, чтобы пользователь видел «что попробовать», а не только метрики.
            // Важно: v2 — приоритетно; legacy — только справочно.
            var strategies = string.Join(", ", _recommendedStrategies);

            var header = string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary)
                ? "[V2] Диагноз определён"
                : _lastV2DiagnosisSummary;

            var applyHint = $"Что попробовать: нажмите «Применить рекомендации v2» (включит: {strategies})";

            // Legacy показываем только если есть v2 рекомендации (и только как справочно)
            var legacyTokens = _legacyRecommendedStrategies
                .Where(t => !_recommendedStrategies.Contains(t))
                .ToList();

            var legacyText = legacyTokens.Count == 0
                ? null
                : $"Legacy (справочно): {string.Join(", ", legacyTokens)}";

            return legacyText == null
                ? $"{header}\n{applyHint}"
                : $"{header}\n{applyHint}\n{legacyText}";
        }

        private static bool IsStrategyActive(string strategy, BypassController bypassController)
        {
            return strategy.ToUpperInvariant() switch
            {
                "TLS_FRAGMENT" => bypassController.IsFragmentEnabled,
                "TLS_DISORDER" => bypassController.IsDisorderEnabled,
                "TLS_FAKE" => bypassController.IsFakeEnabled,
                "TLS_FAKE_FRAGMENT" => bypassController.IsFakeEnabled && bypassController.IsFragmentEnabled,
                "DROP_RST" => bypassController.IsDropRstEnabled,
                "DOH" => bypassController.IsDoHEnabled,
                _ => false
            };
        }

        #endregion

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
                // ipconfig /flushdns на русской Windows часто пишет OEM866
                var oem866 = System.Text.Encoding.GetEncoding(866);
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = oem866,
                    StandardErrorEncoding = oem866
                };

                using var process = System.Diagnostics.Process.Start(startInfo);
                if (process != null)
                {
                    var stdoutTask = process.StandardOutput.ReadToEndAsync();
                    var stderrTask = process.StandardError.ReadToEndAsync();
                    await process.WaitForExitAsync().ConfigureAwait(false);

                    var output = (await stdoutTask.ConfigureAwait(false)).Trim();
                    var error = (await stderrTask.ConfigureAwait(false)).Trim();

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        Log($"[DNS] Flush result: {output}");
                    }
                    else if (!string.IsNullOrWhiteSpace(error))
                    {
                        Log($"[DNS] Flush error: {error}");
                    }
                    else
                    {
                        Log("[DNS] Flush completed");
                    }
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
