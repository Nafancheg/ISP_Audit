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
        private readonly BypassStateManager _stateManager;
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

        public bool LastRunWasUserCancelled { get; private set; }

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

        // Пост-Apply ретест (практический UX): после применения обхода
        // сразу запускаем короткий ретест по цели, чтобы пользователь видел эффект.
        private bool _isPostApplyRetestRunning;
        private string _postApplyRetestStatus = "";
        private CancellationTokenSource? _postApplyRetestCts;

        // Legacy (справочно): не влияет на основную рекомендацию v2
        private readonly HashSet<string> _legacyRecommendedStrategies = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _legacyManualRecommendations = new(StringComparer.OrdinalIgnoreCase);

        // Последний v2 диагноз (для панели рекомендаций)
        private string _lastV2DiagnosisSummary = "";

        // Последний v2 план (объектно, без парсинга строк) для ручного применения.
        private BypassPlan? _lastV2Plan;
        private string _lastV2PlanHostKey = "";

        // Планы v2 храним по целям, чтобы Apply мог работать по выбранному хосту,
        // а не по «последнему сообщению в логе».
        private readonly ConcurrentDictionary<string, BypassPlan> _v2PlansByHost =
            new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan V2ApplyTimeout = TimeSpan.FromSeconds(8);

        private static readonly HashSet<string> ServiceStrategies = new(StringComparer.OrdinalIgnoreCase)
        {
            "TLS_FRAGMENT",
            "TLS_DISORDER",
            "TLS_FAKE",
            "TLS_FAKE_FRAGMENT",
            "DROP_RST",
            "DOH",
            "DROP_UDP_443",
            "ALLOW_NO_SNI",

            // Back-compat: старые токены (оставляем, чтобы не ломать парсинг старых логов/текста)
            "QUIC_TO_TCP",
            "NO_SNI"
        };

        // Настройки
        public int SilenceTimeoutSeconds { get; set; } = 60;
        public bool EnableSilenceTimeout { get; set; } = true;
        private const int WarmupSeconds = 15;

        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<string>? OnLog;
        public event Action<string>? OnPipelineMessage;
        public event Action? OnDiagnosticComplete;

        public DiagnosticOrchestrator(BypassStateManager stateManager)
        {
            _stateManager = stateManager ?? throw new ArgumentNullException(nameof(stateManager));
            _trafficEngine = _stateManager.TrafficEngine;
        }

        public DiagnosticOrchestrator(TrafficEngine trafficEngine)
            : this(BypassStateManager.GetOrCreate(trafficEngine, baseProfile: null, log: null))
        {
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

        public bool HasRecommendations => _lastV2Plan != null;

        public bool HasAnyRecommendations => _recommendedStrategies.Count > 0
            || _manualRecommendations.Count > 0
            || _lastV2Plan != null
            || !string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary);

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

        public bool IsPostApplyRetestRunning
        {
            get => _isPostApplyRetestRunning;
            private set
            {
                _isPostApplyRetestRunning = value;
                OnPropertyChanged(nameof(IsPostApplyRetestRunning));
            }
        }

        public string PostApplyRetestStatus
        {
            get => _postApplyRetestStatus;
            private set
            {
                _postApplyRetestStatus = value;
                OnPropertyChanged(nameof(PostApplyRetestStatus));
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

                LastRunWasUserCancelled = false;

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

                // Оверлей отключён (UX: не показываем отдельное сервисное окно)
                OverlayWindow? overlay = null;

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
                var effectiveTestTimeout = bypassController.IsVpnDetected
                    ? TimeSpan.FromSeconds(8)
                    : TimeSpan.FromSeconds(3);

                var pipelineConfig = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = enableAutoBypass,
                    MaxConcurrentTests = 5,
                    TestTimeout = effectiveTestTimeout
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

                        try
                        {
                            // Важно для QUIC→TCP (DROP UDP/443): режим селективный и требует цели.
                            // Если цель не задана, то опция может быть включена, но фактически не будет глушить UDP/443.
                            var existingTarget = bypassController.GetOutcomeTargetHost();

                            // Пытаемся восстановить имя по SNI/DNS кешу.
                            var ipKey = ip.ToString();
                            string? resolvedHost = null;
                            if (_dnsParser != null)
                            {
                                _dnsParser.SniCache.TryGetValue(ipKey, out resolvedHost);
                                if (string.IsNullOrWhiteSpace(resolvedHost))
                                {
                                    _dnsParser.DnsCache.TryGetValue(ipKey, out resolvedHost);
                                }
                            }

                            var candidateTarget = !string.IsNullOrWhiteSpace(resolvedHost)
                                ? resolvedHost!.Trim()
                                : ipKey;

                            // Обновляем цель по последнему UDP blockage.
                            // Важно: иначе цель может «залипнуть» на первом событии,
                            // а последующие QUIC блокировки (часто CDN/шарды) не смогут корректно активировать
                            // селективный DROP UDP/443 при ручном включении тумблера.
                            var shouldUpdateTarget = string.IsNullOrWhiteSpace(existingTarget)
                                || !string.Equals(existingTarget, candidateTarget, StringComparison.OrdinalIgnoreCase);

                            if (shouldUpdateTarget)
                            {
                                bypassController.SetOutcomeTargetHost(candidateTarget);
                                Log($"[Orchestrator] Outcome target host set from UDP blockage: {ipKey} -> {candidateTarget}");

                                // Если QUIC→TCP уже включён, нужно пере-применить опции, чтобы селективный UDP/443 получил цели.
                                if (bypassController.IsQuicFallbackEnabled)
                                {
                                    _ = bypassController.ApplyBypassOptionsAsync();
                                }
                            }
                        }
                        catch
                        {
                            // Не даём вспомогательной логике ломать диагностику.
                        }
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
                var effectiveTestTimeout = bypassController.IsVpnDetected
                    ? TimeSpan.FromSeconds(8)
                    : TimeSpan.FromSeconds(3);

                var pipelineConfig = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false, // Bypass уже настроен контроллером
                    MaxConcurrentTests = 5,
                    TestTimeout = effectiveTestTimeout
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
                LastRunWasUserCancelled = true;

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

        #region Recommendations

        private void TrackRecommendation(string msg, BypassController bypassController)
        {
            if (string.IsNullOrWhiteSpace(msg)) return;

            // v2 — главный источник рекомендаций. Legacy сохраняем только как справочное.
            var isV2 = msg.TrimStart().StartsWith("[V2]", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("v2:", StringComparison.OrdinalIgnoreCase);

            // B5: v2 — единственный источник рекомендаций.
            // Legacy строки допускаются в логах, но не должны влиять на UI рекомендации.
            if (!isV2)
            {
                return;
            }

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
                    // Уже включено вручную — считаем это ручным применением,
                    // чтобы панель рекомендаций была видима и не исчезала.
                    _recommendedStrategies.Remove(token);
                    _legacyRecommendedStrategies.Remove(token);
                    _manualRecommendations.Add(token);
                    continue;
                }

                if (ServiceStrategies.Contains(token))
                {
                    _recommendedStrategies.Add(token);
                }
                else
                {
                    _manualRecommendations.Add(token);
                }
            }

            UpdateRecommendationTexts(bypassController);
        }

        private void StoreV2Plan(string hostKey, BypassPlan plan, BypassController bypassController)
        {
            if (NoiseHostFilter.Instance.IsNoiseHost(hostKey))
            {
                // Шум не должен перетирать «активный» план рекомендаций и засорять Apply.
                return;
            }

            _v2PlansByHost[hostKey] = plan;

            _lastV2Plan = plan;
            _lastV2PlanHostKey = hostKey;

            // План сформирован для конкретной цели — «прикалываем» v2-цель к hostKey плана,
            // чтобы последующие сообщения по другим хостам не ломали Apply (и UX панели рекомендаций).
            _lastV2DiagnosisHostKey = hostKey;

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

            if (plan.DropUdp443)
            {
                var token = "DROP_UDP_443";
                if (!IsStrategyActive(token, bypassController))
                {
                    _recommendedStrategies.Add(token);
                }
            }

            if (plan.AllowNoSni)
            {
                var token = "ALLOW_NO_SNI";
                if (!IsStrategyActive(token, bypassController))
                {
                    _recommendedStrategies.Add(token);
                }
            }

            _lastV2DiagnosisSummary = string.IsNullOrWhiteSpace(hostKey)
                ? $"([V2] диагноз={plan.ForDiagnosis} уверенность={plan.PlanConfidence}%: {plan.Reasoning})"
                : $"([V2] диагноз={plan.ForDiagnosis} уверенность={plan.PlanConfidence}%: {plan.Reasoning}) (цель: {hostKey})";

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
                // Ключ цели: предпочитаем SNI (человеко‑понятный), иначе берём IP из "host:port".
                var candidateHostKey = string.Empty;
                var sni = TryExtractInlineToken(msg, "SNI");
                if (!string.IsNullOrWhiteSpace(sni) && sni != "-")
                {
                    candidateHostKey = sni;
                }
                else
                {
                    var afterPrefix = msg.Substring(2).TrimStart();
                    var firstToken = afterPrefix.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(firstToken))
                    {
                        candidateHostKey = firstToken.Split(':').FirstOrDefault() ?? "";
                    }
                }

                // Если план уже построен, не позволяем сообщениям по другим хостам «перетереть» цель,
                // иначе кнопка Apply может начать вести себя как "ничего не происходит".
                if (_lastV2Plan != null
                    && !string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                    && !string.IsNullOrWhiteSpace(candidateHostKey)
                    && !string.Equals(candidateHostKey, _lastV2PlanHostKey, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                if (!string.IsNullOrWhiteSpace(candidateHostKey))
                {
                    _lastV2DiagnosisHostKey = candidateHostKey;
                }

                // Вытаскиваем компактный текст v2 в скобках (он уже пользовательский)
                var m = Regex.Match(msg, @"\(\s*\[V2\][^\)]*\)", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var tail = m.Value.Trim();
                    _lastV2DiagnosisSummary = string.IsNullOrWhiteSpace(_lastV2DiagnosisHostKey)
                        ? $"{tail}"
                        : $"{tail} (цель: {_lastV2DiagnosisHostKey})";
                }
            }
            catch
            {
                // Игнорируем ошибки парсинга
            }
        }

        private static string? TryExtractInlineToken(string msg, string token)
        {
            try
            {
                var m = Regex.Match(msg, $@"\b{Regex.Escape(token)}=([^\s\|]+)", RegexOptions.IgnoreCase);
                return m.Success ? m.Groups[1].Value.Trim() : null;
            }
            catch
            {
                return null;
            }
        }

        private static string FormatStrategyTokenForUi(string token)
        {
            // Должно совпадать с текстами тумблеров в MainWindow.xaml.
            return token.ToUpperInvariant() switch
            {
                "TLS_FRAGMENT" => "Frag",
                "TLS_DISORDER" => "Frag+Rev",
                "TLS_FAKE" => "TLS Fake",
                "DROP_RST" => "Drop RST",
                "DROP_UDP_443" => "QUIC→TCP",
                "ALLOW_NO_SNI" => "No SNI",
                // Back-compat
                "QUIC_TO_TCP" => "QUIC→TCP",
                "NO_SNI" => "No SNI",
                "DOH" => "🔒 DoH",
                _ => token
            };
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
                "DropUdp443" => "DROP_UDP_443",
                "AllowNoSni" => "ALLOW_NO_SNI",

                // Back-compat
                "QUIC_TO_TCP" => "DROP_UDP_443",
                "NO_SNI" => "ALLOW_NO_SNI",
                _ => t.ToUpperInvariant()
            };
        }

        private static bool PlanHasApplicableActions(BypassPlan plan)
            => plan.Strategies.Count > 0 || plan.DropUdp443 || plan.AllowNoSni;

        public Task ApplyRecommendationsAsync(BypassController bypassController)
            => ApplyRecommendationsAsync(bypassController, preferredHostKey: null);

        public async Task ApplyRecommendationsForDomainAsync(BypassController bypassController, string domainSuffix)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));
            if (string.IsNullOrWhiteSpace(domainSuffix)) return;

            var domain = domainSuffix.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(domain)) return;

            // На данном этапе это управляемая "гибридная" логика:
            // - UI может предложить доменный режим (по анализу доменных семейств в UI-слое)
            // - здесь мы берём последний применимый v2 план из поддоменов и применяем его,
            //   но выставляем OutcomeTargetHost именно на домен.
            var candidates = _v2PlansByHost
                .Where(kv =>
                {
                    var k = kv.Key;
                    if (string.IsNullOrWhiteSpace(k)) return false;
                    if (string.Equals(k, domain, StringComparison.OrdinalIgnoreCase)) return true;
                    return k.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
                })
                .Select(kv => (HostKey: kv.Key, Plan: kv.Value))
                .ToList();

            if (candidates.Count == 0)
            {
                Log($"[V2][APPLY] Domain '{domain}': нет сохранённых планов");
                return;
            }

            // Предпочитаем план от последнего v2 (если он из этого домена), иначе берём первый применимый.
            BypassPlan? plan = null;
            string? sourceHost = null;

            if (!string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                && (_lastV2PlanHostKey.Equals(domain, StringComparison.OrdinalIgnoreCase)
                    || _lastV2PlanHostKey.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                && _v2PlansByHost.TryGetValue(_lastV2PlanHostKey, out var lastPlan)
                && PlanHasApplicableActions(lastPlan))
            {
                plan = lastPlan;
                sourceHost = _lastV2PlanHostKey;
            }
            else
            {
                foreach (var c in candidates)
                {
                    if (!PlanHasApplicableActions(c.Plan)) continue;
                    plan = c.Plan;
                    sourceHost = c.HostKey;
                    break;
                }
            }

            if (plan == null || !PlanHasApplicableActions(plan))
            {
                Log($"[V2][APPLY] Domain '{domain}': нет применимых действий в планах");
                return;
            }

            Log($"[V2][APPLY] Domain '{domain}': apply from '{sourceHost}'");
            await ApplyPlanInternalAsync(bypassController, domain, plan).ConfigureAwait(false);
        }

        public async Task ApplyRecommendationsAsync(BypassController bypassController, string? preferredHostKey)
        {
            // 1) Пытаемся применить план для выбранной цели (если UI передал её).
            if (!string.IsNullOrWhiteSpace(preferredHostKey)
                && _v2PlansByHost.TryGetValue(preferredHostKey.Trim(), out var preferredPlan)
                && PlanHasApplicableActions(preferredPlan))
            {
                await ApplyPlanInternalAsync(bypassController, preferredHostKey.Trim(), preferredPlan).ConfigureAwait(false);
                return;
            }

            // 2) Fallback: старый режим «последний v2 план».
            if (_lastV2Plan == null || !PlanHasApplicableActions(_lastV2Plan)) return;

            // Защита от «устаревшего» плана: применяем только если план относится
            // к последней цели, для которой был показан v2-диагноз.
            if (!string.IsNullOrWhiteSpace(_lastV2DiagnosisHostKey)
                && !string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                && !string.Equals(_lastV2PlanHostKey, _lastV2DiagnosisHostKey, StringComparison.OrdinalIgnoreCase))
            {
                Log($"[V2][APPLY] WARN: planHost={_lastV2PlanHostKey}; lastDiagHost={_lastV2DiagnosisHostKey} (план/цель разошлись)");
            }

            var hostKey = !string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                ? _lastV2PlanHostKey
                : _lastV2DiagnosisHostKey;

            await ApplyPlanInternalAsync(bypassController, hostKey, _lastV2Plan).ConfigureAwait(false);
        }

        private async Task ApplyPlanInternalAsync(BypassController bypassController, string hostKey, BypassPlan plan)
        {
            if (NoiseHostFilter.Instance.IsNoiseHost(hostKey))
            {
                Log($"[V2][APPLY] Skip: шумовой хост '{hostKey}'");
                return;
            }

            _applyCts?.Dispose();
            _applyCts = new CancellationTokenSource();

            using var linked = _cts != null
                ? CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, _applyCts.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(_applyCts.Token);

            var ct = linked.Token;

            var planTokens = plan.Strategies
                .Select(s => MapStrategyToken(s.Id.ToString()))
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .ToList();
            if (plan.DropUdp443) planTokens.Add("DROP_UDP_443");
            if (plan.AllowNoSni) planTokens.Add("ALLOW_NO_SNI");
            var planStrategies = planTokens.Count == 0 ? "(none)" : string.Join(", ", planTokens);

            var beforeState = BuildBypassStateSummary(bypassController);

            try
            {
                Log($"[V2][APPLY] host={hostKey}; plan={planStrategies}; before={beforeState}");
                await bypassController.ApplyV2PlanAsync(plan, hostKey, V2ApplyTimeout, ct).ConfigureAwait(false);

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

        /// <summary>
        /// Автоматический ретест сразу после Apply (короткий прогон, чтобы увидеть практический эффект обхода).
        /// </summary>
        public Task StartPostApplyRetestAsync(BypassController bypassController, string? preferredHostKey)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));

            // Не мешаем активной диагностике: там pipeline уже работает и сам обновляет результаты.
            if (IsDiagnosticRunning)
            {
                PostApplyRetestStatus = "Ретест после Apply: пропущен (идёт диагностика)";
                return Task.CompletedTask;
            }

            var hostKey = ResolveBestHostKeyForApply(preferredHostKey);
            if (string.IsNullOrWhiteSpace(hostKey))
            {
                PostApplyRetestStatus = "Ретест после Apply: нет цели";
                return Task.CompletedTask;
            }

            try
            {
                _postApplyRetestCts?.Cancel();
            }
            catch
            {
            }

            _postApplyRetestCts = new CancellationTokenSource();
            var ct = _postApplyRetestCts.Token;

            IsPostApplyRetestRunning = true;
            PostApplyRetestStatus = $"Ретест после Apply: запуск ({hostKey})";

            return Task.Run(async () =>
            {
                try
                {
                    var effectiveTestTimeout = bypassController.IsVpnDetected
                        ? TimeSpan.FromSeconds(8)
                        : TimeSpan.FromSeconds(3);

                    var pipelineConfig = new PipelineConfig
                    {
                        EnableLiveTesting = true,
                        EnableAutoBypass = false,
                        MaxConcurrentTests = 5,
                        TestTimeout = effectiveTestTimeout
                    };

                    // Собираем IP-адреса цели: DNS + локальные кеши.
                    var hosts = await BuildPostApplyRetestHostsAsync(hostKey, port: 443, ct).ConfigureAwait(false);
                    if (hosts.Count == 0)
                    {
                        PostApplyRetestStatus = $"Ретест после Apply: не удалось определить IP ({hostKey})";
                        return;
                    }

                    PostApplyRetestStatus = $"Ретест после Apply: проверяем {hosts.Count} IP…";

                    var progress = new Progress<string>(msg =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.Invoke(() =>
                            {
                                // Важно: обновляем рекомендации/диагнозы так же, как при обычной диагностике.
                                TrackV2DiagnosisSummary(msg);
                                TrackRecommendation(msg, bypassController);
                                Log($"[PostApplyRetest] {msg}");
                                OnPipelineMessage?.Invoke(msg);
                            });
                        }
                        catch
                        {
                        }
                    });

                    using var pipeline = new LiveTestingPipeline(
                        pipelineConfig,
                        progress,
                        _trafficEngine,
                        _dnsParser,
                        new UnifiedTrafficFilter(),
                        null,
                        bypassController.AutoHostlist);

                    pipeline.OnV2PlanBuilt += (k, p) =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.Invoke(() => StoreV2Plan(k, p, bypassController));
                        }
                        catch
                        {
                        }
                    };

                    foreach (var h in hosts)
                    {
                        await pipeline.EnqueueHostAsync(h).ConfigureAwait(false);
                    }

                    await pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                    PostApplyRetestStatus = "Ретест после Apply: завершён";
                }
                catch (OperationCanceledException)
                {
                    PostApplyRetestStatus = "Ретест после Apply: отменён";
                }
                catch (Exception ex)
                {
                    PostApplyRetestStatus = $"Ретест после Apply: ошибка ({ex.Message})";
                }
                finally
                {
                    IsPostApplyRetestRunning = false;
                }
            }, ct);
        }

        /// <summary>
        /// «Рестарт коннекта» (мягкий nudge): на короткое время дропаем трафик к целевым IP:443,
        /// чтобы приложение инициировало новое соединение уже под применённым bypass.
        /// </summary>
        public async Task NudgeReconnectAsync(BypassController bypassController, string? preferredHostKey)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));

            var hostKey = ResolveBestHostKeyForApply(preferredHostKey);
            if (string.IsNullOrWhiteSpace(hostKey))
            {
                PostApplyRetestStatus = "Рестарт коннекта: нет цели";
                return;
            }

            // Достаём IP-адреса (IPv4) и делаем короткий drop.
            var ips = await ResolveCandidateIpsAsync(hostKey, ct: CancellationToken.None).ConfigureAwait(false);
            if (ips.Count == 0)
            {
                PostApplyRetestStatus = $"Рестарт коннекта: IP не определены ({hostKey})";
                return;
            }

            if (!_trafficEngine.IsRunning)
            {
                try
                {
                    await _stateManager.StartEngineAsync().ConfigureAwait(false);
                }
                catch
                {
                    // Если движок не стартует (нет прав/драйвера) — просто выходим без падения.
                    PostApplyRetestStatus = "Рестарт коннекта: движок не запущен (нужны права администратора)";
                    return;
                }
            }

            var ttl = TimeSpan.FromSeconds(2);
            var filterName = $"TempReconnectNudge:{DateTime.UtcNow:HHmmss}";
            var filter = new IspAudit.Core.Traffic.Filters.TemporaryEndpointBlockFilter(
                filterName,
                ips,
                ttl,
                port: 443,
                blockTcp: true,
                blockUdp: true);

            PostApplyRetestStatus = $"Рестарт коннекта: блокирую {ips.Count} IP на {ttl.TotalSeconds:0}с…";
            _stateManager.RegisterEngineFilter(filter);

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(ttl + TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
                    _stateManager.RemoveEngineFilter(filterName);
                }
                catch
                {
                }
            });

            // После nudging — запускаем быстрый ретест, чтобы увидеть эффект.
            _ = StartPostApplyRetestAsync(bypassController, hostKey);
        }

        private string ResolveBestHostKeyForApply(string? preferredHostKey)
        {
            if (!string.IsNullOrWhiteSpace(preferredHostKey)) return preferredHostKey.Trim();
            if (!string.IsNullOrWhiteSpace(_lastV2PlanHostKey)) return _lastV2PlanHostKey.Trim();
            if (!string.IsNullOrWhiteSpace(_lastV2DiagnosisHostKey)) return _lastV2DiagnosisHostKey.Trim();
            return string.Empty;
        }

        private async Task<System.Collections.Generic.List<HostDiscovered>> BuildPostApplyRetestHostsAsync(
            string hostKey,
            int port,
            CancellationToken ct)
        {
            var list = new System.Collections.Generic.List<HostDiscovered>();
            var ips = await ResolveCandidateIpsAsync(hostKey, ct).ConfigureAwait(false);
            foreach (var ip in ips)
            {
                var key = $"{ip}:{port}:TCP";
                // Для домена передаём Hostname/SNI, чтобы TLS проверялся именно с SNI.
                var host = !IPAddress.TryParse(hostKey, out _)
                    ? new HostDiscovered(key, ip, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                    {
                        Hostname = hostKey,
                        SniHostname = hostKey
                    }
                    : new HostDiscovered(key, ip, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow);

                list.Add(host);
            }

            return list;
        }

        private async Task<System.Collections.Generic.List<IPAddress>> ResolveCandidateIpsAsync(string hostKey, CancellationToken ct)
        {
            var result = new System.Collections.Generic.List<IPAddress>();
            var seen = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

            hostKey = (hostKey ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(hostKey)) return result;

            if (IPAddress.TryParse(hostKey, out var directIp))
            {
                result.Add(directIp);
                return result;
            }

            // 1) Локальные кеши DNS/SNI (если сервисы ещё живы)
            try
            {
                if (_dnsParser != null)
                {
                    foreach (var kv in _dnsParser.DnsCache)
                    {
                        if (!IsHostKeyMatch(kv.Value, hostKey)) continue;
                        if (IPAddress.TryParse(kv.Key, out var ip) && seen.Add(ip.ToString()))
                        {
                            result.Add(ip);
                        }
                    }

                    foreach (var kv in _dnsParser.SniCache)
                    {
                        if (!IsHostKeyMatch(kv.Value, hostKey)) continue;
                        if (IPAddress.TryParse(kv.Key, out var ip) && seen.Add(ip.ToString()))
                        {
                            result.Add(ip);
                        }
                    }
                }
            }
            catch
            {
            }

            // 2) DNS resolve (может вернуть несколько IP)
            try
            {
                var dnsTask = System.Net.Dns.GetHostAddressesAsync(hostKey, ct);
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(4), ct);
                var completed = await Task.WhenAny(dnsTask, timeoutTask).ConfigureAwait(false);
                if (completed == dnsTask)
                {
                    var ips = await dnsTask.ConfigureAwait(false);
                    foreach (var ip in ips)
                    {
                        if (ip == null) continue;
                        if (seen.Add(ip.ToString())) result.Add(ip);
                    }
                }
            }
            catch
            {
            }

            return result;
        }

        private static bool IsHostKeyMatch(string candidate, string hostKey)
        {
            if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(hostKey)) return false;
            candidate = candidate.Trim();
            hostKey = hostKey.Trim();

            if (candidate.Equals(hostKey, StringComparison.OrdinalIgnoreCase)) return true;
            return candidate.EndsWith("." + hostKey, StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildBypassStateSummary(BypassController bypassController)
        {
            // Коротко и стабильно: только ключевые флаги.
            return $"Frag={(bypassController.IsFragmentEnabled ? 1 : 0)},Dis={(bypassController.IsDisorderEnabled ? 1 : 0)},Fake={(bypassController.IsFakeEnabled ? 1 : 0)},DropRst={(bypassController.IsDropRstEnabled ? 1 : 0)},QuicToTcp={(bypassController.IsQuicFallbackEnabled ? 1 : 0)},NoSni={(bypassController.IsAllowNoSniEnabled ? 1 : 0)},DoH={(bypassController.IsDoHEnabled ? 1 : 0)}";
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

            // Важно для UX: если v2 уже диагностировал проблему/построил план,
            // панель рекомендаций не должна «исчезать» сразу после ручного включения тумблеров.
            var hasAny = _recommendedStrategies.Count > 0
                || _manualRecommendations.Count > 0
                || _lastV2Plan != null
                || !string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary);

            if (!hasAny)
            {
                RecommendedStrategiesText = "Нет рекомендаций";
            }
            else if (_recommendedStrategies.Count == 0)
            {
                var header = string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary)
                    ? "[V2] Диагноз определён"
                    : _lastV2DiagnosisSummary;

                // Если план был, но рекомендации уже включены вручную — объясняем, почему кнопка может быть не нужна.
                RecommendedStrategiesText = _lastV2Plan != null
                    ? $"{header}\nРекомендации уже применены (вручную или ранее)"
                    : $"{header}\nАвтоматических рекомендаций нет";
            }
            else
            {
                RecommendedStrategiesText = BuildRecommendationPanelText();
            }

            var manualText = _manualRecommendations.Count == 0
                ? null
                : $"Ручные действия: {string.Join(", ", _manualRecommendations)}";

            ManualRecommendationsText = manualText ?? "";

            OnPropertyChanged(nameof(HasRecommendations));
            OnPropertyChanged(nameof(HasAnyRecommendations));

            // Подсказка остаётся статичной, но триггерим обновление, чтобы UI мог показать tooltip
            OnPropertyChanged(nameof(RecommendationHintText));
        }

        private string BuildRecommendationPanelText()
        {
            // Пишем текст так, чтобы пользователь видел «что попробовать», а не только метрики.
            // Важно: v2 — приоритетно; legacy — только справочно.
            var strategies = string.Join(", ", _recommendedStrategies.Select(FormatStrategyTokenForUi));

            var header = string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary)
                ? "[V2] Диагноз определён"
                : _lastV2DiagnosisSummary;

            var applyHint = $"Что попробовать: нажмите «Применить рекомендации v2» (включит: {strategies})";

            return $"{header}\n{applyHint}";
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
                "DROP_UDP_443" => bypassController.IsQuicFallbackEnabled,
                "ALLOW_NO_SNI" => bypassController.IsAllowNoSniEnabled,
                // Back-compat
                "QUIC_TO_TCP" => bypassController.IsQuicFallbackEnabled,
                "NO_SNI" => bypassController.IsAllowNoSniEnabled,
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
