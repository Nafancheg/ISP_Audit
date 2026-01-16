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
using IspAudit.ViewModels.OrchestratorState;

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
        private readonly PostApplyRetestState _postApplyRetest = new();

        // Reconnect-nudge: короткий TTL-блок endpoint-ов, чтобы принудить переподключение.
        private string _endpointBlockStatus = "";

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
            get => _postApplyRetest.IsRunning;
            private set
            {
                _postApplyRetest.IsRunning = value;
                OnPropertyChanged(nameof(IsPostApplyRetestRunning));
            }
        }

        public string PostApplyRetestStatus
        {
            get => _postApplyRetest.Status;
            private set
            {
                _postApplyRetest.Status = value;
                OnPropertyChanged(nameof(PostApplyRetestStatus));
            }
        }

        public string EndpointBlockStatus
        {
            get => _endpointBlockStatus;
            private set
            {
                _endpointBlockStatus = value;
                OnPropertyChanged(nameof(EndpointBlockStatus));
            }
        }

        #endregion

    }
}
