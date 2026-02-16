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
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Windows;
using IspAudit;
using IspAudit.Core.Interfaces;
using System.Windows.Media;
using System.Net;
using IspAudit.ViewModels.OrchestratorState;
using System.Threading.Tasks.Sources;
using System.Runtime.CompilerServices;

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
        // P1.5: сериализация операций оркестратора.
        // Цель: не допускать пересечений критических секций (cts/pipeline/collector dispose + start/stop).
        private readonly SemaphoreSlim _operationGate = new(1, 1);

        private sealed class GateLease : IDisposable
        {
            private SemaphoreSlim? _gate;

            public GateLease(SemaphoreSlim gate)
            {
                _gate = gate;
            }

            public void Dispose()
            {
                var gate = Interlocked.Exchange(ref _gate, null);
                if (gate == null) return;
                try { gate.Release(); } catch { }
            }
        }

        private async Task<GateLease> EnterOperationGateAsync()
        {
            await _operationGate.WaitAsync().ConfigureAwait(false);
            return new GateLease(_operationGate);
        }

        private CancellationTokenSource? _cts;
        private CancellationTokenSource? _applyCts;

        // Транзакционность Start/Cancel:
        // Cancel может быть нажат в очень раннее окно, когда IsDiagnosticRunning уже true,
        // но _cts ещё не создан (до инициализации сервисов). Тогда отмену нельзя терять.
        private volatile bool _cancelRequested;

        // Последняя цель (hostKey), извлечённая из INTEL-диагноза в UI сообщениях.
        // Нужна, чтобы не применять INTEL-план «не к той цели», когда рекомендации обновились.
        private string _lastIntelDiagnosisHostKey = "";

        // Мониторинговые сервисы
        private ConnectionMonitorService? _connectionMonitor;
        private readonly TrafficEngine _trafficEngine;
        private readonly BypassStateManager _stateManager;
        private readonly NoiseHostFilter _noiseHostFilter;
        private readonly ITrafficFilter _trafficFilter;
        private readonly ILiveTestingPipelineFactory _pipelineFactory;
        private readonly IBlockageStateStoreFactory _stateStoreFactory;
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

        // P2.3: прогресс Apply (чтобы не было ощущения "кнопка не работает").
        private bool _isApplyRunning;
        private string _applyStatusText = "";

        // P1.5: защита от гонок manual vs auto apply.
        // Внутренний gate BypassController защищает реальное применение, но этот флаг
        // защищает UI/cts/обвязку Orchestrator от параллельного входа.
        private int _applyInFlight;

        // P1.1: дедупликация apply — не применяем повторно одинаковый план для той же цели.
        // Ключ: нормализованная цель (для доменов — SLD+TLD эвристика, как в auto-apply).
        private readonly ConcurrentDictionary<string, string> _lastAppliedPlanSignatureByTarget = new(StringComparer.OrdinalIgnoreCase);

        // Legacy (справочно): не влияет на основную рекомендацию INTEL
        private readonly HashSet<string> _legacyRecommendedStrategies = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _legacyManualRecommendations = new(StringComparer.OrdinalIgnoreCase);

        // Последний INTEL-диагноз (для панели рекомендаций)
        private string _lastIntelDiagnosisSummary = "";

        // Последний INTEL-план (объектно, без парсинга строк) для ручного применения.
        private BypassPlan? _lastIntelPlan;
        private string _lastIntelPlanHostKey = "";

        // Планы INTEL храним по целям, чтобы Apply мог работать по выбранному хосту,
        // а не по «последнему сообщению в логе».
        private readonly ConcurrentDictionary<string, BypassPlan> _intelPlansByHost =
            new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan IntelApplyTimeout = TimeSpan.FromSeconds(8);

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

        // P1.8: семантика Post-Apply проверки (OK/FAIL/PARTIAL/UNKNOWN) для UI.
        public event Action<string, string, string, string?>? OnPostApplyCheckVerdict;

        // P1.9: расширенный сигнал post-apply вердикта с correlationId/txId.
        // Нужен для строгой связки: Apply(txId) → PostApplyRetest(txId) → wins.
        public event Action<string, string, string, string?, string?>? OnPostApplyCheckVerdictV2;

        /// <summary>
        /// Делегат для показа ошибки/предупреждения (заголовок, текст).
        /// Инъектируется из View-слоя для соблюдения MVVM.
        /// </summary>
        public Action<string, string>? ShowError { get; set; }

        /// <summary>
        /// Делегат для подтверждения действия (заголовок, текст) → true/false.
        /// Инъектируется из View-слоя для соблюдения MVVM.
        /// </summary>
        public Func<string, string, bool>? ConfirmAction { get; set; }

        public DiagnosticOrchestrator(
            BypassStateManager stateManager,
            NoiseHostFilter noiseHostFilter,
            ITrafficFilter trafficFilter,
            ILiveTestingPipelineFactory pipelineFactory,
            IBlockageStateStoreFactory stateStoreFactory)
        {
            _stateManager = stateManager ?? throw new ArgumentNullException(nameof(stateManager));
            _trafficEngine = _stateManager.TrafficEngine;
            _noiseHostFilter = noiseHostFilter ?? throw new ArgumentNullException(nameof(noiseHostFilter));
            _trafficFilter = trafficFilter ?? throw new ArgumentNullException(nameof(trafficFilter));
            _pipelineFactory = pipelineFactory ?? throw new ArgumentNullException(nameof(pipelineFactory));
            _stateStoreFactory = stateStoreFactory ?? throw new ArgumentNullException(nameof(stateStoreFactory));
        }

        public DiagnosticOrchestrator(
            TrafficEngine trafficEngine,
            NoiseHostFilter noiseHostFilter,
            ITrafficFilter trafficFilter,
            ILiveTestingPipelineFactory pipelineFactory,
            IBlockageStateStoreFactory stateStoreFactory)
            : this(BypassStateManager.GetOrCreate(trafficEngine, baseProfile: null, log: null), noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory)
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

        public bool HasRecommendations => _lastIntelPlan != null;

        public bool HasAnyRecommendations => _recommendedStrategies.Count > 0
            || _manualRecommendations.Count > 0
            || _lastIntelPlan != null
            || !string.IsNullOrWhiteSpace(_lastIntelDiagnosisSummary);

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

        public bool IsApplyRunning
        {
            get => _isApplyRunning;
            private set
            {
                if (_isApplyRunning == value) return;
                _isApplyRunning = value;
                OnPropertyChanged(nameof(IsApplyRunning));
            }
        }

        public string ApplyStatusText
        {
            get => _applyStatusText;
            private set
            {
                if (string.Equals(_applyStatusText, value, StringComparison.Ordinal)) return;
                _applyStatusText = value;
                OnPropertyChanged(nameof(ApplyStatusText));
            }
        }

        #endregion

    }
}
