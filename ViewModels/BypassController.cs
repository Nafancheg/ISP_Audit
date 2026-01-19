using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Media;
using System.Collections.ObjectModel;
using System.Threading;
using IspAudit.Bypass;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.IntelligenceV2.Execution;
using IspAudit.Core.Traffic;
using IspAudit.Utils;
using IspAudit.Wpf;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Контроллер bypass-стратегий.
    /// Управляет toggle-кнопками (Fragment, Disorder, Fake, DROP_RST, DoH),
    /// работает через TlsBypassService (TrafficEngine управляется сервисом).
    /// </summary>
    public partial class BypassController : INotifyPropertyChanged
    {
        private readonly BypassStateManager _stateManager;
        private TlsBypassOptions _currentOptions;
        private TlsFragmentPreset? _selectedPreset;

        private readonly AutoHostlistService _autoHostlist;
        private bool _isAutoHostlistEnabled;
        private string _autoHostlistText = "(пока пусто)";

        // Флаги, не связанные напрямую с TLS bypass сервисом
        private bool _isDoHEnabled;
        private bool _isBypassActive;
        private bool _isVpnDetected;
        private string _vpnWarningText = "";
        private string _compatibilityWarning = "";
        private string _bypassWarningText = "";
        private string _bypassMetricsText = "";
        private string _bypassSemanticGroupsText = "";
        private string _bypassSemanticGroupsSummaryText = "";
        private System.Windows.Media.Brush _bypassVerdictBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246));
        private string _bypassVerdictText = "";
        private string _bypassPlanText = "-";
        private string _bypassMetricsSince = "-";
        private string _bypassVerdictReason = "";

        // Наблюдаемость QUIC→TCP и ретест outcome
        private string _quicModeText = "QUIC→TCP: выключен";
        private string _quicRuntimeStatusText = "";
        private System.Windows.Media.Brush _quicRuntimeStatusBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246));
        private long _lastUdp443Dropped;
        private DateTime _lastUdp443DroppedUtc = DateTime.MinValue;
        private string _outcomeProbeStatusText = "";
        private bool _isOutcomeProbeRunning;

        // DNS Presets
        private string _selectedDnsPreset = "Hybrid (CF + Yandex)";
        public List<string> AvailableDnsPresets { get; } = new()
        {
            "Cloudflare",
            "Google",
            "Yandex",
            "Hybrid (CF + Yandex)"
        };
        // QUIC fallback scope
        public ICommand SetQuicFallbackScopeCommand { get; private set; } = null!;

        public ICommand SetDnsPresetCommand { get; private set; } = null!;
        public ICommand RunOutcomeProbeNowCommand { get; private set; } = null!;

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Событие для логирования (MainViewModel подписывается)
        /// </summary>
        public event Action<string>? OnLog;

        public List<TlsFragmentPreset> FragmentPresets { get; }

        /// <summary>
        /// Auto-hostlist: список кандидатов (текстом), обновляется по сигналам в pipeline.
        /// </summary>
        public string AutoHostlistText
        {
            get => _autoHostlistText;
            private set
            {
                if (_autoHostlistText != value)
                {
                    _autoHostlistText = value;
                    OnPropertyChanged(nameof(AutoHostlistText));
                    OnPropertyChanged(nameof(AutoHostlistCount));
                }
            }
        }

        public int AutoHostlistCount => _autoHostlist.VisibleCount;

        public bool IsAutoHostlistEnabled
        {
            get => _isAutoHostlistEnabled;
            set
            {
                if (_isAutoHostlistEnabled == value) return;
                _isAutoHostlistEnabled = value;
                _autoHostlist.Enabled = value;
                if (!value)
                {
                    _autoHostlist.Clear();
                }
                RefreshAutoHostlistText();
                OnPropertyChanged(nameof(IsAutoHostlistEnabled));
            }
        }

        /// <summary>
        /// Сервис Auto-hostlist (передаётся в pipeline).
        /// </summary>
        public AutoHostlistService AutoHostlist => _autoHostlist;

        /// <summary>
        /// Статусы Semantic Groups (ENABLED/PARTIAL/NO_TRAFFIC) из policy-driven execution.
        /// Пусто, если feature не активен/не применим.
        /// </summary>
        public string BypassSemanticGroupsText
        {
            get => _bypassSemanticGroupsText;
            private set
            {
                if (_bypassSemanticGroupsText != value)
                {
                    _bypassSemanticGroupsText = value;
                    OnPropertyChanged(nameof(BypassSemanticGroupsText));
                }
            }
        }

        /// <summary>
        /// Короткая (1 строка) сводка Semantic Groups — показывается в шапке bypass-панели.
        /// </summary>
        public string BypassSemanticGroupsSummaryText
        {
            get => _bypassSemanticGroupsSummaryText;
            private set
            {
                if (_bypassSemanticGroupsSummaryText != value)
                {
                    _bypassSemanticGroupsSummaryText = value;
                    OnPropertyChanged(nameof(BypassSemanticGroupsSummaryText));
                }
            }
        }

        public TlsFragmentPreset? SelectedFragmentPreset
        {
            get => _selectedPreset;
            set
            {
                if (value != null && _selectedPreset != value)
                {
                    _selectedPreset = value;
                    _currentOptions = _currentOptions with
                    {
                        FragmentSizes = value.Sizes,
                        PresetName = value.Name
                    };
                    OnPropertyChanged(nameof(SelectedFragmentPreset));
                    OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                    PersistFragmentPreset();
                    _ = ApplyBypassOptionsAsync();
                }
            }
        }

        public string SelectedFragmentPresetLabel => _selectedPreset != null ? $"{_selectedPreset.Name} ({string.Join('/', _currentOptions.FragmentSizes)})" : string.Empty;

        public BypassController(BypassStateManager stateManager)
        {
            _stateManager = stateManager ?? throw new ArgumentNullException(nameof(stateManager));
            _currentOptions = _stateManager.GetOptionsSnapshot();

            _autoHostlist = new AutoHostlistService();
            _autoHostlist.Changed += () =>
            {
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    RefreshAutoHostlistText();
                });
            };

            // По умолчанию при старте всё выключено (в т.ч. assist-флаги QUIC→TCP / No SNI)
            _currentOptions = _currentOptions with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false,
                DropUdp443 = false,
                AllowNoSni = false
            };

            FragmentPresets = _stateManager.FragmentPresets.ToList();
            _selectedPreset = FragmentPresets
                .FirstOrDefault(p => string.Equals(p.Name, _currentOptions.PresetName, StringComparison.OrdinalIgnoreCase))
                ?? FragmentPresets.FirstOrDefault();

            if (_selectedPreset != null)
            {
                _currentOptions = _currentOptions with
                {
                    FragmentSizes = _selectedPreset.Sizes,
                    PresetName = _selectedPreset.Name
                };
            }

            _stateManager.MetricsUpdated += OnMetricsUpdated;
            _stateManager.VerdictChanged += OnVerdictChanged;
            _stateManager.StateChanged += OnStateChanged;

            SetDnsPresetCommand = new RelayCommand(param =>
            {
                if (param is string preset)
                {
                    SelectedDnsPreset = preset;
                }
            }, _ => true);

            RunOutcomeProbeNowCommand = new RelayCommand(_ =>
            {
                _ = RunOutcomeProbeNowUiAsync();
            }, _ => true);
            SetQuicFallbackScopeCommand = new RelayCommand(param =>
            {
                // Параметр ожидается: "Selective" или "Global"
                var scope = (param as string ?? string.Empty).Trim();
                if (scope.Equals("Global", StringComparison.OrdinalIgnoreCase))
                {
                    IsQuicFallbackGlobal = true;
                    return;
                }

                if (scope.Equals("Selective", StringComparison.OrdinalIgnoreCase))
                {
                    IsQuicFallbackGlobal = false;
                }
            }, _ => true);

            RefreshQuicObservability(null);
        }

        public BypassController(TrafficEngine trafficEngine)
            : this(BypassStateManager.GetOrCreate(trafficEngine, baseProfile: null, log: null))
        {
        }

        internal BypassController(TlsBypassService tlsService, BypassProfile baseProfile)
        {
            if (tlsService == null) throw new ArgumentNullException(nameof(tlsService));
            if (baseProfile == null) throw new ArgumentNullException(nameof(baseProfile));

            _stateManager = BypassStateManager.GetOrCreateFromService(tlsService, baseProfile, Log);
            _currentOptions = _stateManager.GetOptionsSnapshot();

            _autoHostlist = new AutoHostlistService();
            _autoHostlist.Changed += () =>
            {
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    RefreshAutoHostlistText();
                });
            };

            // По умолчанию при старте всё выключено (в т.ч. assist-флаги QUIC→TCP / No SNI)
            _currentOptions = _currentOptions with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false,
                DropUdp443 = false,
                AllowNoSni = false
            };

            FragmentPresets = _stateManager.FragmentPresets.ToList();
            _selectedPreset = FragmentPresets
                .FirstOrDefault(p => string.Equals(p.Name, _currentOptions.PresetName, StringComparison.OrdinalIgnoreCase))
                ?? FragmentPresets.FirstOrDefault();

            if (_selectedPreset != null)
            {
                _currentOptions = _currentOptions with
                {
                    FragmentSizes = _selectedPreset.Sizes,
                    PresetName = _selectedPreset.Name
                };
            }

            _stateManager.MetricsUpdated += OnMetricsUpdated;
            _stateManager.VerdictChanged += OnVerdictChanged;
            _stateManager.StateChanged += OnStateChanged;

            SetDnsPresetCommand = new RelayCommand(param =>
            {
                if (param is string preset)
                {
                    SelectedDnsPreset = preset;
                }
            }, _ => true);

            RunOutcomeProbeNowCommand = new RelayCommand(_ =>
            {
                _ = RunOutcomeProbeNowUiAsync();
            }, _ => true);

            SetQuicFallbackScopeCommand = new RelayCommand(param =>
            {
                var scope = (param as string ?? string.Empty).Trim();
                if (scope.Equals("Global", StringComparison.OrdinalIgnoreCase))
                {
                    IsQuicFallbackGlobal = true;
                    return;
                }

                if (scope.Equals("Selective", StringComparison.OrdinalIgnoreCase))
                {
                    IsQuicFallbackGlobal = false;
                }
            }, _ => true);

            RefreshQuicObservability(null);
        }

        private void RefreshAutoHostlistText()
        {
            AutoHostlistText = _autoHostlist.GetDisplayText();
        }

        #region Properties

        /// <summary>
        /// Выбранный пресет DNS
        /// </summary>
        public string SelectedDnsPreset
        {
            get => _selectedDnsPreset;
            set
            {
                if (_selectedDnsPreset != value)
                {
                    _selectedDnsPreset = value;
                    OnPropertyChanged(nameof(SelectedDnsPreset));
                    // Если DoH уже включен, переприменяем с новым пресетом
                    if (IsDoHEnabled)
                    {
                        _ = ApplyDoHAsync();
                    }
                }
            }
        }

        /// <summary>
        /// Показывать ли панель управления bypass (только при admin правах)
        /// </summary>
        public bool ShowBypassPanel => TrafficEngine.HasAdministratorRights;

        /// <summary>
        /// Сервис TLS bypass (единый источник настроек и метрик).
        /// </summary>
        public TlsBypassService TlsService => _stateManager.TlsService;

        /// <summary>
        /// Bypass активен в данный момент
        /// </summary>
        public bool IsBypassActive
        {
            get => _isBypassActive;
            private set { _isBypassActive = value; OnPropertyChanged(nameof(IsBypassActive)); }
        }

        /// <summary>
        /// TLS Fragment включен (фрагменты в правильном порядке)
        /// </summary>
        public bool IsFragmentEnabled
        {
            get => _currentOptions.FragmentEnabled;
            set
            {
                if (_currentOptions.FragmentEnabled == value) return;

                // Взаимоисключение с Disorder
                if (value && _currentOptions.DisorderEnabled)
                {
                    _currentOptions = _currentOptions with { DisorderEnabled = false, FragmentEnabled = true };
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                }
                else
                {
                    _currentOptions = _currentOptions with { FragmentEnabled = value };
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                }

                NotifyActiveStatesChanged();
                CheckCompatibility();
                _ = ApplyBypassOptionsAsync();
            }
        }

        /// <summary>
        /// TLS Disorder включен (фрагменты в ОБРАТНОМ порядке)
        /// </summary>
        public bool IsDisorderEnabled
        {
            get => _currentOptions.DisorderEnabled;
            set
            {
                if (_currentOptions.DisorderEnabled == value) return;

                // Взаимоисключение с Fragment
                if (value && _currentOptions.FragmentEnabled)
                {
                    _currentOptions = _currentOptions with { FragmentEnabled = false, DisorderEnabled = true };
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                }
                else
                {
                    _currentOptions = _currentOptions with { DisorderEnabled = value };
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                }

                NotifyActiveStatesChanged();
                CheckCompatibility();
                _ = ApplyBypassOptionsAsync();
            }
        }

        /// <summary>
        /// TLS Fake включен
        /// </summary>
        public bool IsFakeEnabled
        {
            get => _currentOptions.FakeEnabled;
            set
            {
                if (_currentOptions.FakeEnabled == value) return;

                _currentOptions = _currentOptions with { FakeEnabled = value };
                OnPropertyChanged(nameof(IsFakeEnabled));
                NotifyActiveStatesChanged();
                CheckCompatibility();
                _ = ApplyBypassOptionsAsync();
            }
        }

        /// <summary>
        /// DROP RST включен
        /// </summary>
        public bool IsDropRstEnabled
        {
            get => _currentOptions.DropRstEnabled;
            set
            {
                if (_currentOptions.DropRstEnabled == value) return;

                _currentOptions = _currentOptions with { DropRstEnabled = value };
                OnPropertyChanged(nameof(IsDropRstEnabled));
                NotifyActiveStatesChanged();
                CheckCompatibility();
                _ = ApplyBypassOptionsAsync();
            }
        }

        /// <summary>
        /// QUIC fallback: глушить UDP/443, чтобы клиент откатился на TCP/HTTPS.
        /// </summary>
        public bool IsQuicFallbackEnabled
        {
            get => _currentOptions.DropUdp443;
            set
            {
                if (_currentOptions.DropUdp443 == value) return;

                _currentOptions = _currentOptions with { DropUdp443 = value };
                OnPropertyChanged(nameof(IsQuicFallbackEnabled));
                PersistAssistSettings();
                NotifyActiveStatesChanged();
                CheckCompatibility();
                RefreshQuicObservability(null);
                _ = ApplyBypassOptionsAsync();
            }
        }

        public bool IsQuicFallbackGlobal
        {
            get => _currentOptions.DropUdp443Global;
            set
            {
                if (_currentOptions.DropUdp443Global == value) return;
                _currentOptions = _currentOptions with { DropUdp443Global = value };
                OnPropertyChanged(nameof(IsQuicFallbackGlobal));
                PersistAssistSettings();

                RefreshQuicObservability(null);

                // Если QUIC fallback уже включён — нужно пере-применить, чтобы фильтр начал/перестал
                // глушить UDP/443 глобально без зависимости от цели.
                if (IsQuicFallbackEnabled)
                {
                    _ = ApplyBypassOptionsAsync();
                }
            }
        }

        public string QuicModeText
        {
            get => _quicModeText;
            private set
            {
                if (_quicModeText == value) return;
                _quicModeText = value;
                OnPropertyChanged(nameof(QuicModeText));
            }
        }

        public string QuicRuntimeStatusText
        {
            get => _quicRuntimeStatusText;
            private set
            {
                if (_quicRuntimeStatusText == value) return;
                _quicRuntimeStatusText = value;
                OnPropertyChanged(nameof(QuicRuntimeStatusText));
            }
        }

        public System.Windows.Media.Brush QuicRuntimeStatusBrush
        {
            get => _quicRuntimeStatusBrush;
            private set
            {
                _quicRuntimeStatusBrush = value;
                OnPropertyChanged(nameof(QuicRuntimeStatusBrush));
            }
        }

        public bool IsOutcomeProbeRunning
        {
            get => _isOutcomeProbeRunning;
            private set
            {
                if (_isOutcomeProbeRunning == value) return;
                _isOutcomeProbeRunning = value;
                OnPropertyChanged(nameof(IsOutcomeProbeRunning));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        public string OutcomeProbeStatusText
        {
            get => _outcomeProbeStatusText;
            private set
            {
                if (_outcomeProbeStatusText == value) return;
                _outcomeProbeStatusText = value;
                OnPropertyChanged(nameof(OutcomeProbeStatusText));
            }
        }

        /// <summary>
        /// Разрешить применение TLS-обхода даже когда SNI не распознан/отсутствует.
        /// </summary>
        public bool IsAllowNoSniEnabled
        {
            get => _currentOptions.AllowNoSni;
            set
            {
                if (_currentOptions.AllowNoSni == value) return;

                _currentOptions = _currentOptions with { AllowNoSni = value };
                OnPropertyChanged(nameof(IsAllowNoSniEnabled));
                PersistAssistSettings();
                NotifyActiveStatesChanged();
                CheckCompatibility();
                _ = ApplyBypassOptionsAsync();
            }
        }

        /// <summary>
        /// DoH (DNS-over-HTTPS) включен
        /// </summary>
        public bool IsDoHEnabled
        {
            get => _isDoHEnabled;
            set
            {
                if (_isDoHEnabled != value)
                {
                    _isDoHEnabled = value;
                    OnPropertyChanged(nameof(IsDoHEnabled));
                    CheckCompatibility();
                    if (value)
                    {
                        _ = ApplyDoHAsync();
                    }
                    else
                    {
                        _ = RestoreDoHAsync();
                    }
                }
            }
        }

        /// <summary>
        /// Обнаружен ли VPN
        /// </summary>
        public bool IsVpnDetected
        {
            get => _isVpnDetected;
            private set { _isVpnDetected = value; OnPropertyChanged(nameof(IsVpnDetected)); }
        }

        /// <summary>
        /// Текст предупреждения о VPN
        /// </summary>
        public string VpnWarningText
        {
            get => _vpnWarningText;
            private set { _vpnWarningText = value; OnPropertyChanged(nameof(VpnWarningText)); }
        }

        /// <summary>
        /// Предупреждение о несовместимости стратегий
        /// </summary>
        public string CompatibilityWarning
        {
            get => _compatibilityWarning;
            private set
            {
                _compatibilityWarning = value;
                OnPropertyChanged(nameof(CompatibilityWarning));
                OnPropertyChanged(nameof(HasCompatibilityWarning));
            }
        }

        /// <summary>
        /// Есть ли предупреждение о несовместимости
        /// </summary>
        public bool HasCompatibilityWarning => !string.IsNullOrEmpty(CompatibilityWarning);

        /// <summary>
        /// Предупреждение о состоянии bypass
        /// </summary>
        public string BypassWarningText
        {
            get => _bypassWarningText;
            private set { _bypassWarningText = value; OnPropertyChanged(nameof(BypassWarningText)); }
        }

        /// <summary>
        /// Текущая активная стратегия bypass (для отображения в UI badge)
        /// </summary>
        public string CurrentBypassStrategy
        {
            get
            {
                var parts = new List<string>();
                if (IsFragmentEnabled) parts.Add("Fragment");
                if (IsDisorderEnabled) parts.Add("Disorder");
                if (IsFakeEnabled) parts.Add("Fake");
                if (IsDropRstEnabled) parts.Add("DROP RST");
                if (IsQuicFallbackEnabled) parts.Add("DROP UDP/443");
                if (IsAllowNoSniEnabled) parts.Add("AllowNoSNI");
                return parts.Count > 0 ? string.Join(" + ", parts) : "Выключен";
            }
        }

        // Свойства для подсветки кнопок в UI
        public bool IsTlsFragmentActive => IsFragmentEnabled && IsBypassActive;
        public bool IsTlsDisorderActive => IsDisorderEnabled && IsBypassActive;
        public bool IsTlsFakeActive => IsFakeEnabled && IsBypassActive;
        public bool IsDropRstActive => IsDropRstEnabled && IsBypassActive;
        public bool IsDoHActive => IsDoHEnabled;

        #region Bypass Metrics & Verdict

        /// <summary>
        /// Текстовое представление метрик bypass (фрагментации/RST)
        /// </summary>
        public string BypassMetricsText
        {
            get => _bypassMetricsText;
            private set { _bypassMetricsText = value; OnPropertyChanged(nameof(BypassMetricsText)); }
        }

        /// <summary>
        /// План фрагментации, применённый в фильтре
        /// </summary>
        public string BypassPlanText
        {
            get => _bypassPlanText;
            private set { _bypassPlanText = value; OnPropertyChanged(nameof(BypassPlanText)); }
        }

        /// <summary>
        /// Метрики считаются с момента последнего применения опций
        /// </summary>
        public string BypassMetricsSince
        {
            get => _bypassMetricsSince;
            private set { _bypassMetricsSince = value; OnPropertyChanged(nameof(BypassMetricsSince)); }
        }

        /// <summary>
        /// Причина текущего вердикта (для tooltip)
        /// </summary>
        public string BypassVerdictReason
        {
            get => _bypassVerdictReason;
            private set { _bypassVerdictReason = value; OnPropertyChanged(nameof(BypassVerdictReason)); }
        }

        /// <summary>
        /// Автокоррекция агрессивного пресета по метрикам
        /// </summary>
        public bool IsAutoAdjustAggressive
        {
            get => _currentOptions.AutoAdjustAggressive;
            set
            {
                if (_currentOptions.AutoAdjustAggressive == value) return;

                _currentOptions = _currentOptions with { AutoAdjustAggressive = value };
                OnPropertyChanged(nameof(IsAutoAdjustAggressive));
                PersistFragmentPreset();
                _ = ApplyBypassOptionsAsync();
            }
        }

        /// <summary>
        /// Цвет фона блока метрик (градация состояния)
        /// </summary>
        public System.Windows.Media.Brush BypassVerdictBrush
        {
            get => _bypassVerdictBrush;
            private set { _bypassVerdictBrush = value; OnPropertyChanged(nameof(BypassVerdictBrush)); }
        }

        /// <summary>
        /// Краткий вердикт по метрикам
        /// </summary>
        public string BypassVerdictText
        {
            get => _bypassVerdictText;
            private set { _bypassVerdictText = value; OnPropertyChanged(nameof(BypassVerdictText)); }
        }

        #endregion

        #endregion

        // Приватные методы и обработчики метрик/состояний вынесены в partial-файлы:
        // - BypassController.Internal.cs
        // - BypassController.Metrics.cs
    }
}
