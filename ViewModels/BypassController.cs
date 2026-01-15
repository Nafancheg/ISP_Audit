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

        #region Initialization

        /// <summary>
        /// Инициализация bypass и DoH при запуске приложения
        /// </summary>
        public async Task InitializeOnStartupAsync()
        {
            // Проверка VPN
            CheckVpnStatus();

            // Crash recovery + watchdog инициализируем всегда (даже без admin),
            // чтобы корректно обработать некорректно завершённую прошлую сессию.
            try
            {
                await _stateManager.InitializeOnStartupAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log($"[Bypass][Watchdog] Init failed: {ex.Message}");
            }

            // Crash-recovery (P0): если предыдущая сессия меняла DNS/DoH и не успела откатиться,
            // пытаемся восстановить настройки сразу при старте.
            try
            {
                if (FixService.HasBackupFile)
                {
                    if (TrafficEngine.HasAdministratorRights)
                    {
                        Log("[DoH] Detected leftover DNS backup from previous session. Restoring...");
                        var (success, error) = await FixService.RestoreDnsAsync().ConfigureAwait(false);
                        Log(success ? "[DoH] DNS restored on startup (crash recovery)." : $"[DoH] Startup restore failed: {error}");
                    }
                    else
                    {
                        Log("[DoH] Detected leftover DNS backup, but no admin rights to restore.");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[DoH] Startup restore exception: {ex.Message}");
            }

            if (!TrafficEngine.HasAdministratorRights)
            {
                Log("[Bypass] No admin rights - bypass not available");
                return;
            }

            try
            {
                Log("[Bypass] Initializing bypass on application startup...");

                // Автоматическое включение отключено по результатам аудита (риск скрытого поведения)
                // _isDisorderEnabled = true;
                // _isFragmentEnabled = false;
                // _isDropRstEnabled = true;

                // Не включаем DoH автоматически по наличию backup.
                // Backup может означать незавершённую прошлую сессию (мы уже попытались восстановить выше).

                // Проверяем текущее состояние DNS (в фоновом потоке, чтобы не фризить UI)
                var activePreset = await Task.Run(() => FixService.DetectActivePreset());

                if (activePreset != null)
                {
                    // Меняем выбранный пресет ТОЛЬКО если есть backup (то есть это состояние выставляло приложение).
                    // Если backup нет, совпадение DNS может быть «чужим» или результатом старой/нечистой сессии,
                    // и мы не должны автоматически переключать выбор пользователя на Cloudflare/Google и т.п.
                    if (FixService.HasBackupFile)
                    {
                        _selectedDnsPreset = activePreset;
                        OnPropertyChanged(nameof(SelectedDnsPreset));
                        _isDoHEnabled = true;
                        OnPropertyChanged(nameof(IsDoHEnabled));
                        Log($"[Bypass] Detected active DoH preset (restorable): {activePreset}");
                    }
                    else
                    {
                        // Если бэкапа нет — просто логируем факт, но не меняем preset и не включаем DoH.
                        if (_isDoHEnabled)
                        {
                            _isDoHEnabled = false;
                            OnPropertyChanged(nameof(IsDoHEnabled));
                        }
                        Log($"[Bypass] Detected active DNS provider: {activePreset} (DoH not confirmed)");
                    }
                }
                else
                {
                    // Если пресет не обнаружен, снимаем галочку (даже если был бэкап, значит состояние рассинхронизировано)
                    if (_isDoHEnabled)
                    {
                        _isDoHEnabled = false;
                        OnPropertyChanged(nameof(IsDoHEnabled));
                    }
                }

                OnPropertyChanged(nameof(IsDisorderEnabled));
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                // IsDoHEnabled уже обновлен выше

                // Проверяем совместимость после включения опций
                CheckCompatibility();

                // Применяем WinDivert bypass
                await ApplyBypassOptionsAsync().ConfigureAwait(false);

                Log($"[Bypass] Startup complete: {_currentOptions.ToReadableStrategy()}");
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Failed to initialize bypass on startup: {ex.Message}");
            }
        }

        #endregion

        #region Core Methods

        private sealed record BypassStateSnapshot(TlsBypassOptions Options, bool DoHEnabled, string SelectedDnsPreset);

        private BypassStateSnapshot CaptureStateSnapshot()
        {
            return new BypassStateSnapshot(_currentOptions, _isDoHEnabled, SelectedDnsPreset);
        }

        private async Task RestoreSnapshotAsync(BypassStateSnapshot snapshot)
        {
            _currentOptions = snapshot.Options;
            _isDoHEnabled = snapshot.DoHEnabled;
            _selectedDnsPreset = snapshot.SelectedDnsPreset;

            Application.Current?.Dispatcher.Invoke(() =>
            {
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDisorderEnabled));
                OnPropertyChanged(nameof(IsFakeEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                OnPropertyChanged(nameof(IsDoHEnabled));
                OnPropertyChanged(nameof(IsDoHActive));
                OnPropertyChanged(nameof(SelectedDnsPreset));
                NotifyActiveStatesChanged();
                CheckCompatibility();
            });

            await ApplyBypassOptionsAsync(CancellationToken.None).ConfigureAwait(false);

            if (_isDoHEnabled)
            {
                await ApplyDoHAsync().ConfigureAwait(false);
            }
            else
            {
                await DisableDoHAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Применить текущие настройки bypass
        /// </summary>
        public Task ApplyBypassOptionsAsync()
        {
            return ApplyBypassOptionsAsync(CancellationToken.None);
        }

        /// <summary>
        /// Применить текущие настройки bypass (с поддержкой отмены)
        /// </summary>
        public async Task ApplyBypassOptionsAsync(CancellationToken cancellationToken)
        {
            try
            {
                var normalized = _currentOptions.Normalize();
                _currentOptions = normalized;
                await _stateManager.ApplyTlsOptionsAsync(normalized, cancellationToken).ConfigureAwait(false);

                SafeUiInvoke(NotifyActiveStatesChanged);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Error applying options: {ex.Message}");
            }
        }

        /// <summary>
        /// Применить DoH (DNS-over-HTTPS)
        /// </summary>
        public async Task ApplyDoHAsync()
        {
            try
            {
                string presetName = SelectedDnsPreset;
                Log($"[DoH] Applying DNS-over-HTTPS ({presetName})...");

                var (success, error) = await FixService.ApplyDnsFixAsync(presetName).ConfigureAwait(false);

                SafeUiInvoke(() =>
                {
                    if (success)
                    {
                        Log($"[DoH] DoH enabled: {presetName}");
                    }
                    else
                    {
                        Log($"[DoH] Failed: {error}");
                        _isDoHEnabled = false;
                        OnPropertyChanged(nameof(IsDoHEnabled));
                        OnPropertyChanged(nameof(IsDoHActive));
                    }
                });
            }
            catch (Exception ex)
            {
                Log($"[DoH] Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Восстановить исходные настройки DNS
        /// </summary>
        public async Task RestoreDoHAsync()
        {
            try
            {
                Log($"[DoH] Restoring original DNS settings...");
                var (success, error) = await FixService.RestoreDnsAsync().ConfigureAwait(false);

                SafeUiInvoke(() =>
                {
                    if (success)
                    {
                        Log($"[DoH] DNS settings restored.");
                    }
                    else
                    {
                        Log($"[DoH] Restore failed: {error}");
                    }
                    OnPropertyChanged(nameof(IsDoHActive));
                });
            }
            catch (Exception ex)
            {
                Log($"[DoH] Error restoring DNS: {ex.Message}");
            }
        }

        private static void SafeUiInvoke(Action action)
        {
            try
            {
                var dispatcher = Application.Current?.Dispatcher;
                if (dispatcher == null || dispatcher.HasShutdownStarted || dispatcher.HasShutdownFinished)
                {
                    action();
                    return;
                }

                if (dispatcher.CheckAccess())
                {
                    action();
                }
                else
                {
                    dispatcher.BeginInvoke(action);
                }
            }
            catch
            {
                // ignore
            }
        }

        /// <summary>
        /// Отключить все опции bypass
        /// </summary>
        public Task DisableAllAsync()
        {
            return DisableAllAsync(CancellationToken.None);
        }

        /// <summary>
        /// Отключить все опции bypass (с поддержкой отмены)
        /// </summary>
        public async Task DisableAllAsync(CancellationToken cancellationToken)
        {
            _currentOptions = _currentOptions with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false,
                DropUdp443 = false,
                AllowNoSni = false
            };

            OnPropertyChanged(nameof(IsFragmentEnabled));
            OnPropertyChanged(nameof(IsDisorderEnabled));
            OnPropertyChanged(nameof(IsFakeEnabled));
            OnPropertyChanged(nameof(IsDropRstEnabled));
            OnPropertyChanged(nameof(IsQuicFallbackEnabled));
            OnPropertyChanged(nameof(IsAllowNoSniEnabled));
            NotifyActiveStatesChanged();
            CheckCompatibility();

            await ApplyBypassOptionsAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Отключить DoH и восстановить исходные DNS настройки.
        /// </summary>
        public async Task DisableDoHAsync()
        {
            if (!_isDoHEnabled)
            {
                return;
            }

            _isDoHEnabled = false;

            Application.Current?.Dispatcher.Invoke(() =>
            {
                OnPropertyChanged(nameof(IsDoHEnabled));
                OnPropertyChanged(nameof(IsDoHActive));
            });

            await RestoreDoHAsync().ConfigureAwait(false);
            }

        /// <summary>
        /// Применить v2 план рекомендаций (ТОЛЬКО вручную), с таймаутом/отменой и безопасным откатом.
        /// </summary>
        public async Task ApplyV2PlanAsync(BypassPlan plan, TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (plan == null) throw new ArgumentNullException(nameof(plan));

            cancellationToken.ThrowIfCancellationRequested();

            var strategiesText = plan.Strategies.Count == 0
                ? "(пусто)"
                : string.Join(", ", plan.Strategies.Select(s => s.Id));

            Log($"[V2][Executor] Apply requested: диагноз={plan.ForDiagnosis} conf={plan.PlanConfidence}% стратегии={strategiesText}");
            if (!string.IsNullOrWhiteSpace(plan.Reasoning))
            {
                Log($"[V2][Executor] Reasoning: {plan.Reasoning}");
            }

            var snapshot = CaptureStateSnapshot();
            Log($"[V2][Executor] Timeout={(timeout > TimeSpan.Zero ? timeout.TotalSeconds.ToString("0.##") + "s" : "none")}; before={snapshot.Options.ToReadableStrategy()}; DoH={(snapshot.DoHEnabled ? "on" : "off")}; DNS={snapshot.SelectedDnsPreset}");

            using var timeoutCts = timeout > TimeSpan.Zero ? new CancellationTokenSource(timeout) : null;
            using var linked = timeoutCts != null
                ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            try
            {
                linked.Token.ThrowIfCancellationRequested();
                    _currentOptions = _stateManager.GetOptionsSnapshot();
                var updated = _currentOptions;
                var enableDoH = false;
                TlsFragmentPreset? requestedPreset = null;
                bool? requestedAutoAdjustAggressive = null;

                foreach (var strategy in plan.Strategies)
                {
                    switch (strategy.Id)
                    {
                        case StrategyId.TlsFragment:
                            updated = updated with { FragmentEnabled = true, DisorderEnabled = false };

                            // Опциональные параметры стратегии: пресет/размеры/auto-adjust.
                            // Если параметров нет — сохраняем текущий выбранный пресет пользователя.
                            if (strategy.Parameters != null && strategy.Parameters.Count > 0)
                            {
                                if (TlsFragmentPlanParamsParser.TryParse(strategy.Parameters, out var parsed))
                                {
                                    if (parsed.Sizes != null && parsed.Sizes.Count > 0)
                                    {
                                        var sizes = parsed.Sizes.ToList();
                                        requestedPreset = ResolveOrCreatePresetBySizes(sizes);
                                        Log($"[V2][Executor] TlsFragment param: sizes=[{string.Join(",", sizes)}] → preset='{requestedPreset.Name}'");
                                    }
                                    else if (!string.IsNullOrWhiteSpace(parsed.PresetName))
                                    {
                                        var resolved = ResolvePresetByNameOrAlias(parsed.PresetName);
                                        if (resolved != null)
                                        {
                                            requestedPreset = resolved;
                                            Log($"[V2][Executor] TlsFragment param: preset='{parsed.PresetName}' → '{resolved.Name}'");
                                        }
                                        else
                                        {
                                            Log($"[V2][Executor] TlsFragment param: preset='{parsed.PresetName}' не распознан — пропуск");
                                        }
                                    }

                                    if (parsed.AutoAdjustAggressive.HasValue)
                                    {
                                        requestedAutoAdjustAggressive = parsed.AutoAdjustAggressive.Value;
                                        Log($"[V2][Executor] TlsFragment param: autoAdjustAggressive={(requestedAutoAdjustAggressive.Value ? "true" : "false")}");
                                    }
                                }
                            }
                            break;
                        case StrategyId.AggressiveFragment:
                            // Агрессивная фрагментация: используем пресет «Агрессивный» + авто-подстройку.
                            updated = updated with { FragmentEnabled = true, DisorderEnabled = false };
                            requestedPreset = FragmentPresets
                                .FirstOrDefault(p => string.Equals(p.Name, "Агрессивный", StringComparison.OrdinalIgnoreCase));
                            requestedAutoAdjustAggressive = true;
                            break;
                        case StrategyId.TlsDisorder:
                            updated = updated with { DisorderEnabled = true, FragmentEnabled = false };
                            break;
                        case StrategyId.TlsFakeTtl:
                            updated = updated with { FakeEnabled = true };
                            break;
                        case StrategyId.DropRst:
                            updated = updated with { DropRstEnabled = true };
                            break;
                        case StrategyId.UseDoh:
                            enableDoH = true;
                            break;
                        case StrategyId.QuicObfuscation:
                            // Реализация MVP: QUIC obfuscation = QUIC→TCP fallback (DROP UDP/443).
                            updated = updated with { DropUdp443 = true };
                            Log("[V2][Executor] QuicObfuscation: включаем QUIC→TCP (DROP UDP/443)");
                            break;
                        case StrategyId.HttpHostTricks:
                            updated = updated with { HttpHostTricksEnabled = true };
                            Log("[V2][Executor] HttpHostTricks: включаем HTTP Host tricks");
                            break;
                        case StrategyId.BadChecksum:
                            updated = updated with { BadChecksumEnabled = true };
                            Log("[V2][Executor] BadChecksum: включаем bad checksum (только для фейковых пакетов)");
                            break;
                        default:
                            // Нереализованные/неподдерживаемые в bypass контроллере стратегии пропускаем.
                            Log($"[V2][Executor] Стратегия {strategy.Id} не поддерживается контроллером — пропуск");
                            break;
                    }
                }

                // Assist-флаги из плана (включаем только если селектор их рекомендовал).
                if (plan.DropUdp443)
                {
                    updated = updated with { DropUdp443 = true };
                    Log("[V2][Executor] Assist: включаем QUIC→TCP (DROP UDP/443)");
                }

                if (plan.AllowNoSni)
                {
                    updated = updated with { AllowNoSni = true };
                    Log("[V2][Executor] Assist: включаем No SNI (разрешить обход без SNI)");
                }

                if (requestedPreset != null)
                {
                    // Если пресет создан из параметров v2 и отсутствует в списке — добавим, чтобы UI мог корректно отобразить выбранный вариант.
                    if (!FragmentPresets.Any(p => string.Equals(p.Name, requestedPreset.Name, StringComparison.OrdinalIgnoreCase)
                        && p.Sizes.SequenceEqual(requestedPreset.Sizes)))
                    {
                        FragmentPresets.Add(requestedPreset);
                    }

                    _selectedPreset = requestedPreset;
                    updated = updated with
                    {
                        FragmentSizes = requestedPreset.Sizes,
                        PresetName = requestedPreset.Name
                    };
                }

                if (requestedAutoAdjustAggressive.HasValue)
                {
                    updated = updated with { AutoAdjustAggressive = requestedAutoAdjustAggressive.Value };
                }
                else if (requestedPreset != null && string.Equals(requestedPreset.Name, "Агрессивный", StringComparison.OrdinalIgnoreCase))
                {
                    // Если явно выбрали агрессивный пресет (даже через TlsFragment), логично включить авто-подстройку.
                    updated = updated with { AutoAdjustAggressive = true };
                }

                _currentOptions = updated;

                Log($"[V2][Executor] Target={_currentOptions.ToReadableStrategy()}; DoH={(enableDoH ? "on" : "off")}; DNS={SelectedDnsPreset}");

                linked.Token.ThrowIfCancellationRequested();

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                    OnPropertyChanged(nameof(IsFakeEnabled));
                    OnPropertyChanged(nameof(IsDropRstEnabled));
                    OnPropertyChanged(nameof(IsQuicFallbackEnabled));
                    OnPropertyChanged(nameof(IsAllowNoSniEnabled));
                    OnPropertyChanged(nameof(IsAutoAdjustAggressive));
                    OnPropertyChanged(nameof(SelectedFragmentPreset));
                    OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                    NotifyActiveStatesChanged();
                    CheckCompatibility();
                });

                // Сохраняем параметры фрагментации/пресета и флаг авто-подстройки.
                PersistFragmentPreset();

                // Сохраняем assist-флаги (QUIC→TCP / No SNI) в профиль.
                PersistAssistSettings();

                Log("[V2][Executor] Applying bypass options...");
                await ApplyBypassOptionsAsync(linked.Token).ConfigureAwait(false);
                Log("[V2][Executor] Bypass options applied");

                linked.Token.ThrowIfCancellationRequested();

                if (enableDoH && !_isDoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Log("[V2][Executor] Applying DoH (enable)");
                    _isDoHEnabled = true;
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        OnPropertyChanged(nameof(IsDoHEnabled));
                        OnPropertyChanged(nameof(IsDoHActive));
                    });
                    await ApplyDoHAsync().ConfigureAwait(false);
                }

                if (!enableDoH && _isDoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Log("[V2][Executor] Applying DoH (disable)");
                    await DisableDoHAsync().ConfigureAwait(false);
                }

                Log($"[V2][Executor] Apply complete: after={_currentOptions.ToReadableStrategy()}; DoH={(_isDoHEnabled ? "on" : "off")}; DNS={SelectedDnsPreset}");
            }
            catch (OperationCanceledException)
            {
                var cancelReason = timeoutCts?.IsCancellationRequested == true
                    ? "timeout"
                    : (cancellationToken.IsCancellationRequested ? "cancel" : "cancel");
                Log($"[V2][Executor] Apply {cancelReason} — rollback");
                Log($"[V2][Executor] Rollback to: {snapshot.Options.ToReadableStrategy()}; DoH={(snapshot.DoHEnabled ? "on" : "off")}; DNS={snapshot.SelectedDnsPreset}");
                await RestoreSnapshotAsync(snapshot).ConfigureAwait(false);
                Log($"[V2][Executor] Rollback complete: after={_currentOptions.ToReadableStrategy()}; DoH={(_isDoHEnabled ? "on" : "off")}; DNS={SelectedDnsPreset}");
                throw;
            }
            catch (Exception ex)
            {
                Log($"[V2][Executor] Apply failed: {ex.Message} — rollback");
                Log($"[V2][Executor] Rollback to: {snapshot.Options.ToReadableStrategy()}; DoH={(snapshot.DoHEnabled ? "on" : "off")}; DNS={snapshot.SelectedDnsPreset}");
                await RestoreSnapshotAsync(snapshot).ConfigureAwait(false);
                Log($"[V2][Executor] Rollback complete: after={_currentOptions.ToReadableStrategy()}; DoH={(_isDoHEnabled ? "on" : "off")}; DNS={SelectedDnsPreset}");
                throw;
            }
        }

        /// <summary>
        /// Overload: применить v2 план и одновременно задать цель для HTTPS outcome-check.
        /// </summary>
        public Task ApplyV2PlanAsync(BypassPlan plan, string? outcomeTargetHost, TimeSpan timeout, CancellationToken cancellationToken)
        {
            _stateManager.SetOutcomeTargetHost(outcomeTargetHost);
            return ApplyV2PlanAsync(plan, timeout, cancellationToken);
        }

        public string GetOutcomeTargetHost() => _stateManager.GetOutcomeTargetHost();

        public void SetOutcomeTargetHost(string? host) => _stateManager.SetOutcomeTargetHost(host);

        private TlsFragmentPreset? ResolvePresetByNameOrAlias(string presetName)
        {
            if (string.IsNullOrWhiteSpace(presetName))
            {
                return null;
            }

            var normalized = presetName.Trim();

            // Поддерживаем русские названия пресетов.
            var direct = FragmentPresets.FirstOrDefault(p => string.Equals(p.Name, normalized, StringComparison.OrdinalIgnoreCase));
            if (direct != null)
            {
                return direct;
            }

            // Алиасы (на будущее / на случай JSON-конфига).
            var alias = normalized.ToLowerInvariant();
            var mapped = alias switch
            {
                "standard" or "std" => "Стандарт",
                "moderate" or "medium" => "Умеренный",
                "aggressive" or "agg" => "Агрессивный",
                "profile" => "Профиль",
                _ => null
            };

            if (mapped == null)
            {
                return null;
            }

            return FragmentPresets.FirstOrDefault(p => string.Equals(p.Name, mapped, StringComparison.OrdinalIgnoreCase));
        }

        private TlsFragmentPreset ResolveOrCreatePresetBySizes(List<int> sizes)
        {
            var normalized = NormalizeFragmentSizes(sizes);
            if (normalized.Count == 0)
            {
                // Фоллбек: не должно случиться (проверяется выше), но держим безопасно.
                normalized = new List<int> { 64 };
            }

            var existing = FragmentPresets.FirstOrDefault(p => p.Sizes.SequenceEqual(normalized));
            if (existing != null)
            {
                return existing;
            }

            // Синтетический пресет только при явных размерах из плана.
            return new TlsFragmentPreset("План v2", normalized, "Сгенерировано из параметров стратегии v2");
        }

        private static List<int> NormalizeFragmentSizes(IEnumerable<int> input)
        {
            var safe = input
                .Where(v => v > 0)
                .Select(v => Math.Max(4, v))
                .Take(4)
                .ToList();

            return safe;
        }

        /// <summary>
        /// Применить рекомендации из классификатора (без повторного включения активных стратегий).
        /// </summary>
        public async Task ApplyRecommendedAsync(IEnumerable<string> strategies)
        {
            if (strategies == null) return;

            var unique = strategies
                .Select(s => s?.Trim())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s!.ToUpperInvariant())
                .Distinct()
                .ToList();

            if (!unique.Any()) return;

            var updated = _currentOptions;
            var enableDoH = false;

            foreach (var strategy in unique)
            {
                switch (strategy)
                {
                    case "TLS_FRAGMENT":
                        updated = updated with { FragmentEnabled = true, DisorderEnabled = false };
                        break;
                    case "TLS_DISORDER":
                        updated = updated with { DisorderEnabled = true, FragmentEnabled = false };
                        break;
                    case "TLS_FAKE":
                        updated = updated with { FakeEnabled = true };
                        break;
                    case "TLS_FAKE_FRAGMENT":
                        updated = updated with { FakeEnabled = true, FragmentEnabled = true, DisorderEnabled = false };
                        break;
                    case "DROP_RST":
                        updated = updated with { DropRstEnabled = true };
                        break;
                    case "DOH":
                        enableDoH = true;
                        break;
                    default:
                        break;
                }
            }

            _currentOptions = updated;

            Application.Current?.Dispatcher.Invoke(() =>
            {
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDisorderEnabled));
                OnPropertyChanged(nameof(IsFakeEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                NotifyActiveStatesChanged();
                CheckCompatibility();
            });

            await ApplyBypassOptionsAsync().ConfigureAwait(false);

            if (enableDoH && !IsDoHEnabled)
            {
                _isDoHEnabled = true;
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OnPropertyChanged(nameof(IsDoHEnabled));
                    OnPropertyChanged(nameof(IsDoHActive));
                });
                await ApplyDoHAsync().ConfigureAwait(false);
            }

            Log($"[Bypass] Применены рекомендации: {string.Join(',', unique)}");
        }

        /// <summary>
        /// Включить преимптивный bypass (вызывается при старте диагностики)
        /// </summary>
        public async Task EnablePreemptiveBypassAsync()
        {
            if (!TrafficEngine.HasAdministratorRights) return;

            Log("[Bypass] Enabling preemptive TLS_DISORDER + DROP_RST...");

            try
            {
                _currentOptions = _currentOptions with
                {
                    FragmentEnabled = false,
                    DisorderEnabled = true,
                    FakeEnabled = false,
                    DropRstEnabled = true
                };

                await _stateManager.ApplyPreemptiveAsync().ConfigureAwait(false);
                _currentOptions = _stateManager.GetOptionsSnapshot();

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                    OnPropertyChanged(nameof(IsFakeEnabled));
                    OnPropertyChanged(nameof(IsDropRstEnabled));
                    NotifyActiveStatesChanged();
                });

                Log("[Bypass] Preemptive bypass enabled");
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Failed: {ex.Message}");
            }
        }

        #endregion

        // Приватные методы и обработчики метрик/состояний вынесены в partial-файлы:
        // - BypassController.Internal.cs
        // - BypassController.Metrics.cs
    }
}
