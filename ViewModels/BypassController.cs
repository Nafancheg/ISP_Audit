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
    public class BypassController : INotifyPropertyChanged
    {
        private readonly TlsBypassService _tlsService;
        private readonly BypassProfile _baseProfile;
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
        
        // DNS Presets
        private string _selectedDnsPreset = "Hybrid (CF + Yandex)";
        public List<string> AvailableDnsPresets { get; } = new() 
        { 
            "Cloudflare", 
            "Google", 
            "Yandex", 
            "Hybrid (CF + Yandex)" 
        };

        public ICommand SetDnsPresetCommand { get; }

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

        public BypassController(TrafficEngine trafficEngine)
        {
            _baseProfile = BypassProfile.CreateDefault();
            _tlsService = new TlsBypassService(trafficEngine, _baseProfile, Log);
            _currentOptions = _tlsService.GetOptionsSnapshot();

            _autoHostlist = new AutoHostlistService();
            _autoHostlist.Changed += () =>
            {
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    RefreshAutoHostlistText();
                });
            };

            // По умолчанию при старте всё выключено (в т.ч. DROP RST)
            _currentOptions = _currentOptions with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false
            };

            FragmentPresets = _tlsService.FragmentPresets.ToList();
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

            _tlsService.MetricsUpdated += OnMetricsUpdated;
            _tlsService.VerdictChanged += OnVerdictChanged;
            _tlsService.StateChanged += OnStateChanged;

            SetDnsPresetCommand = new RelayCommand(param =>
            {
                if (param is string preset)
                {
                    SelectedDnsPreset = preset;
                }
            }, _ => true);
        }

        internal BypassController(TlsBypassService tlsService, BypassProfile baseProfile)
        {
            _baseProfile = baseProfile ?? throw new ArgumentNullException(nameof(baseProfile));
            _tlsService = tlsService ?? throw new ArgumentNullException(nameof(tlsService));
            _currentOptions = _tlsService.GetOptionsSnapshot();

            _autoHostlist = new AutoHostlistService();
            _autoHostlist.Changed += () =>
            {
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    RefreshAutoHostlistText();
                });
            };

            // По умолчанию при старте всё выключено (в т.ч. DROP RST)
            _currentOptions = _currentOptions with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false
            };

            FragmentPresets = _tlsService.FragmentPresets.ToList();
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

            _tlsService.MetricsUpdated += OnMetricsUpdated;
            _tlsService.VerdictChanged += OnVerdictChanged;
            _tlsService.StateChanged += OnStateChanged;

            SetDnsPresetCommand = new RelayCommand(param =>
            {
                if (param is string preset)
                {
                    SelectedDnsPreset = preset;
                }
            }, _ => true);
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
        public TlsBypassService TlsService => _tlsService;

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
                
                // Предварительная установка DoH по наличию бэкапа (чтобы UI не прыгал)
                if (FixService.HasBackupFile)
                {
                    _isDoHEnabled = true;
                    OnPropertyChanged(nameof(IsDoHEnabled));
                }

                // Проверяем текущее состояние DNS (в фоновом потоке, чтобы не фризить UI)
                var activePreset = await Task.Run(() => FixService.DetectActivePreset());
                
                if (activePreset != null)
                {
                    _selectedDnsPreset = activePreset;
                    OnPropertyChanged(nameof(SelectedDnsPreset));
                    
                    // Включаем галочку DoH только если есть файл бэкапа (индикатор того, что это мы настроили)
                    // Просто наличие 8.8.8.8 не гарантирует включенный DoH/HTTPS
                    if (FixService.HasBackupFile)
                    {
                        _isDoHEnabled = true;
                        Log($"[Bypass] Detected active DoH preset (restorable): {activePreset}");
                    }
                    else
                    {
                        // Если бэкапа нет, но DNS совпадает — не включаем DoH автоматически
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
                await _tlsService.ApplyAsync(normalized, cancellationToken).ConfigureAwait(false);

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    NotifyActiveStatesChanged();
                });
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
                
                Application.Current?.Dispatcher.Invoke(() =>
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
                
                Application.Current?.Dispatcher.Invoke(() =>
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
                DropRstEnabled = false
            };

            OnPropertyChanged(nameof(IsFragmentEnabled));
            OnPropertyChanged(nameof(IsDisorderEnabled));
            OnPropertyChanged(nameof(IsFakeEnabled));
            OnPropertyChanged(nameof(IsDropRstEnabled));
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

                var updated = _currentOptions;
                var enableDoH = false;

                foreach (var strategy in plan.Strategies)
                {
                    switch (strategy.Id)
                    {
                        case StrategyId.TlsFragment:
                            updated = updated with { FragmentEnabled = true, DisorderEnabled = false };
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
                        default:
                            // Нереализованные/неподдерживаемые в bypass контроллере стратегии пропускаем.
                            Log($"[V2][Executor] Стратегия {strategy.Id} не поддерживается контроллером — пропуск");
                            break;
                    }
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
                    NotifyActiveStatesChanged();
                    CheckCompatibility();
                });

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

                await _tlsService.ApplyPreemptiveAsync().ConfigureAwait(false);
                _currentOptions = _tlsService.GetOptionsSnapshot();

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

        #region Private Methods

        private void CheckCompatibility()
        {
            var warnings = new List<string>();
            
            // Fragment + Disorder = взаимоисключающие
            if (IsFragmentEnabled && IsDisorderEnabled)
            {
                warnings.Add("⚠️ Fragment + Disorder — выберите одну из стратегий фрагментации");
            }
            
            // Fake без фрагментации — менее эффективно
            if (IsFakeEnabled && !IsFragmentEnabled && !IsDisorderEnabled)
            {
                warnings.Add("ℹ️ Fake без фрагментации — рекомендуется добавить Fragment или Disorder");
            }
            
            // DoH без других опций — только DNS защита
            if (IsDoHEnabled && !IsFragmentEnabled && !IsDisorderEnabled && !IsFakeEnabled && !IsDropRstEnabled)
            {
                warnings.Add("ℹ️ Только DoH — защищает DNS, но DPI может блокировать трафик");
            }
            
            // Только DROP RST без фрагментации — частичная защита
            if (IsDropRstEnabled && !IsFragmentEnabled && !IsDisorderEnabled && !IsFakeEnabled)
            {
                warnings.Add("ℹ️ Только DROP RST — защита от RST-инъекций, но SNI виден DPI");
            }
            
            CompatibilityWarning = warnings.Count > 0 ? string.Join("\n", warnings) : "";
        }

        private void CheckVpnStatus()
        {
            try
            {
                if (NetUtils.LikelyVpnActive())
                {
                    IsVpnDetected = true;
                    VpnWarningText = "🔒 Обнаружен VPN — bypass может быть не нужен или конфликтовать с VPN";
                    Log("[VPN] VPN detected - bypass may conflict");
                }
                else
                {
                    IsVpnDetected = false;
                    VpnWarningText = "";
                }
            }
            catch (Exception ex)
            {
                Log($"[VPN] Error checking VPN status: {ex.Message}");
            }
        }

        private void UpdateBypassWarning()
        {
            // TODO: Check if RST blocking is actually active in TrafficEngine
            // For now, assume it works if enabled
            BypassWarningText = "";
        }

        private void NotifyActiveStatesChanged()
        {
            OnPropertyChanged(nameof(CurrentBypassStrategy));
            OnPropertyChanged(nameof(IsTlsFragmentActive));
            OnPropertyChanged(nameof(IsTlsDisorderActive));
            OnPropertyChanged(nameof(IsTlsFakeActive));
            OnPropertyChanged(nameof(IsDropRstActive));
        }

        private void OnMetricsUpdated(TlsBypassMetrics metrics)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                _currentOptions = _tlsService.GetOptionsSnapshot();
                OnPropertyChanged(nameof(SelectedFragmentPresetLabel));

                var plan = string.IsNullOrWhiteSpace(metrics.Plan) ? "-" : metrics.Plan;
                var planWithPreset = string.IsNullOrWhiteSpace(metrics.PresetName) ? plan : $"{plan} · {metrics.PresetName}";
                BypassPlanText = string.IsNullOrWhiteSpace(planWithPreset) ? "-" : planWithPreset;
                BypassMetricsSince = metrics.Since;
                BypassMetricsText =
                    $"TLS: {metrics.TlsHandled}; thr: {metrics.FragmentThreshold}; min: {metrics.MinChunk}; Hello@443: {metrics.ClientHellosObserved}; <thr: {metrics.ClientHellosShort}; !=443: {metrics.ClientHellosNon443}; фрагм.: {metrics.ClientHellosFragmented}; RST(443,bypass): {metrics.RstDroppedRelevant}; RST(всего): {metrics.RstDropped}";
            });
        }

        private void OnVerdictChanged(TlsBypassVerdict verdict)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                BypassVerdictText = verdict.Text;
                BypassVerdictReason = verdict.Reason;
                BypassVerdictBrush = verdict.Color switch
                {
                    VerdictColor.Green => new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 252, 231)),
                    VerdictColor.Yellow => new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 249, 195)),
                    VerdictColor.Red => new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 226, 226)),
                    _ => new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246))
                };
            });
        }

        private void OnStateChanged(TlsBypassState state)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                var oldOptions = _currentOptions;
                _currentOptions = _tlsService.GetOptionsSnapshot();
                IsBypassActive = state.IsActive;
                
                var planWithPreset = string.IsNullOrWhiteSpace(state.Plan)
                    ? _currentOptions.PresetName
                    : $"{state.Plan} · {_currentOptions.PresetName}";
                BypassPlanText = string.IsNullOrWhiteSpace(planWithPreset) ? "-" : planWithPreset;
                BypassMetricsSince = state.Since;

                if (oldOptions.FragmentEnabled != _currentOptions.FragmentEnabled) OnPropertyChanged(nameof(IsFragmentEnabled));
                if (oldOptions.DisorderEnabled != _currentOptions.DisorderEnabled) OnPropertyChanged(nameof(IsDisorderEnabled));
                if (oldOptions.FakeEnabled != _currentOptions.FakeEnabled) OnPropertyChanged(nameof(IsFakeEnabled));
                if (oldOptions.DropRstEnabled != _currentOptions.DropRstEnabled) OnPropertyChanged(nameof(IsDropRstEnabled));
                
                OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                CheckCompatibility();
                NotifyActiveStatesChanged();
            });
        }

        private void PersistFragmentPreset()
        {
            // Сохраняем только параметры фрагментации/пресета, чтобы не перетирать другие поля профиля
            // (например, TTL trick/AutoTTL, redirect rules и будущие расширения).
            BypassProfile.TryUpdateFragmentSettings(
                _currentOptions.FragmentSizes,
                _currentOptions.PresetName,
                _currentOptions.AutoAdjustAggressive);
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