using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Threading;
using System.Windows.Media;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Utils;
using IspAudit.Wpf;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Контроллер bypass-стратегий.
    /// Управляет toggle-кнопками (Fragment, Disorder, Fake, DROP_RST, DoH),
    /// использует TrafficEngine и BypassFilter.
    /// </summary>
    public class BypassController : INotifyPropertyChanged
    {
        private readonly TrafficEngine _trafficEngine;
        private readonly BypassProfile _baseProfile;
        private readonly DispatcherTimer _metricsTimer;
        private BypassFilter? _currentFilter;
        private IReadOnlyList<int> _currentFragmentSizes;
        private FragmentPreset? _selectedPreset;
        
        // Независимые флаги для каждой опции bypass
        private bool _isFragmentEnabled;
        private bool _isDisorderEnabled;
        private bool _isFakeEnabled;
        private bool _isDropRstEnabled;
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
        private bool _isAutoAdjustAggressive;
        private DateTime? _greenSince;
        private bool _autoAdjustedDown;
        private bool _autoAdjustedUp;
        
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

        public List<FragmentPreset> FragmentPresets { get; }

        public FragmentPreset? SelectedFragmentPreset
        {
            get => _selectedPreset;
            set
            {
                if (value != null && _selectedPreset != value)
                {
                    _selectedPreset = value;
                    _currentFragmentSizes = value.Sizes;
                    OnPropertyChanged(nameof(SelectedFragmentPreset));
                    OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                    PersistFragmentPreset();
                    _ = ApplyBypassOptionsAsync();
                }
            }
        }

        public string SelectedFragmentPresetLabel => _selectedPreset != null ? $"{_selectedPreset.Name} ({string.Join('/', _selectedPreset.Sizes)})" : string.Empty;

        public BypassController(TrafficEngine trafficEngine)
        {
            _trafficEngine = trafficEngine;
            _baseProfile = BypassProfile.CreateDefault();
            _currentFragmentSizes = _baseProfile.TlsFragmentSizes ?? new List<int> { _baseProfile.TlsFirstFragmentSize };
            _currentFragmentSizes = _currentFragmentSizes.Select(v => Math.Max(4, v)).ToList();
            FragmentPresets = new List<FragmentPreset>
            {
                new("Стандарт", new List<int>{64}, "Баланс: один фрагмент 64 байта"),
                new("Умеренный", new List<int>{96}, "Чуть крупнее фрагмент для совместимости"),
                new("Агрессивный", new List<int>{32,32}.Select(v => Math.Max(4, v)).ToList(), "Два мелких фрагмента для сложных DPI (мин. 4 байта)"),
                new("Профиль", _currentFragmentSizes, "Из файла профиля")
            };
            _selectedPreset = FragmentPresets.FirstOrDefault();
            SetDnsPresetCommand = new RelayCommand(param => 
            {
                if (param is string preset)
                {
                    SelectedDnsPreset = preset;
                }
            }, _ => true);

            _metricsTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            _metricsTimer.Tick += (_, _) => UpdateMetrics();
            _metricsTimer.Start();
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
            get => _isFragmentEnabled;
            set 
            { 
                if (_isFragmentEnabled != value)
                {
                    _isFragmentEnabled = value;
                    // Fragment и Disorder взаимоисключающие
                    if (value && _isDisorderEnabled)
                    {
                        _isDisorderEnabled = false;
                        OnPropertyChanged(nameof(IsDisorderEnabled));
                    }
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                    CheckCompatibility();
                    _ = ApplyBypassOptionsAsync();
                }
            }
        }

        /// <summary>
        /// TLS Disorder включен (фрагменты в ОБРАТНОМ порядке)
        /// </summary>
        public bool IsDisorderEnabled
        {
            get => _isDisorderEnabled;
            set 
            { 
                if (_isDisorderEnabled != value)
                {
                    _isDisorderEnabled = value;
                    // Fragment и Disorder взаимоисключающие
                    if (value && _isFragmentEnabled)
                    {
                        _isFragmentEnabled = false;
                        OnPropertyChanged(nameof(IsFragmentEnabled));
                    }
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                    CheckCompatibility();
                    _ = ApplyBypassOptionsAsync();
                }
            }
        }

        /// <summary>
        /// TLS Fake включен
        /// </summary>
        public bool IsFakeEnabled
        {
            get => _isFakeEnabled;
            set 
            { 
                if (_isFakeEnabled != value)
                {
                    _isFakeEnabled = value; 
                    OnPropertyChanged(nameof(IsFakeEnabled));
                    CheckCompatibility();
                    _ = ApplyBypassOptionsAsync();
                }
            }
        }

        /// <summary>
        /// DROP RST включен
        /// </summary>
        public bool IsDropRstEnabled
        {
            get => _isDropRstEnabled;
            set 
            { 
                if (_isDropRstEnabled != value)
                {
                    _isDropRstEnabled = value; 
                    OnPropertyChanged(nameof(IsDropRstEnabled));
                    CheckCompatibility();
                    _ = ApplyBypassOptionsAsync();
                }
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
            get => _isAutoAdjustAggressive;
            set
            {
                if (_isAutoAdjustAggressive != value)
                {
                    _isAutoAdjustAggressive = value;
                    OnPropertyChanged(nameof(IsAutoAdjustAggressive));
                    ResetAutoAdjustState();
                }
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
                
                Log("[Bypass] Startup complete: Disorder + DROP RST");
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Failed to initialize bypass on startup: {ex.Message}");
            }
        }

        #endregion

        #region Core Methods

        /// <summary>
        /// Применить текущие настройки bypass
        /// </summary>
        public async Task ApplyBypassOptionsAsync()
        {
            try
            {
                // Remove old filter
                _trafficEngine.RemoveFilter("BypassFilter");

                // Если ничего не включено — отключаем bypass
                if (!IsFragmentEnabled && !IsDisorderEnabled && !IsFakeEnabled && !IsDropRstEnabled)
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        IsBypassActive = false;
                        NotifyActiveStatesChanged();
                        Log("[Bypass] All options disabled");
                    });
                    return;
                }

                // Собираем профиль из текущих флагов
                var tlsStrategy = TlsBypassStrategy.None;
                if (IsDisorderEnabled && IsFakeEnabled)
                    tlsStrategy = TlsBypassStrategy.FakeDisorder;
                else if (IsFragmentEnabled && IsFakeEnabled)
                    tlsStrategy = TlsBypassStrategy.FakeFragment;
                else if (IsDisorderEnabled)
                    tlsStrategy = TlsBypassStrategy.Disorder;
                else if (IsFakeEnabled)
                    tlsStrategy = TlsBypassStrategy.Fake;
                else if (IsFragmentEnabled)
                    tlsStrategy = TlsBypassStrategy.Fragment;

                var fragmentSizes = _currentFragmentSizes ?? Array.Empty<int>();

                var profile = new BypassProfile
                {
                    DropTcpRst = IsDropRstEnabled,
                    FragmentTlsClientHello = IsFragmentEnabled || IsDisorderEnabled || IsFakeEnabled,
                    TlsStrategy = tlsStrategy,
                    TlsFirstFragmentSize = _baseProfile.TlsFirstFragmentSize,
                    TlsFragmentThreshold = _baseProfile.TlsFragmentThreshold,
                    TlsFragmentSizes = fragmentSizes,
                    TtlTrick = _baseProfile.TtlTrick,
                    TtlTrickValue = _baseProfile.TtlTrickValue,
                    RedirectRules = _baseProfile.RedirectRules
                };

                // Create and register filter
                var filter = new BypassFilter(profile, Log, _selectedPreset?.Name ?? "");
                _trafficEngine.RegisterFilter(filter);

                // Ensure engine is running
                if (!_trafficEngine.IsRunning)
                {
                    await _trafficEngine.StartAsync().ConfigureAwait(false);
                }

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    IsBypassActive = true;
                    NotifyActiveStatesChanged();
                    var chunks = fragmentSizes.Any() ? string.Join('/', fragmentSizes) : "default";
                    Log($"[Bypass] Options applied: {CurrentBypassStrategy} | TLS chunks: {chunks}, threshold: {profile.TlsFragmentThreshold}");
                    _currentFilter = filter;
                    BypassMetricsSince = DateTime.Now.ToString("HH:mm:ss");
                    ResetAutoAdjustState();
                    UpdateMetrics();
                });
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
        public async Task DisableAllAsync()
        {
            _isFragmentEnabled = false;
            _isDisorderEnabled = false;
            _isFakeEnabled = false;
            _isDropRstEnabled = false;
            
            OnPropertyChanged(nameof(IsFragmentEnabled));
            OnPropertyChanged(nameof(IsDisorderEnabled));
            OnPropertyChanged(nameof(IsFakeEnabled));
            OnPropertyChanged(nameof(IsDropRstEnabled));
            
            await ApplyBypassOptionsAsync().ConfigureAwait(false);
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
                // Fix: Actually enable Disorder, not Fragment
                _isDisorderEnabled = true; 
                _isFragmentEnabled = false;
                _isDropRstEnabled = true;
                // Note: DoH state is NOT changed here. It remains as set by user or startup logic.
                
                await ApplyBypassOptionsAsync().ConfigureAwait(false);
                
                Application.Current?.Dispatcher.Invoke(() => 
                {
                    IsBypassActive = true;
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                    OnPropertyChanged(nameof(IsFragmentEnabled));
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

        private void UpdateMetrics()
        {
            var snapshot = _currentFilter?.GetMetrics();
            if (snapshot == null)
            {
                BypassMetricsText = "Фрагментация выключена";
                BypassVerdictText = "Bypass выключен";
                BypassVerdictBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246));
                BypassPlanText = "-";
                BypassMetricsSince = "-";
                return;
            }

            var plan = string.IsNullOrWhiteSpace(snapshot.Value.LastFragmentPlan) ? "-" : snapshot.Value.LastFragmentPlan;
            BypassPlanText = plan;
            BypassMetricsText = $"TLS обработано: {snapshot.Value.TlsHandled}; фрагментировано: {snapshot.Value.ClientHellosFragmented}; RST(443,bypass): {snapshot.Value.RstDroppedRelevant}; RST(всего): {snapshot.Value.RstDropped}; план: {plan}";

            // Градация по релевантным RST: считаем только RST на 443 для соединений, где применялась фрагментация; первые 5 RST считаем шумом
            System.Windows.Media.Brush brush;
            string verdict;
            var fragmentsRaw = snapshot.Value.ClientHellosFragmented;
            var fragments = Math.Max(1, fragmentsRaw);
            var rstRelevant = snapshot.Value.RstDroppedRelevant;
            var rstEffective = Math.Max(0, rstRelevant - 5); // шум до 5 RST
            var ratio = fragmentsRaw == 0 ? double.PositiveInfinity : (double)rstEffective / fragments;
            string reason;

            if (fragmentsRaw == 0)
            {
                brush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 226, 226));
                verdict = "Внимание: нет фрагментаций — включите Fragment/Disorder";
                reason = "Фрагментаций нет";
            }
            else if (fragmentsRaw < 10)
            {
                brush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(243, 244, 246));
                verdict = "Мало данных: <10 фрагментаций";
                reason = "Собираем статистику";
            }
            else if (ratio > 4.0)
            {
                brush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 226, 226));
                verdict = "Внимание: много RST относительно фрагментаций";
                reason = $"ratio={ratio:F2} > 4";
            }
            else if (ratio > 1.5)
            {
                brush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(254, 249, 195));
                verdict = "Есть RST, но обход работает (умеренно)";
                reason = $"ratio={ratio:F2} > 1.5";
            }
            else
            {
                brush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 252, 231));
                verdict = "Хорошо: RST мало, обход устойчив";
                reason = $"ratio={ratio:F2} в норме";
            }

            BypassVerdictBrush = brush;
            BypassVerdictText = verdict;
            BypassVerdictReason = reason;

            EvaluateAutoAdjust(snapshot.Value, brush, ratio);
        }

        private void EvaluateAutoAdjust(BypassFilter.BypassMetricsSnapshot snapshot, System.Windows.Media.Brush verdictBrush, double ratio)
        {
            if (!_isAutoAdjustAggressive)
            {
                return;
            }

            if (!string.Equals(_selectedPreset?.Name, "Агрессивный", StringComparison.OrdinalIgnoreCase))
            {
                ResetAutoAdjustState();
                return;
            }

            var fragments = snapshot.ClientHellosFragmented;
            var rstRelevant = snapshot.RstDroppedRelevant;

            // Правило 1: ранние частые RST — ужать самый маленький чанк до 4 байт
            if (!_autoAdjustedDown && fragments >= 5 && fragments <= 20 && rstRelevant > 2 * fragments)
            {
                var adjusted = _currentFragmentSizes.Select(v => Math.Max(4, v)).ToList();
                var min = adjusted.Min();
                var idx = adjusted.IndexOf(min);
                adjusted[idx] = 4;
                _currentFragmentSizes = adjusted;
                OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                Log($"[Bypass][AutoAdjust] Aggressive: high RST ratio ({rstRelevant}/{fragments}), set min chunk=4");
                _autoAdjustedDown = true;
                _ = ApplyBypassOptionsAsync();
                return;
            }

            // Правило 2: стабильный зелёный > 30 сек — усилить (слегка уменьшить минимальный чанк, но не ниже 4)
            var isGreen = verdictBrush is SolidColorBrush sc && sc.Color == System.Windows.Media.Color.FromRgb(220, 252, 231);
            if (isGreen)
            {
                _greenSince ??= DateTime.Now;
            }
            else
            {
                _greenSince = null;
            }

            if (isGreen && !_autoAdjustedUp && _greenSince.HasValue && DateTime.Now - _greenSince.Value > TimeSpan.FromSeconds(30))
            {
                var adjusted = _currentFragmentSizes.Select(v => Math.Max(4, v)).ToList();
                var min = adjusted.Min();
                var idx = adjusted.IndexOf(min);
                var newVal = Math.Max(4, min - 4);
                if (newVal < min)
                {
                    adjusted[idx] = newVal;
                    _currentFragmentSizes = adjusted;
                    OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                    Log("[Bypass][AutoAdjust] Aggressive: stable green 30s, slightly tightening fragmentation");
                    _autoAdjustedUp = true;
                    _ = ApplyBypassOptionsAsync();
                }
            }
        }

        private void ResetAutoAdjustState()
        {
            _greenSince = null;
            _autoAdjustedDown = false;
            _autoAdjustedUp = false;
        }

        private void PersistFragmentPreset()
        {
            var merged = new BypassProfile
            {
                DropTcpRst = _baseProfile.DropTcpRst,
                FragmentTlsClientHello = _baseProfile.FragmentTlsClientHello,
                TlsStrategy = _baseProfile.TlsStrategy,
                TlsFirstFragmentSize = _baseProfile.TlsFirstFragmentSize,
                TlsFragmentThreshold = _baseProfile.TlsFragmentThreshold,
                TlsFragmentSizes = _currentFragmentSizes,
                TtlTrick = _baseProfile.TtlTrick,
                TtlTrickValue = _baseProfile.TtlTrickValue,
                RedirectRules = _baseProfile.RedirectRules
            };

            BypassProfile.Save(merged);
        }

        private void Log(string message)
        {
            OnLog?.Invoke(message);
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public record FragmentPreset(string Name, IReadOnlyList<int> Sizes, string Description);

        #endregion
    }
}