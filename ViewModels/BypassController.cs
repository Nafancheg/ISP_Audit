using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Bypass;
using IspAudit.Utils;
using ISPAudit.Utils;
using IspAudit.Wpf;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace ISPAudit.ViewModels
{
    /// <summary>
    /// Контроллер bypass-стратегий.
    /// Управляет toggle-кнопками (Fragment, Disorder, Fake, DROP_RST, DoH),
    /// владеет WinDivertBypassManager, проверяет VPN.
    /// </summary>
    public class BypassController : INotifyPropertyChanged
    {
        private WinDivertBypassManager? _bypassManager;
        
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

        public BypassController()
        {
            SetDnsPresetCommand = new RelayCommand(param => 
            {
                if (param is string preset)
                {
                    SelectedDnsPreset = preset;
                }
            }, _ => true);
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
        public bool ShowBypassPanel => WinDivertBypassManager.HasAdministratorRights;

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
        /// Доступ к менеджеру bypass (для DiagnosticOrchestrator)
        /// </summary>
        public WinDivertBypassManager? BypassManager => _bypassManager;

        #endregion

        #region Initialization

        /// <summary>
        /// Инициализация bypass и DoH при запуске приложения
        /// </summary>
        public async void InitializeOnStartupAsync()
        {
            // Проверка VPN
            CheckVpnStatus();

            if (!WinDivertBypassManager.HasAdministratorRights)
            {
                Log("[Bypass] No admin rights - bypass not available");
                return;
            }

            try
            {
                Log("[Bypass] Initializing bypass on application startup...");
                
                _bypassManager = new WinDivertBypassManager();
                _bypassManager.StateChanged += (s, e) => Application.Current?.Dispatcher.Invoke(UpdateBypassWarning);
                
                // Включаем Fragment + DROP RST при старте
                _isFragmentEnabled = true;
                _isDropRstEnabled = true;
                
                // Если есть файл бэкапа DNS, значит DoH остался включенным с прошлого раза
                if (FixService.HasBackupFile)
                {
                    _isDoHEnabled = true;
                    Log("[Bypass] Detected existing DNS backup - assuming DoH is active");
                }
                else
                {
                    _isDoHEnabled = false;
                }
                
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                OnPropertyChanged(nameof(IsDoHEnabled));
                
                // Проверяем совместимость после включения опций
                CheckCompatibility();
                
                // Применяем WinDivert bypass
                await ApplyBypassOptionsAsync().ConfigureAwait(false);
                
                // DoH не применяем автоматически
                // await ApplyDoHAsync().ConfigureAwait(false);
                
                Log("[Bypass] Startup complete: Fragment + DROP RST");
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
            if (_bypassManager == null)
            {
                _bypassManager = new WinDivertBypassManager();
                _bypassManager.StateChanged += (s, e) => Application.Current?.Dispatcher.Invoke(UpdateBypassWarning);
            }

            try
            {
                // Если ничего не включено — отключаем bypass
                if (!IsFragmentEnabled && !IsDisorderEnabled && !IsFakeEnabled && !IsDropRstEnabled)
                {
                    if (_bypassManager.State == BypassState.Enabled)
                    {
                        await _bypassManager.DisableAsync().ConfigureAwait(false);
                    }
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        IsBypassActive = false;
                        NotifyActiveStatesChanged();
                        Log("[Bypass] All options disabled");
                    });
                    return;
                }

                // Отключаем перед переконфигурацией
                if (_bypassManager.State == BypassState.Enabled)
                {
                    await _bypassManager.DisableAsync().ConfigureAwait(false);
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

                var profile = new BypassProfile
                {
                    DropTcpRst = IsDropRstEnabled,
                    FragmentTlsClientHello = IsFragmentEnabled || IsDisorderEnabled || IsFakeEnabled,
                    TlsStrategy = tlsStrategy,
                    TlsFirstFragmentSize = 2,
                    TlsFragmentThreshold = 16,
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                await _bypassManager.EnableAsync(profile).ConfigureAwait(false);

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    IsBypassActive = true;
                    NotifyActiveStatesChanged();
                    Log($"[Bypass] Options applied: {CurrentBypassStrategy}");
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
            if (!WinDivertBypassManager.HasAdministratorRights) return;
            
            Log("[Bypass] Enabling preemptive TLS_DISORDER + DROP_RST...");
            
            var profile = BypassProfile.CreateDefault();
            try
            {
                if (_bypassManager == null)
                {
                    _bypassManager = new WinDivertBypassManager();
                    _bypassManager.StateChanged += (s, e) => Application.Current?.Dispatcher.Invoke(UpdateBypassWarning);
                }
                
                await _bypassManager.EnableAsync(profile).ConfigureAwait(false);
                
                Application.Current?.Dispatcher.Invoke(() => 
                {
                    IsBypassActive = true;
                    _isFragmentEnabled = true;
                    _isDropRstEnabled = true;
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
            
            // VPN + Bypass warning removed from here as it is already shown in VpnWarningText
            
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
            if (_bypassManager != null && _bypassManager.State == BypassState.Enabled)
            {
                if (IsDropRstEnabled && !_bypassManager.IsRstBlockerActive)
                {
                    BypassWarningText = "⚠️ Обход активен без RST-защиты (возможны разрывы)";
                }
                else
                {
                    BypassWarningText = "";
                }
            }
            else
            {
                BypassWarningText = "";
            }
        }

        private void NotifyActiveStatesChanged()
        {
            OnPropertyChanged(nameof(CurrentBypassStrategy));
            OnPropertyChanged(nameof(IsTlsFragmentActive));
            OnPropertyChanged(nameof(IsTlsDisorderActive));
            OnPropertyChanged(nameof(IsTlsFakeActive));
            OnPropertyChanged(nameof(IsDropRstActive));
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
