using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using MaterialDesignThemes.Wpf;
using IspAudit.Bypass;
using IspAudit.Models;
using IspAudit.Utils;
using IspAudit.Wpf;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Главная ViewModel.
    /// После рефакторинга: тонкий координатор между BypassController,
    /// DiagnosticOrchestrator и TestResultsManager.
    /// ~400 строк вместо 2100+
    /// </summary>
    public class MainViewModelRefactored : INotifyPropertyChanged
    {
        #region Logging

        private static readonly string LogsDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
        private static readonly string LogFilePath = InitializeLogFilePath();

        private static string InitializeLogFilePath()
        {
            try
            {
                Directory.CreateDirectory(LogsDirectory);

                var existingLogs = Directory.GetFiles(LogsDirectory, "isp_audit_vm_*.log")
                    .OrderBy(File.GetCreationTimeUtc)
                    .ToList();

                while (existingLogs.Count > 9)
                {
                    var toDelete = existingLogs[0];
                    existingLogs.RemoveAt(0);
                    try { File.Delete(toDelete); } catch { }
                }

                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                return Path.Combine(LogsDirectory, $"isp_audit_vm_{timestamp}.log");
            }
            catch
            {
                return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "isp_audit_vm_fallback.log");
            }
        }

        private static void Log(string message)
        {
            try
            {
                File.AppendAllText(LogFilePath, $"[{DateTime.Now:HH:mm:ss.fff}] {message}\n");
                System.Diagnostics.Debug.WriteLine(message);
            }
            catch { }
        }

        #endregion

        #region Controllers (Composition)

        /// <summary>
        /// Контроллер bypass-стратегий
        /// </summary>
        public BypassController Bypass { get; }

        /// <summary>
        /// Оркестратор диагностики
        /// </summary>
        public DiagnosticOrchestrator Orchestrator { get; }

        /// <summary>
        /// Менеджер результатов тестирования
        /// </summary>
        public TestResultsManager Results { get; }

        #endregion

        #region UI State

        private string _screenState = "start";
        private string _exePath = "";
        private string _currentAction = "";
        private string _userMessage = "Готов к диагностике. Выберите приложение и нажмите 'Начать'.";
        private bool _enableLiveTesting = true;
        private bool _enableAutoBypass = true;
        private bool _isBasicTestMode = false;
        private bool _isDarkTheme = false;

        public bool IsDarkTheme
        {
            get => _isDarkTheme;
            set
            {
                if (_isDarkTheme != value)
                {
                    _isDarkTheme = value;
                    OnPropertyChanged(nameof(IsDarkTheme));
                    ApplyTheme(value);
                }
            }
        }

        public string ScreenState
        {
            get => _screenState;
            set
            {
                var oldState = _screenState;
                _screenState = value;
                OnPropertyChanged(nameof(ScreenState));
                OnPropertyChanged(nameof(IsStart));
                OnPropertyChanged(nameof(IsRunning));
                OnPropertyChanged(nameof(IsDone));
                OnPropertyChanged(nameof(ShowSummary));
                OnPropertyChanged(nameof(ShowReport));
                OnPropertyChanged(nameof(RunningStatusText));
                OnPropertyChanged(nameof(StartButtonText));

                Log($"✓ ScreenState: '{oldState}' → '{value}'");

                if (value == "start")
                {
                    Results.ResetStatuses();
                }
            }
        }

        public bool IsStart => ScreenState == "start";
        public bool IsRunning => ScreenState == "running" || Orchestrator.IsDiagnosticRunning;
        public bool IsDone => ScreenState == "done";
        public bool ShowSummary => IsDone;
        public bool ShowReport => IsDone;

        public string ExePath
        {
            get => _exePath;
            set { _exePath = value; OnPropertyChanged(nameof(ExePath)); }
        }

        private bool _isUnlimitedTime;
        public bool IsUnlimitedTime
        {
            get => _isUnlimitedTime;
            set { _isUnlimitedTime = value; OnPropertyChanged(nameof(IsUnlimitedTime)); }
        }

        private bool _isNetworkChangePromptVisible;
        private string _networkChangePromptText = string.Empty;
        private bool _isNetworkRevalidating;
        private CancellationTokenSource? _networkRevalidateCts;

        public bool IsNetworkChangePromptVisible
        {
            get => _isNetworkChangePromptVisible;
            private set
            {
                if (_isNetworkChangePromptVisible == value) return;
                _isNetworkChangePromptVisible = value;
                OnPropertyChanged(nameof(IsNetworkChangePromptVisible));
            }
        }

        public string NetworkChangePromptText
        {
            get => _networkChangePromptText;
            private set
            {
                if (string.Equals(_networkChangePromptText, value, StringComparison.Ordinal)) return;
                _networkChangePromptText = value;
                OnPropertyChanged(nameof(NetworkChangePromptText));
            }
        }

        private bool _isSteamMode;
        public bool IsSteamMode
        {
            get => _isSteamMode;
            set { _isSteamMode = value; OnPropertyChanged(nameof(IsSteamMode)); }
        }

        public string CurrentAction
        {
            get => _currentAction;
            set
            {
                if (string.Equals(_currentAction, value, StringComparison.Ordinal)) return;
                _currentAction = value;
                OnPropertyChanged(nameof(CurrentAction));
            }
        }

        public string UserMessage
        {
            get => _userMessage;
            set
            {
                if (string.Equals(_userMessage, value, StringComparison.Ordinal)) return;
                _userMessage = value;
                OnPropertyChanged(nameof(UserMessage));
            }
        }

        public bool EnableLiveTesting
        {
            get => _enableLiveTesting;
            set { _enableLiveTesting = value; OnPropertyChanged(nameof(EnableLiveTesting)); }
        }

        public bool EnableAutoBypass
        {
            get => _enableAutoBypass;
            set { _enableAutoBypass = value; OnPropertyChanged(nameof(EnableAutoBypass)); }
        }

        public bool IsBasicTestMode
        {
            get => _isBasicTestMode;
            set { _isBasicTestMode = value; OnPropertyChanged(nameof(IsBasicTestMode)); }
        }

        public string RunningStatusText => $"Диагностика: {Results.CurrentTest} из {Results.TotalTargets}";
        public string StartButtonText => IsRunning ? "Остановить диагностику" : "Начать диагностику";

        // Прокси-свойства для счётчиков (для совместимости с существующим XAML)
        public ObservableCollection<TestResult> TestResults => Results.TestResults;
        public int TotalTargets => Results.TotalTargets;
        public int ProgressBarMax => Results.ProgressBarMax;
        public int CurrentTest => Results.CurrentTest;
        public int CompletedTests => Results.CompletedTests;
        public int PassCount => Results.PassCount;
        public int FailCount => Results.FailCount;
        public int WarnCount => Results.WarnCount;

        // Прокси-свойства для Orchestrator
        public int FlowEventsCount => Orchestrator.FlowEventsCount;
        public int ConnectionsDiscovered => Orchestrator.ConnectionsDiscovered;
        public string FlowModeText => Orchestrator.FlowModeText;
        public string DiagnosticStatus => Orchestrator.DiagnosticStatus;
        public bool IsDiagnosticRunning => Orchestrator.IsDiagnosticRunning;
        public string AutoBypassStatus => Orchestrator.AutoBypassStatus;
        public string AutoBypassVerdict => Orchestrator.AutoBypassVerdict;
        public string AutoBypassMetrics => Orchestrator.AutoBypassMetrics;
        public System.Windows.Media.Brush AutoBypassStatusBrush => Orchestrator.AutoBypassStatusBrush;
        public bool HasRecommendations => Orchestrator.HasRecommendations;
        public bool HasAnyRecommendations => Orchestrator.HasAnyRecommendations;
        public string RecommendedStrategiesText => Orchestrator.RecommendedStrategiesText;
        public string ManualRecommendationsText => Orchestrator.ManualRecommendationsText;
        public string RecommendationHintText => Orchestrator.RecommendationHintText;

        private TestResult? _selectedTestResult;
        public TestResult? SelectedTestResult
        {
            get => _selectedTestResult;
            set
            {
                if (ReferenceEquals(_selectedTestResult, value)) return;
                _selectedTestResult = value;
                OnPropertyChanged(nameof(SelectedTestResult));

                // Важно для QUIC→TCP (селективный режим): если цель не задана, UDP/443 по IPv4 не глушится.
                // Самый понятный UX: цель берём из выбранной строки результатов (если это не шумовой хост).
                TryUpdateOutcomeTargetFromSelection(_selectedTestResult);
            }
        }

        private void TryUpdateOutcomeTargetFromSelection(TestResult? selected)
        {
            try
            {
                if (selected == null) return;

                var hostKey = GetPreferredHostKey(selected);
                if (string.IsNullOrWhiteSpace(hostKey)) return;

                if (NoiseHostFilter.Instance.IsNoiseHost(hostKey)) return;

                Bypass.SetOutcomeTargetHost(hostKey);
            }
            catch
            {
                // Наблюдаемость/UX не должны ломать UI
            }
        }

        private bool _isApplyingRecommendations;
        public bool IsApplyingRecommendations
        {
            get => _isApplyingRecommendations;
            private set
            {
                if (_isApplyingRecommendations == value) return;
                _isApplyingRecommendations = value;
                OnPropertyChanged(nameof(IsApplyingRecommendations));
                OnPropertyChanged(nameof(ApplyRecommendationsButtonText));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        public string ApplyRecommendationsButtonText => IsApplyingRecommendations
            ? "Применяю…"
            : "Применить рекомендации v2";

        // Прокси-свойства для BypassController
        public bool ShowBypassPanel => Bypass.ShowBypassPanel;
        public bool IsBypassActive => Bypass.IsBypassActive;
        public bool IsFragmentEnabled { get => Bypass.IsFragmentEnabled; set => Bypass.IsFragmentEnabled = value; }
        public bool IsDisorderEnabled { get => Bypass.IsDisorderEnabled; set => Bypass.IsDisorderEnabled = value; }
        public bool IsFakeEnabled { get => Bypass.IsFakeEnabled; set => Bypass.IsFakeEnabled = value; }
        public bool IsDropRstEnabled { get => Bypass.IsDropRstEnabled; set => Bypass.IsDropRstEnabled = value; }
        public bool IsQuicFallbackEnabled { get => Bypass.IsQuicFallbackEnabled; set => Bypass.IsQuicFallbackEnabled = value; }
        public bool IsQuicFallbackGlobal { get => Bypass.IsQuicFallbackGlobal; set => Bypass.IsQuicFallbackGlobal = value; }
        public bool IsAllowNoSniEnabled { get => Bypass.IsAllowNoSniEnabled; set => Bypass.IsAllowNoSniEnabled = value; }
        public bool IsDoHEnabled { get => Bypass.IsDoHEnabled; set => Bypass.IsDoHEnabled = value; }
        public bool IsVpnDetected => Bypass.IsVpnDetected;
        public string VpnWarningText => Bypass.VpnWarningText;
        public string CompatibilityWarning => Bypass.CompatibilityWarning;
        public bool HasCompatibilityWarning => Bypass.HasCompatibilityWarning;
        public string BypassWarningText => Bypass.BypassWarningText;
        public string CurrentBypassStrategy => Bypass.CurrentBypassStrategy;
        public bool IsTlsFragmentActive => Bypass.IsTlsFragmentActive;
        public bool IsTlsDisorderActive => Bypass.IsTlsDisorderActive;
        public bool IsTlsFakeActive => Bypass.IsTlsFakeActive;
        public bool IsDropRstActive => Bypass.IsDropRstActive;
        public bool IsDoHActive => Bypass.IsDoHActive;
        public List<TlsFragmentPreset> FragmentPresets => Bypass.FragmentPresets;
        public TlsFragmentPreset? SelectedFragmentPreset { get => Bypass.SelectedFragmentPreset; set => Bypass.SelectedFragmentPreset = value; }
        public string SelectedFragmentPresetLabel => Bypass.SelectedFragmentPresetLabel;
        public string BypassMetricsText => Bypass.BypassMetricsText;
        public System.Windows.Media.Brush BypassVerdictBrush => Bypass.BypassVerdictBrush;
        public string BypassVerdictText => Bypass.BypassVerdictText;

        // Traffic Engine Performance
        private double _trafficEngineLatency;
        public double TrafficEngineLatency
        {
            get => _trafficEngineLatency;
            set
            {
                _trafficEngineLatency = value;
                OnPropertyChanged(nameof(TrafficEngineLatency));
                OnPropertyChanged(nameof(TrafficEngineLatencyText));
                OnPropertyChanged(nameof(TrafficEngineLatencyColor));
            }
        }

        public string TrafficEngineLatencyText => $"{TrafficEngineLatency:F3} ms";

        public System.Windows.Media.Brush TrafficEngineLatencyColor
        {
            get
            {
                if (TrafficEngineLatency < 0.5) return System.Windows.Media.Brushes.Green;
                if (TrafficEngineLatency < 2.0) return System.Windows.Media.Brushes.Orange;
                return System.Windows.Media.Brushes.Red;
            }
        }

        #endregion

        #region Commands

        public ICommand StartCommand { get; }
        public ICommand StartLiveTestingCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand SetStateCommand { get; }
        public ICommand ReportCommand { get; }
        public ICommand DetailsCommand { get; }
        public ICommand BrowseExeCommand { get; }
        public ICommand ToggleThemeCommand { get; }

        // Bypass Toggle Commands
        public ICommand ToggleFragmentCommand { get; }
        public ICommand ToggleDisorderCommand { get; }
        public ICommand ToggleFakeCommand { get; }
        public ICommand ToggleDropRstCommand { get; }
        public ICommand ToggleDoHCommand { get; }
        public ICommand DisableAllBypassCommand { get; }
        public ICommand ApplyRecommendationsCommand { get; }
        public ICommand ConnectFromResultCommand { get; }

        // P0.6: Network change staged revalidation
        public ICommand NetworkRevalidateCommand { get; }
        public ICommand NetworkDisableBypassCommand { get; }
        public ICommand NetworkIgnoreCommand { get; }

        #endregion

        #region Constructor

        private readonly IspAudit.Core.Traffic.TrafficEngine _trafficEngine;
        private readonly BypassStateManager _bypassState;

        private readonly NetworkChangeMonitor? _networkChangeMonitor;
        private volatile bool _pendingNetworkChangePrompt;

        private volatile bool _pendingRetestAfterRun;
        private string _pendingRetestReason = "";

        public MainViewModelRefactored()
        {
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log("MainViewModelRefactored: Инициализация");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Create TrafficEngine
            var progress = new Progress<string>(msg => Log(msg));
            _trafficEngine = new IspAudit.Core.Traffic.TrafficEngine(progress);

            _trafficEngine.OnPerformanceUpdate += ms =>
            {
                Application.Current?.Dispatcher.Invoke(() => TrafficEngineLatency = ms);
            };

            // Единый владелец bypass/TrafficEngine
            _bypassState = BypassStateManager.GetOrCreate(_trafficEngine, baseProfile: null, log: Log);

            // Создаём контроллеры
            Bypass = new BypassController(_bypassState);
            Orchestrator = new DiagnosticOrchestrator(_bypassState);
            Results = new TestResultsManager();

            // Подписываемся на события
            Bypass.OnLog += Log;
            Bypass.PropertyChanged += (s, e) =>
            {
                OnPropertyChanged(e.PropertyName ?? "");
                CheckAndRetestFailedTargets(e.PropertyName);
                if (e.PropertyName == nameof(Bypass.IsBypassActive)) CheckTrafficEngineState();
            };

            Orchestrator.OnLog += Log;
            Orchestrator.OnPipelineMessage += msg =>
            {
                CurrentAction = msg;
                Results.ParsePipelineMessage(msg);
                UpdateUserMessage(msg);
            };
            Orchestrator.OnDiagnosticComplete += () =>
            {
                ScreenState = "done";
                CommandManager.InvalidateRequerySuggested();

                if (_pendingRetestAfterRun)
                {
                    _pendingRetestAfterRun = false;
                    if (!Orchestrator.LastRunWasUserCancelled)
                    {
                        _ = RunPendingRetestAfterRunAsync();
                    }
                    else
                    {
                        Log($"[AutoRetest] Skip scheduled retest after cancel (reason={_pendingRetestReason})");
                        _pendingRetestReason = "";
                    }
                }

                if (_pendingNetworkChangePrompt)
                {
                    _pendingNetworkChangePrompt = false;
                    ShowNetworkChangePrompt();
                }
            };
            Orchestrator.PropertyChanged += (s, e) =>
            {
                OnPropertyChanged(e.PropertyName ?? "");
                if (e.PropertyName == nameof(Orchestrator.IsDiagnosticRunning))
                {
                    OnPropertyChanged(nameof(IsRunning));
                    OnPropertyChanged(nameof(StartButtonText));
                    CheckTrafficEngineState();
                }
                if (e.PropertyName == nameof(Orchestrator.HasRecommendations))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            };

            Results.OnLog += Log;
            Results.PropertyChanged += (s, e) =>
            {
                OnPropertyChanged(e.PropertyName ?? "");
                OnPropertyChanged(nameof(RunningStatusText));
            };

            // Инициализация результатов
            Results.Initialize();

            // Команды
            StartLiveTestingCommand = new RelayCommand(async _ => await StartOrCancelAsync(), _ => true);
            StartCommand = StartLiveTestingCommand;
            CancelCommand = new RelayCommand(_ => Orchestrator.Cancel(), _ => IsRunning || IsApplyingRecommendations);
            SetStateCommand = new RelayCommand(state => ScreenState = state?.ToString() ?? "start");
            ReportCommand = new RelayCommand(_ => GenerateReport(), _ => IsDone);
            DetailsCommand = new RelayCommand(param => ShowDetailsDialog(param as TestResult), _ => true);
            BrowseExeCommand = new RelayCommand(_ => BrowseExe(), _ => !IsRunning);
            ToggleThemeCommand = new RelayCommand(_ => IsDarkTheme = !IsDarkTheme);

            // Bypass Commands
            ToggleFragmentCommand = new RelayCommand(_ => Bypass.IsFragmentEnabled = !Bypass.IsFragmentEnabled, _ => ShowBypassPanel);
            ToggleDisorderCommand = new RelayCommand(_ => Bypass.IsDisorderEnabled = !Bypass.IsDisorderEnabled, _ => ShowBypassPanel);
            ToggleFakeCommand = new RelayCommand(_ => Bypass.IsFakeEnabled = !Bypass.IsFakeEnabled, _ => ShowBypassPanel);
            ToggleDropRstCommand = new RelayCommand(_ => Bypass.IsDropRstEnabled = !Bypass.IsDropRstEnabled, _ => ShowBypassPanel);
            ToggleDoHCommand = new RelayCommand(_ => Bypass.IsDoHEnabled = !Bypass.IsDoHEnabled, _ => ShowBypassPanel);
            DisableAllBypassCommand = new RelayCommand(async _ =>
            {
                await Bypass.DisableAllAsync();
                EnableAutoBypass = false; // Также отключаем авто-включение при следующем старте
            },
                _ => ShowBypassPanel && (IsFragmentEnabled || IsDisorderEnabled || IsFakeEnabled || IsDropRstEnabled));

            ApplyRecommendationsCommand = new RelayCommand(async _ => await ApplyRecommendationsAsync(), _ => HasRecommendations && !IsApplyingRecommendations);

            // Применение стратегии/плана из конкретной строки результата ("карточки").
            // UX: пользователь видит стратегию рядом с целью и нажимает "Подключить" именно для неё.
            ConnectFromResultCommand = new RelayCommand(async param => await ConnectFromResultAsync(param as TestResult),
                param => ShowBypassPanel && !IsApplyingRecommendations);

            NetworkRevalidateCommand = new RelayCommand(async _ => await RunNetworkRevalidationAsync(), _ => ShowBypassPanel && IsNetworkChangePromptVisible);
            NetworkDisableBypassCommand = new RelayCommand(async _ => await DisableBypassFromNetworkPromptAsync(), _ => ShowBypassPanel && IsNetworkChangePromptVisible);
            NetworkIgnoreCommand = new RelayCommand(_ => HideNetworkChangePrompt(), _ => IsNetworkChangePromptVisible);

            // NetworkChange monitor (P0.6): запускаем только когда есть WPF Application.
            // В smoke/console окружении Application.Current обычно null, и мы избегаем подписок на системные события.
            if (Application.Current != null)
            {
                _networkChangeMonitor = new NetworkChangeMonitor(Log);
                _networkChangeMonitor.NetworkChanged += _ =>
                {
                    try
                    {
                        Application.Current?.Dispatcher.Invoke(() => OnNetworkChanged());
                    }
                    catch
                    {
                        // ignore
                    }
                };
                _networkChangeMonitor.Start();
            }

            Log("✓ MainViewModelRefactored инициализирован");
        }

        public async Task InitializeAsync()
        {
            // Инициализация bypass при старте
            await Bypass.InitializeOnStartupAsync();
        }

        public async Task ShutdownAsync()
        {
            // 1) Останавливаем диагностику/применение рекомендаций, если они идут.
            try
            {
                Orchestrator.Cancel();
            }
            catch
            {
                // ignore
            }

            // 2) Отключаем bypass (WinDivert/фильтры) и восстанавливаем DNS, если мы его меняли.
            try
            {
                if (ShowBypassPanel)
                {
                    await Bypass.DisableAllAsync().ConfigureAwait(false);

                    // Критично: если DoH/DNS фикс включался через FixService, после выхода нужно вернуть исходные DNS.
                    // Иначе пользователь может остаться на DNS провайдера, который у него не работает.
                    if (IspAudit.Utils.FixService.HasBackupFile)
                    {
                        await Bypass.RestoreDoHAsync().ConfigureAwait(false);
                    }
                }
            }
            catch
            {
                // ignore
            }

            // 3) Отмечаем корректное завершение сессии bypass.
            try
            {
                _bypassState.MarkCleanShutdown();
                Log("[Bypass][Watchdog] Clean shutdown отмечен");
            }
            catch
            {
                // ignore
            }

            // 4) Чистим монитор смены сети.
            try
            {
                _networkChangeMonitor?.Dispose();
            }
            catch
            {
                // ignore
            }
        }

        public void OnAppExit()
        {
            try
            {
                _bypassState.MarkCleanShutdown();
                Log("[Bypass][Watchdog] Clean shutdown отмечен");
            }
            catch
            {
                // ignore
            }

            try
            {
                _networkChangeMonitor?.Dispose();
            }
            catch
            {
                // ignore
            }
        }

        private void OnNetworkChanged()
        {
            Log("[P0.6][NET] Событие смены сети");

            // UX: если обход не включён (нет опций) — уведомление не нужно.
            var snapshot = _bypassState.GetOptionsSnapshot();
            if (!snapshot.IsAnyEnabled())
            {
                Log("[P0.6][NET] Skip: bypass options not enabled");
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[P0.6][NET] Skip: bypass panel hidden (no admin rights)");
                return;
            }

            // Если сейчас идёт диагностика — откладываем UX до завершения.
            if (IsRunning || IsApplyingRecommendations)
            {
                _pendingNetworkChangePrompt = true;
                Log("[P0.6][NET] Defer prompt: diagnostic/apply in progress");
                return;
            }

            ShowNetworkChangePrompt();
        }

        private void ShowNetworkChangePrompt()
        {
            IsNetworkChangePromptVisible = true;
            NetworkChangePromptText =
                "Обнаружена смена сети.\n" +
                "Рекомендуется перепроверить состояние обхода.\n" +
                "Действия: «Проверить», «Отключить», «Игнорировать».";
        }

        private void HideNetworkChangePrompt()
        {
            try
            {
                _networkRevalidateCts?.Cancel();
                _networkRevalidateCts?.Dispose();
            }
            catch
            {
                // ignore
            }
            finally
            {
                _networkRevalidateCts = null;
            }

            IsNetworkChangePromptVisible = false;
        }

        private async Task DisableBypassFromNetworkPromptAsync()
        {
            try
            {
                await Bypass.DisableAllAsync();
                EnableAutoBypass = false;

                NetworkChangePromptText =
                    "Bypass отключён.\n" +
                    "Если проблема осталась — запустите полную диагностику.";
            }
            catch (Exception ex)
            {
                NetworkChangePromptText = $"Ошибка отключения bypass: {ex.Message}";
            }
        }

        private async Task RunNetworkRevalidationAsync()
        {
            if (_isNetworkRevalidating)
            {
                return;
            }

            _isNetworkRevalidating = true;
            try
            {
                _networkRevalidateCts?.Cancel();
                _networkRevalidateCts?.Dispose();
                _networkRevalidateCts = new CancellationTokenSource();
                var ct = _networkRevalidateCts.Token;

                NetworkChangePromptText = "Проверяю состояние обхода…";

                // Stage 1: health/activation (быстро)
                var activation = _bypassState.GetActivationStatusSnapshot();
                Log($"[P0.6][STAGE1] ACT={activation.Text}; {activation.Details}");

                // Stage 2: outcome check (активный probe)
                var host = _bypassState.GetOutcomeTargetHost();
                if (string.IsNullOrWhiteSpace(host))
                {
                    Log("[P0.6][STAGE2] OUT=UNKNOWN: no target host");
                }

                var outcome = await _bypassState.RunOutcomeProbeNowAsync(cancellationToken: ct);
                Log($"[P0.6][STAGE2] OUT={outcome.Text}; {outcome.Details}");

                // Stage 3: предложение запустить полную диагностику
                NetworkChangePromptText =
                    "Проверка завершена.\n" +
                    $"Stage 1: ACT: {activation.Text}.\n" +
                    $"Stage 2: OUT: {outcome.Text}.\n" +
                    "Stage 3: если проблема осталась — нажмите «Начать диагностику» для полного прогона.";
            }
            catch (OperationCanceledException)
            {
                NetworkChangePromptText = "Проверка отменена.";
            }
            catch (Exception ex)
            {
                NetworkChangePromptText = $"Ошибка проверки: {ex.Message}";
            }
            finally
            {
                _isNetworkRevalidating = false;
            }
        }

        #endregion

        #region Command Handlers

        private async Task ApplyRecommendationsAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey);
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения рекомендаций");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения рекомендаций: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ConnectFromResultAsync(TestResult? test)
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[V2][APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            if (test == null)
            {
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                // Подсветим выбранную цель + выставим OutcomeTargetHost (селективный QUIC→TCP зависит от этого).
                SelectedTestResult = test;

                var preferredHostKey = GetPreferredHostKey(test);
                if (string.IsNullOrWhiteSpace(preferredHostKey))
                {
                    Log("[V2][APPLY] Нет hostKey для выбранной строки (SNI/Host/Name пуст)");
                    return;
                }

                // Если для этой цели есть v2 план — применяем его.
                // Если плана нет, ApplyRecommendationsAsync просто ничего не сделает (и это лучше, чем включать тумблеры вслепую).
                await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey);
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения стратегии из карточки");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения стратегии из карточки: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private static string? GetPreferredHostKey(TestResult? test)
        {
            try
            {
                if (test?.Target == null) return null;

                if (!string.IsNullOrWhiteSpace(test.Target.SniHost)) return test.Target.SniHost.Trim();
                if (!string.IsNullOrWhiteSpace(test.Target.Host)) return test.Target.Host.Trim();
                if (!string.IsNullOrWhiteSpace(test.Target.Name)) return test.Target.Name.Trim();
                return null;
            }
            catch
            {
                return null;
            }
        }

        private async Task StartOrCancelAsync()
        {
            if (IsRunning)
            {
                Log("→ Cancelling diagnostic");
                Orchestrator.Cancel();
            }
            else
            {
                await StartDiagnosticAsync();
            }
        }

        private async Task StartDiagnosticAsync()
        {
            string targetExePath;

            if (IsBasicTestMode)
            {
                targetExePath = GetTestNetworkAppPath() ?? "";
                if (string.IsNullOrEmpty(targetExePath))
                {
                    MessageBox.Show("Не удалось найти TestNetworkApp.exe", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                Log($"[Mode] Basic Test: {targetExePath}");
            }
            else
            {
                if (string.IsNullOrEmpty(ExePath) || !File.Exists(ExePath))
                {
                    MessageBox.Show("Файл не найден.", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                targetExePath = ExePath;
                Log($"[Mode] Normal: {targetExePath}");
            }

            ScreenState = "running";
            Results.Clear();

            Orchestrator.EnableSilenceTimeout = !IsUnlimitedTime;
            await Orchestrator.RunAsync(targetExePath, Bypass, Results, EnableAutoBypass, IsSteamMode);
        }

        private void BrowseExe()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*",
                Title = "Выберите exe файл приложения"
            };

            if (dialog.ShowDialog() == true)
            {
                ExePath = dialog.FileName;
                Log($"[BrowseExe] Selected: {ExePath}");
            }
        }

        private void GenerateReport()
        {
            try
            {
                var report = new
                {
                    Date = DateTime.Now,
                    ExePath = ExePath,
                    Summary = new
                    {
                        Total = TotalTargets,
                        Passed = PassCount,
                        Failed = FailCount,
                        Warnings = WarnCount
                    },
                    Results = TestResults.Select(t => new
                    {
                        Host = t.Target.Host,
                        Name = t.Target.Name,
                        Service = t.Target.Service,
                        Status = t.Status.ToString(),
                        Details = t.Details,
                        Error = t.Error,
                        BypassStrategy = t.BypassStrategy,
                        Flags = new
                        {
                            t.IsRstInjection,
                            t.IsHttpRedirect,
                            t.IsRetransmissionHeavy,
                            t.IsUdpBlockage
                        }
                    }).ToList()
                };

                var json = System.Text.Json.JsonSerializer.Serialize(report,
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                var filename = $"isp_audit_report_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filename);

                File.WriteAllText(path, json);
                Log($"[Report] Saved: {path}");

                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
            }
            catch (Exception ex)
            {
                Log($"[Report] Error: {ex.Message}");
                MessageBox.Show($"Ошибка создания отчета: {ex.Message}", "Ошибка",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowDetailsDialog(TestResult? result)
        {
            if (result == null) return;

            try
            {
                var window = new IspAudit.Windows.TestDetailsWindow(result)
                {
                    Owner = Application.Current.MainWindow
                };
                window.ShowDialog();
            }
            catch (Exception ex)
            {
                Log($"[ShowDetails] Error: {ex.Message}");
            }
        }

        #endregion

        #region Helper Methods

        private string? GetTestNetworkAppPath()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;

            var path = Path.Combine(baseDir, "TestNetworkApp.exe");
            if (File.Exists(path)) return path;

            path = Path.Combine(baseDir, "TestNetworkApp", "bin", "Publish", "TestNetworkApp.exe");
            if (File.Exists(path)) return path;

            return null;
        }

        private void UpdateUserMessage(string msg)
        {
            var cleanMsg = msg;

            if (cleanMsg.StartsWith("["))
            {
                var closeBracket = cleanMsg.IndexOf(']');
                if (closeBracket > 0)
                {
                    cleanMsg = cleanMsg.Substring(closeBracket + 1).Trim();
                }
            }

            if (cleanMsg.Contains("ConnectionMonitor")) cleanMsg = "Анализ сетевых соединений...";
            if (cleanMsg.Contains("WinDivert")) cleanMsg = "Инициализация драйвера перехвата...";
            if (cleanMsg.Contains("DNS")) cleanMsg = "Проверка DNS запросов...";

            if (System.Text.RegularExpressions.Regex.IsMatch(cleanMsg, @"\d+\.\d+\.\d+\.\d+:\d+"))
            {
                cleanMsg = "Обнаружено соединение с сервером...";
            }

            UserMessage = cleanMsg;
        }

        private async void CheckAndRetestFailedTargets(string? propertyName)
        {
            if (string.IsNullOrEmpty(propertyName)) return;

            // Проверяем, что изменилось именно свойство bypass
            if (propertyName != nameof(Bypass.IsFragmentEnabled) &&
                propertyName != nameof(Bypass.IsDisorderEnabled) &&
                propertyName != nameof(Bypass.IsFakeEnabled) &&
                propertyName != nameof(Bypass.IsDropRstEnabled) &&
                propertyName != nameof(Bypass.IsQuicFallbackEnabled) &&
                propertyName != nameof(Bypass.IsAllowNoSniEnabled) &&
                propertyName != nameof(Bypass.IsDoHEnabled))
            {
                return;
            }

            // Во время активной диагностики Orchestrator.RetestTargetsAsync запрещён.
            // Поэтому откладываем ретест до завершения (done).
            if (IsRunning)
            {
                _pendingRetestAfterRun = true;
                _pendingRetestReason = propertyName;
                Log($"[AutoRetest] Bypass option changed ({propertyName}) during running. Retest scheduled after diagnostic ends.");
                return;
            }

            // Если диагностика ещё не завершена — ничего не делаем.
            if (!IsDone) return;

            // Находим проблемные цели (не OK)
            var failedTargets = Results.TestResults
                .Where(r => r.Status != TestStatus.Pass)
                .Select(r => r.Target)
                .ToList();

            if (failedTargets.Count == 0) return;

            Log($"[AutoRetest] Bypass option changed ({propertyName}). Retesting {failedTargets.Count} failed targets...");

            // Запускаем ретест
            await Orchestrator.RetestTargetsAsync(failedTargets, Bypass);
        }

        private async Task RunPendingRetestAfterRunAsync()
        {
            try
            {
                if (!IsDone) return;

                var failedTargets = Results.TestResults
                    .Where(r => r.Status != TestStatus.Pass)
                    .Select(r => r.Target)
                    .ToList();

                if (failedTargets.Count == 0) return;

                Log($"[AutoRetest] Running scheduled retest after run (reason={_pendingRetestReason}). Targets={failedTargets.Count}");
                await Orchestrator.RetestTargetsAsync(failedTargets, Bypass);
            }
            catch (Exception ex)
            {
                Log($"[AutoRetest] Error: {ex.Message}");
            }
            finally
            {
                _pendingRetestReason = "";
            }
        }

        private void ApplyTheme(bool isDark)
        {
            var paletteHelper = new PaletteHelper();
            var theme = paletteHelper.GetTheme();
            theme.SetBaseTheme(isDark ? BaseTheme.Dark : BaseTheme.Light);
            paletteHelper.SetTheme(theme);
        }

        private void CheckTrafficEngineState()
        {
            if (!Bypass.IsBypassActive && !Orchestrator.IsDiagnosticRunning)
            {
                if (_trafficEngine.IsRunning)
                {
                    Log("[Main] Stopping TrafficEngine (no active consumers)...");
                    _ = _trafficEngine.StopAsync();
                }
            }
        }

        #endregion

        #region INotifyPropertyChanged

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
