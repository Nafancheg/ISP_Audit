using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using ISPAudit.Models;
using IspAudit.Tests;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace ISPAudit.ViewModels
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

        public string CurrentAction
        {
            get => _currentAction;
            set { _currentAction = value; OnPropertyChanged(nameof(CurrentAction)); }
        }

        public string UserMessage
        {
            get => _userMessage;
            set { _userMessage = value; OnPropertyChanged(nameof(UserMessage)); }
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

        // Прокси-свойства для BypassController
        public bool ShowBypassPanel => Bypass.ShowBypassPanel;
        public bool IsBypassActive => Bypass.IsBypassActive;
        public bool IsFragmentEnabled { get => Bypass.IsFragmentEnabled; set => Bypass.IsFragmentEnabled = value; }
        public bool IsDisorderEnabled { get => Bypass.IsDisorderEnabled; set => Bypass.IsDisorderEnabled = value; }
        public bool IsFakeEnabled { get => Bypass.IsFakeEnabled; set => Bypass.IsFakeEnabled = value; }
        public bool IsDropRstEnabled { get => Bypass.IsDropRstEnabled; set => Bypass.IsDropRstEnabled = value; }
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

        #endregion

        #region Commands

        public ICommand StartCommand { get; }
        public ICommand StartLiveTestingCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand SetStateCommand { get; }
        public ICommand ReportCommand { get; }
        public ICommand DetailsCommand { get; }
        public ICommand BrowseExeCommand { get; }
        
        // Bypass Toggle Commands
        public ICommand ToggleFragmentCommand { get; }
        public ICommand ToggleDisorderCommand { get; }
        public ICommand ToggleFakeCommand { get; }
        public ICommand ToggleDropRstCommand { get; }
        public ICommand ToggleDoHCommand { get; }
        public ICommand DisableAllBypassCommand { get; }

        #endregion

        #region Constructor

        public MainViewModelRefactored()
        {
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log("MainViewModelRefactored: Инициализация");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Создаём контроллеры
            Bypass = new BypassController();
            Orchestrator = new DiagnosticOrchestrator();
            Results = new TestResultsManager();

            // Подписываемся на события
            Bypass.OnLog += Log;
            Bypass.PropertyChanged += (s, e) => OnPropertyChanged(e.PropertyName ?? "");
            
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
            };
            Orchestrator.PropertyChanged += (s, e) => 
            {
                OnPropertyChanged(e.PropertyName ?? "");
                if (e.PropertyName == nameof(Orchestrator.IsDiagnosticRunning))
                {
                    OnPropertyChanged(nameof(IsRunning));
                    OnPropertyChanged(nameof(StartButtonText));
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
            CancelCommand = new RelayCommand(_ => Orchestrator.Cancel(), _ => IsRunning);
            SetStateCommand = new RelayCommand(state => ScreenState = state?.ToString() ?? "start");
            ReportCommand = new RelayCommand(_ => GenerateReport(), _ => IsDone);
            DetailsCommand = new RelayCommand(param => ShowDetailsDialog(param as TestResult), _ => true);
            BrowseExeCommand = new RelayCommand(_ => BrowseExe(), _ => !IsRunning);

            // Bypass Commands
            ToggleFragmentCommand = new RelayCommand(_ => Bypass.IsFragmentEnabled = !Bypass.IsFragmentEnabled, _ => ShowBypassPanel);
            ToggleDisorderCommand = new RelayCommand(_ => Bypass.IsDisorderEnabled = !Bypass.IsDisorderEnabled, _ => ShowBypassPanel);
            ToggleFakeCommand = new RelayCommand(_ => Bypass.IsFakeEnabled = !Bypass.IsFakeEnabled, _ => ShowBypassPanel);
            ToggleDropRstCommand = new RelayCommand(_ => Bypass.IsDropRstEnabled = !Bypass.IsDropRstEnabled, _ => ShowBypassPanel);
            ToggleDoHCommand = new RelayCommand(_ => Bypass.IsDoHEnabled = !Bypass.IsDoHEnabled, _ => ShowBypassPanel);
            DisableAllBypassCommand = new RelayCommand(async _ => await Bypass.DisableAllAsync(), 
                _ => ShowBypassPanel && (IsFragmentEnabled || IsDisorderEnabled || IsFakeEnabled || IsDropRstEnabled));

            // Инициализация bypass при старте
            Bypass.InitializeOnStartupAsync();

            Log("✓ MainViewModelRefactored инициализирован");
        }

        #endregion

        #region Command Handlers

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
            
            await Orchestrator.RunAsync(targetExePath, Bypass, Results, EnableAutoBypass);
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
                        BypassStrategy = t.BypassStrategy
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
                var window = new ISPAudit.Windows.TestDetailsWindow(result)
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

            if (cleanMsg.Contains("FlowMonitor")) cleanMsg = "Анализ сетевого потока...";
            if (cleanMsg.Contains("WinDivert")) cleanMsg = "Инициализация драйвера перехвата...";
            if (cleanMsg.Contains("DNS")) cleanMsg = "Проверка DNS запросов...";
            
            if (System.Text.RegularExpressions.Regex.IsMatch(cleanMsg, @"\d+\.\d+\.\d+\.\d+:\d+"))
            {
                cleanMsg = "Обнаружено соединение с сервером...";
            }

            UserMessage = cleanMsg;
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
