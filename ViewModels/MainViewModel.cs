using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using System.IO;
using ISPAudit.Models;
using ISPAudit.Utils;
using IspAudit;
using IspAudit.Tests;
using IspAudit.Bypass;
using IspAudit.Utils;

namespace ISPAudit.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private static readonly string LogFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "isp_audit_vm_log.txt");
        
        private static void Log(string message)
        {
            try
            {
                File.AppendAllText(LogFilePath, $"[{DateTime.Now:HH:mm:ss.fff}] {message}\n");
                System.Diagnostics.Debug.WriteLine(message);
            }
            catch { }
        }
        
        private string _selectedScenario = "profile";
        private string _screenState = "start";
        private CancellationTokenSource? _cts;
        private Config? _config;
        private Dictionary<string, TestResult> _testResultMap = new();
        private string _hostInput = "";
        private string _exePath = "";
        private string _selectedProfile = "Star Citizen";
        private string _currentAction = "";

        public ObservableCollection<TestResult> TestResults { get; set; }
        public ObservableCollection<string> AvailableProfiles { get; set; }

        public string CurrentAction
        {
            get => _currentAction;
            set
            {
                _currentAction = value;
                OnPropertyChanged(nameof(CurrentAction));
            }
        }

        public string SelectedScenario
        {
            get => _selectedScenario;
            set
            {
                _selectedScenario = value;
                OnPropertyChanged(nameof(SelectedScenario));
                OnPropertyChanged(nameof(IsHostScenario));
                OnPropertyChanged(nameof(IsExeScenario));
                OnPropertyChanged(nameof(IsProfileScenario));
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
                Log($"  IsStart={IsStart}, IsRunning={IsRunning}, IsDone={IsDone}");
                
                if (value == "done")
                {
                    Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    Log("ШАГ 4: СОСТОЯНИЕ 'DONE'");
                    Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    Log("UI должен показывать:");
                    Log($"  ✓ Заголовок: 'Проверка завершена'");
                    Log($"  ✓ Summary блок с счётчиками:");
                    Log($"      Успешно: {PassCount} (зелёный)");
                    Log($"      Ошибки: {FailCount} (красный)");
                    Log($"      Предупреждения: {WarnCount} (жёлтый)");
                    Log($"  ✓ Карточки тестов: ВИДИМЫ в ScrollViewer ({TestResults.Count} шт)");
                    Log($"  ✓ Кнопки: 'Экспорт отчета' и 'Новая проверка'");
                    Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                }
                
                UpdateTestStates();
            }
        }

        public bool IsHostScenario
        {
            get => SelectedScenario == "host";
            set { if (value) SelectedScenario = "host"; }
        }

        public bool IsExeScenario
        {
            get => SelectedScenario == "exe";
            set { if (value) SelectedScenario = "exe"; }
        }

        public bool IsProfileScenario
        {
            get => SelectedScenario == "profile";
            set { if (value) SelectedScenario = "profile"; }
        }

        public bool IsStart => ScreenState == "start";
        public bool IsRunning => ScreenState == "running" || _isExeScenarioRunning;
        public bool IsDone => ScreenState == "done";
        public bool ShowSummary => IsDone;
        public bool ShowReport => IsDone;

        public string HostInput
        {
            get => _hostInput;
            set
            {
                _hostInput = value;
                OnPropertyChanged(nameof(HostInput));
            }
        }

        public string ExePath
        {
            get => _exePath;
            set
            {
                _exePath = value;
                OnPropertyChanged(nameof(ExePath));
            }
        }

        public string SelectedProfile
        {
            get => _selectedProfile;
            set
            {
                _selectedProfile = value;
                OnPropertyChanged(nameof(SelectedProfile));
            }
        }

        public string ProfileName => "Default";
        public string ProfileTestMode => "general";

        public int TotalTargets => TestResults?.Count ?? 0;
        public int CurrentTest => TestResults?.Count(t => t.Status == TestStatus.Running || t.Status == TestStatus.Pass || t.Status == TestStatus.Fail || t.Status == TestStatus.Warn) ?? 0;
        public int CompletedTests => TestResults?.Count(t => t.Status == TestStatus.Pass || t.Status == TestStatus.Fail || t.Status == TestStatus.Warn) ?? 0;
        public int PassCount => TestResults?.Count(t => t.Status == TestStatus.Pass) ?? 0;
        public int FailCount => TestResults?.Count(t => t.Status == TestStatus.Fail) ?? 0;
        public int WarnCount => TestResults?.Count(t => t.Status == TestStatus.Warn) ?? 0;

        public string RunningStatusText => $"Выполняется {CurrentTest} из {TotalTargets}";
        public string StartButtonText => IsRunning ? "Остановить тест" : "Начать проверку";

        // Fix System Properties
        public ObservableCollection<AppliedFix> ActiveFixes { get; set; } = new();
        public bool HasActiveFixes => ActiveFixes.Count > 0;
        public string ActiveFixesMessage => $"Активны исправления системы ({ActiveFixes.Count})";

        public ICommand StartCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand SetStateCommand { get; }
        public ICommand ChooseExeCommand { get; }
        public ICommand ReportCommand { get; }
        public ICommand DetailsCommand { get; }
        public ICommand FixCommand { get; }
        public ICommand RollbackFixCommand { get; }
        public ICommand RollbackAllCommand { get; }

        // Exe Scenario Properties
        private string _stage1Status = "";
        private string _stage2Status = "";
        private string _stage3Status = "";
        private int _stage1HostsFound = 0;
        private int _stage2ProblemsFound = 0;
        private int _stage1Progress = 0;
        private int _stage2Progress = 0;
        private int _stage3Progress = 0;
        private bool _stage1Complete = false;
        private bool _stage2Complete = false;
        private bool _stage3Complete = false;
        private bool _isExeScenarioRunning = false;
        private GameProfile? _capturedProfile;
        private List<BlockageProblem>? _detectedProblems;
        private BypassProfile? _plannedBypass;

        public string Stage1Status
        {
            get => _stage1Status;
            set { _stage1Status = value; OnPropertyChanged(nameof(Stage1Status)); }
        }

        public string Stage2Status
        {
            get => _stage2Status;
            set { _stage2Status = value; OnPropertyChanged(nameof(Stage2Status)); }
        }

        public string Stage3Status
        {
            get => _stage3Status;
            set { _stage3Status = value; OnPropertyChanged(nameof(Stage3Status)); }
        }

        public int Stage1HostsFound
        {
            get => _stage1HostsFound;
            set { _stage1HostsFound = value; OnPropertyChanged(nameof(Stage1HostsFound)); }
        }

        public int Stage2ProblemsFound
        {
            get => _stage2ProblemsFound;
            set { _stage2ProblemsFound = value; OnPropertyChanged(nameof(Stage2ProblemsFound)); }
        }

        public int Stage1Progress
        {
            get => _stage1Progress;
            set { _stage1Progress = value; OnPropertyChanged(nameof(Stage1Progress)); }
        }

        public int Stage2Progress
        {
            get => _stage2Progress;
            set { _stage2Progress = value; OnPropertyChanged(nameof(Stage2Progress)); }
        }

        public int Stage3Progress
        {
            get => _stage3Progress;
            set { _stage3Progress = value; OnPropertyChanged(nameof(Stage3Progress)); }
        }

        public bool Stage1Complete
        {
            get => _stage1Complete;
            set { _stage1Complete = value; OnPropertyChanged(nameof(Stage1Complete)); OnPropertyChanged(nameof(CanRunStage2)); }
        }

        public bool Stage2Complete
        {
            get => _stage2Complete;
            set { _stage2Complete = value; OnPropertyChanged(nameof(Stage2Complete)); OnPropertyChanged(nameof(CanRunStage3)); }
        }

        public bool Stage3Complete
        {
            get => _stage3Complete;
            set { _stage3Complete = value; OnPropertyChanged(nameof(Stage3Complete)); }
        }

        public bool CanRunStage2 => Stage1Complete && _capturedProfile != null;
        public bool CanRunStage3 => Stage2Complete && _detectedProblems != null && _detectedProblems.Any();

        public ICommand AnalyzeTrafficCommand { get; }
        public ICommand DiagnoseCommand { get; }
        public ICommand ApplyBypassCommand { get; }
        public ICommand ViewStage1ResultsCommand { get; }
        public ICommand BrowseExeCommand { get; }
        public ICommand ResetExeScenarioCommand { get; }

        public MainViewModel()
        {
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log("ШАГ 1: НАЧАЛЬНОЕ СОСТОЯНИЕ (Constructor)");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            // Инициализация списка профилей
            AvailableProfiles = new ObservableCollection<string>
            {
                "Star Citizen",
                "Default"
            };
            Log($"✓ Профили загружены: {string.Join(", ", AvailableProfiles)}");

            InitializeTestResults();
            Log($"✓ TestResults инициализирована (Count={TestResults?.Count ?? 0})");
            Log($"✓ ScreenState = '{ScreenState}' (ожидается 'start')");
            Log($"✓ IsStart = {IsStart} (ожидается true)");
            Log($"✓ IsRunning = {IsRunning} (ожидается false)");

            StartCommand = new RelayCommand(async _ => 
            {
                Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log("ШАГ 2: НАЖАТИЕ 'НАЧАТЬ ПРОВЕРКУ'");
                Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log($"IsRunning={IsRunning}, ScreenState={ScreenState}, Scenario={SelectedScenario}");
                
                if (IsRunning)
                {
                    Log("→ Тест уже запущен. Вызов CancelAudit()");
                    CancelAudit();
                }
                else
                {
                    // Для Exe-сценария сразу запускаем Stage1
                    if (IsExeScenario)
                    {
                        Log("→ Exe сценарий: запуск Stage1 (RunStage1AnalyzeTrafficAsync)");
                        await RunStage1AnalyzeTrafficAsync();
                    }
                    else
                    {
                        Log("→ Вызов RunAuditAsync()");
                        await RunAuditAsync();
                    }
                }
            }, _ => !IsRunning); // Кнопка активна только когда НЕ запущен тест
            CancelCommand = new RelayCommand(_ => CancelAudit(), _ => IsRunning && _cts != null);
            SetStateCommand = new RelayCommand(state => 
            {
                ScreenState = state.ToString();
                // Обновляем CanExecute для команд
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            });
            ChooseExeCommand = new RelayCommand(_ => ChooseExeFile(), _ => IsStart);
            ReportCommand = new RelayCommand(_ => { /* Generate report */ }, _ => IsDone);
            DetailsCommand = new RelayCommand(param => ShowDetailsDialog(param as TestResult), _ => true);
            
            // Fix Commands
            FixCommand = new RelayCommand(async param => await ApplyFixAsync(param as TestResult), _ => true);
            RollbackFixCommand = new RelayCommand(async param => await RollbackFixAsync(param as AppliedFix), _ => true);
            RollbackAllCommand = new RelayCommand(async _ => await RollbackAllFixesAsync(), _ => HasActiveFixes);

            // Exe Scenario Commands
            BrowseExeCommand = new RelayCommand(_ => BrowseExe(), _ => !IsRunning);
            AnalyzeTrafficCommand = new RelayCommand(async _ => await RunStage1AnalyzeTrafficAsync(), _ => !string.IsNullOrEmpty(ExePath) && !IsRunning && !Stage1Complete);
            ViewStage1ResultsCommand = new RelayCommand(_ => ViewStage1Results(), _ => _capturedProfile != null);
            DiagnoseCommand = new RelayCommand(async _ => await RunStage2DiagnoseAsync(), _ => CanRunStage2 && !IsRunning);
            ApplyBypassCommand = new RelayCommand(async _ => await RunStage3ApplyBypassAsync(), _ => CanRunStage3 && !IsRunning);
            ResetExeScenarioCommand = new RelayCommand(_ => ResetExeScenario(), 
                _ => (Stage1Complete || Stage2Complete || Stage3Complete) && !IsRunning);
            
            // Load Fix History on startup
            LoadFixHistory();
            
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log("ШАГ 1: ЗАВЕРШЁН. UI должен показывать:");
            Log("  ✓ Центральный текст: 'Готов к проверке'");
            Log("  ✓ Кнопка: 'Начать проверку' (активна)");
            Log("  ✓ Выбор сценария: активен");
            Log("  ✓ Карточки тестов: НЕ ВИДИМЫ (TestResults.Count=0)");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        }

        private async Task RunAuditAsync()
        {
            try
            {
                Log("→ 2.1: LoadProfileAndUpdateTargets()...");
                if (!LoadProfileAndUpdateTargets())
                {
                    Log("[ERROR] LoadProfileAndUpdateTargets() вернул false - отмена");
                    return;
                }
                Log($"✓ 2.1: Профиль загружен. TestResults.Count={TestResults?.Count ?? 0}");
                
                Log("→ 2.2: Смена ScreenState на 'running'...");
                ScreenState = "running";
                Log($"✓ 2.2: ScreenState='{ScreenState}'");
                Log($"  Ожидается в UI:");
                Log($"    ✓ Выбор сценария: ЗАБЛОКИРОВАН");
                Log($"    ✓ Кнопка текст: 'Остановить тест'");
                Log($"    ✓ Центральная область: переключена на ScrollViewer");
                Log($"    ✓ Текст: 'Выполняется проверка...'");
                Log($"    ✓ ProgressStepper: ВИДИМ (0/{TotalTargets})");
                Log($"    ✓ КАРТОЧКИ ТЕСТОВ: ДОЛЖНЫ ПОЯВИТЬСЯ ({TestResults?.Count ?? 0} шт)");
                
                Log("→ 2.3: CreateConfig()...");
                _config = CreateConfig();
                if (_config == null)
                {
                    Log("[ERROR] CreateConfig() вернул null - отмена");
                    return;
                }
                Log($"✓ 2.3: Config создан");

                Log("→ 2.4: Создание CancellationTokenSource и Progress...");
                _cts = new CancellationTokenSource();
                var progress = new Progress<TestProgress>(HandleTestProgress);
                Log($"✓ 2.4: CTS и Progress созданы");

                Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log("ШАГ 3: ВЫПОЛНЕНИЕ ТЕСТОВ");
                Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log($"→ 3.1: Запуск AuditRunner.RunAsync()...");
                Log($"  TotalTargets={TotalTargets}, CurrentTest={CurrentTest}, CompletedTests={CompletedTests}");
                
                var report = await AuditRunner.RunAsync(_config, progress, _cts.Token).ConfigureAwait(false);
                
                Log($"✓ 3.X: AuditRunner.RunAsync() завершён");
                Log($"  ФИНАЛЬНЫЕ СЧЁТЧИКИ:");
                Log($"    PassCount={PassCount}");
                Log($"    FailCount={FailCount}");
                Log($"    WarnCount={WarnCount}");
                Log($"    CompletedTests={CompletedTests}/{TotalTargets}");

                Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log("ШАГ 4: ЗАВЕРШЕНИЕ ТЕСТОВ");
                Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                
                System.Windows.Application.Current?.Dispatcher.Invoke(() => 
                {
                    ScreenState = "done";
                });
            }
            catch (OperationCanceledException)
            {
                Log("[INFO] Тесты отменены пользователем");
                System.Windows.Application.Current?.Dispatcher.Invoke(() => 
                {
                    ScreenState = "done";
                });
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Исключение в RunAuditAsync: {ex.GetType().Name}");
                Log($"  Message: {ex.Message}");
                Log($"  StackTrace:\n{ex.StackTrace}");
                
                System.Windows.Application.Current?.Dispatcher.Invoke(() => ScreenState = "done");
            }
            finally
            {
                _cts?.Dispose();
                _cts = null;
            }
        }

        private void CancelAudit()
        {
            _cts?.Cancel();
        }

        private void ChooseExeFile()
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*",
                Title = "Выберите exe файл"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                ExePath = openFileDialog.FileName;
            }
        }

        private bool LoadProfileAndUpdateTargets()
        {
            Log($"\n>>> LoadProfileAndUpdateTargets() START");
            Log($"    SelectedScenario: {SelectedScenario}");
            
            Target[] targets;

            if (IsProfileScenario)
            {
                Log($"    Mode: PROFILE");
                Log($"    SelectedProfile: {SelectedProfile}");
                
                // Профиль: загружаем из JSON
                var profileName = SelectedProfile.Replace(" ", ""); // "Star Citizen" -> "StarCitizen"
                Log($"    Loading profile: {profileName}");
                Config.LoadGameProfile(profileName);
                
                if (Config.ActiveProfile?.Targets != null)
                {
                    Log($"    Profile loaded. Targets count: {Config.ActiveProfile.Targets.Count}");
                    targets = Config.ActiveProfile.Targets.Select(t => new Target
                    {
                        Name = t.Name,
                        Host = t.Host,
                        Service = t.Service ?? "Unknown",
                        Critical = t.Critical,
                        FallbackIp = t.FallbackIp ?? ""
                    }).ToArray();
                    
                    foreach (var t in targets)
                    {
                        Log($"      - {t.Name}: {t.Host} ({t.Service})");
                    }
                }
                else
                {
                    Log($"    !!! Profile is NULL or has no targets");
                    targets = Array.Empty<Target>();
                }
            }
            else if (IsHostScenario)
            {
                Log($"    Mode: HOST");
                Log($"    HostInput: '{HostInput}'");
                
                // Хост: создаем одну цель из ввода пользователя
                if (string.IsNullOrWhiteSpace(HostInput))
                {
                    Log($"    !!! HostInput is empty - showing error");
                    System.Windows.MessageBox.Show("Введите хост или IP-адрес", "Ошибка", 
                        System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    return false;
                }

                targets = new[]
                {
                    new Target
                    {
                        Name = HostInput,
                        Host = HostInput,
                        Service = "Произвольный хост",
                        Critical = true,
                        FallbackIp = ""
                    }
                };
                Log($"    Created target: {HostInput}");
            }
            else if (IsExeScenario)
            {
                Log($"    Mode: EXE");
                Log($"    ExePath: '{ExePath}'");
                
                // Приложение: загрузка профиля по имени exe файла
                if (string.IsNullOrWhiteSpace(ExePath))
                {
                    Log($"    !!! ExePath is empty - showing error");
                    System.Windows.MessageBox.Show("Выберите exe файл", "Ошибка", 
                        System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    return false;
                }

                if (!System.IO.File.Exists(ExePath))
                {
                    Log($"    !!! File does not exist - showing error");
                    System.Windows.MessageBox.Show($"Файл не найден: {ExePath}", "Ошибка", 
                        System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    return false;
                }

                // Получаем имя exe файла без расширения (например, StarCitizen.exe → StarCitizen)
                var exeNameWithoutExtension = System.IO.Path.GetFileNameWithoutExtension(ExePath);
                Log($"    Exe name (without extension): '{exeNameWithoutExtension}'");

                // Ищем профиль с таким же именем
                var profilesDir = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Profiles");
                var profilePath = System.IO.Path.Combine(profilesDir, $"{exeNameWithoutExtension}.json");
                
                Log($"    Looking for profile: {profilePath}");

                if (System.IO.File.Exists(profilePath))
                {
                    // Профиль найден → загружаем его
                    Log($"    Profile found! Loading...");
                    try
                    {
                        Config.LoadGameProfile(exeNameWithoutExtension);
                        
                        if (Config.ActiveProfile?.Targets != null)
                        {
                            Log($"    Profile loaded. Targets count: {Config.ActiveProfile.Targets.Count}");
                            targets = Config.ActiveProfile.Targets.Select(t => new Target
                            {
                                Name = t.Name,
                                Host = t.Host,
                                Service = t.Service ?? "Unknown",
                                Critical = t.Critical,
                                FallbackIp = t.FallbackIp ?? ""
                            }).ToArray();
                            
                            foreach (var t in targets)
                            {
                                Log($"      - {t.Name}: {t.Host} ({t.Service})");
                            }
                        }
                        else
                        {
                            Log($"    !!! Profile loaded but has no targets");
                            targets = Array.Empty<Target>();
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"    !!! Error loading profile: {ex.Message}");
                        System.Windows.MessageBox.Show($"Ошибка загрузки профиля: {ex.Message}", "Ошибка",
                            System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                        return false;
                    }
                }
                else
                {
                    // Профиль не найден → предлагаем ручной ввод хоста
                    Log($"    !!! Profile not found: {profilePath}");
                    var result = System.Windows.MessageBox.Show(
                        $"Профиль для {exeNameWithoutExtension}.exe не найден.\n\n" +
                        $"Хотите ввести хост вручную для проверки?",
                        "Профиль не найден",
                        System.Windows.MessageBoxButton.YesNo,
                        System.Windows.MessageBoxImage.Question);

                    if (result == System.Windows.MessageBoxResult.No)
                        return false;

                    // Переключаем на Host-сценарий и просим ввести хост
                    Log($"    Switching to Host scenario");
                    SelectedScenario = "Host";
                    System.Windows.MessageBox.Show(
                        "Перейдите в режим \"По хосту\" и введите адрес вручную.",
                        "Информация",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information);
                    return false;
                }
            }
            else
            {
                Log($"    !!! Unknown scenario");
                targets = Array.Empty<Target>();
            }

            // Обновляем TestResults
            Log($"    Updating TestResults. Targets count: {targets.Length}");
            TestResults.Clear();
            foreach (var target in targets)
            {
                var testResult = new TestResult { Target = target, Status = TestStatus.Idle };
                TestResults.Add(testResult);
                Log($"      Added TestResult: {target.Name} -> Status={testResult.Status}");
            }

            // Обновляем map
            Log($"    Updating _testResultMap");
            _testResultMap.Clear();
            foreach (var result in TestResults)
            {
                _testResultMap[result.Target.Name] = result;
                Log($"      Map['{result.Target.Name}'] = TestResult");
            }

            Log($">>> LoadProfileAndUpdateTargets() END. Success=TRUE\n");
            return true;
        }

        private Config? CreateConfig()
        {
            var config = new Config
            {
                Targets = TestResults.Select(t => t.Target.Host).ToList(),
                Ports = TargetCatalog.CreateDefaultTcpPorts(),
                EnableDns = true,
                EnableTcp = true,
                EnableHttp = true,
                EnableTrace = false,
                NoTrace = true
            };

            return config;
        }

        private void HandleTestProgress(TestProgress progress)
        {
            // Диспетчеризация в UI поток
            System.Windows.Application.Current?.Dispatcher.Invoke(() =>
            {
                CurrentAction = progress.Status;
                
                // Парсинг имени цели из Status (формат: "TargetName: действие")
                var targetName = ExtractTargetName(progress.Status);
                
                if (string.IsNullOrEmpty(targetName))
                {
                    // Системный тест без конкретной цели (Firewall, ISP, Router, Software)
                    // Логируем, но не создаём TestResult (эти тесты отображаются отдельно)
                    Log($"[SYS] {progress.Kind}: {progress.Status} (Success={progress.Success})");
                    return;
                }

                // Поиск TestResult по имени цели
                if (!_testResultMap.TryGetValue(targetName, out var testResult))
                {
                    Log($"[WARN] Target '{targetName}' not found in map (available: {string.Join(", ", _testResultMap.Keys)})");
                    return;
                }

                var oldStatus = testResult.Status;
                
                // Обновление статуса на основе TestProgress
                if (progress.Status.Contains("старт"))
                {
                    testResult.Status = TestStatus.Running;
                    testResult.Details = $"[{DateTime.Now:HH:mm:ss}] Запуск теста {progress.Kind}\n";
                    if (!string.IsNullOrEmpty(progress.Message))
                    {
                        testResult.Details += $"{progress.Message}\n";
                    }
                    Log($"  → 3.N: [{progress.Kind}] {targetName}: {oldStatus} → Running");
                    Log($"      UI должен показать: синяя точка, текст 'Проверяем…'");
                }
                else if (progress.Status.Contains("завершено"))
                {
                    // Инициализируем Details если не установлен
                    if (string.IsNullOrEmpty(testResult.Details))
                    {
                        testResult.Details = $"[{DateTime.Now:HH:mm:ss}] Тест {progress.Kind}\n";
                    }
                    
                    // Добавляем информацию о завершении
                    testResult.Details += $"[{DateTime.Now:HH:mm:ss}] Завершено: {progress.Message ?? "успешно"}\n";
                    
                    if (progress.Success == true)
                    {
                        testResult.Status = TestStatus.Pass;
                        Log($"  ✓ 3.N: [{progress.Kind}] {targetName}: {oldStatus} → Pass");
                        Log($"      UI должен показать: зелёная точка, текст 'Успешно'");
                    }
                    else if (progress.Success == false)
                    {
                        testResult.Status = TestStatus.Fail;
                        testResult.Error = progress.Message ?? "Ошибка";
                        
                        // Определяем FixType на основе типа теста и сообщения
                        var fixInfo = DetermineFixType(progress.Kind, progress.Message);
                        testResult.FixType = fixInfo.fixType;
                        testResult.FixInstructions = fixInfo.instructions;
                        
                        Log($"  ✗ 3.N: [{progress.Kind}] {targetName}: {oldStatus} → Fail (FixType={testResult.FixType})");
                        Log($"      UI должен показать: красная точка, текст '{testResult.Error}'");
                        Log($"      Кнопка 'Исправить': {(testResult.ShowFixButton ? "ВИДИМА" : "скрыта")}");
                    }
                    else
                    {
                        testResult.Status = TestStatus.Warn;
                        testResult.Error = progress.Message ?? "Предупреждение";
                        Log($"  ⚠ 3.N: [{progress.Kind}] {targetName}: {oldStatus} → Warn");
                        Log($"      UI должен показать: жёлтая точка, текст '{testResult.Error}'");
                    }
                    
                    Log($"      СЧЁТЧИКИ: Pass={PassCount}, Fail={FailCount}, Warn={WarnCount}, Completed={CompletedTests}/{TotalTargets}");
                }
                else if (progress.Status.Contains("пропущено"))
                {
                    // НЕ СБРАСЫВАЕМ статус в Idle - оставляем предыдущий результат
                    Log($"  ○ 3.N: [{progress.Kind}] {targetName}: пропущено (статус={oldStatus})");
                }

                // Обновление счетчиков
                OnPropertyChanged(nameof(PassCount));
                OnPropertyChanged(nameof(FailCount));
                OnPropertyChanged(nameof(WarnCount));
                OnPropertyChanged(nameof(CurrentTest));
                OnPropertyChanged(nameof(CompletedTests));
            });
        }

        private string? ExtractTargetName(string status)
        {
            // Формат: "TargetName: действие"
            var colonIndex = status.IndexOf(':');
            if (colonIndex > 0)
            {
                return status.Substring(0, colonIndex).Trim();
            }
            return null;
        }

        private (FixType fixType, string? instructions) DetermineFixType(TestKind kind, string? message)
        {
            if (string.IsNullOrEmpty(message))
                return (FixType.None, null);

            var msgLower = message.ToLowerInvariant();

            // DNS проблемы → DNS fix
            if (kind == TestKind.DNS)
            {
                if (msgLower.Contains("dns_filtered") || msgLower.Contains("dns_bogus") || 
                    msgLower.Contains("заблокирован") || msgLower.Contains("не разрешается"))
                {
                    return (FixType.DnsChange, "Изменить DNS на Cloudflare (1.1.1.1) с поддержкой DoH");
                }
            }

            // Firewall проблемы → Firewall fix
            if (kind == TestKind.FIREWALL)
            {
                if (msgLower.Contains("заблокирован") || msgLower.Contains("blocked") || msgLower.Contains("порт"))
                {
                    return (FixType.FirewallRule, "Добавить правило Windows Firewall для разрешения портов");
                }
            }

            // ISP проблемы → Manual (VPN)
            if (kind == TestKind.ISP)
            {
                if (msgLower.Contains("dpi") || msgLower.Contains("cgnat") || 
                    msgLower.Contains("блокировка") || msgLower.Contains("провайдер"))
                {
                    return (FixType.Manual, "Рекомендуется использовать VPN для обхода блокировок провайдера. DPI и CGNAT требуют изменения сетевой конфигурации на уровне провайдера.");
                }
            }

            // TCP проблемы с портами → Firewall fix
            if (kind == TestKind.TCP)
            {
                if (msgLower.Contains("недоступен") || msgLower.Contains("timeout") || msgLower.Contains("порт"))
                {
                    return (FixType.FirewallRule, "Проверить Windows Firewall и добавить исключения для портов");
                }
            }

            return (FixType.None, null);
        }

        private void InitializeTestResults()
        {
            // Используем цели из TargetCatalog
            var catalogTargets = TargetCatalog.Targets;
            
            var targets = catalogTargets.Select(t => new Target
            {
                Name = t.Name,
                Host = t.Host,
                Service = t.Service ?? "Unknown",
                Critical = false, // TODO: получать из профиля
                FallbackIp = "" // TODO: получать из профиля
            }).ToArray();

            TestResults = new ObservableCollection<TestResult>(
                targets.Select(t => new TestResult { Target = t, Status = TestStatus.Idle })
            );

            // Заполняем map для быстрого поиска по имени
            _testResultMap.Clear();
            foreach (var result in TestResults)
            {
                _testResultMap[result.Target.Name] = result;
            }
        }

        private void UpdateTestStates()
        {
            if (ScreenState == "start")
            {
                foreach (var test in TestResults)
                    test.Status = TestStatus.Idle;
            }
            // Состояния "running" и "done" обновляются через HandleTestProgress
            // Не используем hardcoded индексы

            OnPropertyChanged(nameof(CurrentTest));
            OnPropertyChanged(nameof(CompletedTests));
            OnPropertyChanged(nameof(PassCount));
            OnPropertyChanged(nameof(FailCount));
            OnPropertyChanged(nameof(WarnCount));
            OnPropertyChanged(nameof(RunningStatusText));
        }

        private void ShowDetailsDialog(TestResult? result)
        {
            if (result == null)
            {
                Log("[ShowDetailsDialog] ERROR: result is null");
                return;
            }
            
            Log($"[ShowDetailsDialog] Opening for: {result.Target?.Name ?? "NULL"}");
            Log($"[ShowDetailsDialog] Status: {result.Status}");
            Log($"[ShowDetailsDialog] Details length: {result.Details?.Length ?? 0}");
            
            try
            {
                var detailsWindow = new ISPAudit.Windows.TestDetailsWindow(result)
                {
                    Owner = System.Windows.Application.Current.MainWindow
                };
                Log("[ShowDetailsDialog] Window created, calling ShowDialog()...");
                detailsWindow.ShowDialog();
                Log("[ShowDetailsDialog] Dialog closed");
            }
            catch (Exception ex)
            {
                Log($"[ShowDetailsDialog] EXCEPTION: {ex.Message}");
                Log($"[ShowDetailsDialog] StackTrace: {ex.StackTrace}");
            }
        }

        #region Fix System Methods

        private void LoadFixHistory()
        {
            try
            {
                var fixes = FixHistoryManager.Load();
                ActiveFixes.Clear();
                foreach (var fix in fixes)
                {
                    ActiveFixes.Add(fix);
                }
                OnPropertyChanged(nameof(HasActiveFixes));
                OnPropertyChanged(nameof(ActiveFixesMessage));
                Log($"[FixHistory] Loaded {fixes.Count} active fixes");
            }
            catch (Exception ex)
            {
                Log($"[FixHistory] ERROR loading: {ex.Message}");
            }
        }

        private async Task ApplyFixAsync(TestResult? result)
        {
            if (result == null) return;

            try
            {
                Log($"[ApplyFix] Starting for: {result.Target?.Name}, FixType: {result.FixType}");
                
                AppliedFix? appliedFix = null;
                string error = string.Empty;
                bool success = false;

                switch (result.FixType)
                {
                    case FixType.DnsChange:
                        (success, appliedFix, error) = await FixService.ApplyDnsFixAsync();
                        break;
                    
                    case FixType.FirewallRule:
                        // TODO: Получить порты из TestResult
                        var ports = new[] { 8000, 8001, 8002, 8003 };
                        (success, appliedFix, error) = await FixService.ApplyFirewallFixAsync(ports, "ISP_Audit_Fix");
                        break;
                    
                    case FixType.Manual:
                        // Показать инструкции пользователю
                        System.Windows.MessageBox.Show(
                            result.FixInstructions ?? "Необходимо ручное исправление",
                            "Инструкции по исправлению",
                            System.Windows.MessageBoxButton.OK,
                            System.Windows.MessageBoxImage.Information
                        );
                        return;
                    
                    default:
                        Log($"[ApplyFix] Unknown FixType: {result.FixType}");
                        return;
                }

                if (success && appliedFix != null)
                {
                    ActiveFixes.Add(appliedFix);
                    OnPropertyChanged(nameof(HasActiveFixes));
                    OnPropertyChanged(nameof(ActiveFixesMessage));
                    Log($"[ApplyFix] SUCCESS: {appliedFix.Description}");
                    
                    System.Windows.MessageBox.Show(
                        $"Исправление применено успешно:\n{appliedFix.Description}",
                        "Успех",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information
                    );
                }
                else
                {
                    Log($"[ApplyFix] FAILED: {error}");
                    System.Windows.MessageBox.Show(
                        $"Ошибка применения исправления:\n{error}",
                        "Ошибка",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Error
                    );
                }
            }
            catch (Exception ex)
            {
                Log($"[ApplyFix] EXCEPTION: {ex.Message}");
            }
        }

        private async Task RollbackFixAsync(AppliedFix? fix)
        {
            if (fix == null) return;

            try
            {
                Log($"[RollbackFix] Starting for: {fix.Description}");
                
                bool success = false;
                string error = string.Empty;

                switch (fix.Type)
                {
                    case FixType.DnsChange:
                        (success, error) = await FixService.RollbackDnsFixAsync(fix);
                        break;
                    
                    case FixType.FirewallRule:
                        (success, error) = await FixService.RollbackFirewallFixAsync(fix);
                        break;
                    
                    default:
                        Log($"[RollbackFix] Unknown FixType: {fix.Type}");
                        return;
                }

                if (success)
                {
                    ActiveFixes.Remove(fix);
                    OnPropertyChanged(nameof(HasActiveFixes));
                    OnPropertyChanged(nameof(ActiveFixesMessage));
                    Log($"[RollbackFix] SUCCESS: {fix.Description}");
                }
                else
                {
                    Log($"[RollbackFix] FAILED: {error}");
                    System.Windows.MessageBox.Show(
                        $"Ошибка отката исправления:\n{error}",
                        "Ошибка",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Error
                    );
                }
            }
            catch (Exception ex)
            {
                Log($"[RollbackFix] EXCEPTION: {ex.Message}");
            }
        }

        private async Task RollbackAllFixesAsync()
        {
            try
            {
                Log($"[RollbackAll] Starting for {ActiveFixes.Count} fixes");
                
                var fixesToRollback = ActiveFixes.ToList();
                foreach (var fix in fixesToRollback)
                {
                    await RollbackFixAsync(fix);
                }
                
                Log($"[RollbackAll] Completed");
            }
            catch (Exception ex)
            {
                Log($"[RollbackAll] EXCEPTION: {ex.Message}");
            }
        }

        #endregion

        #region Exe Scenario - Stage Methods

        /// <summary>
        /// Открыть диалог выбора .exe файла
        /// </summary>
        private void BrowseExe()
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*",
                Title = "Выберите exe файл приложения"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                ExePath = openFileDialog.FileName;
                Log($"[BrowseExe] Selected: {ExePath}");
            }
        }

        /// <summary>
        /// Показать окно с результатами Stage 1 (захваченные цели)
        /// </summary>
        private void ViewStage1Results()
        {
            if (_capturedProfile == null)
            {
                Log("[ViewStage1Results] No captured profile available");
                return;
            }

            Log($"[ViewStage1Results] Opening window with {_capturedProfile.Targets.Count} targets");
            
            var window = new IspAudit.Windows.CapturedTargetsWindow(_capturedProfile)
            {
                Owner = System.Windows.Application.Current.MainWindow
            };
            window.ShowDialog();
        }

        /// <summary>
        /// Сбросить состояние Exe-сценария и начать заново
        /// </summary>
        private void ResetExeScenario()
        {
            Log("[ResetExeScenario] Сброс состояния Exe-сценария...");
            
            // Сбросить captured data
            _capturedProfile = null;
            _detectedProblems = null;
            _plannedBypass = null;
            
            // Сбросить флаги
            Stage1Complete = false;
            Stage2Complete = false;
            Stage3Complete = false;
            
            // Сбросить счётчики
            Stage1HostsFound = 0;
            Stage2ProblemsFound = 0;
            
            // Сбросить статусы
            Stage1Status = "";
            Stage2Status = "";
            Stage3Status = "";
            
            // Сбросить прогресс
            Stage1Progress = 0;
            Stage2Progress = 0;
            Stage3Progress = 0;
            
            // Очистить TestResults
            TestResults.Clear();
            
            // НЕ сбрасываем ExePath - пользователь может захотеть оставить его
            // ExePath = "";
            
            // Переоценить команды
            CommandManager.InvalidateRequerySuggested();
            
            Log("[ResetExeScenario] Сброс завершён. Готов к новому анализу.");
        }

        /// <summary>
        /// Stage 1: Анализ трафика процесса
        /// </summary>
        private async Task RunStage1AnalyzeTrafficAsync()
        {
            // Защита от race condition
            if (_isExeScenarioRunning) return;
            
            try
            {
                Log("[Stage1] Starting traffic analysis...");
                Stage1Status = "Проверка прав администратора...";
                Stage1Complete = false;
                Stage1HostsFound = 0;
                Stage1Progress = 0;

                // WinDivert SOCKET layer требует прав администратора
                if (!IsAdministrator())
                {
                    Stage1Status = "Ошибка: требуются права администратора";
                    Log("[Stage1] FAILED: Administrator rights required for WinDivert");
                    
                    System.Windows.MessageBox.Show(
                        "Для захвата трафика требуются права администратора.\n\n" +
                        "Запустите ISP_Audit от имени администратора.",
                        "Требуются права администратора",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Warning
                    );
                    return;
                }
                
                // Устанавливаем флаг блокировки ПОСЛЕ проверки admin прав
                _isExeScenarioRunning = true;
                OnPropertyChanged(nameof(IsRunning));
                CommandManager.InvalidateRequerySuggested();

                Stage1Status = "Запуск процесса...";

                // Запускаем процесс (если exe путь указан)
                System.Diagnostics.Process? process = null;
                
                if (!string.IsNullOrEmpty(ExePath) && File.Exists(ExePath))
                {
                    var startInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = ExePath,
                        UseShellExecute = true,
                        WorkingDirectory = Path.GetDirectoryName(ExePath)
                    };

                    process = System.Diagnostics.Process.Start(startInfo);
                    if (process == null)
                    {
                        Stage1Status = "Ошибка: не удалось запустить процесс";
                        Log("[Stage1] Process.Start() returned null");
                        return;
                    }

                    var pid = process.Id;
                    Log($"[Stage1] Process started: EXE={Path.GetFileName(ExePath)}, PID={pid}");

                    // Сразу запускаем захват, чтобы не пропустить handshake
                    Stage1Status = $"Процесс запущен (PID={pid}), старт захвата...";
                    Log($"[Stage1] Starting capture immediately...");
                    
                    // Анализируем трафик 30 секунд
                    var progress = new Progress<string>(msg =>
                    {
                        Stage1Status = msg;
                        Log($"[Stage1] {msg}");
                    });

                    _capturedProfile = await TrafficAnalyzer.AnalyzeProcessTrafficAsync(
                        pid,
                        TimeSpan.FromSeconds(30),
                        progress,
                        CancellationToken.None
                    ).ConfigureAwait(false);

                    Stage1HostsFound = _capturedProfile?.Targets?.Count ?? 0;
                    Stage1Complete = true;
                    Stage1Progress = 100;

                    if (Stage1HostsFound == 0)
                    {
                        Stage1Status = "Захват завершен: соединения не обнаружены";
                        Log("[Stage1] WARNING: No network connections captured. Process may not have established connections or already exited.");
                        
                        // Показываем MessageBox с диагностикой
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                        {
                            System.Windows.MessageBox.Show(
                                "Не удалось захватить сетевые соединения.\n\n" +
                                "Возможные причины:\n" +
                                "• Приложение не устанавливало соединения за 30 секунд\n" +
                                "• Соединения были слишком кратковременными\n" +
                                "• Файрволл блокирует приложение\n\n" +
                                "Проверьте Output окно для деталей.",
                                "Stage 1: Соединения не обнаружены",
                                System.Windows.MessageBoxButton.OK,
                                System.Windows.MessageBoxImage.Warning
                            );
                        });
                    }
                    else
                    {
                        Stage1Status = $"✓ Завершено: обнаружено {Stage1HostsFound} целей";
                        Log($"[Stage1] SUCCESS: {Stage1HostsFound} unique hosts captured");
                        
                        // Логируем список захваченных целей
                        if (_capturedProfile?.Targets != null)
                        {
                            Log($"[Stage1] Captured targets:");
                            foreach (var target in _capturedProfile.Targets.Take(10))
                            {
                                Log($"[Stage1]   → {target.Host} ({target.Service})");
                            }
                            if (_capturedProfile.Targets.Count > 10)
                                Log($"[Stage1]   ... и еще {_capturedProfile.Targets.Count - 10} целей");
                        }

                        // Сохраняем профиль в файл
                        var exeName = Path.GetFileNameWithoutExtension(ExePath);
                        var profilePath = Path.Combine("Profiles", $"{exeName}_captured.json");
                        
                        try
                        {
                            Directory.CreateDirectory("Profiles");
                            var json = System.Text.Json.JsonSerializer.Serialize(_capturedProfile, new System.Text.Json.JsonSerializerOptions 
                            { 
                                WriteIndented = true 
                            });
                            await File.WriteAllTextAsync(profilePath, json);
                            Log($"[Stage1] Profile saved to: {profilePath}");
                            
                            // Автоматически запускаем Stage 2 если есть захваченные цели
                            if (Stage1HostsFound > 0)
                            {
                                Log($"[Stage1] Автоматический переход к Stage 2...");
                                _ = RunStage2DiagnoseAsync();
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"[Stage1] Failed to save profile: {ex.Message}");
                        }
                    }

                    // Закрываем процесс
                    if (!process.HasExited)
                    {
                        process.Kill();
                    }
                }
                else
                {
                    Stage1Status = "Ошибка: файл exe не найден";
                }
            }
            catch (Exception ex)
            {
                Log($"[Stage1] EXCEPTION: {ex.Message}");
                Stage1Status = $"Ошибка: {ex.Message}";
            }
            finally
            {
                // Гарантированный сброс флага даже при исключениях
                _isExeScenarioRunning = false;
                OnPropertyChanged(nameof(IsRunning));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        /// <summary>
        /// Stage 2: Диагностика проблем
        /// </summary>
        private async Task RunStage2DiagnoseAsync()
        {
            // Защита от race condition
            if (_isExeScenarioRunning) return;
            
            try
            {
                Log("[Stage2] Starting diagnostics...");
                Stage2Status = "Запуск тестов...";
                Stage2Complete = false;
                Stage2ProblemsFound = 0;
                Stage2Progress = 0;

                if (_capturedProfile == null)
                {
                    Stage2Status = "Ошибка: профиль не захвачен (выполните Stage 1 сначала)";
                    Log("[Stage2] ERROR: _capturedProfile is null");
                    
                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        System.Windows.MessageBox.Show(
                            "Профиль не захвачен.\n\n" +
                            "Выполните Stage 1 (Анализ трафика) сначала.",
                            "Stage 2: Ошибка",
                            System.Windows.MessageBoxButton.OK,
                            System.Windows.MessageBoxImage.Warning
                        );
                    });
                    return;
                }
                
                // Устанавливаем флаг блокировки ПОСЛЕ всех проверок
                _isExeScenarioRunning = true;
                OnPropertyChanged(nameof(IsRunning));
                CommandManager.InvalidateRequerySuggested();

                Log($"[Stage2] Using captured profile with {_capturedProfile.Targets.Count} targets");
                
                // Инициализируем TestResults из захваченного профиля
                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    TestResults.Clear();
                    foreach (var target in _capturedProfile.Targets)
                    {
                        TestResults.Add(new TestResult
                        {
                            Target = new Target 
                            { 
                                Name = target.Service,
                                Host = target.Host,
                                Service = target.Service,
                                Critical = target.Critical,
                                FallbackIp = target.FallbackIp ?? ""
                            },
                            Status = TestStatus.Idle
                        });
                    }
                });

                // Создаем Config из захваченного профиля
                _config = new Config
                {
                    Targets = _capturedProfile.Targets.Select(t => t.Host).ToList(),
                    HttpTimeoutSeconds = 6,
                    TcpTimeoutSeconds = 5,
                    UdpTimeoutSeconds = 2
                };

                _cts = new CancellationTokenSource();
                var progress = new Progress<TestProgress>(p =>
                {
                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        HandleTestProgress(p); // существующий код
                        
                        // Добавить подсчёт прогресса для Exe-scenario
                        if (_capturedProfile != null)
                        {
                            var totalTargets = _capturedProfile.Targets.Count;
                            var completedTargets = TestResults.Count(r => r.Status != TestStatus.Running && r.Status != TestStatus.Idle);
                            Stage2Progress = totalTargets > 0 ? (completedTargets * 100 / totalTargets) : 0;
                        }
                    });
                });

                Stage2Status = "Запуск тестов диагностики...";
                Log("[Stage2] Running audit with captured targets...");

                // Запускаем тесты
                try
                {
                    var report = await AuditRunner.RunAsync(_config, progress, _cts.Token).ConfigureAwait(false);
                    Log($"[Stage2] Audit completed. Analyzing results...");
                }
                catch (OperationCanceledException)
                {
                    Log("[Stage2] Audit cancelled");
                    Stage2Status = "Диагностика отменена";
                    return;
                }

                Stage2Status = "Анализ результатов...";

                // Классифицируем проблемы
                var testResults = await System.Windows.Application.Current.Dispatcher.InvokeAsync(() => TestResults.ToList());
                _detectedProblems = ProblemClassifier.ClassifyProblems(testResults);

                Stage2ProblemsFound = _detectedProblems.Count;

                if (_detectedProblems.Any())
                {
                    // Генерируем стратегию обхода
                    var planningProgress = new Progress<string>(msg =>
                    {
                        Stage2Status = msg;
                        Log($"[Stage2] {msg}");
                    });

                    _plannedBypass = BypassStrategyPlanner.PlanBypassStrategy(
                        _detectedProblems,
                        _capturedProfile,
                        planningProgress
                    );

                    Stage2Complete = true;
                    Stage2Progress = 100;
                    Stage2Status = $"✓ Обнаружено проблем: {Stage2ProblemsFound}";
                    Log($"[Stage2] SUCCESS: {Stage2ProblemsFound} problems detected");
                    
                    // Автоматически запускаем Stage 3 если есть проблемы
                    if (_detectedProblems != null && _detectedProblems.Any())
                    {
                        Log($"[Stage2] Автоматический переход к Stage 3...");
                        _ = RunStage3ApplyBypassAsync();
                    }
                }
                else
                {
                    Stage2Status = "✓ Проблем не обнаружено - все тесты успешны";
                    Stage2Complete = true;
                    Stage2Progress = 100;
                    Log("[Stage2] No problems detected");
                    
                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        System.Windows.MessageBox.Show(
                            "Диагностика завершена успешно!\n\n" +
                            "Проблем с подключением не обнаружено.\n" +
                            "Применение обхода не требуется.",
                            "Stage 2: Завершено",
                            System.Windows.MessageBoxButton.OK,
                            System.Windows.MessageBoxImage.Information
                        );
                    });
                }
            }
            catch (Exception ex)
            {
                Log($"[Stage2] EXCEPTION: {ex.Message}");
                Stage2Status = $"Ошибка: {ex.Message}";
            }
            finally
            {
                // Гарантированный сброс флага даже при исключениях
                _isExeScenarioRunning = false;
                OnPropertyChanged(nameof(IsRunning));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        /// <summary>
        /// Stage 3: Применение обхода
        /// </summary>
        private async Task RunStage3ApplyBypassAsync()
        {
            // Защита от race condition
            if (_isExeScenarioRunning) return;
            
            try
            {
                Log("[Stage3] Starting bypass application...");
                Stage3Status = "Применение исправлений...";
                Stage3Complete = false;
                Stage3Progress = 0;

                if (_detectedProblems == null || _plannedBypass == null)
                {
                    Stage3Status = "Ошибка: нет данных для применения";
                    return;
                }
                
                // Устанавливаем флаг блокировки ПОСЛЕ всех проверок
                _isExeScenarioRunning = true;
                OnPropertyChanged(nameof(IsRunning));
                CommandManager.InvalidateRequerySuggested();

                // Определяем, что нужно применить
                bool needsDns = BypassStrategyPlanner.RequiresDnsChange(_detectedProblems);
                bool needsWinDivert = BypassStrategyPlanner.CanBypassWithWinDivert(_detectedProblems);

                var progress = new Progress<string>(msg =>
                {
                    Stage3Status = msg;
                    Log($"[Stage3] {msg}");
                    
                    // Парсинг сообщений для определения прогресса DNS fix
                    if (needsDns)
                    {
                        // Если DNS + WinDivert: DNS = 0-70%, WinDivert = 70-100%
                        // Если только DNS: DNS = 0-100%
                        int dnsMaxProgress = needsWinDivert ? 70 : 100;
                        
                        if (msg.Contains("Тестирование") || msg.Contains("1.1.1.1"))
                        {
                            Stage3Progress = dnsMaxProgress * 20 / 100;
                        }
                        else if (msg.Contains("8.8.8.8"))
                        {
                            Stage3Progress = dnsMaxProgress * 40 / 100;
                        }
                        else if (msg.Contains("9.9.9.9"))
                        {
                            Stage3Progress = dnsMaxProgress * 60 / 100;
                        }
                        else if (msg.Contains("успешно применен"))
                        {
                            Stage3Progress = dnsMaxProgress;
                        }
                    }
                });

                // Проверяем, нужна ли смена DNS
                if (needsDns)
                {
                    Stage3Progress = 10;
                    Stage3Status = "Применение DNS исправления...";
                    var dnsResult = await DnsFixApplicator.ApplyDnsFixAsync(progress, CancellationToken.None).ConfigureAwait(false);

                    if (!dnsResult.Success)
                    {
                        if (dnsResult.RequiresElevation)
                        {
                            Stage3Status = "Ошибка: требуются права администратора";
                        }
                        else if (dnsResult.RequiresVpn)
                        {
                            Stage3Status = "Ошибка: все DoH провайдеры заблокированы, требуется VPN";
                        }
                        else
                        {
                            Stage3Status = $"Ошибка DNS: {dnsResult.Error}";
                        }
                        Log($"[Stage3] DNS Fix FAILED: {dnsResult.Error}");
                        return;
                    }

                    Log($"[Stage3] DNS Fix SUCCESS: {dnsResult.AppliedProvider}");
                    Stage3Progress = needsWinDivert ? 70 : 100;
                }

                // Применяем WinDivert bypass (если нужен)
                if (needsWinDivert)
                {
                    // Если только WinDivert (без DNS) → устанавливаем 50%
                    if (!needsDns)
                    {
                        Stage3Progress = 50;
                    }
                    else
                    {
                        Stage3Progress = 80;
                    }
                    
                    Stage3Status = "Применение WinDivert bypass...";
                    
                    // Сохраняем профиль в bypass_profile.json
                    var profileJson = System.Text.Json.JsonSerializer.Serialize(_plannedBypass, new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
                    
                    File.WriteAllText("bypass_profile.json", profileJson);
                    Log("[Stage3] Bypass profile saved to bypass_profile.json");
                    
                    Stage3Status = "WinDivert bypass настроен (требуется ручной запуск)";
                }

                // Проверяем, нужен ли VPN
                if (BypassStrategyPlanner.RequiresVpn(_detectedProblems))
                {
                    Stage3Status += "\n⚠️ Для полного обхода требуется VPN";
                    Log("[Stage3] VPN required for complete bypass");
                }

                Stage3Progress = 100;
                Stage3Complete = true;
                Stage3Status = "Обход настроен успешно";
                Log("[Stage3] SUCCESS: Bypass applied");
            }
            catch (Exception ex)
            {
                Log($"[Stage3] EXCEPTION: {ex.Message}");
                Stage3Status = $"Ошибка: {ex.Message}";
            }
            finally
            {
                // Гарантированный сброс флага даже при исключениях
                _isExeScenarioRunning = false;
                OnPropertyChanged(nameof(IsRunning));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Проверяет, запущено ли приложение с правами администратора
        /// </summary>
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

        #endregion


        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class RelayCommand : ICommand
    {
        private readonly System.Action<object> _execute;
        private readonly System.Func<object, bool> _canExecute;

        public RelayCommand(System.Action<object> execute, System.Func<object, bool> canExecute = null)
        {
            _execute = execute;
            _canExecute = canExecute;
        }

        public bool CanExecute(object parameter) => _canExecute?.Invoke(parameter) ?? true;
        public void Execute(object parameter) => _execute(parameter);
        public event System.EventHandler CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }
    }
}
