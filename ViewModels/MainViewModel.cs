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
using System.Runtime.Versioning;

namespace ISPAudit.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private static readonly string LogsDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
        private static readonly string LogFilePath = InitializeLogFilePath();

        private static string InitializeLogFilePath()
        {
            try
            {
                Directory.CreateDirectory(LogsDirectory);

                // Удаляем старые логи, если их больше 10
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
                // Фолбэк: пишем рядом с exe без ротации, если что-то пошло не так
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
        
        private string _screenState = "start";
        private CancellationTokenSource? _cts;
        private WinDivertBypassManager? _bypassManager;

        private Dictionary<string, TestResult> _testResultMap = new();
        private string _exePath = "";
        private string _currentAction = "";

        public ObservableCollection<TestResult> TestResults { get; set; } = new();

        public string CurrentAction
        {
            get => _currentAction;
            set
            {
                _currentAction = value;
                OnPropertyChanged(nameof(CurrentAction));
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
                    Log($"  ✓ Заголовок: 'Диагностика завершена'");
                    Log($"  ✓ Summary блок с счётчиками:");
                    Log($"      Успешно: {PassCount} (зелёный)");
                    Log($"      Ошибки: {FailCount} (красный)");
                    Log($"      Предупреждения: {WarnCount} (жёлтый)");
                    Log($"  ✓ Карточки тестов: ВИДИМЫ в ScrollViewer ({TestResults.Count} шт)");
                    Log($"  ✓ Кнопки: 'Экспорт отчета' и 'Новая диагностика'");
                    Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                }
                
                UpdateTestStates();
            }
        }

        public bool IsStart => ScreenState == "start";
        public bool IsRunning => ScreenState == "running" || IsDiagnosticRunning;
        public bool IsDone => ScreenState == "done";
        public bool ShowSummary => IsDone;
        public bool ShowReport => IsDone;

        public string ExePath
        {
            get => _exePath;
            set
            {
                _exePath = value;
                OnPropertyChanged(nameof(ExePath));
            }
        }



        public int TotalTargets => TestResults?.Count ?? 0;
        public int ProgressBarMax => TotalTargets == 0 ? 1 : TotalTargets;
        public int CurrentTest => TestResults?.Count(t => t.Status == TestStatus.Running || t.Status == TestStatus.Pass || t.Status == TestStatus.Fail || t.Status == TestStatus.Warn) ?? 0;
        public int CompletedTests => TestResults?.Count(t => t.Status == TestStatus.Pass || t.Status == TestStatus.Fail || t.Status == TestStatus.Warn) ?? 0;
        public int PassCount => TestResults?.Count(t => t.Status == TestStatus.Pass) ?? 0;
        public int FailCount => TestResults?.Count(t => t.Status == TestStatus.Fail) ?? 0;
        public int WarnCount => TestResults?.Count(t => t.Status == TestStatus.Warn) ?? 0;

        public string RunningStatusText => $"Диагностика: {CurrentTest} из {TotalTargets}";
        public string StartButtonText => IsRunning ? "Остановить диагностику" : "Начать диагностику";

        // Fix System Properties
        public ObservableCollection<AppliedFix> ActiveFixes { get; set; } = new();
        public bool HasActiveFixes => ActiveFixes.Count > 0;
        public string ActiveFixesMessage => $"Активны исправления системы ({ActiveFixes.Count})";

        public ICommand StartCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand SetStateCommand { get; }

        public ICommand ReportCommand { get; }
        public ICommand DetailsCommand { get; }
        public ICommand FixCommand { get; }
        public ICommand RollbackFixCommand { get; }
        public ICommand RollbackAllCommand { get; }
        
        // Exe Scenario Properties
        private bool _isDiagnosticRunning = false;
        private string _diagnosticStatus = "";


        public bool IsDiagnosticRunning
        {
            get => _isDiagnosticRunning;
            set
            {
                _isDiagnosticRunning = value;
                OnPropertyChanged(nameof(IsDiagnosticRunning));
                OnPropertyChanged(nameof(IsRunning)); // Update IsRunning too as it aggregates states
            }
        }

        public string DiagnosticStatus
        {
            get => _diagnosticStatus;
            set
            {
                _diagnosticStatus = value;
                OnPropertyChanged(nameof(DiagnosticStatus));
            }
        }
        private bool _enableLiveTesting = true; // Live testing enabled by default
        private bool _enableAutoBypass = false; // Auto-bypass disabled by default (C2 requirement)
        
        // Monitoring Services (D1 refactoring)
        private FlowMonitorService? _flowMonitor;
        private NetworkMonitorService? _networkMonitor;
        private DnsParserService? _dnsParser;
        private PidTrackerService? _pidTracker;

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





        public ICommand BrowseExeCommand { get; }

        public ICommand StartLiveTestingCommand { get; }

        public MainViewModel()
        {
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log("ШАГ 1: НАЧАЛЬНОЕ СОСТОЯНИЕ (Constructor)");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            


            InitializeTestResults();
            Log($"✓ TestResults инициализирована (Count={TestResults?.Count ?? 0})");
            Log($"✓ ScreenState = '{ScreenState}' (ожидается 'start')");
            Log($"✓ IsStart = {IsStart} (ожидается true)");
            Log($"✓ IsRunning = {IsRunning} (ожидается false)");

            StartLiveTestingCommand = new RelayCommand(async _ => 
            {
                Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log("ШАГ 2: НАЖАТИЕ 'НАЧАТЬ ДИАГНОСТИКУ' (Unified)");
                Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log($"IsRunning={IsRunning}, ScreenState={ScreenState}");
                
                if (IsRunning)
                {
                    Log("→ Диагностика уже запущена. Вызов CancelAudit()");
                    CancelAudit();
                }
                else
                {
                    Log("→ Exe сценарий: запуск Live Pipeline");
                    await RunLivePipelineAsync();
                }
            }, _ => true); // Always enabled to allow cancellation

            StartCommand = StartLiveTestingCommand; // Alias for backward compatibility if needed

            CancelCommand = new RelayCommand(_ => CancelAudit(), _ => IsRunning && _cts != null);
            SetStateCommand = new RelayCommand(state => 
            {
                ScreenState = state?.ToString() ?? string.Empty;
                // Обновляем CanExecute для команд
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            });

            ReportCommand = new RelayCommand(_ => GenerateReport(), _ => IsDone);
            DetailsCommand = new RelayCommand(param => ShowDetailsDialog(param as TestResult), _ => true);
            
            // Fix Commands
            FixCommand = new RelayCommand(async param => await ApplyFixAsync(param as TestResult), _ => true);
            RollbackFixCommand = new RelayCommand(async param => await RollbackFixAsync(param as AppliedFix), _ => true);
            RollbackAllCommand = new RelayCommand(async _ => await RollbackAllFixesAsync(), _ => HasActiveFixes);

            // Exe Scenario Commands
            BrowseExeCommand = new RelayCommand(_ => BrowseExe(), _ => !IsRunning);
            
            // Load Fix History on startup
            LoadFixHistory();
            
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log("ШАГ 1: ЗАВЕРШЁН. UI должен показывать:");
            Log("  ✓ Центральный текст: 'Готов к диагностике'");
            Log("  ✓ Кнопка: 'Начать диагностику' (активна)");
            Log("  ✓ Выбор сценария: активен");
            Log("  ✓ Карточки тестов: НЕ ВИДИМЫ (TestResults.Count=0)");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
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
                        FixApplied = t.FixType != FixType.None
                    }).ToList(),
                    ActiveFixes = ActiveFixes.Select(f => new 
                    {
                        Type = f.Type.ToString(),
                        Description = f.Description,
                        AppliedAt = f.AppliedAt
                    }).ToList()
                };

                var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                var filename = $"isp_audit_report_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filename);
                
                File.WriteAllText(path, json);
                
                Log($"[Report] Saved to {path}");
                
                // Open folder with report
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
            }
            catch (Exception ex)
            {
                Log($"[Report] Error generating report: {ex.Message}");
                System.Windows.MessageBox.Show($"Ошибка создания отчета: {ex.Message}", "Ошибка", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
        }

        private void CancelAudit()
        {
            if (_cts == null || _cts.IsCancellationRequested)
            {
                Log("[CancelAudit] Токен отмены уже активирован или отсутствует");
                return;
            }
            
            Log("[CancelAudit] Отправка сигнала отмены...");
            _cts?.Cancel();
            
            // Немедленное обновление UI после отмены
            System.Windows.Application.Current?.Dispatcher.Invoke(() =>
            {
                IsDiagnosticRunning = false; // Сразу сбрасываем флаг
                ScreenState = "start"; // Возвращаем в начальное состояние
                DiagnosticStatus = "Диагностика отменена";
                Log("[UI] CancelAudit: UI обновлен, ScreenState='start', IsDiagnosticRunning=false");
                CommandManager.InvalidateRequerySuggested();
            });
        }





        private void HandleTestProgress(TestProgress progress)
        {
            // Диспетчеризация в UI поток
            System.Windows.Application.Current?.Dispatcher.Invoke(() =>
            {
                CurrentAction = progress.Status;
                
                // Парсинг имени цели из Status (формат: "TargetName: действие")
                var targetName = ExtractTargetName(progress.Status);
                
                TestResult? testResult = null;
                
                // Для диагностических тестов используем Kind как ключ
                if (string.IsNullOrEmpty(targetName))
                {
                    // Системный тест (Software, Firewall, Router, ISP)
                    var diagnosticKey = progress.Kind.ToString();
                    
                    if (_testResultMap.TryGetValue(diagnosticKey, out var diagResult))
                    {
                        targetName = diagnosticKey;
                        testResult = diagResult;
                    }
                    else
                    {
                        return; // Игнорируем неизвестные тесты
                    }
                }
                else
                {
                    // Поиск TestResult по имени цели
                    if (!_testResultMap.TryGetValue(targetName, out testResult))
                    {
                        Log($"[WARN] Target '{targetName}' not found");
                        return;
                    }
                }
                
                if (testResult == null)
                    return;

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
                    }
                    else if (progress.Success == false)
                    {
                        testResult.Status = TestStatus.Fail;
                        testResult.Error = progress.Message ?? "Ошибка";
                        
                        // Определяем FixType на основе типа теста и сообщения
                        var fixInfo = DetermineFixType(progress.Kind, progress.Message);
                        testResult.FixType = fixInfo.fixType;
                        testResult.FixInstructions = fixInfo.instructions;
                        
                        Log($"[✗] {targetName} [{progress.Kind}]: {testResult.Error}");
                    }
                    else
                    {
                        testResult.Status = TestStatus.Warn;
                        testResult.Error = progress.Message ?? "Предупреждение";
                        Log($"[⚠] {targetName} [{progress.Kind}]: {testResult.Error}");
                    }
                }
                else if (progress.Status.Contains("пропущено"))
                {
                    // НЕ СБРАСЫВАЕМ статус в Idle - оставляем предыдущий результат
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
                return;
            }
            
            try
            {
                var detailsWindow = new ISPAudit.Windows.TestDetailsWindow(result)
                {
                    Owner = System.Windows.Application.Current.MainWindow
                };
                detailsWindow.ShowDialog();
            }
            catch (Exception ex)
            {
                Log($"[ShowDetailsDialog] EXCEPTION: {ex.Message}");
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

                    case FixType.Bypass:
                        if (_bypassManager == null) _bypassManager = new WinDivertBypassManager();
                        
                        var strategy = result.BypassStrategy ?? "UNKNOWN";
                        // Маппинг стратегий
                        if (strategy == "TCP_RST_DROP") strategy = "DROP_RST";
                        
                        // Получаем IP цели
                        System.Net.IPAddress? targetIp = null;
                        if (result.Target != null)
                        {
                            try {
                                var addresses = System.Net.Dns.GetHostAddresses(result.Target.Host);
                                targetIp = addresses.FirstOrDefault();
                            } catch {}
                        }

                        await _bypassManager.ApplyBypassStrategyAsync(strategy, targetIp);
                        
                        appliedFix = new AppliedFix 
                        { 
                            Type = FixType.Bypass, 
                            Description = $"WinDivert Bypass: {strategy} for {result.Target?.Host ?? "Unknown"}",
                            OriginalSettings = new Dictionary<string, string> { { "Strategy", strategy } }
                        };
                        success = true;
                        break;
                    
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
                    
                    // Обновляем UI результата
                    result.Status = TestStatus.Warn; 
                    result.Details += $"\n[Fix] Исправление применено: {appliedFix.Description}";
                    
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

                    case FixType.Bypass:
                        if (_bypassManager != null)
                        {
                            await _bypassManager.DisableAsync();
                            success = true;
                        }
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

        private async Task RunLivePipelineAsync()
        {
            try
            {
                Log("→ RunLivePipelineAsync()");
                
                if (!OperatingSystem.IsWindows() || !IsAdministrator())
                {
                    System.Windows.MessageBox.Show(
                        "Для захвата трафика требуются права администратора.\n\n" +
                        "Запустите приложение от имени администратора.", 
                        "Требуются права администратора", 
                        System.Windows.MessageBoxButton.OK, 
                        System.Windows.MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(ExePath) || !File.Exists(ExePath))
                {
                    System.Windows.MessageBox.Show("Файл не найден.", "Ошибка", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                    return;
                }

                // Обновление состояния UI
                ScreenState = "running";
                IsDiagnosticRunning = true;
                DiagnosticStatus = "Запуск приложения...";
                TestResults.Clear();
                OnPropertyChanged(nameof(CompletedTests)); // Важно: сначала обновляем Value (0), чтобы не превысить старый Maximum
                OnPropertyChanged(nameof(TotalTargets));   // Затем обновляем Maximum (0)
                OnPropertyChanged(nameof(ProgressBarMax));
                
                // Настройка отмены
                _cts = new CancellationTokenSource();
                
                // Шаг 1: Запуск мониторинговых сервисов (D1)
                Log("[Services] Starting monitoring services...");
                var progress = new Progress<string>(msg => 
                {
                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        DiagnosticStatus = msg;
                        Log($"[Pipeline] {msg}");
                        ParsePipelineMessage(msg);
                    });
                });
                
                // 1.1 Flow Monitor
                _flowMonitor = new FlowMonitorService(progress);
                await _flowMonitor.StartAsync(_cts.Token).ConfigureAwait(false);
                
                // 1.2 Network Monitor (для DNS)
                _networkMonitor = new NetworkMonitorService("udp.DstPort == 53 or udp.SrcPort == 53", progress);
                await _networkMonitor.StartAsync(_cts.Token).ConfigureAwait(false);
                
                // 1.3 DNS Parser (подписывается на Network Monitor)
                _dnsParser = new DnsParserService(_networkMonitor, progress);
                await _dnsParser.StartAsync().ConfigureAwait(false);
                
                // Шаг 2: Warmup через TestNetworkApp (его трафик попадет в сервисы)
                try
                {
                    Log("[Warmup] Starting TestNetworkApp for Flow warmup...");
                    await WarmupFlowWithTestNetworkAppAsync(_cts.Token).ConfigureAwait(false);
                }
                catch (Exception warmupEx)
                {
                    Log($"[Warmup] Error (non-critical): {warmupEx.Message}");
                }
                
                // Шаг 3: Запуск целевого процесса
                DiagnosticStatus = "Запуск целевого приложения...";
                Log($"[Pipeline] Starting process: {ExePath}");
                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = ExePath,
                        UseShellExecute = true
                    }
                };
                
                if (!process.Start())
                {
                    throw new Exception("Не удалось запустить процесс");
                }
                
                var pid = process.Id;
                Log($"[Pipeline] Process started: PID={pid}");
                
                // Шаг 4: Запуск PID Tracker (отслеживание новых процессов)
                _pidTracker = new PidTrackerService(pid, progress);
                await _pidTracker.StartAsync(_cts.Token).ConfigureAwait(false);
                
                // Запускаем фоновое разрешение имен целей
                _ = PreResolveTargetsAsync();
                
                DiagnosticStatus = "Анализ трафика...";

                // Инициализация BypassManager (C3)
                if (_bypassManager == null)
                {
                    _bypassManager = new WinDivertBypassManager();
                }

                // Запуск анализатора с Live Testing (НОВАЯ ВЕРСИЯ — использует сервисы)
                // Блокирует до завершения захвата (таймаут или отмена)
                var profile = await TrafficAnalyzer.AnalyzeProcessTrafficAsync(
                    pid,
                    TimeSpan.FromMinutes(10), // Long timeout for live testing session
                    _flowMonitor!,   // Используем уже работающий Flow monitor
                    _pidTracker!,    // Используем уже работающий PID tracker
                    _dnsParser!,     // Используем уже работающий DNS parser
                    progress,
                    _cts.Token,
                    enableLiveTesting: true,
                    enableAutoBypass: EnableAutoBypass,
                    bypassManager: _bypassManager
                );
                
                Log($"[Pipeline] Finished. Captured {profile?.Targets?.Count ?? 0} targets.");
                
                ScreenState = "done";
            }
            catch (OperationCanceledException)
            {
                Log("[Pipeline] Cancelled by user");
                ScreenState = "done";
            }
            catch (Exception ex)
            {
                Log($"[Pipeline] Error: {ex.Message}");
                System.Windows.MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка Pipeline", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                ScreenState = "done";
            }
            finally
            {
                // Остановка мониторинговых сервисов (D1)
                try
                {
                    Log("[Services] Stopping monitoring services...");
                    if (_pidTracker != null) await _pidTracker.StopAsync().ConfigureAwait(false);
                    if (_dnsParser != null) await _dnsParser.StopAsync().ConfigureAwait(false);
                    if (_networkMonitor != null) await _networkMonitor.StopAsync().ConfigureAwait(false);
                    if (_flowMonitor != null) await _flowMonitor.StopAsync().ConfigureAwait(false);
                    
                    _pidTracker?.Dispose();
                    _dnsParser?.Dispose();
                    _networkMonitor?.Dispose();
                    _flowMonitor?.Dispose();
                    
                    _pidTracker = null;
                    _dnsParser = null;
                    _networkMonitor = null;
                    _flowMonitor = null;
                }
                catch (Exception ex)
                {
                    Log($"[Services] Error stopping services: {ex.Message}");
                }
                
                IsDiagnosticRunning = false;
                _cts?.Dispose();
                _cts = null;
                
                // Обновляем UI
                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    CommandManager.InvalidateRequerySuggested();
                });
            }
        }
        
        #endregion

        #region Helper Methods

        private string? _lastUpdatedHost;

        private System.Collections.Concurrent.ConcurrentDictionary<string, Target> _resolvedIpMap = new();

        private System.Collections.Concurrent.ConcurrentDictionary<string, bool> _pendingResolutions = new();

        /// <summary>
        /// Прогревает Flow-слой через однократный запуск TestNetworkApp до старта основной диагностики.
        /// Используется только в dev/QA сценариях для проверки таймингов Flow (D1).
        /// Ошибки прогрева логируются, но не мешают основному UX.
        /// </summary>
        private async Task WarmupFlowWithTestNetworkAppAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Ищем TestNetworkApp.exe рядом с основным ISP_Audit.exe (однофайловый прогрев)
                var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                var testAppPath = System.IO.Path.Combine(baseDir, "TestNetworkApp.exe");
                if (!File.Exists(testAppPath))
                {
                    Log($"[Warmup] TestNetworkApp not found at '{testAppPath}', skipping warmup");
                    return;
                }

                Log($"[Warmup] Starting TestNetworkApp: {testAppPath}");

                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = testAppPath,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                if (!process.Start())
                {
                    Log("[Warmup] Failed to start TestNetworkApp");
                    return;
                }

                // Ждём завершения или отмены
                try
                {
                    using (cancellationToken.Register(() =>
                    {
                        try { if (!process.HasExited) process.Kill(); } catch { }
                    }))
                    {
                        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    Log("[Warmup] Cancelled by user");
                    return;
                }

                Log($"[Warmup] TestNetworkApp finished with code {process.ExitCode}");
            }
            catch (Exception ex)
            {
                Log($"[Warmup] Error: {ex.Message}");
            }
        }

        private async Task ResolveUnknownHostAsync(string ip)
        {
            if (_resolvedIpMap.ContainsKey(ip) || _pendingResolutions.ContainsKey(ip)) return;
            
            _pendingResolutions.TryAdd(ip, true);

            try 
            {
                var entry = await System.Net.Dns.GetHostEntryAsync(ip);
                if (!string.IsNullOrEmpty(entry.HostName))
                {
                    var newTarget = new Target 
                    { 
                        Name = entry.HostName, 
                        Host = ip, 
                        Service = "Resolved" 
                    };
                    
                    _resolvedIpMap[ip] = newTarget;

                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        var result = TestResults.FirstOrDefault(t => t.Target.Host == ip);
                        if (result != null)
                        {
                            result.Target = newTarget;
                        }
                    });
                }
            }
            catch 
            {
                // Ignore failures
            }
            finally
            {
                _pendingResolutions.TryRemove(ip, out _);
            }
        }

        private async Task PreResolveTargetsAsync()
        {
            await Task.Run(async () => 
            {
                try
                {
                    Log("[PreResolve] Starting target resolution...");
                    _resolvedIpMap.Clear();
                    
                    var targets = TargetCatalog.Targets;
                    foreach (var t in targets)
                    {
                        try
                        {
                            // Add FallbackIP if exists
                            if (!string.IsNullOrEmpty(t.FallbackIp))
                            {
                                _resolvedIpMap[t.FallbackIp] = new Target 
                                { 
                                    Name = t.Name, 
                                    Host = t.Host, 
                                    Service = t.Service,
                                    Critical = t.Critical,
                                    FallbackIp = t.FallbackIp 
                                };
                            }

                            // Resolve Host
                            var addresses = await System.Net.Dns.GetHostAddressesAsync(t.Host);
                            foreach (var ip in addresses)
                            {
                                var ipStr = ip.ToString();
                                if (!_resolvedIpMap.ContainsKey(ipStr))
                                {
                                    _resolvedIpMap[ipStr] = new Target 
                                    { 
                                        Name = t.Name, 
                                        Host = t.Host, 
                                        Service = t.Service,
                                        Critical = t.Critical,
                                        FallbackIp = t.FallbackIp ?? ""
                                    };
                                }
                            }
                        }
                        catch { }
                    }
                    Log($"[PreResolve] Resolved {_resolvedIpMap.Count} IPs for {targets.Count} targets");
                    
                    // Update existing results that might have been added as IPs
                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        foreach (var result in TestResults)
                        {
                            if (result.Target.Name == result.Target.Host && _resolvedIpMap.TryGetValue(result.Target.Host, out var resolvedTarget))
                            {
                                result.Target = resolvedTarget;
                                Log($"[PreResolve] Updated {result.Target.Host} to {resolvedTarget.Name}");
                            }
                        }
                    });
                }
                catch (Exception ex)
                {
                    Log($"[PreResolve] Error: {ex.Message}");
                }
            });
        }

        private void ParsePipelineMessage(string msg)
        {
            try 
            {
                if (msg.StartsWith("✓ "))
                {
                    // Формат: "✓ 1.2.3.4:80 (20ms)"
                    var parts = msg.Substring(2).Split(' ');
                    var hostPort = parts[0].Split(':');
                    if (hostPort.Length == 2)
                    {
                        var host = hostPort[0];
                        UpdateTestResult(host, TestStatus.Pass, msg);
                        _lastUpdatedHost = host;
                    }
                }
                else if (msg.StartsWith("❌ "))
                {
                    // Формат: "❌ 1.2.3.4:443 | DNS:✓ TCP:✓ TLS:✗ | TLS_DPI"
                    var parts = msg.Substring(2).Split('|');
                    if (parts.Length > 0)
                    {
                        var hostPortStr = parts[0].Trim().Split(' ')[0];
                        var hostPort = hostPortStr.Split(':');
                        if (hostPort.Length == 2)
                        {
                            var host = hostPort[0];
                            UpdateTestResult(host, TestStatus.Fail, msg);
                            _lastUpdatedHost = host;
                        }
                    }
                }
                else if (msg.Contains("→ Стратегия:") && !string.IsNullOrEmpty(_lastUpdatedHost))
                {
                    // Формат: "   → Стратегия: TLS_FRAGMENT"
                    var parts = msg.Split(':');
                    if (parts.Length >= 2)
                    {
                        var strategy = parts[1].Trim();
                        var result = TestResults.FirstOrDefault(t => t.Target.Host == _lastUpdatedHost || t.Target.Name == _lastUpdatedHost);
                        if (result != null)
                        {
                            result.BypassStrategy = strategy;
                            
                            // ROUTER_REDIRECT (Fake IP) - это не ошибка, а информация об особенности сети (клиент в VPN/туннеле)
                            if (strategy == "ROUTER_REDIRECT")
                            {
                                result.Status = TestStatus.Warn;
                                result.Details = result.Details?.Replace("Блокировка", "Информация: Fake IP (VPN/туннель)") ?? "Fake IP обнаружен";
                                Log($"[UI] ROUTER_REDIRECT → Status=Warn для {_lastUpdatedHost}");
                            }
                            // Если есть стратегия обхода (настоящая блокировка), значит можно исправить
                            else if (strategy != "NONE" && strategy != "UNKNOWN")
                            {
                                result.Fixable = true;
                                result.FixType = FixType.Bypass;
                                result.FixInstructions = $"Применить стратегию обхода: {strategy}";
                                
                                // Принудительное обновление биндинга ShowFixButton
                                result.OnPropertyChanged(nameof(result.ShowFixButton));
                                Log($"[UI] ShowFixButton=True для {_lastUpdatedHost}: {strategy}");
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private void UpdateTestResult(string host, TestStatus status, string details)
        {
            var existing = TestResults.FirstOrDefault(t => t.Target.Host == host || t.Target.Name == host);
            if (existing != null)
            {
                existing.Status = status;
                existing.Details = details;
                if (status == TestStatus.Fail)
                {
                    existing.Error = details;
                }
            }
            else
            {
                // Пытаемся найти цель в каталоге для получения метаданных (FallbackIp и т.д.)
                // Сначала ищем по имени/хосту
                var knownTarget = TargetCatalog.Targets.FirstOrDefault(t => 
                    t.Host.Equals(host, StringComparison.OrdinalIgnoreCase) || 
                    t.Name.Equals(host, StringComparison.OrdinalIgnoreCase));

                Target target;
                if (knownTarget != null)
                {
                    target = new Target 
                    { 
                        Name = knownTarget.Name, 
                        Host = knownTarget.Host, 
                        Service = knownTarget.Service,
                        Critical = knownTarget.Critical,
                        FallbackIp = knownTarget.FallbackIp ?? ""
                    };
                }
                // Если не нашли по имени, ищем в кэше разрешенных IP
                else if (_resolvedIpMap.TryGetValue(host, out var resolvedTarget))
                {
                    target = resolvedTarget;
                }
                else
                {
                    target = new Target { Name = host, Host = host, Service = "Обнаружено" };
                    _ = ResolveUnknownHostAsync(host);
                }

                var result = new TestResult { Target = target, Status = status, Details = details };
                if (status == TestStatus.Fail)
                {
                    result.Error = details;
                }
                TestResults.Add(result);
                OnPropertyChanged(nameof(TotalTargets));
                OnPropertyChanged(nameof(ProgressBarMax));
            }
            
            OnPropertyChanged(nameof(PassCount));
            OnPropertyChanged(nameof(FailCount));
            OnPropertyChanged(nameof(WarnCount));
        }

        /// <summary>
        /// Проверяет, запущено ли приложение с правами администратора
        /// </summary>
        [SupportedOSPlatform("windows")] 
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


        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class RelayCommand : ICommand
    {
        private readonly System.Action<object?> _execute;
        private readonly System.Func<object?, bool>? _canExecute;

        public RelayCommand(System.Action<object?> execute, System.Func<object?, bool>? canExecute = null)
        {
            _execute = execute;
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
        public void Execute(object? parameter) => _execute(parameter);
        public event System.EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }
    }
}
