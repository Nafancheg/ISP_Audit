using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Collections.Concurrent;
using ISPAudit.Models;
using IspAudit;

namespace ISPAudit.ViewModels
{
    /// <summary>
    /// Менеджер результатов тестирования.
    /// Управляет ObservableCollection<TestResult>, парсит сообщения pipeline,
    /// применяет эвристики для классификации блокировок.
    /// </summary>
    public class TestResultsManager : INotifyPropertyChanged
    {
        private readonly ConcurrentDictionary<string, TestResult> _testResultMap = new();
        private readonly ConcurrentDictionary<string, Target> _resolvedIpMap = new();
        private readonly ConcurrentDictionary<string, bool> _pendingResolutions = new();
        private string? _lastUpdatedHost;

        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<string>? OnLog;

        /// <summary>
        /// Коллекция результатов тестирования (для UI binding)
        /// </summary>
        public ObservableCollection<TestResult> TestResults { get; } = new();

        #region Счётчики

        public int TotalTargets => TestResults.Count;
        public int ProgressBarMax => TotalTargets == 0 ? 1 : TotalTargets;
        public int CurrentTest => TestResults.Count(t => 
            t.Status == TestStatus.Running || 
            t.Status == TestStatus.Pass || 
            t.Status == TestStatus.Fail || 
            t.Status == TestStatus.Warn);
        public int CompletedTests => TestResults.Count(t => 
            t.Status == TestStatus.Pass || 
            t.Status == TestStatus.Fail || 
            t.Status == TestStatus.Warn);
        public int PassCount => TestResults.Count(t => t.Status == TestStatus.Pass);
        public int FailCount => TestResults.Count(t => t.Status == TestStatus.Fail);
        public int WarnCount => TestResults.Count(t => t.Status == TestStatus.Warn);

        #endregion

        #region Initialization

        /// <summary>
        /// Инициализация результатов из каталога целей
        /// </summary>
        public void Initialize()
        {
            var catalogTargets = TargetCatalog.Targets;
            
            TestResults.Clear();
            _testResultMap.Clear();

            foreach (var t in catalogTargets)
            {
                var target = new Target
                {
                    Name = t.Name,
                    Host = t.Host,
                    Service = t.Service ?? "Unknown",
                    Critical = false,
                    FallbackIp = ""
                };
                
                var result = new TestResult { Target = target, Status = TestStatus.Idle };
                TestResults.Add(result);
                _testResultMap[target.Name] = result;
            }

            NotifyCountersChanged();
        }

        /// <summary>
        /// Очистка результатов для нового запуска
        /// </summary>
        public void Clear()
        {
            TestResults.Clear();
            _testResultMap.Clear();
            _resolvedIpMap.Clear();
            _lastUpdatedHost = null;
            NotifyCountersChanged();
        }

        /// <summary>
        /// Сброс всех статусов в Idle
        /// </summary>
        public void ResetStatuses()
        {
            foreach (var test in TestResults)
            {
                test.Status = TestStatus.Idle;
            }
            NotifyCountersChanged();
        }

        #endregion

        #region Update Methods

        /// <summary>
        /// Обновление результата теста
        /// </summary>
        public void UpdateTestResult(string host, TestStatus status, string details)
        {
            var existing = TestResults.FirstOrDefault(t => 
                t.Target.Host == host || t.Target.Name == host);
            
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
                // Пытаемся найти цель в каталоге
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
            }
            
            NotifyCountersChanged();
        }

        /// <summary>
        /// Парсинг сообщений от pipeline
        /// </summary>
        public void ParsePipelineMessage(string msg)
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
                            
                            // Если цель - IP адрес, убираем "DNS:✓" из сообщения
                            if (IPAddress.TryParse(host, out _))
                            {
                                msg = msg.Replace("DNS:✓ ", "").Replace("DNS:✓", "");
                            }

                            var status = TestStatus.Fail;
                            if (msg.Contains("TLS_DPI"))
                            {
                                msg += "\nℹ️ Обнаружены признаки DPI (фильтрации трафика).";
                                
                                var heuristic = AnalyzeHeuristicSeverity(host);
                                if (heuristic.status == TestStatus.Warn)
                                {
                                    status = TestStatus.Warn;
                                    msg += $"\n⚠️ {heuristic.note}";
                                }
                                else
                                {
                                    bool isRelatedToPassing = TestResults.Any(t => 
                                        t.Status == TestStatus.Pass && 
                                        AreHostsRelated(t.Target, host));

                                    if (isRelatedToPassing)
                                    {
                                        status = TestStatus.Warn;
                                        msg += " Связанный сервис доступен, вероятно это частичная блокировка или служебный запрос.";
                                    }
                                }
                            }
                            
                            UpdateTestResult(host, status, msg);
                            _lastUpdatedHost = host;
                        }
                    }
                }
                else if (msg.StartsWith("✓✓ "))
                {
                    // Успешный bypass
                    var match = System.Text.RegularExpressions.Regex.Match(msg, @"! (.*?) теперь доступен");
                    if (match.Success)
                    {
                        var hostPort = match.Groups[1].Value.Trim();
                        var host = hostPort.Split(':')[0];
                        
                        var existing = TestResults.FirstOrDefault(t => 
                            t.Target.Host == host || t.Target.Name == host);
                        var newDetails = msg;
                        if (existing != null && !string.IsNullOrEmpty(existing.Details))
                        {
                            newDetails = existing.Details + "\n" + msg;
                        }
                        
                        UpdateTestResult(host, TestStatus.Pass, newDetails);
                        _lastUpdatedHost = host;
                    }
                }
                else if (msg.StartsWith("✗ ") && !string.IsNullOrEmpty(_lastUpdatedHost))
                {
                    // Неудачный bypass
                    var existing = TestResults.FirstOrDefault(t => 
                        t.Target.Host == _lastUpdatedHost || t.Target.Name == _lastUpdatedHost);
                    if (existing != null)
                    {
                        existing.Details += "\n" + msg;
                    }
                }
                else if (msg.Contains("→ Стратегия:") && !string.IsNullOrEmpty(_lastUpdatedHost))
                {
                    var parts = msg.Split(':');
                    if (parts.Length >= 2)
                    {
                        var strategy = parts[1].Trim();
                        var result = TestResults.FirstOrDefault(t => 
                            t.Target.Host == _lastUpdatedHost || t.Target.Name == _lastUpdatedHost);
                        if (result != null)
                        {
                            result.BypassStrategy = strategy;
                            
                            if (strategy == "ROUTER_REDIRECT")
                            {
                                result.Status = TestStatus.Warn;
                                result.Details = result.Details?.Replace("Блокировка", "Информация: Fake IP (VPN/туннель)") 
                                    ?? "Fake IP обнаружен";
                                Log($"[UI] ROUTER_REDIRECT → Status=Warn для {_lastUpdatedHost}");
                            }
                            else if (strategy != "NONE" && strategy != "UNKNOWN")
                            {
                                Log($"[UI] Bypass strategy for {_lastUpdatedHost}: {strategy}");
                            }
                        }
                    }
                }
                else if ((msg.StartsWith("[BYPASS]") || msg.StartsWith("ℹ") || msg.StartsWith("⚠")) 
                    && !string.IsNullOrEmpty(_lastUpdatedHost))
                {
                    var result = TestResults.FirstOrDefault(t => 
                        t.Target.Host == _lastUpdatedHost || t.Target.Name == _lastUpdatedHost);
                    if (result != null && (result.Details == null || !result.Details.Contains(msg)))
                    {
                        result.Details = (result.Details ?? "") + $"\n{msg}";
                    }
                }
            }
            catch { }
        }

        #endregion

        #region DNS Resolution

        /// <summary>
        /// Предварительное разрешение целей
        /// </summary>
        public async System.Threading.Tasks.Task PreResolveTargetsAsync()
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

                        var dnsResult = await IspAudit.Utils.NetUtils.ResolveWithFallbackAsync(t.Host);
                        
                        foreach (var ip in dnsResult.Addresses)
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
                
                // Обновляем существующие результаты
                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    foreach (var result in TestResults)
                    {
                        if (result.Target.Name == result.Target.Host && 
                            _resolvedIpMap.TryGetValue(result.Target.Host, out var resolvedTarget))
                        {
                            result.Target = resolvedTarget;
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                Log($"[PreResolve] Error: {ex.Message}");
            }
        }

        private async System.Threading.Tasks.Task ResolveUnknownHostAsync(string ip)
        {
            if (_resolvedIpMap.ContainsKey(ip) || _pendingResolutions.ContainsKey(ip)) return;
            
            _pendingResolutions.TryAdd(ip, true);

            try 
            {
                var dnsResult = await IspAudit.Utils.NetUtils.ResolveWithFallbackAsync(ip);
                if (dnsResult.Addresses.Count > 0)
                {
                    string hostName = ip;
                    try 
                    {
                        var entry = await System.Net.Dns.GetHostEntryAsync(ip);
                        if (!string.IsNullOrEmpty(entry.HostName)) hostName = entry.HostName;
                    }
                    catch {}

                    var newTarget = new Target 
                    { 
                        Name = hostName, 
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
                            
                            if (dnsResult.SystemDnsFailed)
                            {
                                result.Details += "\n⚠️ Имя хоста разрешено через DoH (системный DNS недоступен/фильтруется)";
                                if (result.Status == TestStatus.Pass) result.Status = TestStatus.Warn;
                            }
                        }
                    });
                }
            }
            catch { }
            finally
            {
                _pendingResolutions.TryRemove(ip, out _);
            }
        }

        #endregion

        #region Heuristics

        private (TestStatus status, string note) AnalyzeHeuristicSeverity(string host)
        {
            host = host.ToLowerInvariant();

            // Microsoft / Windows Infrastructure
            if (host.EndsWith(".ax-msedge.net") || 
                host.EndsWith(".windows.net") || 
                host.EndsWith(".microsoft.com") || 
                host.EndsWith(".live.com") ||
                host.EndsWith(".msn.com") ||
                host.EndsWith(".bing.com") ||
                host.EndsWith(".office.net"))
            {
                return (TestStatus.Warn, "Служебный трафик Microsoft/Windows. Обычно не влияет на работу сторонних приложений.");
            }

            // Analytics / Ads / Trackers
            if (host.Contains("google-analytics") || 
                host.Contains("doubleclick") || 
                host.Contains("googlesyndication") ||
                host.Contains("scorecardresearch") ||
                host.Contains("usercentrics") ||
                host.Contains("appsflyer") ||
                host.Contains("adjust.com"))
            {
                return (TestStatus.Warn, "Аналитика/Реклама. Блокировка не критична.");
            }

            // Azure Cloud Load Balancers
            if (host.Contains(".cloudapp.azure.com") || 
                host.EndsWith(".trafficmanager.net") ||
                host.EndsWith(".azurewebsites.net"))
            {
                return (TestStatus.Warn, "Облачный шлюз (Azure). Если приложение работает, это может быть фоновый/служебный запрос.");
            }

            return (TestStatus.Fail, "");
        }

        private bool AreHostsRelated(Target passingTarget, string failingHost)
        {
            // Проверка по имени сервиса
            string? failingService = TestResults.FirstOrDefault(t => t.Target.Host == failingHost)?.Target.Service;
            
            if (failingService == null)
            {
                var def = TargetCatalog.TryGetByHost(failingHost);
                if (def != null) failingService = def.Service;
            }
            
            if (!string.IsNullOrEmpty(failingService) && 
                !string.IsNullOrEmpty(passingTarget.Service) &&
                failingService.Equals(passingTarget.Service, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Эвристика по вхождению имени хоста
            var passingHost = passingTarget.Host;
            if (IPAddress.TryParse(passingHost, out _)) return false;

            var parts = passingHost.Split('.');
            if (parts.Length >= 2)
            {
                var coreName = parts.Length > 2 ? parts[parts.Length - 2] : parts[0];
                
                if (coreName.Length > 3 && failingHost.Contains(coreName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        #endregion

        #region Private Methods

        private void NotifyCountersChanged()
        {
            OnPropertyChanged(nameof(TotalTargets));
            OnPropertyChanged(nameof(ProgressBarMax));
            OnPropertyChanged(nameof(CurrentTest));
            OnPropertyChanged(nameof(CompletedTests));
            OnPropertyChanged(nameof(PassCount));
            OnPropertyChanged(nameof(FailCount));
            OnPropertyChanged(nameof(WarnCount));
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
