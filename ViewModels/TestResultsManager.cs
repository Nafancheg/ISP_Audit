using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using IspAudit.Models;
using IspAudit;
using IspAudit.Utils;

namespace IspAudit.ViewModels
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

        private readonly Queue<(DateTime Time, bool IsSuccess)> _healthHistory = new();
        
        private double _healthScore = 100;
        public double HealthScore
        {
            get => _healthScore;
            set
            {
                if (Math.Abs(_healthScore - value) > 0.1)
                {
                    _healthScore = value;
                    OnPropertyChanged(nameof(HealthScore));
                    OnPropertyChanged(nameof(HealthColor));
                }
            }
        }

        public string HealthColor => HealthScore > 80 ? "#10B981" : (HealthScore > 50 ? "#EAB308" : "#EF4444");

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

        public void Initialize()
        {
            TestResults.Clear();
            _testResultMap.Clear();
            _resolvedIpMap.Clear();
            _pendingResolutions.Clear();
            _lastUpdatedHost = null;
        }

        /// <summary>
        /// Сброс статусов существующих записей в Idle (для повторного запуска)
        /// </summary>
        public void ResetStatuses()
        {
            foreach (var test in TestResults)
            {
                test.Status = TestStatus.Idle;
                test.Details = string.Empty;
                test.Error = null!; // сбрасываем в null намеренно
            }
            NotifyCountersChanged();
        }

        /// <summary>
        /// Полная очистка результатов (для нового запуска диагностики)
        /// </summary>
        public void Clear()
        {
            Initialize();
            NotifyCountersChanged();
        }

        /// <summary>
        /// Обновление результата теста
        /// </summary>
        public void UpdateTestResult(string host, TestStatus status, string details)
        {
            // КРИТИЧНО: Фильтруем шумные хосты ПЕРЕД созданием карточки
            if (NoiseHostFilter.Instance.IsNoiseHost(host))
            {
                // Если карточка уже существует - удаляем её
                var toRemove = TestResults.FirstOrDefault(t => 
                    t.Target.Host == host || t.Target.Name == host);
                if (toRemove != null)
                {
                    TestResults.Remove(toRemove);
                    _testResultMap.TryRemove(host, out _);
                    Log($"[UI] Удалена шумовая карточка: {host}");
                    NotifyCountersChanged();
                }
                return; // Не создаём новую карточку для шума
            }

            var normalizedHost = NormalizeHost(host);

            var existing = TestResults.FirstOrDefault(t => 
                NormalizeHost(t.Target.Host).Equals(normalizedHost, StringComparison.OrdinalIgnoreCase) || 
                NormalizeHost(t.Target.Name).Equals(normalizedHost, StringComparison.OrdinalIgnoreCase) ||
                t.Target.FallbackIp == host);
            
            if (existing != null)
            {
                existing.Status = status;
                existing.Details = details;
                
                // Parse flags from details
                existing.IsRstInjection = details.Contains("TCP_RST_INJECTION") || details.Contains("RST-инжект");
                existing.IsHttpRedirect = details.Contains("HTTP_REDIRECT_DPI") || details.Contains("HTTP-редирект");
                existing.IsRetransmissionHeavy = details.Contains("TCP_RETRY_HEAVY") || details.Contains("ретрансмиссий:");
                existing.IsUdpBlockage = details.Contains("UDP_BLOCKAGE") || details.Contains("UDP потерь");

                if (status == TestStatus.Fail)
                {
                    existing.Error = details;
                }
            }
            else
            {
                var target = new Target
                {
                    Name = host,
                    Host = host,
                    Service = "Unknown",
                    Critical = false,
                    FallbackIp = ""
                };

                existing = new TestResult { Target = target, Status = status, Details = details };
                
                // Parse flags from details
                existing.IsRstInjection = details.Contains("TCP_RST_INJECTION") || details.Contains("RST-инжект");
                existing.IsHttpRedirect = details.Contains("HTTP_REDIRECT_DPI") || details.Contains("HTTP-редирект");
                existing.IsRetransmissionHeavy = details.Contains("TCP_RETRY_HEAVY") || details.Contains("ретрансмиссий:");
                existing.IsUdpBlockage = details.Contains("UDP_BLOCKAGE") || details.Contains("UDP потерь");

                if (status == TestStatus.Fail)
                {
                    existing.Error = details;
                }
                TestResults.Add(existing);
            }

            // Update health history
            if (status == TestStatus.Pass || status == TestStatus.Fail)
            {
                lock (_healthHistory)
                {
                    _healthHistory.Enqueue((DateTime.UtcNow, status == TestStatus.Pass));
                    
                    // Prune older than 60s
                    var cutoff = DateTime.UtcNow.AddSeconds(-60);
                    while (_healthHistory.Count > 0 && _healthHistory.Peek().Time < cutoff)
                    {
                        _healthHistory.Dequeue();
                    }

                    // Calculate score
                    if (_healthHistory.Count > 0)
                    {
                        double success = _healthHistory.Count(x => x.IsSuccess);
                        HealthScore = (success / _healthHistory.Count) * 100.0;
                    }
                    else
                    {
                        HealthScore = 100;
                    }
                }
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
                // Обработка сообщения о фильтрации шума - удаляем карточку
                if (msg.StartsWith("[NOISE]") || msg.Contains("Шум обнаружен:"))
                {
                    // Форматы:
                    // "[NOISE] Отфильтрован: hostname"
                    // "[NOISE] Отфильтрован (late): hostname"
                    // "[Collector] Шум обнаружен: IP → hostname"
                    string? host = null;
                    string? ip = null;
                    
                    if (msg.Contains("Отфильтрован"))
                    {
                        host = msg.Split(':').LastOrDefault()?.Trim();
                    }
                    else if (msg.Contains("Шум обнаружен:"))
                    {
                        var parts = msg.Split(new[] { " → " }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 2)
                        {
                            ip = parts[0].Split(':').LastOrDefault()?.Trim();
                            host = parts[1].Trim();
                        }
                    }
                    
                    if (!string.IsNullOrEmpty(host) || !string.IsNullOrEmpty(ip))
                    {
                        var toRemove = TestResults.FirstOrDefault(t => 
                            (!string.IsNullOrEmpty(host) && (t.Target.Host.Equals(host, StringComparison.OrdinalIgnoreCase) || t.Target.Name.Equals(host, StringComparison.OrdinalIgnoreCase))) ||
                            (!string.IsNullOrEmpty(ip) && (t.Target.Host == ip || t.Target.FallbackIp == ip)));
                        if (toRemove != null)
                        {
                            TestResults.Remove(toRemove);
                            Log($"[UI] Удалена шумовая карточка: {host ?? ip}");
                            NotifyCountersChanged();
                        }
                    }
                    return;
                }

                if (msg.StartsWith("✓ "))
                {
                    // Формат: "✓ hostname:port (20ms)" или "✓ 1.2.3.4:port (20ms)"
                    var parts = msg.Substring(2).Split(' ');
                    var hostPort = parts[0].Split(':');
                    if (hostPort.Length == 2)
                    {
                        var host = hostPort[0];
                        
                        // КРИТИЧНО: Проверяем на шум - не создаём карточку для успешных шумовых хостов
                        if (NoiseHostFilter.Instance.IsNoiseHost(host))
                        {
                            // Удаляем карточку, если она была создана ранее (ищем по всем полям)
                            var toRemove = TestResults.FirstOrDefault(t => 
                                t.Target.Host.Equals(host, StringComparison.OrdinalIgnoreCase) || 
                                t.Target.Name.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                                t.Target.FallbackIp == host);
                            if (toRemove != null)
                            {
                                TestResults.Remove(toRemove);
                                Log($"[UI] Удалена шумовая карточка (успех): {host}");
                                NotifyCountersChanged();
                            }
                            return;
                        }
                        
                        // Обновляем существующую карточку или создаём новую
                        UpdateTestResult(host, TestStatus.Pass, StripNameTokens(msg));
                        _lastUpdatedHost = host;

                        ApplyNameTokensFromMessage(host, msg);
                    }
                }
                else if (msg.Contains("[Collector] Новое соединение"))
                {
                    // Формат: "[Collector] Новое соединение #1: hostname:443 (proto=6, pid=3796)"
                    // или:    "[Collector] Новое соединение #1: 142.251.38.142:443 (proto=6, pid=3796)"
                    var parts = msg.Split(new[] { ": " }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        var hostPortPart = parts[1].Split(' ')[0]; // "hostname:443" или "142.251.38.142:443"
                        var hostPort = hostPortPart.Split(':');
                        if (hostPort.Length == 2)
                        {
                            var host = hostPort[0];
                            
                            // Фильтр уже применён в TrafficCollector, но проверим ещё раз
                            if (NoiseHostFilter.Instance.IsNoiseHost(host))
                            {
                                return;
                            }
                            
                            UpdateTestResult(host, TestStatus.Running, "Обнаружено соединение...");
                            _lastUpdatedHost = host;

                            ApplyNameTokensFromMessage(host, msg);
                        }
                    }
                }
                else if (msg.Contains("[Collector] Hostname обновлен"))
                {
                    // Формат: "[Collector] Hostname обновлен: 142.251.38.142 → google.com"
                    var parts = msg.Split(new[] { " → " }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 2)
                    {
                        var ipPart = parts[0].Split(new[] { ": " }, StringSplitOptions.RemoveEmptyEntries).Last();
                        var newHostname = parts[1].Trim();
                        
                        // КРИТИЧНО: Проверяем, не является ли новый hostname шумовым
                        if (NoiseHostFilter.Instance.IsNoiseHost(newHostname))
                        {
                            // Удаляем карточку, если она была создана для IP
                            var toRemove = TestResults.FirstOrDefault(t => t.Target.Host == ipPart || t.Target.FallbackIp == ipPart);
                            if (toRemove != null)
                            {
                                TestResults.Remove(toRemove);
                                Log($"[UI] Удалена шумовая карточка после резолва: {ipPart} → {newHostname}");
                                NotifyCountersChanged();
                            }
                            return;
                        }
                        
                        // Ключ карточки остаётся IP. Обновляем только отображаемое имя,
                        // если SNI ещё не известен.
                        var existingByIp = TestResults.FirstOrDefault(t => t.Target.Host == ipPart || t.Target.FallbackIp == ipPart);
                        if (existingByIp != null)
                        {
                            if (string.IsNullOrWhiteSpace(existingByIp.Target.SniHost))
                            {
                                // Используем DNS имя как заголовок, но не меняем Host (ключ)
                                if (existingByIp.Target.Name == ipPart)
                                {
                                    var old = existingByIp.Target;
                                    existingByIp.Target = new Target
                                    {
                                        Name = newHostname,
                                        Host = old.Host,
                                        Service = old.Service,
                                        Critical = old.Critical,
                                        FallbackIp = old.FallbackIp,
                                        SniHost = old.SniHost,
                                        ReverseDnsHost = old.ReverseDnsHost
                                    };
                                }
                            }
                        }
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
                            
                            // КРИТИЧНО: Проверяем на шум перед созданием карточки ошибки
                            if (NoiseHostFilter.Instance.IsNoiseHost(host))
                            {
                                // Удаляем существующую карточку (ищем по всем полям)
                                var toRemove = TestResults.FirstOrDefault(t => 
                                    t.Target.Host.Equals(host, StringComparison.OrdinalIgnoreCase) || 
                                    t.Target.Name.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                                    t.Target.FallbackIp == host);
                                if (toRemove != null)
                                {
                                    TestResults.Remove(toRemove);
                                    Log($"[UI] Удалена шумовая карточка при ошибке: {host}");
                                    NotifyCountersChanged();
                                }
                                return;
                            }
                            
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
                            
                            UpdateTestResult(host, status, StripNameTokens(msg));
                            _lastUpdatedHost = host;

                            ApplyNameTokensFromMessage(host, msg);
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
                else if ((msg.Contains("→ Стратегия:") || msg.Contains("💡 Рекомендация:")) && !string.IsNullOrEmpty(_lastUpdatedHost))
                {
                    var parts = msg.Split(':');
                    if (parts.Length >= 2)
                    {
                        // Для "💡 Рекомендация: DROP_RST" берем вторую часть
                        // Для "→ Стратегия: DROP_RST" тоже вторую
                        var strategy = parts[1].Trim();
                        
                        // Если в строке есть скобки с деталями (фейлов за 60s...), отрезаем их для поля стратегии
                        var parenIndex = strategy.IndexOf('(');
                        if (parenIndex > 0)
                        {
                            strategy = strategy.Substring(0, parenIndex).Trim();
                        }

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

        private void ApplyNameTokensFromMessage(string hostKey, string msg)
        {
            try
            {
                // Формат добавляется pipeline: "SNI=... RDNS=..." (значения без пробелов)
                var sni = ExtractToken(msg, "SNI");
                var rdns = ExtractToken(msg, "RDNS");

                if (string.IsNullOrWhiteSpace(sni) && string.IsNullOrWhiteSpace(rdns)) return;

                var result = TestResults.FirstOrDefault(t => t.Target.Host == hostKey || t.Target.FallbackIp == hostKey);
                if (result == null) return;

                if (!string.IsNullOrWhiteSpace(sni) && sni != "-")
                {
                    var old = result.Target;
                    var newName = !string.Equals(old.Name, sni, StringComparison.OrdinalIgnoreCase) ? sni : old.Name;
                    result.Target = new Target
                    {
                        Name = newName,
                        Host = old.Host,
                        Service = old.Service,
                        Critical = old.Critical,
                        FallbackIp = old.FallbackIp,
                        SniHost = sni,
                        ReverseDnsHost = old.ReverseDnsHost
                    };
                }

                if (!string.IsNullOrWhiteSpace(rdns) && rdns != "-")
                {
                    var old = result.Target;
                    result.Target = new Target
                    {
                        Name = old.Name,
                        Host = old.Host,
                        Service = old.Service,
                        Critical = old.Critical,
                        FallbackIp = old.FallbackIp,
                        SniHost = old.SniHost,
                        ReverseDnsHost = rdns
                    };
                }
            }
            catch
            {
            }
        }

        private static string? ExtractToken(string msg, string token)
        {
            // token=VALUE, VALUE до пробела или '|'
            var m = Regex.Match(msg, $@"\b{Regex.Escape(token)}=([^\s\|]+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }

        private static string StripNameTokens(string msg)
        {
            try
            {
                // Убираем хвост вида " SNI=... RDNS=..." (в любом порядке, если появится)
                var cleaned = Regex.Replace(msg, @"\s+SNI=[^\s\|]+", string.Empty, RegexOptions.IgnoreCase);
                cleaned = Regex.Replace(cleaned, @"\s+RDNS=[^\s\|]+", string.Empty, RegexOptions.IgnoreCase);
                // Сжимаем лишние пробелы
                cleaned = Regex.Replace(cleaned, @"\s{2,}", " ").Trim();
                return cleaned;
            }
            catch
            {
                return msg;
            }
        }

        #endregion

        #region DNS Resolution

        /// <summary>
        /// Предварительное разрешение целей
        /// </summary>
        public System.Threading.Tasks.Task PreResolveTargetsAsync()
        {
            try
            {
                Log("[PreResolve] Starting target resolution...");
                _resolvedIpMap.Clear();

                // В новой архитектуре цели формируются динамически, поэтому
                // предварительное разрешение по статическому каталогу не требуется.
                Log($"[PreResolve] Skipped: dynamic targets mode");

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

            // Никакой асинхронной работы здесь больше нет
            return System.Threading.Tasks.Task.CompletedTask;
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

        private string NormalizeHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return host;
            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                return host.Substring(4);
            return host;
        }

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
