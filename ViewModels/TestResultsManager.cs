using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using IspAudit.Core.Diagnostics;
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

        // UI должен быть детерминированным: одинаковые условия → одинаковая карточка.
        // Для пользователя ключом важнее сервис/hostname (SNI), а не IP.
        // Также важен режим «Нестабильно», когда в окне есть и успехи, и ошибки.

        private readonly ConcurrentDictionary<string, string> _ipToUiKey = new();

        private readonly record struct OutcomeHistory(DateTime LastPassUtc, DateTime LastProblemUtc);
        private readonly ConcurrentDictionary<string, OutcomeHistory> _outcomeHistoryByKey = new();

        private static readonly TimeSpan UnstableWindow = TimeSpan.FromSeconds(60);
        
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
        public void UpdateTestResult(string host, TestStatus status, string details, string? fallbackIp = null)
        {
            // КРИТИЧНО: Фильтруем шумные хосты ПЕРЕД созданием карточки.
            // Но делаем это только для «успехов»/непроблемных результатов.
            // Ошибки/нестабильность не скрываем, иначе теряем лицевой эффект.
            if (!string.IsNullOrWhiteSpace(host) &&
                !IPAddress.TryParse(host, out _) &&
                NoiseHostFilter.Instance.IsNoiseHost(host) &&
                (status == TestStatus.Pass || status == TestStatus.Running || status == TestStatus.Idle))
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

            var incomingStatus = status;

            // 1) Детерминированное правило «Нестабильно»: если в окне есть и успех, и проблема
            // (Fail/Warn), то показываем Warn.
            status = ApplyUnstableRule(normalizedHost, status);

            var existing = TestResults.FirstOrDefault(t => 
                NormalizeHost(t.Target.Host).Equals(normalizedHost, StringComparison.OrdinalIgnoreCase) || 
                NormalizeHost(t.Target.Name).Equals(normalizedHost, StringComparison.OrdinalIgnoreCase) ||
                t.Target.FallbackIp == host);
            
            if (existing != null)
            {
                existing.Status = status;
                existing.Details = details;

                // ЯКОРЬ: если карточка уже создана по человеко‑понятному ключу (hostname/SNI),
                // но позже мы узнали реальный IP (fallbackIp), обязательно сохраняем его.
                // Иначе в UI колонка IP начинает показывать hostname.
                if (!string.IsNullOrWhiteSpace(fallbackIp) && IPAddress.TryParse(fallbackIp, out _))
                {
                    var old = existing.Target;
                    if (old != null && string.IsNullOrWhiteSpace(old.FallbackIp))
                    {
                        existing.Target = new Target
                        {
                            Name = old.Name,
                            Host = old.Host,
                            Service = old.Service,
                            Critical = old.Critical,
                            FallbackIp = fallbackIp,
                            SniHost = old.SniHost,
                            ReverseDnsHost = old.ReverseDnsHost
                        };
                    }
                }
                
                // Parse flags from details
                existing.IsRstInjection = BlockageCode.ContainsCode(details, BlockageCode.TcpRstInjection) || details.Contains("RST-инжект");
                existing.IsHttpRedirect = BlockageCode.ContainsCode(details, BlockageCode.HttpRedirectDpi) || details.Contains("HTTP-редирект");
                existing.IsRetransmissionHeavy = BlockageCode.ContainsCode(details, BlockageCode.TcpRetryHeavy) || details.Contains("ретрансмиссий:");
                existing.IsUdpBlockage = BlockageCode.ContainsCode(details, BlockageCode.UdpBlockage) || details.Contains("UDP потерь");

                // Если статус вычислен как Warn из-за нестабильности, но текущий пакет был Fail,
                // сохраняем подробность как Error, чтобы пользователь видел причину.
                if (status == TestStatus.Fail || incomingStatus == TestStatus.Fail)
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
                    FallbackIp = fallbackIp ?? ""
                };

                existing = new TestResult { Target = target, Status = status, Details = details };
                
                // Parse flags from details
                existing.IsRstInjection = BlockageCode.ContainsCode(details, BlockageCode.TcpRstInjection) || details.Contains("RST-инжект");
                existing.IsHttpRedirect = BlockageCode.ContainsCode(details, BlockageCode.HttpRedirectDpi) || details.Contains("HTTP-редирект");
                existing.IsRetransmissionHeavy = BlockageCode.ContainsCode(details, BlockageCode.TcpRetryHeavy) || details.Contains("ретрансмиссий:");
                existing.IsUdpBlockage = BlockageCode.ContainsCode(details, BlockageCode.UdpBlockage) || details.Contains("UDP потерь");

                // Если статус вычислен как Warn из-за нестабильности, но текущий пакет был Fail,
                // сохраняем подробность как Error, чтобы пользователь видел причину.
                if (status == TestStatus.Fail || status == TestStatus.Warn)
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
                // SNI-событие (даёт пользователю понятный ключ сервиса)
                // Формат: "[SNI] Detected: 64.233.164.91 -> youtube.com"
                if (msg.Contains("[SNI] Detected:", StringComparison.OrdinalIgnoreCase))
                {
                    var m = Regex.Match(msg, @"Detected:\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+->\s+(?<host>[^\s\|]+)", RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        var ip = m.Groups["ip"].Value.Trim();
                        var host = NormalizeHost(m.Groups["host"].Value.Trim());
                        if (!string.IsNullOrWhiteSpace(ip) && !string.IsNullOrWhiteSpace(host) && host != "-")
                        {
                            _ipToUiKey[ip] = host;
                            TryMigrateIpCardToNameKey(ip, host);
                        }
                    }
                    return;
                }

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
                            // Важно: шум должен скрывать только «OK/успех».
                            // Карточки с ошибками/предупреждениями не удаляем, иначе теряем лицевой эффект.
                            if (toRemove.Status == TestStatus.Pass || toRemove.Status == TestStatus.Idle || toRemove.Status == TestStatus.Running)
                            {
                                TestResults.Remove(toRemove);
                                Log($"[UI] Удалена шумовая карточка: {host ?? ip}");
                                NotifyCountersChanged();
                            }
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
                        var uiKey = SelectUiKey(host, msg);
                        var fallbackIp = IPAddress.TryParse(host, out _) ? host : null;
                        
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
                        UpdateTestResult(uiKey, TestStatus.Pass, StripNameTokens(msg), fallbackIp);
                        _lastUpdatedHost = uiKey;

                        ApplyNameTokensFromMessage(uiKey, msg);
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

                            // Если по IP уже известен SNI/hostname, используем его как ключ карточки.
                            var uiKey = SelectUiKey(host, msg);
                            var fallbackIp = IPAddress.TryParse(host, out _) ? host : null;
                            
                            // Фильтр уже применён в TrafficCollector, но проверим ещё раз
                            if (NoiseHostFilter.Instance.IsNoiseHost(host))
                            {
                                return;
                            }
                            
                            // ВАЖНО: событие "Новое соединение" может прийти позже итогового результата теста.
                            // Не перетираем Pass/Fail/Warn обратно в Running, иначе UI выглядит "зависшим".
                            var existing = TestResults.FirstOrDefault(t =>
                                t.Target.Host.Equals(uiKey, StringComparison.OrdinalIgnoreCase) ||
                                t.Target.Name.Equals(uiKey, StringComparison.OrdinalIgnoreCase) ||
                                (!string.IsNullOrEmpty(fallbackIp) && t.Target.FallbackIp == fallbackIp));
                            if (existing == null || existing.Status == TestStatus.Idle || existing.Status == TestStatus.Running)
                            {
                                UpdateTestResult(uiKey, TestStatus.Running, "Обнаружено соединение...", fallbackIp);
                                _lastUpdatedHost = uiKey;
                            }

                            ApplyNameTokensFromMessage(uiKey, msg);
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
                                // Важно: не удаляем карточки с проблемами только потому,
                                // что reverse/DNS имя попало под noise-паттерн (например *.1e100.net).
                                if (toRemove.Status == TestStatus.Pass || toRemove.Status == TestStatus.Idle || toRemove.Status == TestStatus.Running)
                                {
                                    TestResults.Remove(toRemove);
                                    Log($"[UI] Удалена шумовая карточка после резолва: {ipPart} → {newHostname}");
                                    NotifyCountersChanged();
                                    return;
                                }

                                // Карточка с проблемой остаётся; при желании можно сохранить имя как rDNS.
                                var old = toRemove.Target;
                                toRemove.Target = new Target
                                {
                                    Name = old.Name,
                                    Host = old.Host,
                                    Service = old.Service,
                                    Critical = old.Critical,
                                    FallbackIp = old.FallbackIp,
                                    SniHost = old.SniHost,
                                    ReverseDnsHost = newHostname
                                };
                            }
                            return;
                        }
                        
                        // Если это не шумовой hostname, используем его как человеко‑понятный ключ.
                        // IP остаётся как технический якорь (FallbackIp) для корреляции.
                        var existingByIp = TestResults.FirstOrDefault(t => t.Target.Host == ipPart || t.Target.FallbackIp == ipPart);
                        if (existingByIp != null)
                        {
                            var normalizedHostname = NormalizeHost(newHostname);
                            if (!string.IsNullOrWhiteSpace(normalizedHostname) && normalizedHostname != "-" && !IPAddress.TryParse(normalizedHostname, out _))
                            {
                                _ipToUiKey[ipPart] = normalizedHostname;
                                TryMigrateIpCardToNameKey(ipPart, normalizedHostname);
                            }

                            if (string.IsNullOrWhiteSpace(existingByIp.Target.SniHost))
                            {
                                // Если SNI ещё не пойман — заполняем колонку SNI DNS-именем
                                var old = existingByIp.Target;
                                existingByIp.Target = new Target
                                {
                                    Name = old.Name,
                                    Host = old.Host,
                                    Service = old.Service,
                                    Critical = old.Critical,
                                    FallbackIp = old.FallbackIp,
                                    SniHost = newHostname,
                                    ReverseDnsHost = old.ReverseDnsHost
                                };
                            }
                        }
                    }
                }
                else if (msg.StartsWith("❌ "))
                {
                    // Формат: "❌ 1.2.3.4:443 | DNS:✓ TCP:✓ TLS:✗ | TLS_AUTH_FAILURE"
                    var parts = msg.Substring(2).Split('|');
                    if (parts.Length > 0)
                    {
                        var hostPortStr = parts[0].Trim().Split(' ')[0];
                        var hostPort = hostPortStr.Split(':');
                        if (hostPort.Length == 2)
                        {
                            var host = hostPort[0];
                            var uiKey = SelectUiKey(host, msg);
                            var fallbackIp = IPAddress.TryParse(host, out _) ? host : null;
                            
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
                            var hasTlsAuthFailure = BlockageCode.ContainsCode(msg, BlockageCode.TlsAuthFailure);
                            if (hasTlsAuthFailure)
                            {
                                msg += "\nℹ️ TLS рукопожатие завершилось ошибкой аутентификации (auth failure). Это факт, но не доказательство DPI.";
                                
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
                            
                            UpdateTestResult(uiKey, status, StripNameTokens(msg), fallbackIp);
                            _lastUpdatedHost = uiKey;

                            ApplyNameTokensFromMessage(uiKey, msg);
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
                    var isV2 = msg.TrimStart().StartsWith("[V2]", StringComparison.OrdinalIgnoreCase);

                    // v2 — единственный источник рекомендаций для UI.
                    // Legacy сообщения могут присутствовать в логе, но не должны менять стратегию карточки.
                    if (!isV2)
                    {
                        return;
                    }

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

                        // v2 может выдавать список стратегий в одной строке (через запятую/плюс),
                        // чтобы не перегружать UI. Для поля стратегии берём первую.
                        var first = strategy
                            .Split(new[] { ',', '+', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                            .FirstOrDefault();
                        if (!string.IsNullOrWhiteSpace(first))
                        {
                            strategy = first;
                        }

                        var result = TestResults.FirstOrDefault(t => 
                            t.Target.Host == _lastUpdatedHost || t.Target.Name == _lastUpdatedHost);
                        if (result != null)
                        {
                            result.BypassStrategy = strategy;
                            if (isV2)
                            {
                                result.IsBypassStrategyFromV2 = true;
                            }
                            
                            if (strategy == "ROUTER_REDIRECT")
                            {
                                result.Status = TestStatus.Warn;
                                result.Details = result.Details?.Replace("Блокировка", "Информация: Fake IP (VPN/туннель)") 
                                    ?? "Fake IP обнаружен";
                                Log($"[UI] ROUTER_REDIRECT → Status=Warn для {_lastUpdatedHost}");
                            }
                            else if (strategy != PipelineContract.BypassNone && strategy != PipelineContract.BypassUnknown)
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
                var dns = ExtractToken(msg, "DNS");
                var rdns = ExtractToken(msg, "RDNS");

                if (string.IsNullOrWhiteSpace(sni) && string.IsNullOrWhiteSpace(rdns)) return;

                var result = TestResults.FirstOrDefault(t => t.Target.Host == hostKey || t.Target.FallbackIp == hostKey);
                if (result == null) return;

                // Если hostKey это IP, а SNI уже есть — мигрируем карточку на человеко-понятный ключ.
                if (IPAddress.TryParse(hostKey, out _) && !string.IsNullOrWhiteSpace(sni) && sni != "-")
                {
                    var normalizedSni = NormalizeHost(sni);
                    _ipToUiKey[hostKey] = normalizedSni;
                    TryMigrateIpCardToNameKey(hostKey, normalizedSni);
                }

                // 1) Настоящий SNI имеет приоритет
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
                // 2) Если SNI не пойман — используем DNS как "хост" для колонки SNI
                else if (!string.IsNullOrWhiteSpace(dns) && dns != "-" && string.IsNullOrWhiteSpace(result.Target.SniHost))
                {
                    var old = result.Target;
                    result.Target = new Target
                    {
                        Name = old.Name,
                        Host = old.Host,
                        Service = old.Service,
                        Critical = old.Critical,
                        FallbackIp = old.FallbackIp,
                        SniHost = dns,
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
                cleaned = Regex.Replace(cleaned, @"\s+DNS=[^\s\|]+", string.Empty, RegexOptions.IgnoreCase);
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

        private string SelectUiKey(string hostFromLine, string msg)
        {
            // 1) Если в сообщении есть SNI/DNS — это приоритетный пользовательский ключ.
            var sni = ExtractToken(msg, "SNI");
            if (!string.IsNullOrWhiteSpace(sni) && sni != "-")
            {
                return NormalizeHost(sni);
            }

            // 2) Если host из строки — IP, но мы уже знаем сопоставление IP→SNI, используем его.
            if (IPAddress.TryParse(hostFromLine, out _) && _ipToUiKey.TryGetValue(hostFromLine, out var mapped))
            {
                return NormalizeHost(mapped);
            }

            // 3) Иначе используем то, что пришло.
            return NormalizeHost(hostFromLine);
        }

        private TestStatus ApplyUnstableRule(string normalizedKey, TestStatus incoming)
        {
            var now = DateTime.UtcNow;
            var history = _outcomeHistoryByKey.GetOrAdd(normalizedKey, _ => new OutcomeHistory(DateTime.MinValue, DateTime.MinValue));

            var lastPass = history.LastPassUtc;
            var lastProblem = history.LastProblemUtc;

            if (incoming == TestStatus.Pass)
            {
                lastPass = now;
            }

            if (incoming == TestStatus.Fail || incoming == TestStatus.Warn)
            {
                lastProblem = now;
            }

            _outcomeHistoryByKey[normalizedKey] = new OutcomeHistory(lastPass, lastProblem);

            var hasRecentPass = lastPass != DateTime.MinValue && now - lastPass <= UnstableWindow;
            var hasRecentProblem = lastProblem != DateTime.MinValue && now - lastProblem <= UnstableWindow;

            // Если в окне есть и успех и проблема — показываем «Нестабильно».
            if (hasRecentPass && hasRecentProblem)
            {
                return TestStatus.Warn;
            }

            return incoming;
        }

        private void TryMigrateIpCardToNameKey(string ip, string nameKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(nameKey)) return;
                if (!IPAddress.TryParse(ip, out _)) return;

                nameKey = NormalizeHost(nameKey);
                if (IPAddress.TryParse(nameKey, out _)) return;

                // Переносим историю исходов на человеко‑понятный ключ.
                // Иначе: Fail мог быть записан на IP, а Pass уже придёт на hostname → UI покажет "Доступно" вместо "Нестабильно".
                MergeOutcomeHistoryKeys(ip, nameKey);

                var ipCard = TestResults.FirstOrDefault(t => t.Target.Host == ip || t.Target.FallbackIp == ip);
                if (ipCard == null) return;

                var normalizedName = NormalizeHost(nameKey);
                var nameCard = TestResults.FirstOrDefault(t =>
                    NormalizeHost(t.Target.Host).Equals(normalizedName, StringComparison.OrdinalIgnoreCase) ||
                    NormalizeHost(t.Target.Name).Equals(normalizedName, StringComparison.OrdinalIgnoreCase));

                if (nameCard == null)
                {
                    // Переименовываем существующую карточку (IP → hostname) и сохраняем IP в FallbackIp.
                    var old = ipCard.Target;
                    ipCard.Target = new Target
                    {
                        Name = nameKey,
                        Host = nameKey,
                        Service = old.Service,
                        Critical = old.Critical,
                        FallbackIp = string.IsNullOrWhiteSpace(old.FallbackIp) ? ip : old.FallbackIp,
                        SniHost = string.IsNullOrWhiteSpace(old.SniHost) ? nameKey : old.SniHost,
                        ReverseDnsHost = old.ReverseDnsHost
                    };
                    return;
                }

                // Если карточка по имени уже существует — сливаем и удаляем IP-карточку.
                if (string.IsNullOrWhiteSpace(nameCard.Target.FallbackIp))
                {
                    var old = nameCard.Target;
                    nameCard.Target = new Target
                    {
                        Name = old.Name,
                        Host = old.Host,
                        Service = old.Service,
                        Critical = old.Critical,
                        FallbackIp = ip,
                        SniHost = old.SniHost,
                        ReverseDnsHost = old.ReverseDnsHost
                    };
                }

                // Берём более «плохой» статус как базовый.
                var mergedStatus = MergeStatus(nameCard.Status, ipCard.Status);
                nameCard.Status = mergedStatus;

                if (!string.IsNullOrWhiteSpace(ipCard.Details) && (string.IsNullOrWhiteSpace(nameCard.Details) || !nameCard.Details.Contains(ipCard.Details, StringComparison.OrdinalIgnoreCase)))
                {
                    nameCard.Details = string.IsNullOrWhiteSpace(nameCard.Details)
                        ? ipCard.Details
                        : nameCard.Details + "\n" + ipCard.Details;
                }

                if (!string.IsNullOrWhiteSpace(ipCard.Error) && string.IsNullOrWhiteSpace(nameCard.Error))
                {
                    nameCard.Error = ipCard.Error;
                }

                TestResults.Remove(ipCard);
                NotifyCountersChanged();
            }
            catch
            {
            }
        }

        private void MergeOutcomeHistoryKeys(string fromKey, string toKey)
        {
            try
            {
                fromKey = NormalizeHost(fromKey);
                toKey = NormalizeHost(toKey);

                if (string.IsNullOrWhiteSpace(fromKey) || string.IsNullOrWhiteSpace(toKey)) return;
                if (fromKey.Equals(toKey, StringComparison.OrdinalIgnoreCase)) return;

                if (!_outcomeHistoryByKey.TryGetValue(fromKey, out var fromHistory))
                {
                    return;
                }

                var toHistory = _outcomeHistoryByKey.GetOrAdd(toKey, _ => new OutcomeHistory(DateTime.MinValue, DateTime.MinValue));

                var merged = new OutcomeHistory(
                    LastPassUtc: fromHistory.LastPassUtc > toHistory.LastPassUtc ? fromHistory.LastPassUtc : toHistory.LastPassUtc,
                    LastProblemUtc: fromHistory.LastProblemUtc > toHistory.LastProblemUtc ? fromHistory.LastProblemUtc : toHistory.LastProblemUtc);

                _outcomeHistoryByKey[toKey] = merged;

                // Удаляем исходный ключ, чтобы не копить мусор.
                _outcomeHistoryByKey.TryRemove(fromKey, out _);
            }
            catch
            {
            }
        }

        private static TestStatus MergeStatus(TestStatus a, TestStatus b)
        {
            static int Rank(TestStatus s) => s switch
            {
                TestStatus.Fail => 4,
                TestStatus.Warn => 3,
                TestStatus.Running => 2,
                TestStatus.Pass => 1,
                _ => 0
            };

            return Rank(a) >= Rank(b) ? a : b;
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
