using System;
using System.Linq;
using System.Net;
using IspAudit.Core.Diagnostics;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        /// <summary>
        /// Обновление результата теста
        /// </summary>
        public void UpdateTestResult(string host, TestStatus status, string details, string? fallbackIp = null)
        {
            // КРИТИЧНО: Фильтруем шумные хосты ПЕРЕД созданием карточки.
            // Шумовые домены (фоновые/служебные) не должны засорять UI и влиять на UX применения обхода,
            // даже если тестер/классификатор ошибочно пометил их как проблемные.
            if (!string.IsNullOrWhiteSpace(host) &&
                !IPAddress.TryParse(host, out _) &&
                _noiseHostFilter.IsNoiseHost(host))
            {
                // Важно: шум должен скрывать только «OK/успех».
                // Если по шумовому ключу пришла проблема (Fail/Warn) — НЕ удаляем и НЕ скрываем,
                // иначе UI выглядит как «мигающий»/хаотичный и теряется контекст диагностики.
                if (status == TestStatus.Pass || status == TestStatus.Idle || status == TestStatus.Running)
                {
                    var toRemove = TestResults.FirstOrDefault(t =>
                        t.Target.Host == host || t.Target.Name == host);
                    if (toRemove != null)
                    {
                        TestResults.Remove(toRemove);
                        _testResultMap.TryRemove(host, out _);
                        Log($"[UI] Удалена шумовая карточка (успех): {host}");
                        NotifyCountersChanged();
                    }
                    return; // Не создаём новую карточку для шумового успеха
                }
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
                existing.UiKey = normalizedHost;
                existing.AggregatedMemberCount = GetAggregatedMemberCount(normalizedHost);

                // P1.9: если это агрегированная строка по groupKey и мы узнали якорный домен,
                // обновим Target.Host/SniHost для корректного DisplayHost.
                if (_groupKeyToAnchorDomain.TryGetValue(normalizedHost, out var anchor) && !string.IsNullOrWhiteSpace(anchor))
                {
                    var old = existing.Target;
                    if (old != null
                        && string.Equals(NormalizeHost(old.Name), normalizedHost, StringComparison.OrdinalIgnoreCase)
                        && (string.IsNullOrWhiteSpace(old.SniHost) || string.Equals(NormalizeHost(old.Host), normalizedHost, StringComparison.OrdinalIgnoreCase)))
                    {
                        existing.Target = new Target
                        {
                            Name = old.Name,
                            Host = anchor,
                            Service = old.Service,
                            Critical = old.Critical,
                            FallbackIp = old.FallbackIp,
                            SniHost = anchor,
                            ReverseDnsHost = old.ReverseDnsHost
                        };
                    }
                }

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
                var anchor = string.Empty;
                if (_groupKeyToAnchorDomain.TryGetValue(normalizedHost, out var cachedAnchor) && !string.IsNullOrWhiteSpace(cachedAnchor))
                {
                    anchor = cachedAnchor;
                }

                var target = new Target
                {
                    // P1.9: если host — это groupKey, то Name хранит groupKey, а Host/SniHost — якорный домен.
                    Name = host,
                    Host = string.IsNullOrWhiteSpace(anchor) ? host : anchor,
                    Service = "Unknown",
                    Critical = false,
                    FallbackIp = fallbackIp ?? "",
                    SniHost = string.IsNullOrWhiteSpace(anchor) ? string.Empty : anchor
                };

                existing = new TestResult { Target = target, Status = status, Details = details };

                existing.UiKey = normalizedHost;
                existing.AggregatedMemberCount = GetAggregatedMemberCount(normalizedHost);

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
    }
}
