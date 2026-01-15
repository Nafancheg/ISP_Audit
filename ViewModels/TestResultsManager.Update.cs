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
                NoiseHostFilter.Instance.IsNoiseHost(host))
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
    }
}
