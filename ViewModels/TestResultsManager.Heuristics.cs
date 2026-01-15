using System;
using System.Linq;
using System.Net;
using IspAudit.Core.Diagnostics;
using IspAudit.Models;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
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
    }
}
