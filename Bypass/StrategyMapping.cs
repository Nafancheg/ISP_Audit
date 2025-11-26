using System.Collections.Generic;
using System.Linq;
using IspAudit.Output;
using IspAudit.Core.Models;

namespace IspAudit.Bypass
{
    public class StrategyRecommendation
    {
        public List<string> Applicable { get; set; } = new();  // WinDivert может применить
        public List<string> Manual { get; set; } = new();      // Требуют действий пользователя
        
        public List<string> GetAll() => Applicable.Concat(Manual).Distinct().ToList();
    }

    public static class StrategyMapping
    {
        public static StrategyRecommendation GetStrategiesFor(TargetReport target)
        {
            var rec = new StrategyRecommendation();

            // 0. Analyze DNS issues
            if (target.dns_status == "DNS_FILTERED" || target.dns_status == "DNS_BOGUS")
            {
                rec.Manual.Add("DOH");
            }

            // 1. Analyze HTTP/TLS issues
            bool httpFailed = target.http_enabled && target.http.Any(h => !h.success || h.is_block_page == true);
            bool tcpOpen = target.tcp_enabled && target.tcp.Any(t => t.open);

            if (httpFailed && tcpOpen)
            {
                rec.Applicable.Add("TLS_FRAGMENT");
                rec.Applicable.Add("TLS_FAKE");
                rec.Applicable.Add("TLS_FAKE_FRAGMENT");
            }

            // 2. Analyze TCP issues
            bool tcpFailed = target.tcp_enabled && !target.tcp.Any(t => t.open);
            if (tcpFailed)
            {
                var minElapsed = target.tcp.Any() ? target.tcp.Min(t => t.elapsed_ms) : 0;
                // TargetReport doesn't have explicit BlockageType per se, usually inferred.
                // We rely on timing.
                AnalyzeTcpFailure(rec, minElapsed, null);
            }

            return rec;
        }

        public static StrategyRecommendation GetStrategiesFor(HostTested result)
        {
            var rec = new StrategyRecommendation();

            // 0. Analyze DNS issues
            if (result.DnsStatus == "DNS_FILTERED" || result.DnsStatus == "DNS_BOGUS")
            {
                rec.Manual.Add("DOH");
            }

            // 1. Analyze TLS/HTTP issues (TCP OK, but TLS Failed)
            if (result.TcpOk && !result.TlsOk)
            {
                rec.Applicable.Add("TLS_FRAGMENT");
                rec.Applicable.Add("TLS_FAKE");
                rec.Applicable.Add("TLS_FAKE_FRAGMENT");
                rec.Applicable.Add("DROP_RST");
            }

            // 2. Analyze TCP issues (TCP Failed)
            if (!result.TcpOk)
            {
                long elapsed = result.TcpLatencyMs ?? 0;
                AnalyzeTcpFailure(rec, elapsed, result.BlockageType);
            }

            return rec;
        }

        private static void AnalyzeTcpFailure(StrategyRecommendation rec, long minElapsed, string? blockageType)
        {
            if (blockageType == "PORT_CLOSED") return;

            bool isTimeout = blockageType == "TCP_TIMEOUT" || minElapsed > 2000;
            bool isRst = blockageType == "TCP_RST" || (minElapsed > 0 && minElapsed < 200);

            if (isRst)
            {
                rec.Applicable.Add("DROP_RST");
            }
            else if (isTimeout)
            {
                rec.Manual.Add("PROXY");
            }
            else
            {
                // Intermediate timing or unknown -> Try DROP_RST just in case
                rec.Applicable.Add("DROP_RST");
            }

            // Fallback: sometimes TCP "fails" but it's actually TLS-level block (DPI drops packet)
            // Add TLS strategies with lower priority
            rec.Applicable.Add("TLS_FRAGMENT");
            rec.Applicable.Add("TLS_FAKE");
            rec.Applicable.Add("TLS_FAKE_FRAGMENT");
        }
    }
}
