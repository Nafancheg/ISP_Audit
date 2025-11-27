using System.Collections.Generic;
using System.Linq;
using IspAudit.Output;
using IspAudit.Core.Models;

namespace IspAudit.Bypass
{
    public class StrategyRecommendation
    {
        // Use HashSet internally to prevent duplicates while maintaining insertion order (mostly)
        // Actually HashSet doesn't guarantee order, but we want priority.
        // So let's use List and check Contains before adding.
        private readonly List<string> _applicable = new();
        private readonly List<string> _manual = new();

        public List<string> Applicable => _applicable;
        public List<string> Manual => _manual;
        
        public void AddApplicable(string strategy)
        {
            if (!_applicable.Contains(strategy)) _applicable.Add(strategy);
        }

        public void AddManual(string strategy)
        {
            if (!_manual.Contains(strategy)) _manual.Add(strategy);
        }

        public List<string> GetAll() => _applicable.Concat(_manual).Distinct().ToList();
    }

    public static class StrategyMapping
    {
        public static StrategyRecommendation GetStrategiesFor(TargetReport target)
        {
            var rec = new StrategyRecommendation();

            // 0. Analyze DNS issues
            if (target.dns_status == "DNS_FILTERED" || target.dns_status == "DNS_BOGUS")
            {
                rec.AddManual("DOH");
            }

            // 1. Analyze HTTP/TLS issues
            bool httpFailed = target.http_enabled && target.http.Any(h => !h.success || h.is_block_page == true);
            bool tcpOpen = target.tcp_enabled && target.tcp.Any(t => t.open);

            if (httpFailed && tcpOpen)
            {
                AddTlsStrategies(rec);
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
                rec.AddManual("DOH");
            }

            // 1. Analyze TLS/HTTP issues (TCP OK, but TLS Failed)
            if (result.TcpOk && !result.TlsOk)
            {
                // Prioritize DROP_RST as it's faster and often sufficient for RST injection on TLS ClientHello
                rec.AddApplicable("DROP_RST");
                AddTlsStrategies(rec);
            }

            // 2. Analyze TCP issues (TCP Failed)
            if (!result.TcpOk)
            {
                long elapsed = result.TcpLatencyMs ?? 0;
                AnalyzeTcpFailure(rec, elapsed, result.BlockageType);
            }

            return rec;
        }

        private static void AddTlsStrategies(StrategyRecommendation rec)
        {
            rec.AddApplicable("TLS_FRAGMENT");
            rec.AddApplicable("TLS_FAKE");
            rec.AddApplicable("TLS_FAKE_FRAGMENT");
        }

        private static void AnalyzeTcpFailure(StrategyRecommendation rec, long minElapsed, string? blockageType)
        {
            if (blockageType == "PORT_CLOSED") return;

            bool isTimeout = blockageType == "TCP_TIMEOUT" || minElapsed > 2000;
            // If minElapsed is 0, it could be a very fast local failure (e.g. interface down) or instant RST.
            // We treat 0 as potential RST too, just to be safe.
            bool isRst = blockageType == "TCP_RST" || minElapsed < 200;

            if (isRst)
            {
                rec.AddApplicable("DROP_RST");
            }
            else if (isTimeout)
            {
                rec.AddManual("PROXY");
            }
            else
            {
                // Intermediate timing or unknown -> Try DROP_RST just in case
                rec.AddApplicable("DROP_RST");
            }

            // Fallback: sometimes TCP "fails" but it's actually TLS-level block (DPI drops packet)
            // Add TLS strategies with lower priority
            AddTlsStrategies(rec);
        }
    }
}
