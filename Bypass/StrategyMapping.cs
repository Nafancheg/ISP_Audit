using System.Collections.Generic;
using System.Linq;
using IspAudit.Output;
using IspAudit.Core.Models;

namespace IspAudit.Bypass
{
    public static class StrategyMapping
    {
        public static List<string> GetStrategiesFor(TargetReport target)
        {
            var strategies = new List<string>();

            // 0. Analyze DNS issues
            if (target.dns_status == "DNS_FILTERED" || target.dns_status == "DNS_BOGUS")
            {
                strategies.Add("DOH");
                // If DNS is broken, other strategies might not work or be relevant yet
                // But we can still try packet-level bypass if IP is known
            }

            // 1. Analyze HTTP/TLS issues
            // If HTTP is enabled and failed (no success OR block page detected)
            bool httpFailed = target.http_enabled && target.http.Any(h => !h.success || h.is_block_page == true);
            
            // Check if TCP is actually open. If TCP is closed, HTTP fail is expected, so we should focus on TCP first.
            bool tcpOpen = target.tcp_enabled && target.tcp.Any(t => t.open);

            if (httpFailed && tcpOpen)
            {
                // TCP works, but HTTP fails -> DPI or Block Page
                // Try fragmentation strategies in order of least invasiveness/most likely to work
                strategies.Add("TLS_FRAGMENT");
                strategies.Add("TLS_FAKE");
                strategies.Add("TLS_FAKE_FRAGMENT");
            }

            // 2. Analyze TCP issues
            bool tcpFailed = target.tcp_enabled && !target.tcp.Any(t => t.open);
            if (tcpFailed)
            {
                // Analyze TCP failure reason based on timing
                // We take the minimum elapsed time to see the fastest failure (likely RST)
                var minElapsed = target.tcp.Any() ? target.tcp.Min(t => t.elapsed_ms) : 0;
                
                if (minElapsed < 200) // Fast failure -> Likely RST injection
                {
                    strategies.Add("DROP_RST");
                }
                else if (minElapsed > 2000) // Slow failure -> Likely Timeout / Drop
                {
                    strategies.Add("PROXY"); // Suggest Proxy/VPN for IP blocks
                    // DROP_RST unlikely to help with timeouts, but sometimes DPI drops SYN-ACK
                    // We can add it as a fallback
                }
                else
                {
                    // Intermediate timing or unknown -> Try DROP_RST just in case
                    strategies.Add("DROP_RST");
                }
            }

            return strategies.Distinct().ToList();
        }

        public static List<string> GetStrategiesFor(HostTested result)
        {
            var strategies = new List<string>();

            // 0. Analyze DNS issues
            if (result.DnsStatus == "DNS_FILTERED" || result.DnsStatus == "DNS_BOGUS")
            {
                strategies.Add("DOH");
            }

            // 1. Analyze TLS/HTTP issues (TCP OK, but TLS Failed)
            if (result.TcpOk && !result.TlsOk)
            {
                // DPI blocking ClientHello or sending RST after handshake
                strategies.Add("TLS_FRAGMENT");
                strategies.Add("TLS_FAKE");
                strategies.Add("TLS_FAKE_FRAGMENT");
                
                // Sometimes RST is sent during TLS handshake
                strategies.Add("DROP_RST");
            }

            // 2. Analyze TCP issues (TCP Failed)
            if (!result.TcpOk)
            {
                if (result.BlockageType == "TCP_RST")
                {
                    strategies.Add("DROP_RST");
                }
                else if (result.BlockageType == "TCP_TIMEOUT")
                {
                    strategies.Add("PROXY");
                }
                else if (result.BlockageType == "PORT_CLOSED")
                {
                    // Port closed -> No bypass possible (server down or firewall)
                    // Return empty list or specific "NONE" strategy
                    return new List<string>(); 
                }
                else
                {
                    // Heuristic based on latency if available
                    if (result.TcpLatencyMs.HasValue && result.TcpLatencyMs < 200)
                    {
                        strategies.Add("DROP_RST");
                    }
                    else
                    {
                        // Default fallback
                        strategies.Add("DROP_RST");
                    }
                }
            }

            return strategies.Distinct().ToList();
        }
    }
}
