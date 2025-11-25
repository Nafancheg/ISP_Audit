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
                // TCP handshake fails -> Could be RST injection or IP block
                strategies.Add("DROP_RST");
                
                // Some DPIs block ClientHello even if TCP handshake succeeds, but here TCP failed.
                // However, sometimes "TCP Failed" in our test might mean "Connect timed out" which could be due to dropped packets.
                // If it's a timeout, RST blocker won't help (unless they send RST later).
                // But if it's immediate failure, it might be RST.
                // We don't have granular "Timeout" vs "Refused" in TcpResult (it just has elapsed_ms).
                // But let's try DROP_RST anyway.
            }

            return strategies.Distinct().ToList();
        }

        public static List<string> GetStrategiesFor(HostTested result)
        {
            var strategies = new List<string>();

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
                // TCP handshake fails -> Could be RST injection
                strategies.Add("DROP_RST");
            }

            return strategies.Distinct().ToList();
        }
    }
}
