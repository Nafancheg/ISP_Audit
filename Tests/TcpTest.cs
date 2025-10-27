using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Linq;
using System.Threading.Tasks;
using IspAudit.Utils;

namespace IspAudit.Tests
{
    public record TcpResult(string ip, int port, bool open, long elapsed_ms);

    public class TcpTest
    {
        private readonly Config _cfg;
        public TcpTest(Config cfg) { _cfg = cfg; }

        public async Task<List<TcpResult>> CheckAsync(string host, List<string> systemIps, IEnumerable<int>? portsOverride = null)
        {
            var results = new List<TcpResult>();
            var ips = new List<IPAddress>();
            foreach (var s in systemIps)
            {
                if (IPAddress.TryParse(s, out var ip)) ips.Add(ip);
            }
            if (ips.Count == 0)
            {
                // Fall back to DNS resolve
                var resolved = await NetUtils.SafeDnsGetV4Async(host).ConfigureAwait(false);
                ips.AddRange(resolved);
            }

            var ports = (portsOverride ?? _cfg.Ports)
                .Where(p => p > 0 && p <= 65535)
                .Distinct()
                .ToList();
            if (ports.Count == 0)
            {
                ports = _cfg.Ports;
            }

            foreach (var ip in ips)
            {
                foreach (var port in ports)
                {
                    var open = await ProbeWithRetry(ip, port).ConfigureAwait(false);
                    results.Add(open);
                }
            }
            return results;
        }

        private async Task<TcpResult> ProbeWithRetry(IPAddress ip, int port)
        {
            var sw = Stopwatch.StartNew();
            bool ok = await NetUtils.TcpConnectTryAsync(ip, port, _cfg.TcpTimeoutSeconds * 1000).ConfigureAwait(false);
            sw.Stop();
            if (!ok)
            {
                await Task.Delay(500).ConfigureAwait(false);
                sw.Restart();
                ok = await NetUtils.TcpConnectTryAsync(ip, port, _cfg.TcpTimeoutSeconds * 1000).ConfigureAwait(false);
                sw.Stop();
            }
            return new TcpResult(ip.ToString(), port, ok, sw.ElapsedMilliseconds);
        }
    }
}

