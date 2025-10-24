using System;
using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;
using IspAudit.Utils;

namespace IspAudit.Tests
{
    public record RstHeuristicResult(string ip, int port, bool connectSucceeded, long elapsedMs);

    public class RstHeuristic
    {
        private readonly Config _cfg;
        public RstHeuristic(Config cfg) { _cfg = cfg; }

        public async Task<RstHeuristicResult> CheckAsync()
        {
            var ip = "1.1.1.1"; // Cloudflare
            int port = 81;       // usually closed
            var sw = Stopwatch.StartNew();
            bool ok = await NetUtils.TcpConnectTryAsync(IPAddress.Parse(ip), port, _cfg.TcpTimeoutSeconds * 1000).ConfigureAwait(false);
            sw.Stop();
            return new RstHeuristicResult(ip, port, ok, sw.ElapsedMilliseconds);
        }
    }
}

