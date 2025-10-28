using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IspAudit.Tests
{
    public record TraceHop(int hop, string ip, string status);
    public record TraceResult(List<string> rawOutput, List<TraceHop> hops);

    public class TracerouteTest
    {
        private readonly Config _cfg;
        public TracerouteTest(Config cfg) { _cfg = cfg; }

        public async Task<TraceResult> RunAsync(string host, IProgress<string>? progress = null, System.Threading.CancellationToken ct = default)
        {
            var lines = new List<string>();
            var hops = new List<TraceHop>();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "tracert",
                    Arguments = $"-d -h 15 -w 2000 {host}", // Уменьшили до 15 хопов и таймаут 2сек на хоп
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.GetEncoding(866), // OEM Russian, чтобы не было кракозябр
                    StandardErrorEncoding = Encoding.GetEncoding(866)
                };
                using var p = new Process { StartInfo = psi };
                p.Start();
                while (!p.StandardOutput.EndOfStream)
                {
                    if (ct.IsCancellationRequested)
                    {
                        try { if (!p.HasExited) p.Kill(); } catch { }
                        ct.ThrowIfCancellationRequested();
                    }
                    var line = await p.StandardOutput.ReadLineAsync().ConfigureAwait(false);
                    if (line == null) break;
                    lines.Add(line);
                    progress?.Report(line);
                    var hop = ParseHop(line);
                    if (hop != null) hops.Add(hop);
                }
                // drain stderr
                var _ = p.StandardError.ReadToEnd();
                // Таймаут: 15 хопов * 2сек + запас = макс 35 сек
                if (!p.WaitForExit(35000))
                {
                    try { if (!p.HasExited) p.Kill(); } catch { }
                    lines.Add("tracert: превышен таймаут ожидания");
                }
            }
            catch (Exception ex)
            {
                lines.Add($"tracert error: {ex.Message}");
            }

            return new TraceResult(lines, hops);
        }

        private static TraceHop? ParseHop(string line)
        {
            // Match: 1   10.0.0.1   1 ms  1 ms  1 ms
            // Or:    2   * * * Request timed out.
            var m = Regex.Match(line, @"^\s*(\d+)\s+([\d\.\*]+)");
            if (!m.Success) return null;
            int hop = int.Parse(m.Groups[1].Value);
            string token = m.Groups[2].Value;
            string ip = token.Contains('*') ? "*" : token;
            string status = token.Contains('*') ? "TimedOut" : "Hop";
            return new TraceHop(hop, ip, status);
        }
    }
}
