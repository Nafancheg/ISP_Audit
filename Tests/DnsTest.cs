using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using IspAudit.Utils;

namespace IspAudit.Tests
{
    public enum DnsStatus { OK, DNS_FILTERED, DNS_BOGUS, WARN }

    public record DnsResult(List<string> SystemV4, List<string> DohV4, DnsStatus Status);

    public class DnsTest
    {
        private readonly Config _cfg;
        private const string DoHUrlTemplate = "https://cloudflare-dns.com/dns-query?name={0}&type=A";

        public DnsTest(Config cfg)
        {
            _cfg = cfg;
        }

        public async Task<DnsResult> ResolveAsync(string host)
        {
            var sysV4 = (await NetUtils.SafeDnsGetV4Async(host).ConfigureAwait(false)).Select(a => a.ToString()).ToList();
            var dohV4 = await ResolveDohAAsync(host).ConfigureAwait(false);

            // Status logic
            var status = DnsStatus.OK;
            if (sysV4.Count == 0 && dohV4.Count > 0)
            {
                status = DnsStatus.DNS_FILTERED;
            }
            else if (sysV4.Any(ip => NetUtils.IsBogusIPv4(IPAddress.Parse(ip))))
            {
                status = DnsStatus.DNS_BOGUS;
            }
            else if (sysV4.Count > 0 && dohV4.Count > 0)
            {
                var s1 = new HashSet<string>(sysV4);
                var s2 = new HashSet<string>(dohV4);
                var inter = s1.Intersect(s2).Any();
                if (!inter) status = DnsStatus.WARN; // possible CDN/geo, flag warn
            }
            return new DnsResult(sysV4, dohV4, status);
        }

        private async Task<List<string>> ResolveDohAAsync(string host)
        {
            var res = new List<string>();
            using var handler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(_cfg.HttpTimeoutSeconds) };
            var url = string.Format(DoHUrlTemplate, Uri.EscapeDataString(host));

            async Task<bool> TryOnce()
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, url);
                    req.Headers.Accept.ParseAdd("application/dns-json");
                    using var resp = await http.SendAsync(req).ConfigureAwait(false);
                    resp.EnsureSuccessStatusCode();
                    var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("Answer", out var ans) && ans.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var entry in ans.EnumerateArray())
                        {
                            if (entry.TryGetProperty("type", out var t) && t.GetInt32() == 1 && entry.TryGetProperty("data", out var data))
                            {
                                var ip = data.GetString();
                                if (!string.IsNullOrWhiteSpace(ip)) res.Add(ip);
                            }
                        }
                    }
                    return true;
                }
                catch (TaskCanceledException)
                {
                    return false;
                }
                catch
                {
                    return true; // don't retry for non-timeouts
                }
            }

            // up to 2 attempts on timeout
            if (!await TryOnce().ConfigureAwait(false))
            {
                await Task.Delay(250).ConfigureAwait(false);
                await TryOnce().ConfigureAwait(false);
            }

            // Filter out bogus entries if any DoH returns nonsense
            res = res.Where(s => IPAddress.TryParse(s, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
            return res.Distinct().ToList();
        }
    }
}

