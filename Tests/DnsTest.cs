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

    public record DnsResult(List<string> SystemV4, List<string> DohV4, List<string> GoogleV4, DnsStatus Status);

    public class DnsTest
    {
        private readonly Config _cfg;
        private const string DoHUrlTemplate = "https://cloudflare-dns.com/dns-query?name={0}&type=A";
        private const string GoogleDnsUrlTemplate = "https://dns.google/resolve?name={0}&type=A";

        public DnsTest(Config cfg)
        {
            _cfg = cfg;
        }

        public async Task<DnsResult> ResolveAsync(string host)
        {
            var sysV4 = (await NetUtils.SafeDnsGetV4Async(host).ConfigureAwait(false)).Select(a => a.ToString()).ToList();
            var dohV4 = await ResolveDohAAsync(host).ConfigureAwait(false);
            var googleV4 = await QueryGoogleDnsAsync(host).ConfigureAwait(false);

            // Simplified status logic - ONLY System DNS determines status
            // DoH and Google DNS are kept for informational purposes only
            var status = DetermineDnsStatus(sysV4);

            return new DnsResult(sysV4, dohV4, googleV4, status);
        }

        private DnsStatus DetermineDnsStatus(List<string> systemV4)
        {
            // 1. System DNS returned no addresses → DNS_FILTERED
            if (systemV4.Count == 0)
            {
                return DnsStatus.DNS_FILTERED;
            }

            // 2. System DNS returned bogus IPs (0.0.0.0, 127.x, etc) → DNS_BOGUS
            if (systemV4.Any(ip => NetUtils.IsBogusIPv4(IPAddress.Parse(ip))))
            {
                return DnsStatus.DNS_BOGUS;
            }

            // 3. System DNS returned valid public addresses → OK
            return DnsStatus.OK;
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
                    return false; // Timeout - retry
                }
                catch (HttpRequestException)
                {
                    return false; // Network error - retry
                }
                catch (System.Net.Sockets.SocketException)
                {
                    return false; // Socket error - retry
                }
                catch
                {
                    return true; // Other errors (JSON parse, etc) - don't retry
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

        private async Task<List<string>> QueryGoogleDnsAsync(string host)
        {
            var res = new List<string>();
            using var handler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(_cfg.HttpTimeoutSeconds) };
            var url = string.Format(GoogleDnsUrlTemplate, Uri.EscapeDataString(host));

            async Task<bool> TryOnce()
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, url);
                    req.Headers.Accept.ParseAdd("application/json");
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
                    return false; // Timeout - retry
                }
                catch (HttpRequestException)
                {
                    return false; // Network error - retry
                }
                catch (System.Net.Sockets.SocketException)
                {
                    return false; // Socket error - retry
                }
                catch
                {
                    return true; // Other errors (JSON parse, etc) - don't retry
                }
            }

            // up to 2 attempts on timeout (3s timeout as per plan)
            if (!await TryOnce().ConfigureAwait(false))
            {
                await Task.Delay(250).ConfigureAwait(false);
                await TryOnce().ConfigureAwait(false);
            }

            // Filter out bogus entries if any Google DNS returns nonsense
            res = res.Where(s => IPAddress.TryParse(s, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
            return res.Distinct().ToList();
        }
    }
}
