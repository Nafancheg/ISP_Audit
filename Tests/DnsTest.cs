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

            // Status logic - comparing three sources: System DNS, DoH (Cloudflare), Google DNS
            var status = DnsStatus.OK;
            bool isVpnProfile = string.Equals(_cfg.Profile, "vpn", StringComparison.OrdinalIgnoreCase);

            if (sysV4.Count == 0 && (dohV4.Count > 0 || googleV4.Count > 0))
            {
                // System DNS returns nothing, but DoH or Google DNS works
                // В VPN-профиле это может быть нормально (VPN DNS не разрешает некоторые домены)
                status = isVpnProfile ? DnsStatus.WARN : DnsStatus.DNS_FILTERED;
            }
            else if (sysV4.Any(ip => NetUtils.IsBogusIPv4(IPAddress.Parse(ip))))
            {
                // System DNS returns truly bogus IPs (0.0.0.0, 127.x, 169.254.x, multicast, etc)
                status = DnsStatus.DNS_BOGUS;
            }
            else if (sysV4.Count > 0 && sysV4.All(ip => NetUtils.IsPrivateIPv4(IPAddress.Parse(ip))) && (dohV4.Count > 0 || googleV4.Count > 0))
            {
                // System DNS returns ONLY private IPs (10.x, 172.16-31.x, 192.168.x), but DoH/Google returns public IPs
                // This is common in corporate networks with proxy/NAT or VPN
                status = DnsStatus.WARN;
            }
            else if (sysV4.Count > 0 && (dohV4.Count > 0 || googleV4.Count > 0))
            {
                // Compare System DNS with DoH and Google DNS
                var sysSet = new HashSet<string>(sysV4);
                var dohSet = new HashSet<string>(dohV4);
                var googleSet = new HashSet<string>(googleV4);

                // Check if System DNS overlaps with DoH or Google DNS
                bool overlapWithDoh = dohSet.Count > 0 && sysSet.Intersect(dohSet).Any();
                bool overlapWithGoogle = googleSet.Count > 0 && sysSet.Intersect(googleSet).Any();

                if (!overlapWithDoh && !overlapWithGoogle)
                {
                    // System DNS differs from BOTH DoH and Google DNS → DNS_FILTERED
                    status = isVpnProfile ? DnsStatus.OK : DnsStatus.DNS_FILTERED;
                }
                else if (!overlapWithDoh || !overlapWithGoogle)
                {
                    // System DNS differs from one source but matches another → WARN
                    status = isVpnProfile ? DnsStatus.OK : DnsStatus.WARN;
                }
            }

            return new DnsResult(sysV4, dohV4, googleV4, status);
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
