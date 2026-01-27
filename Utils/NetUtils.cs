using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.Linq;

namespace IspAudit.Utils
{
    public static class NetUtils
    {
        private const string DoHUrlTemplate = "https://cloudflare-dns.com/dns-query?name={0}&type=A";

        public class DnsResolutionResult
        {
            public List<IPAddress> Addresses { get; set; } = new();
            public bool SystemDnsFailed { get; set; }
            public bool SystemDnsBogus { get; set; }
            public string Source { get; set; } = "System"; // "System" or "DoH"
        }

        /// <summary>
        /// Пытается разрешить имя хоста через системный DNS, а при неудаче - через Cloudflare DoH.
        /// Возвращает результат с метаданными о том, какой метод сработал.
        /// </summary>
        public static async Task<DnsResolutionResult> ResolveWithFallbackAsync(string host)
        {
            var result = new DnsResolutionResult();

            // 1. Пробуем системный DNS
            var systemResult = await SafeDnsGetV4Async(host).ConfigureAwait(false);
            
            if (systemResult.Count == 0)
            {
                result.SystemDnsFailed = true;
            }
            else if (systemResult.Any(IsBogusIPv4))
            {
                result.SystemDnsBogus = true;
                result.SystemDnsFailed = true; // Bogus is effectively a failure
            }
            else
            {
                // System DNS OK
                result.Addresses = systemResult;
                result.Source = "System";
                return result;
            }

            // 2. Если системный DNS вернул пустоту или мусор, пробуем DoH
            try
            {
                var dohResult = await ResolveDohAAsync(host).ConfigureAwait(false);
                if (dohResult.Count > 0)
                {
                    result.Addresses = dohResult;
                    result.Source = "DoH";
                    return result;
                }
            }
            catch { /* Ignore DoH errors */ }

            // Возвращаем что есть (даже если это bogus IP от системы, если DoH не сработал)
            result.Addresses = systemResult;
            return result;
        }

        private static async Task<List<IPAddress>> ResolveDohAAsync(string host)
        {
            var res = new List<IPAddress>();
            try
            {
                using var handler = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
                var url = string.Format(DoHUrlTemplate, Uri.EscapeDataString(host));

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
                            var ipStr = data.GetString();
                            if (IPAddress.TryParse(ipStr, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                            {
                                res.Add(ip);
                            }
                        }
                    }
                }
            }
            catch { }
            return res;
        }

        // Smoke-хук: позволяет детерминированно тестировать ветки логики (например, VPN warning)
        // без зависимости от реального состояния сетевых адаптеров в окружении.
        internal static Func<bool>? LikelyVpnActiveOverrideForSmoke;

        public static bool LikelyVpnActive()
        {
            if (LikelyVpnActiveOverrideForSmoke != null)
            {
                return LikelyVpnActiveOverrideForSmoke();
            }

            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    var name = (ni.Name ?? string.Empty).ToLowerInvariant();
                    var desc = (ni.Description ?? string.Empty).ToLowerInvariant();
                    var type = ni.NetworkInterfaceType;
                    bool looksVpn = type == NetworkInterfaceType.Tunnel
                                    || name.Contains("vpn") || desc.Contains("vpn")
                                    || desc.Contains("wintun") || desc.Contains("wireguard")
                                    || desc.Contains("openvpn") || desc.Contains("tap-") || desc.Contains("tap ")
                                    || desc.Contains("tun") || desc.Contains("ike" + "v" + "2");
                    if (looksVpn) return true;
                }
            }
            catch { }
            return false;
        }
        public static async Task<bool> PingAsync(string host, int timeoutMs)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(host, timeoutMs).ConfigureAwait(false);
                return reply.Status == IPStatus.Success;
            }
            catch { return false; }
        }

        public static async Task<bool> TcpConnectTryAsync(IPAddress ip, int port, int timeoutMs)
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            Socket? sock = null;
            try
            {
                sock = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                var task = sock.ConnectAsync(new IPEndPoint(ip, port));
                using (cts.Token.Register(() => { try { sock.Close(); } catch { } }))
                {
                    await task.ConfigureAwait(false);
                    sock.Close();
                    return true;
                }
            }
            catch
            {
                try { sock?.Close(); } catch { }
                return false;
            }
        }

        public static async Task<List<IPAddress>> SafeDnsGetV4Async(string host)
        {
            try
            {
                var all = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                var list = new List<IPAddress>();
                foreach (var a in all)
                {
                    if (a.AddressFamily == AddressFamily.InterNetwork) list.Add(a);
                }
                return list;
            }
            catch { return new List<IPAddress>(); }
        }

        /// <summary>
        /// Checks if IP is truly bogus (invalid/loopback/link-local/multicast/reserved).
        /// Does NOT include RFC1918 private addresses (10.x, 172.16-31.x, 192.168.x).
        /// Does NOT include 198.18.0.0/15 (used by bypass routers for VPN routing).
        /// </summary>
        public static bool IsBogusIPv4(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            // 0.0.0.0/8 - invalid
            if (b[0] == 0) return true;
            // 127.0.0.0/8 - loopback
            if (b[0] == 127) return true;
            // 169.254.0.0/16 - link-local
            if (b[0] == 169 && b[1] == 254) return true;
            // 224.0.0.0/4 - multicast (224-239)
            if (b[0] >= 224 && b[0] <= 239) return true;
            // 240.0.0.0/4 - reserved (240-255)
            if (b[0] >= 240) return true;
            return false;
        }

        /// <summary>
        /// Checks if IP is RFC1918 private address (10.x, 172.16-31.x, 192.168.x).
        /// These are valid in corporate networks behind NAT/proxy.
        /// </summary>
        public static bool IsPrivateIPv4(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (b[0] == 10) return true;
            // 172.16.0.0/12 => 172.16-31
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            // 192.168.0.0/16
            if (b[0] == 192 && b[1] == 168) return true;
            return false;
        }

        /// <summary>
        /// Проверяет является ли IP из диапазона bypass-роутера (198.18.0.0/15).
        /// Это TEST-NET диапазон (RFC 2544), используется Podkop и другими bypass решениями.
        /// </summary>
        public static bool IsBypassIPv4(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            // 198.18.0.0/15 (198.18.x.x - 198.19.x.x)
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return true;
            return false;
        }

        public static async Task<string> TryGetExternalIpAsync()
        {
            try
            {
                using var h = new HttpClient() { Timeout = TimeSpan.FromSeconds(6) };
                var s = (await h.GetStringAsync("https://ifconfig.co/ip").ConfigureAwait(false)).Trim();
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
            catch { }
            try
            {
                using var h = new HttpClient() { Timeout = TimeSpan.FromSeconds(6) };
                var s = (await h.GetStringAsync("https://api.ipify.org").ConfigureAwait(false)).Trim();
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
            catch { }
            return "<unknown>";
        }

        /// <summary>
        /// Извлекает "главный домен" (SLD+TLD) из имени хоста.
        /// Эвристика: берет последние 2 части, или 3, если TLD короткий (2 символа) и SLD короткий (<=3 символа).
        /// Пример: www.google.com -> google.com, block.mts.ru -> mts.ru, google.co.uk -> google.co.uk
        /// </summary>
        public static string GetMainDomain(string hostname)
        {
            if (string.IsNullOrWhiteSpace(hostname)) return string.Empty;
            if (IPAddress.TryParse(hostname, out _)) return hostname;

            var parts = hostname.Split('.');
            if (parts.Length < 2) return hostname;

            // Simple heuristic for SLD (Second Level Domain)
            var tld = parts[^1].ToLowerInvariant();
            var sld = parts[^2].ToLowerInvariant();

            // Handle co.uk, com.ru, net.ru, org.ru, etc.
            // Если TLD из 2 букв (ru, uk, au) и пред-TLD <= 3 букв (co, com, net, org, pp) -> берем 3 части
            if (parts.Length >= 3 && tld.Length == 2 && sld.Length <= 3)
            {
                return string.Join(".", parts[^3..]).ToLowerInvariant();
            }

            return string.Join(".", parts[^2..]).ToLowerInvariant();
        }
    }
}
