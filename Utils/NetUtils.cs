using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    public static class NetUtils
    {
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
    }
}

