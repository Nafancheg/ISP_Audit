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

        public static bool IsBogusIPv4(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            // 0.0.0.0/8
            if (b[0] == 0) return true;
            // 127.0.0.0/8
            if (b[0] == 127) return true;
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

