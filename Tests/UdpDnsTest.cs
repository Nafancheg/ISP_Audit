using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace IspAudit.Tests
{
    public record UdpDnsResult(string target, bool reply, int? rtt_ms, int replyBytes, string? note);

    public class UdpDnsTest
    {
        private readonly Config _cfg;
        public UdpDnsTest(Config cfg) { _cfg = cfg; }

        public async Task<UdpDnsResult> ProbeAsync()
        {
            var targetIp = "1.1.1.1"; // Cloudflare DNS
            try
            {
                var ip = IPAddress.Parse(targetIp);
                var ep = new IPEndPoint(ip, 53);
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = _cfg.UdpTimeoutSeconds * 1000;

                var query = BuildDnsQuery("example.com");
                var sw = Stopwatch.StartNew();
                await udp.SendAsync(query, query.Length, ep).ConfigureAwait(false);

                var receiveTask = udp.ReceiveAsync();
                var completed = await Task.WhenAny(receiveTask, Task.Delay(_cfg.UdpTimeoutSeconds * 1000)).ConfigureAwait(false);
                if (completed == receiveTask)
                {
                    var res = receiveTask.Result;
                    sw.Stop();
                    // minimal header check: at least 12 bytes and ID matches
                    var ok = res.Buffer.Length >= 12 && res.RemoteEndPoint.Address.Equals(ip);
                    return new UdpDnsResult(targetIp, ok, (int)sw.ElapsedMilliseconds, res.Buffer.Length, null);
                }
                else
                {
                    return new UdpDnsResult(targetIp, false, null, 0, "timeout");
                }
            }
            catch (Exception ex)
            {
                return new UdpDnsResult(targetIp, false, null, 0, ex.Message);
            }
        }

        private static byte[] BuildDnsQuery(string qname)
        {
            var rnd = Random.Shared.Next(0, 0xFFFF);
            // Header 12 bytes
            byte[] header = new byte[12];
            header[0] = (byte)((rnd >> 8) & 0xFF);
            header[1] = (byte)(rnd & 0xFF);
            header[2] = 0x01; // recursion desired
            header[3] = 0x00;
            header[4] = 0x00; header[5] = 0x01; // QDCOUNT = 1
            header[6] = 0x00; header[7] = 0x00; // ANCOUNT = 0
            header[8] = 0x00; header[9] = 0x00; // NSCOUNT = 0
            header[10] = 0x00; header[11] = 0x00; // ARCOUNT = 0

            var labels = qname.Split('.', StringSplitOptions.RemoveEmptyEntries);
            using var ms = new System.IO.MemoryStream();
            ms.Write(header, 0, header.Length);
            foreach (var label in labels)
            {
                var b = System.Text.Encoding.ASCII.GetBytes(label);
                ms.WriteByte((byte)b.Length);
                ms.Write(b, 0, b.Length);
            }
            ms.WriteByte(0x00); // end of QNAME
            ms.WriteByte(0x00); ms.WriteByte(0x01); // QTYPE = A
            ms.WriteByte(0x00); ms.WriteByte(0x01); // QCLASS = IN

            return ms.ToArray();
        }
    }
}

