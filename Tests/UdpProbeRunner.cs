using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using IspAudit.Output;

namespace IspAudit.Tests
{
    public class UdpProbeRunner
    {
        private readonly Config _cfg;
        public UdpProbeRunner(Config cfg) { _cfg = cfg; }

        public async Task<UdpProbeResult> ProbeAsync(UdpProbeDefinition probe)
        {
            return probe.Kind switch
            {
                UdpProbeKind.Dns => await ProbeDnsAsync(probe).ConfigureAwait(false),
                _ => await ProbeRawAsync(probe).ConfigureAwait(false)
            };
        }

        private async Task<UdpProbeResult> ProbeDnsAsync(UdpProbeDefinition probe)
        {
            var result = CreateBaseResult(probe);
            try
            {
                var ip = await ResolveHostAsync(probe.Host).ConfigureAwait(false);
                if (ip == null)
                {
                    result.success = false;
                    result.reply = false;
                    result.note = "нет IPv4";
                    return result;
                }

                var ep = new IPEndPoint(ip, probe.Port);
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = _cfg.UdpTimeoutSeconds * 1000;

                var query = BuildDnsQuery("example.com", out var queryId);
                var sw = Stopwatch.StartNew();
                await udp.SendAsync(query, query.Length, ep).ConfigureAwait(false);

                var receiveTask = udp.ReceiveAsync();
                var completed = await Task.WhenAny(receiveTask, Task.Delay(_cfg.UdpTimeoutSeconds * 1000)).ConfigureAwait(false);
                if (completed == receiveTask)
                {
                    var res = receiveTask.Result;
                    sw.Stop();
                    var (ok, error) = ParseDnsReplySimple(res.Buffer, queryId);
                    result.reply = ok;
                    result.success = ok;
                    result.rtt_ms = (int)sw.ElapsedMilliseconds;
                    result.reply_bytes = res.Buffer.Length;
                    result.note = ok ? "ответ получен" : (error ?? "ответ некорректный");
                }
                else
                {
                    result.reply = false;
                    result.success = false;
                    result.note = "timeout";
                }
            }
            catch (Exception ex)
            {
                result.reply = false;
                result.success = false;
                result.note = ex.Message;
            }

            return result;
        }

        private async Task<UdpProbeResult> ProbeRawAsync(UdpProbeDefinition probe)
        {
            var result = CreateBaseResult(probe);
            try
            {
                var ip = await ResolveHostAsync(probe.Host).ConfigureAwait(false);
                if (ip == null)
                {
                    result.success = false;
                    result.note = "нет IPv4";
                    return result;
                }

                var ep = new IPEndPoint(ip, probe.Port);
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = _cfg.UdpTimeoutSeconds * 1000;
                var payload = ParsePayload(probe.PayloadHex);
                if (payload.Length == 0) payload = new byte[] { 0x00 };

                var sw = Stopwatch.StartNew();
                await udp.SendAsync(payload, payload.Length, ep).ConfigureAwait(false);

                if (probe.ExpectReply)
                {
                    var receiveTask = udp.ReceiveAsync();
                    var completed = await Task.WhenAny(receiveTask, Task.Delay(_cfg.UdpTimeoutSeconds * 1000)).ConfigureAwait(false);
                    if (completed == receiveTask)
                    {
                        var res = receiveTask.Result;
                        sw.Stop();
                        result.reply = true;
                        result.success = true;
                        result.rtt_ms = (int)sw.ElapsedMilliseconds;
                        result.reply_bytes = res.Buffer.Length;
                        result.note = "ответ получен";
                    }
                    else
                    {
                        sw.Stop();
                        result.reply = false;
                        result.success = false;
                        result.note = "timeout";
                    }
                }
                else
                {
                    // Raw probe without expecting reply - low certainty
                    sw.Stop();
                    result.success = true;
                    result.reply = false;
                    result.rtt_ms = null;
                    result.note = "пакет отправлен";
                    result.certainty = "low"; // Can't confirm if packet reached destination
                }
            }
            catch (SocketException ex)
            {
                result.success = false;
                result.reply = false;
                result.note = ex.Message;
            }
            catch (Exception ex)
            {
                result.success = false;
                result.reply = false;
                result.note = ex.Message;
            }

            return result;
        }

        private static async Task<IPAddress?> ResolveHostAsync(string host)
        {
            if (IPAddress.TryParse(host, out var parsed)) return parsed;
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                return addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?? addresses.FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        private static byte[] ParsePayload(string? hex)
        {
            if (string.IsNullOrWhiteSpace(hex)) return Array.Empty<byte>();
            var cleaned = new string(hex.Where(c => !char.IsWhiteSpace(c)).ToArray());
            if (cleaned.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(2);
            }
            if (cleaned.Length % 2 != 0)
            {
                cleaned = "0" + cleaned;
            }
            try
            {
                var bytes = new byte[cleaned.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = Convert.ToByte(cleaned.Substring(i * 2, 2), 16);
                }
                return bytes;
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }

        private static UdpProbeResult CreateBaseResult(UdpProbeDefinition probe)
        {
            return new UdpProbeResult
            {
                name = probe.Name,
                host = probe.Host,
                port = probe.Port,
                service = probe.Service,
                expect_reply = probe.ExpectReply,
                description = probe.Note
            };
        }

        private static (bool, string?) ParseDnsReplySimple(byte[] reply, ushort queryId)
        {
            // Check minimum length
            if (reply.Length < 12)
                return (false, "минимальная длина ответа < 12");

            // Check ID matches
            ushort responseId = (ushort)((reply[0] << 8) | reply[1]);
            if (responseId != queryId)
                return (false, $"ID mismatch: {responseId} != {queryId}");

            // Check RCODE
            int rcode = reply[3] & 0x0F;
            if (rcode != 0)
                return (false, $"RCODE={rcode}");

            return (true, null);
        }

        private static byte[] BuildDnsQuery(string qname, out ushort queryId)
        {
            var rnd = Random.Shared.Next(0, 0xFFFF);
            queryId = (ushort)rnd;
            byte[] header = new byte[12];
            header[0] = (byte)((rnd >> 8) & 0xFF);
            header[1] = (byte)(rnd & 0xFF);
            header[2] = 0x01;
            header[3] = 0x00;
            header[4] = 0x00; header[5] = 0x01;
            header[6] = 0x00; header[7] = 0x00;
            header[8] = 0x00; header[9] = 0x00;
            header[10] = 0x00; header[11] = 0x00;

            var labels = qname.Split('.', StringSplitOptions.RemoveEmptyEntries);
            using var ms = new System.IO.MemoryStream();
            ms.Write(header, 0, header.Length);
            foreach (var label in labels)
            {
                var b = System.Text.Encoding.ASCII.GetBytes(label);
                ms.WriteByte((byte)b.Length);
                ms.Write(b, 0, b.Length);
            }
            ms.WriteByte(0x00);
            ms.WriteByte(0x00); ms.WriteByte(0x01);
            ms.WriteByte(0x00); ms.WriteByte(0x01);

            return ms.ToArray();
        }
    }
}
