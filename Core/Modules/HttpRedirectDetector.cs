using System;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Traffic.Filters;

namespace IspAudit.Core.Modules
{
    /// <summary>
    /// Минимальный детектор HTTP-редиректов (3xx + Location) поверх TrafficMonitorFilter.
    /// Фокусируется на TCP/80 и первых байтах ответа.
    /// </summary>
    public sealed class HttpRedirectDetector
    {
        private const int MaxHeaderBytes = 2048;

        private readonly ConcurrentDictionary<TcpFlowKey, FlowBuffer> _buffers = new();
        private readonly ConcurrentDictionary<IPAddress, RedirectInfo> _redirectsByIp = new();

        private readonly record struct FlowBuffer(byte[] Data, int Length, bool Completed);
        private readonly record struct RedirectInfo(string TargetHost, DateTime FirstSeenUtc, DateTime LastSeenUtc);

        public void Attach(TrafficMonitorFilter filter)
        {
            if (filter == null) throw new ArgumentNullException(nameof(filter));
            filter.OnPacketReceived += OnPacketReceived;
        }

        private void OnPacketReceived(PacketData packet)
        {
            // Минимальный парсер IPv4+TCP, только ответы с порта 80.
            if (packet.Buffer is not { Length: > 40 })
                return;

            var buffer = packet.Buffer;

            var version = (buffer[0] & 0xF0) >> 4;
            if (version != 4)
                return;

            var ihl = buffer[0] & 0x0F;
            var ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || packet.Length < ipHeaderLen + 20)
                return;

            var protocol = buffer[9];
            if (protocol != 6) // TCP
                return;

            var srcIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 12, 4));
            var dstIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 16, 4));

            var tcpOffset = ipHeaderLen;
            if (packet.Length < tcpOffset + 20)
                return;

            ushort ReadUInt16(int offset) => (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

            var srcPort = ReadUInt16(tcpOffset);
            var dstPort = ReadUInt16(tcpOffset + 2);

            // Нас интересуют только ответы с порта 80 (сервер → клиент).
            if (srcPort != 80)
                return;

            var key = TcpFlowKey.Create(srcIp, srcPort, dstIp, dstPort);

            var payloadOffset = tcpOffset + ((buffer[tcpOffset + 12] >> 4) * 4);
            if (payloadOffset >= packet.Length)
                return;

            var payloadLen = packet.Length - payloadOffset;
            if (payloadLen <= 0)
                return;

            var toCopy = Math.Min(payloadLen, MaxHeaderBytes);

            _buffers.AddOrUpdate(
                key,
                _ =>
                {
                    var data = new byte[MaxHeaderBytes];
                    Array.Copy(buffer, payloadOffset, data, 0, toCopy);
                    return new FlowBuffer(data, toCopy, false);
                },
                (_, existing) =>
                {
                    if (existing.Completed || existing.Length >= MaxHeaderBytes)
                        return existing;

                    var data = existing.Data;
                    var free = MaxHeaderBytes - existing.Length;
                    var copyLen = Math.Min(toCopy, free);
                    Array.Copy(buffer, payloadOffset, data, existing.Length, copyLen);
                    var newLen = existing.Length + copyLen;
                    return new FlowBuffer(data, newLen, newLen >= MaxHeaderBytes);
                });

            if (_buffers.TryGetValue(key, out var buf) && !buf.Completed)
            {
                // Пробуем парсить только когда накопили хоть какие-то данные.
                TryParseRedirect(srcIp, buf);
            }
        }

        private void TryParseRedirect(IPAddress serverIp, FlowBuffer buffer)
        {
            try
            {
                var span = new ReadOnlySpan<byte>(buffer.Data, 0, buffer.Length);
                var text = Encoding.ASCII.GetString(span);

                // Грубая проверка на HTTP-ответ 3xx.
                if (!text.StartsWith("HTTP/1.1 3") && !text.StartsWith("HTTP/1.0 3"))
                    return;

                var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headerEnd <= 0)
                    return;

                var headers = text[..headerEnd].Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

                string? location = null;
                foreach (var h in headers)
                {
                    if (h.StartsWith("Location:", StringComparison.OrdinalIgnoreCase))
                    {
                        location = h["Location:".Length..].Trim();
                        break;
                    }
                }

                if (string.IsNullOrEmpty(location))
                    return;

                var host = ExtractHostFromLocation(location);
                if (string.IsNullOrEmpty(host))
                    return;

                var now = DateTime.UtcNow;
                _redirectsByIp.AddOrUpdate(
                    serverIp,
                    _ => new RedirectInfo(host, now, now),
                    (_, info) => new RedirectInfo(host, info.FirstSeenUtc, now));
            }
            catch
            {
                // Детектор не должен ломать пайплайн.
            }
        }

        private static string? ExtractHostFromLocation(string location)
        {
            // Простейший парсер URL: ищем //host[:port]/...
            try
            {
                if (Uri.TryCreate(location, UriKind.Absolute, out var uri))
                {
                    return uri.Host;
                }

                // Относительный путь — хост нам неизвестен.
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Попробовать получить целевой хост редиректа для указанного IP сервера.
        /// </summary>
        public bool TryGetRedirectHost(IPAddress ip, out string? targetHost)
        {
            if (ip == null) throw new ArgumentNullException(nameof(ip));

            if (_redirectsByIp.TryGetValue(ip, out var info))
            {
                targetHost = info.TargetHost;
                return true;
            }

            targetHost = null;
            return false;
        }
    }
}
