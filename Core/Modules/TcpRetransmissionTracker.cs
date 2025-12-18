using System;
using System.Collections.Concurrent;
using System.Net;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Traffic.Filters;

namespace IspAudit.Core.Modules
{
    /// <summary>
    /// Простой трекер TCP-ретрансмиссий на базе TrafficMonitorFilter.
    /// Эвристика: повтор того же seq для того же потока считаем ретрансмиссией.
    /// </summary>
    public sealed class TcpRetransmissionTracker
    {
        private readonly ConcurrentDictionary<TcpFlowKey, FlowState> _flows = new();

        private readonly record struct FlowState(uint LastSeq, DateTime LastSeenUtc, int Retransmissions, int TotalPackets);

        public void Attach(TrafficMonitorFilter filter)
        {
            if (filter == null) throw new ArgumentNullException(nameof(filter));
            filter.OnPacketReceived += OnPacketReceived;
        }

        private void OnPacketReceived(PacketData packet)
        {
            // Минимальный парсер IPv4+TCP. IPv6 пока игнорируем.
            if (packet.Buffer is not { Length: >= 40 })
                return;

            var buffer = packet.Buffer;

            var version = (buffer[0] & 0xF0) >> 4;
            if (version != 4)
                return;

            var ihl = buffer[0] & 0x0F;
            var ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || packet.Length < ipHeaderLen + 20)
                return;

            // Протокол
            var protocol = buffer[9];
            if (protocol != 6) // TCP
                return;

            // IP-адреса
            var srcIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 12, 4));
            var dstIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 16, 4));

            // TCP-заголовок начинается после IP
            var tcpOffset = ipHeaderLen;
            if (packet.Length < tcpOffset + 20)
                return;

            ushort ReadUInt16(int offset) => (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

            var srcPort = ReadUInt16(tcpOffset);
            var dstPort = ReadUInt16(tcpOffset + 2);

            // SEQ
            uint ReadUInt32(int offset) => (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);
            var seq = ReadUInt32(tcpOffset + 4);

            var key = TcpFlowKey.Create(srcIp, srcPort, dstIp, dstPort);
            var now = DateTime.UtcNow;

            _flows.AddOrUpdate(
                key,
                _ => new FlowState(seq, now, 0, 1),
                (_, state) =>
                {
                    // Если seq тот же, что и в прошлый раз, считаем это ретрансмиссией.
                    var retrans = state.LastSeq == seq ? state.Retransmissions + 1 : state.Retransmissions;
                    return new FlowState(seq, now, retrans, state.TotalPackets + 1);
                });
        }

        /// <summary>
        /// Получить статистику (ретрансмиссии и общее число пакетов) для IP-адреса.
        /// </summary>
        public (int Retransmissions, int TotalPackets) GetStatsForIp(IPAddress ip)
        {
            if (ip == null) throw new ArgumentNullException(nameof(ip));

            var totalRetrans = 0;
            var totalPackets = 0;
            foreach (var (key, state) in _flows)
            {
                if (ip.Equals(key.A) || ip.Equals(key.B))
                {
                    totalRetrans += state.Retransmissions;
                    totalPackets += state.TotalPackets;
                }
            }

            return (totalRetrans, totalPackets);
        }

        /// <summary>
        /// Получить количество ретрансмиссий для IP-адреса за всё время наблюдения.
        /// </summary>
        public int GetRetransmissionCountForIp(IPAddress ip)
        {
            return GetStatsForIp(ip).Retransmissions;
        }

        /// <summary>
        /// Эвристика для smoke/диагностики: высокая доля ретрансмиссий может указывать на тихий дроп.
        /// </summary>
        public bool TryGetSuspiciousDrop(IPAddress ip, out string details)
        {
            var (retrans, total) = GetStatsForIp(ip);
            if (total <= 0)
            {
                details = string.Empty;
                return false;
            }

            // Консервативно: считаем сигнал валидным только при достаточной выборке.
            const int minPackets = 20;
            const double ratioThreshold = 0.10; // 10%

            var ratio = (double)retrans / total;
            if (total >= minPackets && ratio >= ratioThreshold)
            {
                details = $"TCP ретрансмиссии: {retrans}/{total} ({ratio:P0})";
                return true;
            }

            details = string.Empty;
            return false;
        }
    }
}
