using System;
using System.Collections.Generic;
using System.Net;
using System.Buffers.Binary;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    /// <summary>
    /// Временный фильтр блокировки трафика для набора endpoint-ов.
    /// Используется для «подталкивания» переподключения приложения после применения обхода.
    /// </summary>
    public sealed class TemporaryEndpointBlockFilter : IPacketFilter
    {
        private readonly HashSet<uint> _ipv4Targets;
        private readonly ushort _port;
        private readonly bool _blockTcp;
        private readonly bool _blockUdp;
        private readonly long _untilTick;

        public string Name { get; }
        public int Priority => 250; // Выше BypassFilter (100): блокируем максимально рано.

        public TemporaryEndpointBlockFilter(
            string name,
            IEnumerable<IPAddress> ipv4Targets,
            TimeSpan ttl,
            ushort port = 443,
            bool blockTcp = true,
            bool blockUdp = true)
        {
            Name = string.IsNullOrWhiteSpace(name) ? "TemporaryEndpointBlockFilter" : name;
            _port = port;
            _blockTcp = blockTcp;
            _blockUdp = blockUdp;
            _untilTick = Environment.TickCount64 + (long)Math.Max(0, ttl.TotalMilliseconds);

            _ipv4Targets = new HashSet<uint>();
            foreach (var ip in ipv4Targets)
            {
                var v = TryToIpv4Int(ip);
                if (v.HasValue)
                {
                    _ipv4Targets.Add(v.Value);
                }
            }
        }

        public bool Process(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            // TTL истёк — больше не блокируем.
            if (Environment.TickCount64 >= _untilTick)
            {
                return true;
            }

            // IPv6 сейчас не парсим (PacketParser упрощённый), поэтому блокируем только IPv4.
            if (!packet.Info.IsIpv4)
            {
                return true;
            }

            if (_ipv4Targets.Count == 0)
            {
                return true;
            }

            var isTcp = packet.Info.IsTcp;
            var isUdp = packet.Info.IsUdp;
            if ((isTcp && !_blockTcp) || (isUdp && !_blockUdp) || (!isTcp && !isUdp))
            {
                return true;
            }

            // Блокируем обе стороны: и исходящие к remote, и входящие от remote.
            var matchesRemote = _ipv4Targets.Contains(packet.Info.DstIpInt) || _ipv4Targets.Contains(packet.Info.SrcIpInt);
            if (!matchesRemote)
            {
                return true;
            }

            // Ограничиваемся портом (по обе стороны), чтобы не ломать лишнее.
            if (packet.Info.DstPort != _port && packet.Info.SrcPort != _port)
            {
                return true;
            }

            // Drop/stop processing.
            return false;
        }

        private static uint? TryToIpv4Int(IPAddress ip)
        {
            try
            {
                if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
                var bytes = ip.GetAddressBytes();
                if (bytes.Length != 4) return null;
                return BinaryPrimitives.ReadUInt32BigEndian(bytes);
            }
            catch
            {
                return null;
            }
        }
    }
}
