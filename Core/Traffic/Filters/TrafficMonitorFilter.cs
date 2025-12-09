using System;
using IspAudit.Utils;

namespace IspAudit.Core.Traffic.Filters
{
    public class TrafficMonitorFilter : IPacketFilter
    {
        public string Name => "TrafficMonitor";
        public int Priority => 0;

        public event Action<PacketData>? OnPacketReceived;
        public int PacketsCount { get; private set; }

        public bool Process(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            PacketsCount++;
            
            if (OnPacketReceived != null)
            {
                var packetCopy = new byte[packet.Length];
                Array.Copy(packet.Buffer, packetCopy, packet.Length);
                
                var pData = new PacketData
                {
                    PacketNumber = PacketsCount,
                    Buffer = packetCopy,
                    Length = packet.Length,
                    IsOutbound = context.IsOutbound,
                    IsLoopback = context.IsLoopback
                };
                
                OnPacketReceived.Invoke(pData);
            }

            return true; // Always pass
        }
    }
}
