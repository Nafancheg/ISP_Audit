using IspAudit.Bypass;

namespace IspAudit.Core.Traffic
{
    public class PacketContext
    {
        internal WinDivertNative.Address Address;
        
        public bool IsOutbound => Address.Outbound;
        public bool IsLoopback => Address.Loopback;
        public bool IsIpv6 => Address.IPv6;
        public bool IsImpostor => Address.Impostor;
        public long Timestamp => Address.Timestamp;
        
        internal PacketContext(WinDivertNative.Address address)
        {
            Address = address;
        }
    }
}
