namespace IspAudit.Core.Traffic
{
    public class PacketInfo
    {
        public bool IsIpv4 { get; set; }
        public bool IsIpv6 { get; set; }
        public int IpHeaderLength { get; set; }
        public uint SrcIpInt { get; set; }
        public uint DstIpInt { get; set; }
        
        public bool IsTcp { get; set; }
        public int TcpHeaderLength { get; set; }
        public ushort SrcPort { get; set; }
        public ushort DstPort { get; set; }
        public bool IsRst { get; set; }
        public bool IsSyn { get; set; }
        public bool IsAck { get; set; }
        public bool IsFin { get; set; }
        
        public bool IsUdp { get; set; }
        
        public int PayloadOffset { get; set; }
        public int PayloadLength { get; set; }
    }
}