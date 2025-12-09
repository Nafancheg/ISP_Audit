namespace IspAudit.Core.Traffic
{
    public class InterceptedPacket
    {
        public byte[] Buffer { get; set; }
        public int Length { get; set; }
        public PacketInfo Info { get; set; }

        public InterceptedPacket(byte[] buffer, int length)
        {
            Buffer = buffer;
            Length = length;
            Info = PacketParser.Parse(buffer, length);
        }
    }
}
