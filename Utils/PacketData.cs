using System;

namespace IspAudit.Utils
{
    /// <summary>
    /// Данные захваченного пакета.
    /// </summary>
    public class PacketData
    {
        public int PacketNumber { get; set; }
        public byte[] Buffer { get; set; } = Array.Empty<byte>();
        public int Length { get; set; }
        public bool IsOutbound { get; set; }
        public bool IsLoopback { get; set; }
    }
}
