using System;
using System.Buffers.Binary;

namespace IspAudit.Core.Traffic
{
    public static class PacketParser
    {
        public static PacketInfo Parse(byte[] buffer, int length)
        {
            var info = new PacketInfo();
            if (length < 20) return info; // Too short

            byte version = (byte)(buffer[0] >> 4);
            if (version == 4)
            {
                info.IsIpv4 = true;
                info.IpHeaderLength = (buffer[0] & 0x0F) * 4;
                if (length < info.IpHeaderLength) return info;

                info.SrcIpInt = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(12, 4));
                info.DstIpInt = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(16, 4));

                byte protocol = buffer[9];
                int offset = info.IpHeaderLength;

                if (protocol == 6) // TCP
                {
                    if (length < offset + 20) return info;
                    info.IsTcp = true;
                    info.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset, 2));
                    info.DstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset + 2, 2));
                    
                    byte dataOffset = (byte)(buffer[offset + 12] >> 4);
                    info.TcpHeaderLength = dataOffset * 4;
                    
                    byte flags = buffer[offset + 13];
                    info.IsFin = (flags & 0x01) != 0;
                    info.IsSyn = (flags & 0x02) != 0;
                    info.IsRst = (flags & 0x04) != 0;
                    info.IsAck = (flags & 0x10) != 0;

                    info.PayloadOffset = offset + info.TcpHeaderLength;
                    info.PayloadLength = length - info.PayloadOffset;
                }
                else if (protocol == 17) // UDP
                {
                    if (length < offset + 8) return info;
                    info.IsUdp = true;
                    info.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset, 2));
                    info.DstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset + 2, 2));
                    
                    info.PayloadOffset = offset + 8;
                    info.PayloadLength = length - info.PayloadOffset;
                }
            }
            else if (version == 6)
            {
                info.IsIpv6 = true;
                // IPv6 parsing is more complex due to extension headers, skipping for now or implementing basic
                // Fixed header is 40 bytes
                info.IpHeaderLength = 40;
                // Next header parsing...
            }

            return info;
        }
    }
}