using System;
using System.Buffers.Binary;
using System.Net;

namespace IspAudit.Core.Traffic
{
    // Unified Packet Parsing Helper
    public static class PacketHelper
    {
        public readonly struct PacketInfo
        {
            public readonly bool IsValid;
            public readonly bool IsIpv4;
            public readonly bool IsTcp;
            public readonly bool IsUdp;
            public readonly bool IsRst;
            public readonly int IpHeaderLength;
            public readonly int TcpHeaderLength;
            public readonly int PayloadOffset;
            public readonly int PayloadLength;
            
            private readonly uint _srcIpInt;
            private readonly uint _dstIpInt;
            private readonly byte[]? _backingBuffer;
            private readonly int _srcIpOffset;
            private readonly int _dstIpOffset;

            public IPAddress SrcIp
            {
                get
                {
                    if (IsIpv4) return new IPAddress(_srcIpInt);
                    if (_backingBuffer == null) return IPAddress.None;
                    return new IPAddress(new ReadOnlySpan<byte>(_backingBuffer, _srcIpOffset, 16));
                }
            }

            public IPAddress DstIp
            {
                get
                {
                    if (IsIpv4) return new IPAddress(_dstIpInt);
                    if (_backingBuffer == null) return IPAddress.None;
                    return new IPAddress(new ReadOnlySpan<byte>(_backingBuffer, _dstIpOffset, 16));
                }
            }

            public readonly uint SrcIpInt => _srcIpInt;
            public readonly uint DstIpInt => _dstIpInt;
            
            public readonly ushort SrcPort;
            public readonly ushort DstPort;

            public PacketInfo(bool isValid, bool isIpv4, bool isTcp, bool isUdp, bool isRst, int ipHeaderLen, int tcpHeaderLen, int payloadOffset, int payloadLen, uint srcInt, uint dstInt, byte[]? backingBuffer, int srcOffset, int dstOffset, ushort srcPort, ushort dstPort)
            {
                IsValid = isValid;
                IsIpv4 = isIpv4;
                IsTcp = isTcp;
                IsUdp = isUdp;
                IsRst = isRst;
                IpHeaderLength = ipHeaderLen;
                TcpHeaderLength = tcpHeaderLen;
                PayloadOffset = payloadOffset;
                PayloadLength = payloadLen;
                _srcIpInt = srcInt;
                _dstIpInt = dstInt;
                _backingBuffer = backingBuffer;
                _srcIpOffset = srcOffset;
                _dstIpOffset = dstOffset;
                SrcPort = srcPort;
                DstPort = dstPort;
            }
        }

        public static PacketInfo Parse(byte[] buffer, int length)
        {
            if (length < 20) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0);

            int version = buffer[0] >> 4;
            bool isIpv4 = version == 4;
            int ipHeaderLength = 0;
            int protocol = 0;
            uint srcIpInt = 0;
            uint dstIpInt = 0;
            int srcIpOffset = 0;
            int dstIpOffset = 0;

            if (isIpv4)
            {
                ipHeaderLength = (buffer[0] & 0x0F) * 4;
                if (length < ipHeaderLength) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0);
                protocol = buffer[9];
                srcIpInt = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(12, 4));
                dstIpInt = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(16, 4));
            }
            else
            {
                ipHeaderLength = 40;
                if (length < ipHeaderLength) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0);
                protocol = buffer[6]; // NextHeader
                srcIpOffset = 8;
                dstIpOffset = 24;
            }

            bool isTcp = protocol == 6;
            bool isUdp = protocol == 17;
            int tcpHeaderLength = 0;
            int payloadOffset = 0;
            int payloadLength = 0;
            ushort srcPort = 0;
            ushort dstPort = 0;
            bool isRst = false;

            if (isTcp)
            {
                if (length < ipHeaderLength + 20) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0);
                srcPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength, 2));
                dstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength + 2, 2));
                tcpHeaderLength = ((buffer[ipHeaderLength + 12] >> 4) & 0xF) * 4;
                payloadOffset = ipHeaderLength + tcpHeaderLength;
                payloadLength = length - payloadOffset;
                isRst = (buffer[ipHeaderLength + 13] & 0x04) != 0;
            }
            else if (isUdp)
            {
                if (length < ipHeaderLength + 8) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, 0, 0, 0, 0);
                srcPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength, 2));
                dstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength + 2, 2));
                payloadOffset = ipHeaderLength + 8;
                payloadLength = length - payloadOffset;
            }

            return new PacketInfo(true, isIpv4, isTcp, isUdp, isRst, ipHeaderLength, tcpHeaderLength, payloadOffset, payloadLength, srcIpInt, dstIpInt, buffer, srcIpOffset, dstIpOffset, srcPort, dstPort);
        }

        public static void RecalculateIpChecksum(byte[] buffer)
        {
            if (buffer.Length < 20) return;
            
            // Only for IPv4
            if ((buffer[0] >> 4) != 4) return;

            // Clear current checksum (offset 10)
            buffer[10] = 0;
            buffer[11] = 0;

            int headerLength = (buffer[0] & 0x0F) * 4;
            uint sum = 0;

            for (int i = 0; i < headerLength; i += 2)
            {
                ushort word = (ushort)((buffer[i] << 8) | buffer[i + 1]);
                sum += word;
            }

            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            ushort checksum = (ushort)~sum;
            buffer[10] = (byte)(checksum >> 8);
            buffer[11] = (byte)(checksum & 0xFF);
        }
    }
}
