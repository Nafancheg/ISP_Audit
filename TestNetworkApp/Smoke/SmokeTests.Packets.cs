using System;
using System.Buffers.Binary;
using System.Net;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        private sealed class DummyPacketSender : IPacketSender
        {
            public bool Send(byte[] packet, int length, ref WinDivertNative.Address addr) => true;
        }

        private static PacketContext CreatePacketContext(bool isOutbound, bool isLoopback)
        {
            var addr = new WinDivertNative.Address
            {
                Timestamp = 0,
                LayerEventFlags = 0,
                Reserved2 = 0,
                Data = default
            };

            // Bit layout см. WinDivertNative.Address: Outbound(17), Loopback(18), IPv6(20) и т.д.
            if (isOutbound)
            {
                addr.LayerEventFlags |= 1u << 17;
            }

            if (isLoopback)
            {
                addr.LayerEventFlags |= 1u << 18;
            }

            return new PacketContext(addr);
        }

        private static void FeedPacket(TrafficMonitorFilter filter, byte[] packetBytes, bool isOutbound, bool isLoopback = false)
        {
            var intercepted = new InterceptedPacket(packetBytes, packetBytes.Length);
            var ctx = CreatePacketContext(isOutbound, isLoopback);
            var sender = new DummyPacketSender();

            filter.Process(intercepted, ctx, sender);
        }

        private static byte[] BuildIpv4TcpPacket(
            IPAddress srcIp,
            IPAddress dstIp,
            ushort srcPort,
            ushort dstPort,
            byte ttl,
            ushort ipId,
            uint seq,
            byte tcpFlags,
            ReadOnlySpan<byte> payload = default)
        {
            var ipHeaderLen = 20;
            var tcpHeaderLen = 20;
            var totalLen = ipHeaderLen + tcpHeaderLen + payload.Length;

            var buffer = new byte[totalLen];

            // IPv4 header
            buffer[0] = 0x45; // Version=4, IHL=5
            buffer[1] = 0;    // TOS
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), (ushort)totalLen);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), ipId);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6, 2), 0); // flags/fragment
            buffer[8] = ttl;
            buffer[9] = 6; // TCP
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(10, 2), 0); // checksum (не нужен для smoke)

            var src = srcIp.GetAddressBytes();
            var dst = dstIp.GetAddressBytes();
            if (src.Length != 4 || dst.Length != 4)
            {
                throw new ArgumentException("Только IPv4 адреса поддерживаются в smoke-пакетах");
            }

            src.CopyTo(buffer, 12);
            dst.CopyTo(buffer, 16);

            // TCP header
            var tcpOffset = ipHeaderLen;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset, 2), srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 2, 2), dstPort);
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(tcpOffset + 4, 4), seq);
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(tcpOffset + 8, 4), 0); // ack

            buffer[tcpOffset + 12] = 0x50; // DataOffset=5 (20 bytes), Reserved=0
            buffer[tcpOffset + 13] = tcpFlags;

            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 14, 2), 8192); // window
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 16, 2), 0);    // checksum
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 18, 2), 0);    // urgent

            if (!payload.IsEmpty)
            {
                payload.CopyTo(buffer.AsSpan(ipHeaderLen + tcpHeaderLen));
            }

            return buffer;
        }

        private static byte[] BuildIpv4UdpPacket(
            IPAddress srcIp,
            IPAddress dstIp,
            ushort srcPort,
            ushort dstPort,
            byte ttl,
            ushort ipId,
            ReadOnlySpan<byte> payload)
        {
            var ipHeaderLen = 20;
            var udpHeaderLen = 8;
            var totalLen = ipHeaderLen + udpHeaderLen + payload.Length;

            var buffer = new byte[totalLen];

            // IPv4 header
            buffer[0] = 0x45;
            buffer[1] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), (ushort)totalLen);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), ipId);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6, 2), 0);
            buffer[8] = ttl;
            buffer[9] = 17; // UDP
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(10, 2), 0);

            var src = srcIp.GetAddressBytes();
            var dst = dstIp.GetAddressBytes();
            if (src.Length != 4 || dst.Length != 4)
            {
                throw new ArgumentException("Только IPv4 адреса поддерживаются в smoke-пакетах");
            }

            src.CopyTo(buffer, 12);
            dst.CopyTo(buffer, 16);

            // UDP header
            var udpOffset = ipHeaderLen;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(udpOffset, 2), srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(udpOffset + 2, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(udpOffset + 4, 2), (ushort)(udpHeaderLen + payload.Length));
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(udpOffset + 6, 2), 0); // checksum

            if (!payload.IsEmpty)
            {
                payload.CopyTo(buffer.AsSpan(ipHeaderLen + udpHeaderLen));
            }

            return buffer;
        }
    }
}
