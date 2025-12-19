using System;
using System.Collections.Generic;
using System.Buffers.Binary;
using System.Net;
using System.Text;
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

        private sealed class CapturePacketSender : IPacketSender
        {
            public List<CapturedPacket> Sent { get; } = new();

            public bool Send(byte[] packet, int length, ref WinDivertNative.Address addr)
            {
                var copy = new byte[length];
                Buffer.BlockCopy(packet, 0, copy, 0, length);
                Sent.Add(new CapturedPacket(copy, length, addr));
                return true;
            }
        }

        private readonly struct CapturedPacket
        {
            public CapturedPacket(byte[] bytes, int length, WinDivertNative.Address address)
            {
                Bytes = bytes;
                Length = length;
                Address = address;
            }

            public byte[] Bytes { get; }
            public int Length { get; }
            public WinDivertNative.Address Address { get; }
        }

        private static byte ReadIpv4Ttl(byte[] packet)
        {
            // TTL: IPv4 offset 8
            return packet[8];
        }

        private static uint ReadTcpSequence(byte[] packet)
        {
            var ipHeaderLen = (packet[0] & 0x0F) * 4;
            return BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ipHeaderLen + 4, 4));
        }

        private static int ReadTcpPayloadLength(byte[] packet)
        {
            var ipHeaderLen = (packet[0] & 0x0F) * 4;
            var totalLen = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
            var tcpHeaderLen = ((packet[ipHeaderLen + 12] >> 4) & 0x0F) * 4;
            return Math.Max(0, totalLen - ipHeaderLen - tcpHeaderLen);
        }

        private static ReadOnlySpan<byte> SliceTcpPayload(byte[] packet)
        {
            var ipHeaderLen = (packet[0] & 0x0F) * 4;
            var tcpHeaderLen = ((packet[ipHeaderLen + 12] >> 4) & 0x0F) * 4;
            var totalLen = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
            var payloadOffset = ipHeaderLen + tcpHeaderLen;
            var payloadLen = Math.Max(0, totalLen - payloadOffset);
            return packet.AsSpan(payloadOffset, payloadLen);
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

        private static byte[] BuildTlsClientHelloPayloadWithSni(string hostname, int desiredTotalLength)
        {
            return BuildTlsClientHelloPayloadInternal(includeSni: true, hostname: hostname, desiredTotalLength: desiredTotalLength);
        }

        private static byte[] BuildTlsClientHelloPayloadWithoutSni(int desiredTotalLength)
        {
            return BuildTlsClientHelloPayloadInternal(includeSni: false, hostname: "", desiredTotalLength: desiredTotalLength);
        }

        private static byte[] BuildTlsClientHelloPayloadInternal(bool includeSni, string hostname, int desiredTotalLength)
        {
            // Собираем простой ClientHello (TLS 1.2) с опциональным расширением server_name.
            // Важно: payload формируется так, чтобы его корректно разобрал минимальный парсер в BypassFilter.HasSniExtension(...).

            var extensions = new List<byte>();

            if (includeSni)
            {
                var hostBytes = Encoding.ASCII.GetBytes(string.IsNullOrWhiteSpace(hostname) ? "example.com" : hostname);

                // server_name extension:
                // ext_type(2)=0x0000, ext_len(2), list_len(2), name_type(1)=0, name_len(2), host
                var serverNameListLen = 1 + 2 + hostBytes.Length;
                var extDataLen = 2 + serverNameListLen;

                extensions.AddRange(new byte[] { 0x00, 0x00 });
                extensions.AddRange(U16(extDataLen));
                extensions.AddRange(U16(serverNameListLen));
                extensions.Add(0x00);
                extensions.AddRange(U16(hostBytes.Length));
                extensions.AddRange(hostBytes);
            }

            // Считаем базовую длину без padding extension.
            var baseRecord = BuildTlsClientHelloRecord(extensions);
            if (desiredTotalLength <= 0)
            {
                return baseRecord;
            }

            if (desiredTotalLength < baseRecord.Length)
            {
                // Нельзя сделать короче минимально-валидного ClientHello.
                return baseRecord;
            }

            if (desiredTotalLength == baseRecord.Length)
            {
                return baseRecord;
            }

            // Добавляем padding extension (0x0015), чтобы довести до нужной длины.
            // Padding extension: type(2)=0x0015, len(2), data(len).
            var padDataLen = desiredTotalLength - baseRecord.Length - 4;
            if (padDataLen < 0)
            {
                // В редком случае desiredTotalLength попал между baseLen и baseLen+3.
                // Тогда добиваем минимально возможным padding (len=0 => +4 байта).
                padDataLen = 0;
            }

            extensions.AddRange(new byte[] { 0x00, 0x15 });
            extensions.AddRange(U16(padDataLen));
            if (padDataLen > 0)
            {
                extensions.AddRange(new byte[padDataLen]);
            }

            var padded = BuildTlsClientHelloRecord(extensions);
            return padded;

            static byte[] BuildTlsClientHelloRecord(List<byte> extensionsBytes)
            {
                // ClientHello body:
                var body = new List<byte>();
                body.AddRange(new byte[] { 0x03, 0x03 }); // client_version TLS 1.2
                body.AddRange(new byte[32]); // random
                body.Add(0x00); // session_id_len
                body.AddRange(U16(2));
                body.AddRange(new byte[] { 0x00, 0x2F });
                body.Add(0x01); // compression_methods_len
                body.Add(0x00); // null
                body.AddRange(U16(extensionsBytes.Count));
                body.AddRange(extensionsBytes);

                // Handshake header: type(1)=1 ClientHello, len(3)
                var hs = new List<byte>();
                hs.Add(0x01);
                hs.AddRange(U24(body.Count));
                hs.AddRange(body);

                // TLS record header: type(1)=0x16 handshake, version(2)=0x0301 TLS1.0, len(2)
                var record = new List<byte>();
                record.Add(0x16);
                record.AddRange(new byte[] { 0x03, 0x01 });
                record.AddRange(U16(hs.Count));
                record.AddRange(hs);

                return record.ToArray();
            }

            static IEnumerable<byte> U16(int value)
                => new byte[] { (byte)((value >> 8) & 0xFF), (byte)(value & 0xFF) };

            static IEnumerable<byte> U24(int value)
                => new byte[] { (byte)((value >> 16) & 0xFF), (byte)((value >> 8) & 0xFF), (byte)(value & 0xFF) };
        }
    }
}
