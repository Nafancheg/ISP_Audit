using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    public class BypassFilter : IPacketFilter
    {
        private readonly BypassProfile _profile;
        private readonly ConcurrentDictionary<ConnectionKey, long> _processedConnections = new();
        private long _packetsProcessed;
        private long _rstDropped;
        private long _clientHellosFragmented;

        public string Name => "BypassFilter";
        public int Priority => 100; // High priority

        public BypassFilter(BypassProfile profile)
        {
            _profile = profile;
        }

        public bool Process(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            Interlocked.Increment(ref _packetsProcessed);

            // 1. RST Blocking
            if (_profile.DropTcpRst && packet.Info.IsTcp && packet.Info.IsRst)
            {
                Interlocked.Increment(ref _rstDropped);
                // Drop packet
                return false;
            }

            // 2. TLS Fragmentation
            if (_profile.TlsStrategy != TlsBypassStrategy.None && 
                packet.Info.IsTcp && 
                packet.Info.PayloadLength >= _profile.TlsFragmentThreshold && 
                packet.Info.DstPort == 443)
            {
                if (IsClientHello(packet.Buffer.AsSpan(packet.Info.PayloadOffset, packet.Info.PayloadLength)))
                {
                    var connectionKey = new ConnectionKey(packet.Info.SrcIpInt, packet.Info.DstIpInt, packet.Info.SrcPort, packet.Info.DstPort);
                    bool isNewConnection = !_processedConnections.ContainsKey(connectionKey);
                    _processedConnections[connectionKey] = Environment.TickCount64;

                    if (ProcessTlsStrategy(packet, context, sender, isNewConnection))
                    {
                        Interlocked.Increment(ref _clientHellosFragmented);
                        return false; // Packet handled (fragmented/faked), drop original
                    }
                }
            }

            return true; // Pass through
        }

        private bool ProcessTlsStrategy(InterceptedPacket packet, PacketContext context, IPacketSender sender, bool isNewConnection)
        {
            bool handled = false;

            if (_profile.TlsStrategy == TlsBypassStrategy.Fake || 
                _profile.TlsStrategy == TlsBypassStrategy.FakeFragment || 
                _profile.TlsStrategy == TlsBypassStrategy.FakeDisorder)
            {
                if (ApplyFakeStrategy(packet, context, sender, isNewConnection))
                {
                    handled = true;
                }
            }

            if (_profile.TlsStrategy == TlsBypassStrategy.Fragment || 
                _profile.TlsStrategy == TlsBypassStrategy.FakeFragment)
            {
                if (ApplyFragmentStrategy(packet, context, sender))
                {
                    handled = true;
                }
            }
            else if (_profile.TlsStrategy == TlsBypassStrategy.Disorder || 
                     _profile.TlsStrategy == TlsBypassStrategy.FakeDisorder)
            {
                if (ApplyDisorderStrategy(packet, context, sender))
                {
                    handled = true;
                }
            }

            return handled;
        }

        private bool ApplyFakeStrategy(InterceptedPacket packet, PacketContext context, IPacketSender sender, bool isNewConnection)
        {
            if (!isNewConnection) return false;

            var length = packet.Length;
            var fakeBuffer = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                Buffer.BlockCopy(packet.Buffer, 0, fakeBuffer, 0, length);

                // Modify Sequence Number (BadSeq): Seq - 10000
                int seqOffset = packet.Info.IpHeaderLength + 4;
                uint seq = BinaryPrimitives.ReadUInt32BigEndian(fakeBuffer.AsSpan(seqOffset, 4));
                BinaryPrimitives.WriteUInt32BigEndian(fakeBuffer.AsSpan(seqOffset, 4), seq - 10000);

                var addr = context.Address; // Copy address struct
                return sender.Send(fakeBuffer, length, ref addr);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(fakeBuffer);
            }
        }

        private bool ApplyFragmentStrategy(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            int firstLen = Math.Min(_profile.TlsFirstFragmentSize, packet.Info.PayloadLength - 1);
            int secondLen = packet.Info.PayloadLength - firstLen;

            if (firstLen <= 0 || secondLen <= 0) return false;

            int headerLen = packet.Info.IpHeaderLength + packet.Info.TcpHeaderLength;
            var firstBuffer = ArrayPool<byte>.Shared.Rent(headerLen + firstLen);
            var secondBuffer = ArrayPool<byte>.Shared.Rent(headerLen + secondLen);

            try
            {
                var addr = context.Address;

                // First Fragment
                Buffer.BlockCopy(packet.Buffer, 0, firstBuffer, 0, headerLen);
                Buffer.BlockCopy(packet.Buffer, packet.Info.PayloadOffset, firstBuffer, headerLen, firstLen);
                AdjustPacketLengths(firstBuffer, packet.Info.IpHeaderLength, packet.Info.TcpHeaderLength, firstLen, packet.Info.IsIpv4);
                sender.Send(firstBuffer, headerLen + firstLen, ref addr);

                // Second Fragment
                Buffer.BlockCopy(packet.Buffer, 0, secondBuffer, 0, headerLen);
                Buffer.BlockCopy(packet.Buffer, packet.Info.PayloadOffset + firstLen, secondBuffer, headerLen, secondLen);
                IncrementTcpSequence(secondBuffer, packet.Info.IpHeaderLength, (uint)firstLen);
                AdjustPacketLengths(secondBuffer, packet.Info.IpHeaderLength, packet.Info.TcpHeaderLength, secondLen, packet.Info.IsIpv4);
                sender.Send(secondBuffer, headerLen + secondLen, ref addr);

                return true;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(firstBuffer);
                ArrayPool<byte>.Shared.Return(secondBuffer);
            }
        }

        private bool ApplyDisorderStrategy(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            int firstLen = Math.Min(_profile.TlsFirstFragmentSize, packet.Info.PayloadLength - 1);
            int secondLen = packet.Info.PayloadLength - firstLen;

            if (firstLen <= 0 || secondLen <= 0) return false;

            int headerLen = packet.Info.IpHeaderLength + packet.Info.TcpHeaderLength;
            var firstBuffer = ArrayPool<byte>.Shared.Rent(headerLen + firstLen);
            var secondBuffer = ArrayPool<byte>.Shared.Rent(headerLen + secondLen);

            try
            {
                var addr = context.Address;

                // Prepare First Fragment (sent SECOND)
                Buffer.BlockCopy(packet.Buffer, 0, firstBuffer, 0, headerLen);
                Buffer.BlockCopy(packet.Buffer, packet.Info.PayloadOffset, firstBuffer, headerLen, firstLen);
                AdjustPacketLengths(firstBuffer, packet.Info.IpHeaderLength, packet.Info.TcpHeaderLength, firstLen, packet.Info.IsIpv4);

                // Prepare Second Fragment (sent FIRST)
                Buffer.BlockCopy(packet.Buffer, 0, secondBuffer, 0, headerLen);
                Buffer.BlockCopy(packet.Buffer, packet.Info.PayloadOffset + firstLen, secondBuffer, headerLen, secondLen);
                IncrementTcpSequence(secondBuffer, packet.Info.IpHeaderLength, (uint)firstLen);
                AdjustPacketLengths(secondBuffer, packet.Info.IpHeaderLength, packet.Info.TcpHeaderLength, secondLen, packet.Info.IsIpv4);

                // Send in REVERSE order
                sender.Send(secondBuffer, headerLen + secondLen, ref addr);
                sender.Send(firstBuffer, headerLen + firstLen, ref addr);

                return true;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(firstBuffer);
                ArrayPool<byte>.Shared.Return(secondBuffer);
            }
        }

        private static bool IsClientHello(ReadOnlySpan<byte> payload)
        {
            if (payload.Length < 7) return false;
            if (payload[0] != 0x16) return false; // TLS Handshake
            if (payload[5] != 0x01) return false; // ClientHello
            return true;
        }

        private static void AdjustPacketLengths(byte[] packet, int ipHeaderLength, int tcpHeaderLength, int payloadLength, bool isIpv4)
        {
            if (isIpv4)
            {
                ushort total = (ushort)(ipHeaderLength + tcpHeaderLength + payloadLength);
                packet[2] = (byte)(total >> 8);
                packet[3] = (byte)(total & 0xFF);
            }
            else
            {
                ushort payload = (ushort)(tcpHeaderLength + payloadLength);
                packet[4] = (byte)(payload >> 8);
                packet[5] = (byte)(payload & 0xFF);
            }
        }

        private static void IncrementTcpSequence(byte[] packet, int ipHeaderLength, uint delta)
        {
            int offset = ipHeaderLength + 4;
            uint sequence = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset, 4));
            sequence += delta;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(offset, 4), sequence);
        }

        private readonly struct ConnectionKey : IEquatable<ConnectionKey>
        {
            public readonly uint SrcIp;
            public readonly uint DstIp;
            public readonly ushort SrcPort;
            public readonly ushort DstPort;

            public ConnectionKey(uint srcIp, uint dstIp, ushort srcPort, ushort dstPort)
            {
                SrcIp = srcIp;
                DstIp = dstIp;
                SrcPort = srcPort;
                DstPort = dstPort;
            }

            public bool Equals(ConnectionKey other)
            {
                return SrcIp == other.SrcIp && DstIp == other.DstIp && SrcPort == other.SrcPort && DstPort == other.DstPort;
            }

            public override bool Equals(object? obj)
            {
                return obj is ConnectionKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(SrcIp, DstIp, SrcPort, DstPort);
            }
        }
    }
}
