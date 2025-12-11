using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Linq;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    public class BypassFilter : IPacketFilter
    {
        private readonly BypassProfile _profile;
        private readonly Action<string>? _log;
        private readonly string _presetName;
        private readonly ConcurrentDictionary<ConnectionKey, ConnectionState> _connections = new();
        private long _packetsProcessed;
        private long _rstDropped;
        private long _rstDroppedRelevant;
        private long _clientHellosFragmented;
        private long _tlsHandled;
        private string _lastFragmentPlan = string.Empty;

        public string Name => "BypassFilter";
        public int Priority => 100; // High priority

        public BypassFilter(BypassProfile profile, Action<string>? logAction = null, string presetName = "")
        {
            _profile = profile;
            _log = logAction;
            _presetName = presetName;
        }

        public bool Process(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            Interlocked.Increment(ref _packetsProcessed);

            // 1. RST Blocking
            if (_profile.DropTcpRst && packet.Info.IsTcp && packet.Info.IsRst)
            {
                Interlocked.Increment(ref _rstDropped);

                if (packet.Info.DstPort == 443)
                {
                    var key = new ConnectionKey(packet.Info.SrcIpInt, packet.Info.DstIpInt, packet.Info.SrcPort, packet.Info.DstPort);
                    if (_connections.TryGetValue(key, out var state) && state.BypassApplied)
                    {
                        Interlocked.Increment(ref _rstDroppedRelevant);
                        _log?.Invoke($"[Bypass][RST] preset={_presetName}, rst@443 after bypass, conn={packet.Info.SrcIpInt}->{packet.Info.DstIpInt}:{packet.Info.DstPort}");
                    }
                }
                // Drop packet
                return false;
            }

            // 2. TLS Fragmentation / Fake / Disorder
            if (packet.Info.IsTcp && 
                packet.Info.PayloadLength >= _profile.TlsFragmentThreshold && 
                packet.Info.DstPort == 443)
            {
                if (IsClientHello(packet.Buffer.AsSpan(packet.Info.PayloadOffset, packet.Info.PayloadLength)))
                {
                    // 2.1 TTL Trick (send fake packet with low TTL)
                    if (_profile.TtlTrick)
                    {
                        ApplyTtlTrick(packet, context, sender);
                    }

                    var connectionKey = new ConnectionKey(packet.Info.SrcIpInt, packet.Info.DstIpInt, packet.Info.SrcPort, packet.Info.DstPort);
                    bool isNewConnection = _connections.TryAdd(connectionKey, new ConnectionState(Environment.TickCount64, false));

                    var fragmentPlan = BuildFragmentPlan(packet);

                    if (ProcessTlsStrategy(packet, context, sender, isNewConnection, fragmentPlan))
                    {
                        Interlocked.Increment(ref _clientHellosFragmented);
                        Interlocked.Increment(ref _tlsHandled);
                        _lastFragmentPlan = fragmentPlan != null ? string.Join('/', fragmentPlan.Select(f => f.PayloadLength)) : "";
                        _log?.Invoke($"[Bypass][TLS] preset={_presetName}, payload={packet.Info.PayloadLength}, plan={_lastFragmentPlan}, strategy={_profile.TlsStrategy}, result=fragmented");
                        _connections.AddOrUpdate(connectionKey,
                            _ => new ConnectionState(Environment.TickCount64, true),
                            (_, existing) => new ConnectionState(existing.FirstSeen, true));
                        return false; // Packet handled (fragmented/faked), drop original
                    }
                }
            }

            return true; // Pass through
        }

        private void ApplyTtlTrick(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            // Create a copy of the packet
            var fakePacket = new byte[packet.Length];
            Array.Copy(packet.Buffer, fakePacket, packet.Length);

            // Set TTL (IPv4 offset 8)
            if (packet.Info.IsIpv4)
            {
                fakePacket[8] = (byte)_profile.TtlTrickValue;
                PacketHelper.RecalculateIpChecksum(fakePacket);
                
                // Send the fake packet
                // Note: We use the same address info, so it goes to the same destination
                var addr = context.Address;
                sender.Send(fakePacket, fakePacket.Length, ref addr);
            }
        }

        private bool ProcessTlsStrategy(
            InterceptedPacket packet,
            PacketContext context,
            IPacketSender sender,
            bool isNewConnection,
            List<FragmentSlice>? fragmentPlan)
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

            if ((_profile.TlsStrategy == TlsBypassStrategy.Fragment || 
                _profile.TlsStrategy == TlsBypassStrategy.FakeFragment) && fragmentPlan != null)
            {
                if (ApplyFragmentStrategy(packet, context, sender, fragmentPlan))
                {
                    handled = true;
                }
            }
            else if ((_profile.TlsStrategy == TlsBypassStrategy.Disorder || 
                     _profile.TlsStrategy == TlsBypassStrategy.FakeDisorder) && fragmentPlan != null)
            {
                if (ApplyDisorderStrategy(packet, context, sender, fragmentPlan))
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

        private bool ApplyFragmentStrategy(InterceptedPacket packet, PacketContext context, IPacketSender sender, List<FragmentSlice> fragments)
        {
            return SendFragments(packet, context, sender, fragments, reverseOrder: false);
        }

        private bool ApplyDisorderStrategy(InterceptedPacket packet, PacketContext context, IPacketSender sender, List<FragmentSlice> fragments)
        {
            return SendFragments(packet, context, sender, fragments, reverseOrder: true);
        }

        private bool SendFragments(InterceptedPacket packet, PacketContext context, IPacketSender sender, List<FragmentSlice> fragments, bool reverseOrder)
        {
            if (fragments.Count < 2) return false;

            int headerLen = packet.Info.IpHeaderLength + packet.Info.TcpHeaderLength;
            var addr = context.Address;
            var ordered = reverseOrder ? fragments.AsEnumerable().Reverse() : fragments;

            foreach (var fragment in ordered)
            {
                var buffer = ArrayPool<byte>.Shared.Rent(headerLen + fragment.PayloadLength);
                try
                {
                    Buffer.BlockCopy(packet.Buffer, 0, buffer, 0, headerLen);
                    Buffer.BlockCopy(packet.Buffer, fragment.PayloadOffset, buffer, headerLen, fragment.PayloadLength);

                    if (fragment.SeqOffset > 0)
                    {
                        IncrementTcpSequence(buffer, packet.Info.IpHeaderLength, (uint)fragment.SeqOffset);
                    }

                    AdjustPacketLengths(buffer, packet.Info.IpHeaderLength, packet.Info.TcpHeaderLength, fragment.PayloadLength, packet.Info.IsIpv4);
                    sender.Send(buffer, headerLen + fragment.PayloadLength, ref addr);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }

            return true;
        }

        private List<FragmentSlice>? BuildFragmentPlan(InterceptedPacket packet)
        {
            var configuredSizes = _profile.TlsFragmentSizes ?? Array.Empty<int>();
            var safeSizes = configuredSizes.Where(v => v > 0).Take(4).ToList();

            if (safeSizes.Count == 0 && _profile.TlsFirstFragmentSize > 0)
            {
                safeSizes.Add(_profile.TlsFirstFragmentSize);
            }

            if (safeSizes.Count == 0)
            {
                return null;
            }

            var fragments = new List<FragmentSlice>();
            var remaining = packet.Info.PayloadLength;
            var consumed = 0;

            foreach (var size in safeSizes)
            {
                if (remaining - size <= 0)
                {
                    break;
                }

                fragments.Add(new FragmentSlice(packet.Info.PayloadOffset + consumed, size, consumed));
                remaining -= size;
                consumed += size;
            }

            if (remaining <= 0)
            {
                return null;
            }

            fragments.Add(new FragmentSlice(packet.Info.PayloadOffset + consumed, remaining, consumed));

            return fragments.Count >= 2 ? fragments : null;
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

        public BypassMetricsSnapshot GetMetrics()
        {
            return new BypassMetricsSnapshot
            {
                PacketsProcessed = Interlocked.Read(ref _packetsProcessed),
                RstDropped = Interlocked.Read(ref _rstDropped),
                RstDroppedRelevant = Interlocked.Read(ref _rstDroppedRelevant),
                ClientHellosFragmented = Interlocked.Read(ref _clientHellosFragmented),
                TlsHandled = Interlocked.Read(ref _tlsHandled),
                LastFragmentPlan = _lastFragmentPlan
            };
        }

        public readonly struct BypassMetricsSnapshot
        {
            public long PacketsProcessed { get; init; }
            public long RstDropped { get; init; }
            public long RstDroppedRelevant { get; init; }
            public long ClientHellosFragmented { get; init; }
            public long TlsHandled { get; init; }
            public string LastFragmentPlan { get; init; }
        }

        private readonly struct ConnectionState
        {
            public ConnectionState(long firstSeen, bool bypassApplied)
            {
                FirstSeen = firstSeen;
                BypassApplied = bypassApplied;
            }

            public long FirstSeen { get; }
            public bool BypassApplied { get; }
        }

        private readonly struct FragmentSlice
        {
            public FragmentSlice(int payloadOffset, int payloadLength, int seqOffset)
            {
                PayloadOffset = payloadOffset;
                PayloadLength = payloadLength;
                SeqOffset = seqOffset;
            }

            public int PayloadOffset { get; }
            public int PayloadLength { get; }
            public int SeqOffset { get; }
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
