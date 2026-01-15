using System;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter
    {
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
