using System;
using System.Buffers.Binary;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;
using Xunit;

namespace ISP_Audit.Tests;

public sealed class TrafficEngineConcurrencyTests
{
    private sealed class NoOpFilter : IPacketFilter
    {
        public string Name { get; }
        public int Priority { get; }

        public NoOpFilter(string name, int priority)
        {
            Name = name;
            Priority = priority;
        }

        public bool Process(InterceptedPacket packet, PacketContext context, IPacketSender sender) => true;
    }

    private static byte[] BuildIpv4TcpPacket(
        IPAddress srcIp,
        IPAddress dstIp,
        ushort srcPort,
        ushort dstPort,
        byte ttl,
        ushort ipId,
        uint seq,
        byte tcpFlags)
    {
        const int ipHeaderLen = 20;
        const int tcpHeaderLen = 20;
        var totalLen = ipHeaderLen + tcpHeaderLen;
        var buffer = new byte[totalLen];

        // IPv4 header
        buffer[0] = 0x45; // Version=4, IHL=5
        buffer[1] = 0;    // TOS
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), (ushort)totalLen);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), ipId);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6, 2), 0); // flags/fragment
        buffer[8] = ttl;
        buffer[9] = 6; // TCP
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(10, 2), 0); // checksum (не нужен для unit)

        var src = srcIp.GetAddressBytes();
        var dst = dstIp.GetAddressBytes();
        if (src.Length != 4 || dst.Length != 4)
        {
            throw new ArgumentException("Только IPv4 адреса поддерживаются в unit-тесте");
        }

        src.CopyTo(buffer, 12);
        dst.CopyTo(buffer, 16);

        // TCP header
        var tcpOffset = ipHeaderLen;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset, 2), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 2, 2), dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(tcpOffset + 4, 4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(tcpOffset + 8, 4), 0); // ack

        buffer[tcpOffset + 12] = 0x50; // DataOffset=5 (20 bytes)
        buffer[tcpOffset + 13] = tcpFlags;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 14, 2), 8192); // window
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 16, 2), 0);    // checksum
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(tcpOffset + 18, 2), 0);    // urgent

        return buffer;
    }

    [Fact]
    public async Task ConcurrentRegisterRemoveAndProcessPacketForSmoke_DoesNotThrow()
    {
        using var engine = new TrafficEngine(progress: null);
        engine.RegisterFilter(new NoOpFilter("Stable", priority: 0));

        var packetBytes = BuildIpv4TcpPacket(
            srcIp: IPAddress.Parse("192.0.2.10"),
            dstIp: IPAddress.Parse("93.184.216.34"),
            srcPort: 12345,
            dstPort: 443,
            ttl: 64,
            ipId: 1,
            seq: 1,
            tcpFlags: 0x02);

        var packet = new InterceptedPacket(packetBytes, packetBytes.Length);

        var addr = new WinDivertNative.Address
        {
            Timestamp = 0,
            LayerEventFlags = (uint)WinDivertNative.Layer.Network | (1u << 17), // Network + Outbound
            Reserved2 = 0,
            Data = default
        };

        var ctx = new PacketContext(addr);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var token = cts.Token;

        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var processed = 0;
        var mutations = 0;

        var churnTask = Task.Run(async () =>
        {
            await start.Task.ConfigureAwait(false);

            for (var i = 0; i < 10_000; i++)
            {
                token.ThrowIfCancellationRequested();

                var name = $"F-{i % 64}";
                engine.RegisterFilter(new NoOpFilter(name, priority: i % 10));
                engine.RemoveFilter(name);
                mutations++;
            }
        }, token);

        var processTask = Task.Run(async () =>
        {
            await start.Task.ConfigureAwait(false);

            for (var i = 0; i < 250_000; i++)
            {
                token.ThrowIfCancellationRequested();
                _ = engine.ProcessPacketForSmoke(packet, ctx);
                processed++;
            }
        }, token);

        start.SetResult();
        await Task.WhenAll(churnTask, processTask).ConfigureAwait(false);

        Assert.True(processed > 0, "Ожидали хотя бы один обработанный пакет");
        Assert.True(mutations > 0, "Ожидали хотя бы одну мутацию списка фильтров");
    }
}
