using System;
using System.Collections.Immutable;
using System.Collections.Generic;
using System.Net;
using System.Buffers.Binary;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    /// <summary>
    /// Временный фильтр блокировки трафика для набора endpoint-ов.
    /// Используется для «подталкивания» переподключения приложения после применения обхода.
    /// </summary>
    public sealed class TemporaryEndpointBlockFilter : IPacketFilter
    {
        private readonly HashSet<uint> _ipv4Targets;
        private readonly ImmutableHashSet<uint> _ipv4TargetsImmutable;
        private readonly ushort _port;
        private readonly bool _blockTcp;
        private readonly bool _blockUdp;
        private readonly long _untilTick;

        // P0.2 Stage 2: TTL endpoint block как TTL-политика с самым высоким приоритетом.
        // Включается через feature-gate; при gate=off используем legacy путь (HashSet + untilTick).
        private readonly DecisionGraphSnapshot? _decisionGraphSnapshot;
        private readonly DateTimeOffset _createdAtUtc;
        private readonly TimeSpan _ttl;

        public string Name { get; }
        public int Priority => 250; // Выше BypassFilter (100): блокируем максимально рано.

        public TemporaryEndpointBlockFilter(
            string name,
            IEnumerable<IPAddress> ipv4Targets,
            TimeSpan ttl,
            ushort port = 443,
            bool blockTcp = true,
            bool blockUdp = true)
        {
            Name = string.IsNullOrWhiteSpace(name) ? "TemporaryEndpointBlockFilter" : name;
            _port = port;
            _blockTcp = blockTcp;
            _blockUdp = blockUdp;
            _ttl = ttl;
            _createdAtUtc = DateTimeOffset.UtcNow;
            _untilTick = Environment.TickCount64 + (long)Math.Max(0, ttl.TotalMilliseconds);

            _ipv4Targets = new HashSet<uint>();
            foreach (var ip in ipv4Targets)
            {
                var v = TryToIpv4Int(ip);
                if (v.HasValue)
                {
                    _ipv4Targets.Add(v.Value);
                }
            }

            _ipv4TargetsImmutable = _ipv4Targets.Count == 0
                ? ImmutableHashSet<uint>.Empty
                : _ipv4Targets.ToImmutableHashSet();

            _decisionGraphSnapshot = TryBuildDecisionGraphSnapshot();
        }

        public bool Process(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            // TTL истёк — больше не блокируем.
            if (Environment.TickCount64 >= _untilTick)
            {
                return true;
            }

            // IPv6 сейчас не парсим (PacketParser упрощённый), поэтому блокируем только IPv4.
            if (!packet.Info.IsIpv4)
            {
                return true;
            }

            if (_ipv4Targets.Count == 0)
            {
                return true;
            }

            var isTcp = packet.Info.IsTcp;
            var isUdp = packet.Info.IsUdp;
            if ((isTcp && !_blockTcp) || (isUdp && !_blockUdp) || (!isTcp && !isUdp))
            {
                return true;
            }

            // Policy-driven путь (P0.2 Stage 2): TTL endpoint block как FlowPolicy с максимальным приоритетом.
            // Важно: поведение меняется только при включённом gate и наличии snapshot.
            var snapshot = _decisionGraphSnapshot;
            if (snapshot != null && PolicyDrivenExecutionGates.PolicyDrivenTtlEndpointBlockEnabled())
            {
                var proto = isTcp ? FlowTransportProtocol.Tcp : FlowTransportProtocol.Udp;
                foreach (var policy in snapshot.GetCandidates(proto, _port, tlsStage: null))
                {
                    if (!IsPolicyActive(policy)) continue;
                    if (policy.Action.Kind != PolicyActionKind.Block) continue;

                    // TTL endpoint block: блокируем обе стороны, поэтому мэтчим remote как src OR dst.
                    if (!MatchesEndpointBlockPolicy(policy, packet.Info.SrcIpInt, packet.Info.DstIpInt, packet.Info.SrcPort, packet.Info.DstPort))
                    {
                        continue;
                    }

                    // Drop/stop processing.
                    return false;
                }

                return true;
            }

            // Блокируем обе стороны: и исходящие к remote, и входящие от remote.
            var matchesRemote = _ipv4Targets.Contains(packet.Info.DstIpInt) || _ipv4Targets.Contains(packet.Info.SrcIpInt);
            if (!matchesRemote)
            {
                return true;
            }

            // Ограничиваемся портом (по обе стороны), чтобы не ломать лишнее.
            if (packet.Info.DstPort != _port && packet.Info.SrcPort != _port)
            {
                return true;
            }

            // Drop/stop processing.
            return false;
        }

        private DecisionGraphSnapshot? TryBuildDecisionGraphSnapshot()
        {
            try
            {
                if (!PolicyDrivenExecutionGates.PolicyDrivenTtlEndpointBlockEnabled())
                {
                    return null;
                }

                if (_ipv4TargetsImmutable.Count == 0)
                {
                    return null;
                }

                // Одна TTL-политика на порт: блокировать трафик к endpoint-ам на порту (в обе стороны проверяем в execution plane).
                var policy = new FlowPolicy
                {
                    Id = $"ttl_endpoint_block:{Name}",
                    Priority = int.MaxValue,
                    Scope = PolicyScope.Local,
                    Ttl = _ttl,
                    CreatedAt = _createdAtUtc,
                    Match = new MatchCondition
                    {
                        // Proto = null => ANY (сработает и для TCP, и для UDP через fallback ключей)
                        Port = _port,
                        DstIpv4Set = _ipv4TargetsImmutable
                    },
                    Action = PolicyAction.Block
                };

                return PolicySetCompiler.CompileOrThrow(new[] { policy });
            }
            catch
            {
                // Наблюдаемость здесь не критична: reconnect-nudge должен быть best-effort.
                return null;
            }
        }

        private static bool IsPolicyActive(FlowPolicy policy)
        {
            try
            {
                if (policy.Ttl is null) return true;
                return DateTimeOffset.UtcNow < policy.CreatedAt + policy.Ttl.Value;
            }
            catch
            {
                return false;
            }
        }

        private static bool MatchesEndpointBlockPolicy(FlowPolicy policy, uint srcIpInt, uint dstIpInt, ushort srcPort, ushort dstPort)
        {
            var match = policy.Match;

            // Порт ограничиваем симметрично (как и в legacy фильтре).
            if (match.Port.HasValue && dstPort != match.Port.Value && srcPort != match.Port.Value)
            {
                return false;
            }

            var set = match.DstIpv4Set;
            if (set is null) return true;
            if (set.Count == 0) return false;

            return set.Contains(srcIpInt) || set.Contains(dstIpInt);
        }

        private static uint? TryToIpv4Int(IPAddress ip)
        {
            try
            {
                if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
                var bytes = ip.GetAddressBytes();
                if (bytes.Length != 4) return null;
                return BinaryPrimitives.ReadUInt32BigEndian(bytes);
            }
            catch
            {
                return null;
            }
        }
    }
}
