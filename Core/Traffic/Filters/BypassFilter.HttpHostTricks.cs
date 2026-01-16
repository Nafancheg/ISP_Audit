using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter
    {
        // HTTP Host tricks: применяем один раз на соединение (src/dst/ports).
        private readonly ConcurrentDictionary<ConnectionKey, byte> _httpHostTricksApplied = new();

        private bool TryApplyHttpHostTricksPolicyDriven(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            // P0.2 Stage 3: TCP/80 Host tricks как политика.
            // Важно: при выключенном gate не меняем поведение (legacy ветка управляется профилем).
            var snapshot = _decisionGraphSnapshot;
            if (snapshot == null) return false;
            if (!PolicyDrivenExecutionGates.PolicyDrivenTcp80HostTricksEnabled()) return false;

            foreach (var policy in snapshot.GetCandidates(FlowTransportProtocol.Tcp, 80, tlsStage: null))
            {
                if (policy.Action.Kind != PolicyActionKind.Strategy) continue;
                if (!string.Equals(policy.Action.StrategyId, PolicyAction.StrategyIdHttpHostTricks, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (TryApplyHttpHostTricks(packet, context, sender))
                {
                    RecordPolicyApplied(policy.Id);
                    return true;
                }

                return false;
            }

            return false;
        }

        private bool TryApplyHttpHostTricks(InterceptedPacket packet, PacketContext context, IPacketSender sender)
        {
            try
            {
                // Ограничиваемся IPv4/обычными TCP пакетами.
                if (!packet.Info.IsIpv4) return false;
                if (packet.Info.PayloadLength <= 0) return false;

                var payload = packet.Buffer.AsSpan(packet.Info.PayloadOffset, packet.Info.PayloadLength);
                if (!TryFindHttpHostHeader(payload, out var hostIndex))
                {
                    return false;
                }

                // Разрезаем внутри слова "Host" (после "Ho").
                var split = hostIndex + 2;
                if (split <= 0 || split >= payload.Length) return false;

                var key = new ConnectionKey(packet.Info.SrcIpInt, packet.Info.DstIpInt, packet.Info.SrcPort, packet.Info.DstPort);
                if (!_httpHostTricksApplied.TryAdd(key, 0))
                {
                    return false;
                }

                var fragments = new List<FragmentSlice>(capacity: 2)
                {
                    new(packet.Info.PayloadOffset, split, 0),
                    new(packet.Info.PayloadOffset + split, payload.Length - split, split),
                };

                if (SendFragments(packet, context, sender, fragments, reverseOrder: false))
                {
                    if (_verbosePacketLog)
                    {
                        _log?.Invoke($"[Bypass][HTTP] preset={_presetName}, hostTricks split={split}, result=segmented");
                    }
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryFindHttpHostHeader(ReadOnlySpan<byte> payload, out int hostIndex)
        {
            // Ищем "\r\nHost:" или "Host:" в начале.
            // Поиск case-insensitive (ASCII), ограничиваемся первыми ~1KB для производительности.
            hostIndex = -1;

            var limit = Math.Min(payload.Length, 1024);
            var span = payload.Slice(0, limit);

            // Вариант 1: начало строки
            if (StartsWithHostHeader(span, 0))
            {
                hostIndex = 0;
                return true;
            }

            // Вариант 2: после CRLF
            for (var i = 0; i + 7 < span.Length; i++)
            {
                if (span[i] != (byte)'\r' || span[i + 1] != (byte)'\n')
                {
                    continue;
                }

                if (StartsWithHostHeader(span, i + 2))
                {
                    hostIndex = i + 2;
                    return true;
                }
            }

            return false;
        }

        private static bool StartsWithHostHeader(ReadOnlySpan<byte> payload, int offset)
        {
            if (offset < 0) return false;
            if (offset + 5 > payload.Length) return false;

            var h0 = payload[offset];
            var h1 = payload[offset + 1];
            var h2 = payload[offset + 2];
            var h3 = payload[offset + 3];
            var h4 = payload[offset + 4];

            // Host:
            if (!IsAsciiLetterEqualIgnoreCase(h0, (byte)'H')) return false;
            if (!IsAsciiLetterEqualIgnoreCase(h1, (byte)'o')) return false;
            if (!IsAsciiLetterEqualIgnoreCase(h2, (byte)'s')) return false;
            if (!IsAsciiLetterEqualIgnoreCase(h3, (byte)'t')) return false;
            if (h4 != (byte)':') return false;

            return true;
        }

        private static bool IsAsciiLetterEqualIgnoreCase(byte value, byte expected)
        {
            // expected — уже в нужном регистре; приводим value к нижнему, если это A-Z.
            if (value >= (byte)'A' && value <= (byte)'Z')
            {
                value = (byte)(value + 32);
            }

            if (expected >= (byte)'A' && expected <= (byte)'Z')
            {
                expected = (byte)(expected + 32);
            }

            return value == expected;
        }
    }
}
