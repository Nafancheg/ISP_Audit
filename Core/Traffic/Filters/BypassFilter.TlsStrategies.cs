using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter
    {
        private readonly ConcurrentDictionary<ConnectionKey, ConnectionState> _connections = new();

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
            List<FragmentSlice>? fragmentPlan,
            TlsBypassStrategy tlsStrategy)
        {
            bool handled = false;

            if (tlsStrategy == TlsBypassStrategy.Fake ||
                tlsStrategy == TlsBypassStrategy.FakeFragment ||
                tlsStrategy == TlsBypassStrategy.FakeDisorder)
            {
                if (ApplyFakeStrategy(packet, context, sender, isNewConnection))
                {
                    handled = true;
                }
            }

            if ((tlsStrategy == TlsBypassStrategy.Fragment ||
                tlsStrategy == TlsBypassStrategy.FakeFragment) && fragmentPlan != null)
            {
                if (ApplyFragmentStrategy(packet, context, sender, fragmentPlan))
                {
                    handled = true;
                }
            }
            else if ((tlsStrategy == TlsBypassStrategy.Disorder ||
                     tlsStrategy == TlsBypassStrategy.FakeDisorder) && fragmentPlan != null)
            {
                if (ApplyDisorderStrategy(packet, context, sender, fragmentPlan))
                {
                    handled = true;
                }
            }

            return handled;
        }

        private bool TrySelectTlsStrategyPolicyDriven(
            InterceptedPacket packet,
            int payloadLength,
            bool hasSni,
            out string? selectedPolicyId,
            out TlsBypassStrategy tlsStrategy)
        {
            selectedPolicyId = null;
            tlsStrategy = _profile.TlsStrategy;

            var snapshot = _decisionGraphSnapshot;
            if (snapshot == null) return false;
            if (!PolicyDrivenExecutionGates.PolicyDrivenTcp443TlsStrategyEnabled()) return false;

            // Stage 4: выбор стратегии для TCP/443 на ClientHello (и NoSni, если SNI отсутствует).
            if (!packet.Info.IsTcp || packet.Info.DstPort != 443) return false;
            if (!packet.Info.IsIpv4 && !packet.Info.IsIpv6) return false;

            var primaryStage = (!hasSni && payloadLength >= _profile.TlsFragmentThreshold)
                ? IspAudit.Core.Models.TlsStage.NoSni
                : IspAudit.Core.Models.TlsStage.ClientHello;

            // Если политика явно не задаёт NoSni, но при этом хочет управлять ClientHello,
            // даём предсказуемый fallback: NoSni → ClientHello.
            // Это также помогает в smoke-тестах с синтетическим ClientHello без SNI.
            var selected = snapshot.EvaluateTcp443TlsClientHello(
                packet.Info.DstIpInt,
                isIpv4: packet.Info.IsIpv4,
                isIpv6: packet.Info.IsIpv6,
                tlsStage: primaryStage);

            if (selected == null && primaryStage == IspAudit.Core.Models.TlsStage.NoSni)
            {
                selected = snapshot.EvaluateTcp443TlsClientHello(
                    packet.Info.DstIpInt,
                    isIpv4: packet.Info.IsIpv4,
                    isIpv6: packet.Info.IsIpv6,
                    tlsStage: IspAudit.Core.Models.TlsStage.ClientHello);
            }

            if (selected == null) return false;
            if (selected.Action.Kind != IspAudit.Core.Models.PolicyActionKind.Strategy) return false;
            if (!string.Equals(selected.Action.StrategyId, IspAudit.Core.Models.PolicyAction.StrategyIdTlsBypassStrategy, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!selected.Action.Parameters.TryGetValue(IspAudit.Core.Models.PolicyAction.ParameterKeyTlsStrategy, out var rawStrategy)
                || string.IsNullOrWhiteSpace(rawStrategy))
            {
                return false;
            }

            if (!Enum.TryParse<TlsBypassStrategy>(rawStrategy, ignoreCase: true, out var parsed))
            {
                return false;
            }

            selectedPolicyId = selected.Id;
            tlsStrategy = parsed;
            return true;
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

                // Bad checksum (MVP): портим TCP checksum только у фейкового пакета.
                // Важно: отправка должна происходить без пересчёта checksum и со сброшенными addr checksum-флагами.
                if (_profile.BadChecksum && sender is IPacketSenderEx senderEx)
                {
                    var tcpChecksumOffset = packet.Info.IpHeaderLength + 16;
                    // Детерминированная порча: если было 0x0000, станет 0xFFFF.
                    var current = BinaryPrimitives.ReadUInt16BigEndian(fakeBuffer.AsSpan(tcpChecksumOffset, 2));
                    BinaryPrimitives.WriteUInt16BigEndian(fakeBuffer.AsSpan(tcpChecksumOffset, 2), (ushort)~current);

                    var badAddr = context.Address;
                    return senderEx.SendEx(fakeBuffer, length, ref badAddr, PacketSendOptions.BadChecksum);
                }

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

        private static bool HasSniExtension(ReadOnlySpan<byte> payload)
        {
            try
            {
                // Минимальный парсер TLS ClientHello для детекта extension type 0x0000 (server_name).
                // Достаточно для smoke-тестов и гейтирования обхода по "наличию SNI".

                // TLS record header: 5 байт
                if (payload.Length < 5 + 4) return false;
                if (payload[0] != 0x16) return false;

                var recordLen = (payload[3] << 8) | payload[4];
                var recordEnd = 5 + recordLen;
                if (recordEnd > payload.Length) recordEnd = payload.Length;

                var handshakeOffset = 5;
                if (handshakeOffset + 4 > recordEnd) return false;
                if (payload[handshakeOffset] != 0x01) return false; // ClientHello

                var helloLen = (payload[handshakeOffset + 1] << 16) | (payload[handshakeOffset + 2] << 8) | payload[handshakeOffset + 3];
                var helloStart = handshakeOffset + 4;
                var helloEnd = helloStart + helloLen;
                if (helloEnd > recordEnd) helloEnd = recordEnd;

                var p = helloStart;

                // client_version(2) + random(32)
                if (p + 2 + 32 > helloEnd) return false;
                p += 2 + 32;

                // session_id
                if (p + 1 > helloEnd) return false;
                var sessionIdLen = payload[p];
                p += 1;
                if (p + sessionIdLen > helloEnd) return false;
                p += sessionIdLen;

                // cipher_suites
                if (p + 2 > helloEnd) return false;
                var cipherLen = (payload[p] << 8) | payload[p + 1];
                p += 2;
                if (p + cipherLen > helloEnd) return false;
                p += cipherLen;

                // compression_methods
                if (p + 1 > helloEnd) return false;
                var compLen = payload[p];
                p += 1;
                if (p + compLen > helloEnd) return false;
                p += compLen;

                // extensions
                if (p + 2 > helloEnd) return false;
                var extLen = (payload[p] << 8) | payload[p + 1];
                p += 2;
                var extEnd = p + extLen;
                if (extEnd > helloEnd) extEnd = helloEnd;

                while (p + 4 <= extEnd)
                {
                    var extType = (payload[p] << 8) | payload[p + 1];
                    var len = (payload[p + 2] << 8) | payload[p + 3];
                    p += 4;
                    if (p + len > extEnd) break;

                    if (extType == 0x0000)
                    {
                        return true;
                    }

                    p += len;
                }
            }
            catch
            {
            }

            return false;
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
    }
}
