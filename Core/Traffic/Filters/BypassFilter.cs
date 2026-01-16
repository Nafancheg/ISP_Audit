using System;
using System.Linq;
using System.Threading;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter : IPacketFilter
    {
        private readonly BypassProfile _profile;
        private readonly Action<string>? _log;
        private readonly string _presetName;
        private static bool _verbosePacketLog = false; // выключаем пометку каждого пакета, чтобы не раздувать лог

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
            var isProbe = IsProbeFlow(packet.Info);

            if (!isProbe)
            {
                Interlocked.Increment(ref _packetsProcessed);
            }

            // QUIC fallback: многие клиенты/браузеры по умолчанию используют QUIC (UDP/443).
            // TLS обход работает только на TCP, поэтому при включённом DropUdp443
            // принудительно глушим UDP:443, чтобы клиент откатился на TCP/HTTPS.
            if (ShouldDropUdp443(packet.Info, isProbe))
            {
                if (!isProbe)
                {
                    Interlocked.Increment(ref _udp443Dropped);
                }
                return false;
            }

            // HTTP Host tricks (MVP/Stage 3): разрезать Host заголовок по границе TCP сегментов.
            // 1) Policy-driven ветка (при включённом gate) — управляется через DecisionGraphSnapshot.
            // 2) Legacy ветка — управляется флагом профиля.
            if (context.IsOutbound
                && packet.Info.IsTcp
                && packet.Info.DstPort == 80
                && packet.Info.PayloadLength >= 16)
            {
                if (TryApplyHttpHostTricksPolicyDriven(packet, context, sender))
                {
                    return false;
                }

                // Legacy: оставляем прежнее поведение при выключенном gate/отсутствии policy.
                if (_profile.HttpHostTricks && TryApplyHttpHostTricks(packet, context, sender))
                {
                    return false;
                }
            }

            var payloadLength = packet.Info.PayloadLength;
            var isTcp = packet.Info.IsTcp;
            var isClientHello = false;
            var hasSni = false;
            ReadOnlySpan<byte> payloadSpan = default;

            if (isTcp && payloadLength >= 7)
            {
                payloadSpan = packet.Buffer.AsSpan(packet.Info.PayloadOffset, payloadLength);
                isClientHello = IsClientHello(payloadSpan);

                if (isClientHello)
                {
                    if (packet.Info.DstPort != 443)
                    {
                        if (!isProbe)
                        {
                            Interlocked.Increment(ref _tlsClientHellosNon443);
                        }
                    }
                    else
                    {
                        if (!isProbe)
                        {
                            Interlocked.Increment(ref _tlsClientHellosObserved);
                        }

                        if (payloadLength < _profile.TlsFragmentThreshold)
                        {
                            if (!isProbe)
                            {
                                Interlocked.Increment(ref _tlsClientHellosShort);
                            }
                        }
                        else
                        {
                            // Полный ClientHello (>= threshold): проверяем наличие SNI.
                            // Если SNI отсутствует, не применяем обход и считаем отдельной метрикой.
                            hasSni = HasSniExtension(payloadSpan);
                            if (!hasSni)
                            {
                                if (!isProbe)
                                {
                                    Interlocked.Increment(ref _tlsClientHellosNoSni);
                                }
                            }
                        }
                    }
                }
            }

            // 1. RST Blocking
            if (_profile.DropTcpRst && packet.Info.IsTcp && packet.Info.IsRst)
            {
                if (!isProbe)
                {
                    Interlocked.Increment(ref _rstDropped);
                }

                if (packet.Info.DstPort == 443)
                {
                    var key = new ConnectionKey(packet.Info.SrcIpInt, packet.Info.DstIpInt, packet.Info.SrcPort, packet.Info.DstPort);
                    if (_connections.TryGetValue(key, out var state) && state.BypassApplied)
                    {
                        if (!isProbe)
                        {
                            Interlocked.Increment(ref _rstDroppedRelevant);
                        }
                        if (_verbosePacketLog)
                        {
                            _log?.Invoke($"[Bypass][RST] preset={_presetName}, rst@443 after bypass, conn={packet.Info.SrcIpInt}->{packet.Info.DstIpInt}:{packet.Info.DstPort}");
                        }
                    }
                }
                // Drop packet
                return false;
            }

            // 2. TLS Fragmentation / Fake / Disorder
            if (isTcp &&
                payloadLength >= _profile.TlsFragmentThreshold &&
                packet.Info.DstPort == 443 &&
                isClientHello &&
                (hasSni || _profile.AllowNoSni))
            {
                // 2.1 TTL Trick (send fake packet with low TTL)
                if (_profile.TtlTrick)
                {
                    ApplyTtlTrick(packet, context, sender);
                }

                var connectionKey = new ConnectionKey(packet.Info.SrcIpInt, packet.Info.DstIpInt, packet.Info.SrcPort, packet.Info.DstPort);
                bool isNewConnection = _connections.TryAdd(connectionKey, new ConnectionState(Environment.TickCount64, false));

                var fragmentPlan = BuildFragmentPlan(packet);

                var effectiveTlsStrategy = _profile.TlsStrategy;
                if (TrySelectTlsStrategyPolicyDriven(packet, payloadLength, hasSni, out var selectedPolicyId, out var policyStrategy))
                {
                    effectiveTlsStrategy = policyStrategy;
                }

                if (effectiveTlsStrategy != TlsBypassStrategy.None
                    && ProcessTlsStrategy(packet, context, sender, isNewConnection, fragmentPlan, effectiveTlsStrategy))
                {
                    if (!isProbe)
                    {
                        Interlocked.Increment(ref _clientHellosFragmented);
                        Interlocked.Increment(ref _tlsHandled);
                        _lastFragmentPlan = fragmentPlan != null ? string.Join('/', fragmentPlan.Select(f => f.PayloadLength)) : "";

                        if (!string.IsNullOrWhiteSpace(selectedPolicyId))
                        {
                            RecordPolicyApplied(selectedPolicyId);
                        }
                    }
                    if (_verbosePacketLog)
                    {
                        _log?.Invoke($"[Bypass][TLS] preset={_presetName}, payload={packet.Info.PayloadLength}, plan={_lastFragmentPlan}, strategy={effectiveTlsStrategy}, result=fragmented");
                    }
                    _connections.AddOrUpdate(connectionKey,
                        _ => new ConnectionState(Environment.TickCount64, true),
                        (_, existing) => new ConnectionState(existing.FirstSeen, true));
                    return false; // Packet handled (fragmented/faked), drop original
                }
            }

            return true; // Pass through
        }
    }
}
