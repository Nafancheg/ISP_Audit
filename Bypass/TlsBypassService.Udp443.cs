using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Core.Models;
using System.Collections.Immutable;

namespace IspAudit.Bypass
{
    public partial class TlsBypassService
    {
        internal void SetFilterForSmoke(BypassFilter filter, DateTime? metricsSince = null, TlsBypassOptions? options = null)
        {
            if (filter == null) throw new ArgumentNullException(nameof(filter));

            lock (_sync)
            {
                _filter = filter;
                if (options != null)
                {
                    _options = options;
                }

                _metricsSince = metricsSince ?? _now();

                // Smoke может подменять фильтр напрямую — пробрасываем текущие target IP.
                _filter.SetUdp443DropTargetIps(_udp443DropTargetIps);

                // И snapshot decision graph (если задан), чтобы smoke мог проверить policy-driven путь.
                _filter.SetDecisionGraphSnapshot(_decisionGraphSnapshot);
            }
        }

        /// <summary>
        /// Для BypassStateManager: задать снимок Decision Graph для policy-driven execution plane.
        /// </summary>
        internal void SetDecisionGraphSnapshotForManager(DecisionGraphSnapshot? snapshot)
        {
            lock (_sync)
            {
                _decisionGraphSnapshot = snapshot;
                _filter?.SetDecisionGraphSnapshot(_decisionGraphSnapshot);
            }
        }

        /// <summary>
        /// Для BypassStateManager: задать observed IPv4 адреса цели, к которым применять DROP UDP/443.
        /// </summary>
        internal void SetUdp443DropTargetIpsForManager(IEnumerable<uint>? dstIpInts)
        {
            var snapshot = dstIpInts == null
                ? Array.Empty<uint>()
                : dstIpInts.Where(v => v != 0).Distinct().Take(32).ToArray();

            lock (_sync)
            {
                _udp443DropTargetIps = snapshot;
                _filter?.SetUdp443DropTargetIps(_udp443DropTargetIps);
            }
        }

        /// <summary>
        /// Best-effort: обновить policy-driven UDP/443 политику (DstIpv4Set) под новый набор targets.
        /// Нужен для сценария, когда policy-driven UDP/443 включён, и targets обновляются без полного Apply.
        /// </summary>
        internal void RefreshUdp443PolicyTargetsForManager(IEnumerable<uint>? dstIpInts)
        {
            try
            {
                var snapshot = dstIpInts == null
                    ? Array.Empty<uint>()
                    : dstIpInts.Where(v => v != 0).Distinct().Take(32).ToArray();

                lock (_sync)
                {
                    if (_decisionGraphSnapshot == null)
                    {
                        // Snapshot отсутствует — обновлять нечего.
                        return;
                    }

                    // Обновляем только селективную политику UDP/443 (если она есть), либо добавляем её.
                    var policies = _decisionGraphSnapshot.Policies;
                    var list = new List<FlowPolicy>(policies.Length + 1);

                    var updatedAny = false;
                    foreach (var p in policies)
                    {
                        if (string.Equals(p.Id, "udp443_quic_fallback_selective", StringComparison.OrdinalIgnoreCase))
                        {
                            var match = p.Match with
                            {
                                DstIpv4Set = snapshot.Length == 0 ? ImmutableHashSet<uint>.Empty : snapshot.ToImmutableHashSet()
                            };

                            list.Add(p with { Match = match });
                            updatedAny = true;
                            continue;
                        }

                        list.Add(p);
                    }

                    if (!updatedAny && snapshot.Length > 0)
                    {
                        list.Add(new FlowPolicy
                        {
                            Id = "udp443_quic_fallback_selective",
                            Priority = 100,
                            Match = new MatchCondition
                            {
                                Proto = FlowTransportProtocol.Udp,
                                Port = 443,
                                DstIpv4Set = snapshot.ToImmutableHashSet()
                            },
                            Action = PolicyAction.DropUdp443,
                            Scope = PolicyScope.Local
                        });
                    }

                    _decisionGraphSnapshot = DecisionGraphSnapshot.Create(list);
                    _filter?.SetDecisionGraphSnapshot(_decisionGraphSnapshot);
                }
            }
            catch
            {
                // best-effort
            }
        }

        internal uint[] GetUdp443DropTargetIpsSnapshot()
        {
            lock (_sync)
            {
                return _udp443DropTargetIps.Length == 0 ? Array.Empty<uint>() : _udp443DropTargetIps.ToArray();
            }
        }

        internal Task PullMetricsOnceAsyncForSmoke() => PullMetricsAsync();

        /// <summary>
        /// Outcome-probe (HTTPS): зарегистрировать 5-tuple соединения, которое нужно исключить из пользовательских метрик.
        /// Важно: обход сохраняется (пакеты всё ещё обрабатываются фильтром), исключаются только счётчики.
        /// </summary>
        internal void RegisterOutcomeProbeFlow(IPEndPoint local, IPEndPoint remote, TimeSpan ttl)
        {
            try
            {
                if (local == null || remote == null) return;
                if (local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return;
                if (remote.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return;

                var srcIp = BinaryPrimitives.ReadUInt32BigEndian(local.Address.GetAddressBytes());
                var dstIp = BinaryPrimitives.ReadUInt32BigEndian(remote.Address.GetAddressBytes());

                lock (_sync)
                {
                    _filter?.RegisterProbeFlow(srcIp, dstIp, (ushort)local.Port, (ushort)remote.Port, ttl);
                }
            }
            catch
            {
                // Игнорируем: это наблюдаемость, не критический путь.
            }
        }
    }
}
