using System;
using System.Collections.Generic;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter
    {
        // Селективный QUIC fallback: drop UDP/443 только для observed IPv4 адресов цели.
        // Важно: PacketInfo хранит IPv4 как uint (DstIpInt), для IPv6 адресов сопоставления нет.
        // Поэтому:
        // - IPv4: drop только если dst ∈ _udp443DropTargetDstIps
        // - IPv6: оставляем прежнее поведение (drop при включённом DropUdp443)
        private volatile uint[] _udp443DropTargetDstIps = Array.Empty<uint>();

        // Policy-driven execution plane (P0.2 Stage 1): snapshot decision graph для UDP/443.
        private volatile DecisionGraphSnapshot? _decisionGraphSnapshot;

        internal void SetDecisionGraphSnapshot(DecisionGraphSnapshot? snapshot)
        {
            _decisionGraphSnapshot = snapshot;
        }

        /// <summary>
        /// Задать observed IPv4 адреса (dst ip), к которым следует применять QUIC fallback (DROP UDP/443).
        /// Если список пуст — для IPv4 трафика DROP не применяется (только IPv6 остаётся как раньше).
        /// </summary>
        internal void SetUdp443DropTargetIps(IEnumerable<uint>? dstIpInts)
        {
            if (dstIpInts == null)
            {
                _udp443DropTargetDstIps = Array.Empty<uint>();
                return;
            }

            var list = new List<uint>();
            foreach (var ip in dstIpInts)
            {
                if (ip == 0) continue;
                list.Add(ip);
            }

            if (list.Count == 0)
            {
                _udp443DropTargetDstIps = Array.Empty<uint>();
                return;
            }

            // Дедуп + стабильный порядок (для детерминизма smoke).
            list.Sort();
            var dedup = new List<uint>(capacity: list.Count);
            uint last = 0;
            var first = true;
            foreach (var v in list)
            {
                if (first)
                {
                    dedup.Add(v);
                    last = v;
                    first = false;
                    continue;
                }

                if (v != last)
                {
                    dedup.Add(v);
                    last = v;
                }
            }

            _udp443DropTargetDstIps = dedup.ToArray();
        }

        private bool ShouldDropUdp443(PacketInfo info, bool isProbe)
        {
            if (!info.IsUdp || info.DstPort != 443) return false;
            if (!_profile.DropUdp443) return false;

            // Глобальный режим: глушим весь UDP/443, без привязки к observed IP цели.
            if (_profile.DropUdp443Global) return true;

            // IPv6: адресов для селективности нет, сохраняем прежнее поведение.
            if (info.IsIpv6) return true;

            // Policy-driven путь (feature gate): при включении используем snapshot.
            // При выключенном gate или отсутствии snapshot — работаем по legacy ветке.
            var snapshot = _decisionGraphSnapshot;
            if (snapshot != null && PolicyDrivenExecutionGates.PolicyDrivenUdp443Enabled())
            {
                // IPv4: оценка по policy (селективность по observed IP цели).
                if (!info.IsIpv4) return false;

                var selected = snapshot.EvaluateUdp443(info.DstIpInt, isIpv4: true, isIpv6: false);
                if (selected != null && selected.Action.Kind == PolicyActionKind.Strategy
                    && string.Equals(selected.Action.StrategyId, PolicyAction.StrategyIdDropUdp443, StringComparison.OrdinalIgnoreCase))
                {
                    if (!isProbe)
                    {
                        RecordPolicyApplied(selected.Id);
                    }
                    return true;
                }

                return false;
            }

            // Legacy: IPv4 drop только к observed адресам цели.
            if (!info.IsIpv4) return false;

            var targets = _udp443DropTargetDstIps;
            if (targets.Length == 0) return false;

            var dst = info.DstIpInt;
            for (var i = 0; i < targets.Length; i++)
            {
                if (targets[i] == dst) return true;
            }

            return false;
        }
    }
}
