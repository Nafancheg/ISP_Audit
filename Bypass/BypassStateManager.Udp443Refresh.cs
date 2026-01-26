using System;
using System.Collections.Generic;
using System.Net;
using IspAudit.Core.Bypass;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
        internal readonly record struct ReactiveUdp443SyncResult(
            bool AnyAttempted,
            bool LegacyTargetsDeliveredToFilter,
            bool PolicySnapshotUpdated,
            bool EngineRunning,
            int TargetCount);

        /// <summary>
        /// Быстрый путь для селективного QUIC→TCP (DROP UDP/443):
        /// добавляет observed IPv4 (dst) в кэш цели и обновляет runtime targets в фильтре
        /// без полного Apply/перезапуска движка.
        ///
        /// Используется при событиях UDP blockage, когда CDN быстро меняет endpoint'ы.
        /// Best-effort: не должен ломать диагностику.
        /// </summary>
        internal void RefreshUdp443SelectiveTargetsFromObservedIpBestEffort(string? hostKey, IPAddress ip)
        {
            try
            {
                _ = TrySyncUdp443SelectiveTargetsFromObservedIp(hostKey, ip);
            }
            catch
            {
                // best-effort
            }
        }

        internal ReactiveUdp443SyncResult TrySyncUdp443SelectiveTargetsFromObservedIp(string? hostKey, IPAddress ip)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(hostKey)) return default;
                if (ip == null) return default;

                // Засеиваем observed IP для конкретной цели.
                SeedObservedIpv4TargetFromIpBestEffort(hostKey, ip);

                // Поддерживаем preferred host как "активную цель" для union.
                RememberUdp443ActiveHost(hostKey);

                // Собираем union observed IPv4 по нескольким активным целям.
                var hosts = GetActiveUdp443HostsSnapshot(hostKey);
                if (hosts.Length == 0) return default;

                var union = new HashSet<uint>();
                foreach (var h in hosts)
                {
                    if (string.IsNullOrWhiteSpace(h)) continue;
                    var ips = GetObservedIpv4TargetsSnapshotForHost(h);
                    if (ips.Length == 0) continue;

                    foreach (var v in ips)
                    {
                        if (v == 0) continue;
                        union.Add(v);
                        if (union.Count >= 32) break;
                    }

                    if (union.Count >= 32) break;
                }

                if (union.Count == 0) return default;

                var sorted = new List<uint>(union);
                sorted.Sort();
                var targets = sorted.Count > 32 ? sorted.GetRange(0, 32).ToArray() : sorted.ToArray();

                using var scope = BypassStateManagerGuard.EnterScope();

                var engineRunning = _trafficEngine.IsRunning;
                var legacyDelivered = _tlsService.TrySetUdp443DropTargetIpsForManager(targets);

                var policyUpdated = false;
                if (PolicyDrivenExecutionGates.PolicyDrivenUdp443Enabled())
                {
                    policyUpdated = _tlsService.TryRefreshUdp443PolicyTargetsForManager(targets);
                }

                return new ReactiveUdp443SyncResult(
                    AnyAttempted: true,
                    LegacyTargetsDeliveredToFilter: legacyDelivered,
                    PolicySnapshotUpdated: policyUpdated,
                    EngineRunning: engineRunning,
                    TargetCount: targets.Length);
            }
            catch
            {
                return default;
            }
        }
    }
}
