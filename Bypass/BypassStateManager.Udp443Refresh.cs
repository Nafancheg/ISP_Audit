using System;
using System.Collections.Generic;
using System.Net;
using IspAudit.Core.Bypass;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
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
                hostKey = (hostKey ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(hostKey)) return;
                if (ip == null) return;

                // Засеиваем observed IP для конкретной цели.
                SeedObservedIpv4TargetFromIpBestEffort(hostKey, ip);

                // Поддерживаем preferred host как "активную цель" для union.
                RememberUdp443ActiveHost(hostKey);

                // Собираем union observed IPv4 по нескольким активным целям.
                var hosts = GetActiveUdp443HostsSnapshot(hostKey);
                if (hosts.Length == 0) return;

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

                if (union.Count == 0) return;

                var sorted = new List<uint>(union);
                sorted.Sort();
                var targets = sorted.Count > 32 ? sorted.GetRange(0, 32).ToArray() : sorted.ToArray();

                using var scope = BypassStateManagerGuard.EnterScope();

                // Обновляем targets в фильтре.
                _tlsService.SetUdp443DropTargetIpsForManager(targets);

                // Если включён policy-driven путь для UDP/443 — обновляем и snapshot,
                // иначе при gate=on targets из legacy массива будут игнорироваться.
                if (PolicyDrivenExecutionGates.PolicyDrivenUdp443Enabled())
                {
                    _tlsService.RefreshUdp443PolicyTargetsForManager(targets);
                }
            }
            catch
            {
                // best-effort
            }
        }
    }
}
