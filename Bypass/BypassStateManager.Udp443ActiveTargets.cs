using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
        // P0.1 Step 1 (подготовка): в runtime может быть несколько активных «групп/целей» одновременно.
        // Для селективного QUIC fallback (DROP UDP/443) это означает, что мы должны глушить UDP/443
        // не только для текущего OutcomeTargetHost, но и для других ранее применённых целей.
        //
        // Реализация MVP:
        // - держим небольшой TTL-кэш активных host (cap)
        // - на Apply в селективном режиме берём union observed IP по этим host
        private static readonly TimeSpan Udp443ActiveHostTtl = TimeSpan.FromMinutes(20);
        private const int Udp443ActiveHostCap = 4;

        private readonly object _udp443ActiveHostsSync = new();
        private readonly ConcurrentDictionary<string, long> _udp443ActiveHostsUntilTick = new(StringComparer.OrdinalIgnoreCase);

        private void RememberUdp443ActiveHost(string host)
        {
            host = (host ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(host)) return;

            var now = NowTick();
            var until = now + (long)Udp443ActiveHostTtl.TotalMilliseconds;

            lock (_udp443ActiveHostsSync)
            {
                _udp443ActiveHostsUntilTick[host] = until;
                PruneExpiredActiveHosts_NoThrow(now);
                EnforceActiveHostsCap_NoThrow();
            }
        }

        private string[] GetActiveUdp443HostsSnapshot(string? preferredHost)
        {
            var host = (preferredHost ?? string.Empty).Trim();
            var now = NowTick();

            lock (_udp443ActiveHostsSync)
            {
                PruneExpiredActiveHosts_NoThrow(now);
                if (!string.IsNullOrWhiteSpace(host))
                {
                    // Поддерживаем актуальность preferred host.
                    RememberUdp443ActiveHost(host);
                }

                if (_udp443ActiveHostsUntilTick.Count == 0)
                {
                    return Array.Empty<string>();
                }

                var list = new List<string>(_udp443ActiveHostsUntilTick.Count);
                foreach (var kv in _udp443ActiveHostsUntilTick)
                {
                    var h = (kv.Key ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(h)) continue;
                    list.Add(h);
                }

                // preferred host — в начало (если есть).
                if (!string.IsNullOrWhiteSpace(host))
                {
                    list.RemoveAll(x => string.Equals(x, host, StringComparison.OrdinalIgnoreCase));
                    list.Insert(0, host);
                }

                return list.ToArray();
            }
        }

        private void PruneExpiredActiveHosts_NoThrow(long nowTick)
        {
            try
            {
                if (_udp443ActiveHostsUntilTick.Count == 0) return;

                List<string>? toRemove = null;
                foreach (var kv in _udp443ActiveHostsUntilTick)
                {
                    if (nowTick > kv.Value)
                    {
                        toRemove ??= new List<string>();
                        toRemove.Add(kv.Key);
                    }
                }

                if (toRemove == null) return;
                foreach (var key in toRemove)
                {
                    _udp443ActiveHostsUntilTick.TryRemove(key, out _);
                }
            }
            catch
            {
                // ignore
            }
        }

        private void EnforceActiveHostsCap_NoThrow()
        {
            try
            {
                if (_udp443ActiveHostsUntilTick.Count <= Udp443ActiveHostCap) return;

                // Удаляем самые "старые" (раньше истекающие).
                var ordered = new List<KeyValuePair<string, long>>(_udp443ActiveHostsUntilTick);
                ordered.Sort((a, b) => a.Value.CompareTo(b.Value));

                var extra = ordered.Count - Udp443ActiveHostCap;
                for (var i = 0; i < extra; i++)
                {
                    _udp443ActiveHostsUntilTick.TryRemove(ordered[i].Key, out _);
                }
            }
            catch
            {
                // ignore
            }
        }
    }
}
