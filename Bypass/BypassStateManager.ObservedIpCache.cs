using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
        // 2.V2.17: селективный QUIC fallback (DROP UDP/443) — храним observed IPv4 адреса цели по host.
        // TTL/cap нужны, чтобы:
        // - не раздувать состояние
        // - автоматически обновляться при смене IP у цели
        private static readonly TimeSpan Udp443DropTargetIpTtl = TimeSpan.FromMinutes(10);
        private const int Udp443DropTargetIpCap = 16;
        private readonly ConcurrentDictionary<string, ObservedIpsEntry> _udp443DropObservedIpsByHost = new(StringComparer.OrdinalIgnoreCase);

        private sealed class ObservedIpsEntry
        {
            public readonly object Sync = new();
            public readonly Dictionary<uint, long> UntilTickByIp = new();
        }

        private static long NowTick() => Environment.TickCount64;

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

        /// <summary>
        /// Best-effort: засеять observed IPv4 адрес цели из одиночного IP (например, из события UDP blockage).
        /// </summary>
        internal void SeedObservedIpv4TargetFromIpBestEffort(string hostKey, IPAddress ip)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(hostKey)) return;
                if (ip == null) return;

                var v4 = TryToIpv4Int(ip);
                if (v4 == null) return;
                var value = v4.Value;
                if (value == 0) return;

                var entry = _udp443DropObservedIpsByHost.GetOrAdd(hostKey, _ => new ObservedIpsEntry());
                var now = NowTick();
                var until = now + (long)Udp443DropTargetIpTtl.TotalMilliseconds;

                lock (entry.Sync)
                {
                    PruneExpired(entry, now);
                    entry.UntilTickByIp[value] = until;

                    // Cap.
                    if (entry.UntilTickByIp.Count > Udp443DropTargetIpCap)
                    {
                        var ordered = new List<KeyValuePair<uint, long>>(entry.UntilTickByIp);
                        ordered.Sort((a, b) => a.Value.CompareTo(b.Value));
                        var extra = ordered.Count - Udp443DropTargetIpCap;
                        for (var i = 0; i < extra; i++)
                        {
                            entry.UntilTickByIp.Remove(ordered[i].Key);
                        }
                    }
                }
            }
            catch
            {
                // best-effort
            }
        }

        /// <summary>
        /// P0.2 Stage 5.4 (интеграция с P0.1): best-effort засеять observed IPv4 адреса цели из
        /// candidate endpoints (например, из apply-transaction). Это помогает policy-driven per-target
        /// политикам (DstIpv4Set) работать сразу, не дожидаясь DNS resolve.
        ///
        /// Важно:
        /// - берём только IPv4 (DecisionGraph селективность пока только по IPv4)
        /// - не очищаем уже наблюдённые IP, а только добавляем/обновляем TTL
        /// </summary>
        internal void SeedObservedIpv4TargetsFromCandidateEndpointsBestEffort(
            string hostKey,
            IReadOnlyList<string>? candidateIpEndpoints)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(hostKey)) return;

                if (candidateIpEndpoints == null || candidateIpEndpoints.Count == 0) return;

                var found = new List<uint>();
                foreach (var raw in candidateIpEndpoints)
                {
                    var s = (raw ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(s)) continue;

                    // Ожидаем формат вроде "1.2.3.4:443" (IPv4). Для безопасного best-effort:
                    // 1) пробуем IP целиком
                    // 2) если есть ':' — берём часть до последнего ':' и пробуем как IP
                    if (!IPAddress.TryParse(s, out var ip))
                    {
                        var idx = s.LastIndexOf(':');
                        if (idx <= 0) continue;
                        var before = s.Substring(0, idx);
                        if (!IPAddress.TryParse(before, out ip)) continue;
                    }

                    var v4 = TryToIpv4Int(ip);
                    if (v4 == null) continue;
                    var value = v4.Value;
                    if (value == 0) continue;
                    if (found.Contains(value)) continue;
                    found.Add(value);
                    if (found.Count >= Udp443DropTargetIpCap) break;
                }

                if (found.Count == 0) return;

                var entry = _udp443DropObservedIpsByHost.GetOrAdd(hostKey, _ => new ObservedIpsEntry());
                var now = NowTick();
                var until = now + (long)Udp443DropTargetIpTtl.TotalMilliseconds;

                lock (entry.Sync)
                {
                    PruneExpired(entry, now);
                    foreach (var ip in found)
                    {
                        entry.UntilTickByIp[ip] = until;
                    }

                    // Cap.
                    if (entry.UntilTickByIp.Count > Udp443DropTargetIpCap)
                    {
                        var ordered = new List<KeyValuePair<uint, long>>(entry.UntilTickByIp);
                        ordered.Sort((a, b) => a.Value.CompareTo(b.Value));
                        var extra = ordered.Count - Udp443DropTargetIpCap;
                        for (var i = 0; i < extra; i++)
                        {
                            entry.UntilTickByIp.Remove(ordered[i].Key);
                        }
                    }
                }
            }
            catch
            {
                // best-effort
            }
        }

        /// <summary>
        /// Internal API для smoke: получить snapshot observed IPv4 целей по host.
        /// </summary>
        internal uint[] GetObservedIpv4TargetsSnapshotForHost(string hostKey)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(hostKey)) return Array.Empty<uint>();

                if (!_udp443DropObservedIpsByHost.TryGetValue(hostKey, out var entry)) return Array.Empty<uint>();

                var now = NowTick();
                lock (entry.Sync)
                {
                    PruneExpired(entry, now);

                    if (entry.UntilTickByIp.Count == 0) return Array.Empty<uint>();

                    var list = new List<uint>(entry.UntilTickByIp.Count);
                    foreach (var ip in entry.UntilTickByIp.Keys)
                    {
                        if (ip != 0) list.Add(ip);
                    }

                    return list.Count == 0 ? Array.Empty<uint>() : list.ToArray();
                }
            }
            catch
            {
                return Array.Empty<uint>();
            }
        }

        private static void PruneExpired(ObservedIpsEntry entry, long nowTick)
        {
            if (entry.UntilTickByIp.Count == 0) return;

            List<uint>? toRemove = null;
            foreach (var kv in entry.UntilTickByIp)
            {
                if (nowTick > kv.Value)
                {
                    toRemove ??= new List<uint>();
                    toRemove.Add(kv.Key);
                }
            }

            if (toRemove == null) return;
            foreach (var ip in toRemove)
            {
                entry.UntilTickByIp.Remove(ip);
            }
        }

        private async Task<uint[]> GetOrSeedUdp443DropTargetsAsync(string host, CancellationToken cancellationToken)
        {
            host = (host ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(host)) return Array.Empty<uint>();

            var entry = _udp443DropObservedIpsByHost.GetOrAdd(host, _ => new ObservedIpsEntry());
            var now = NowTick();

            lock (entry.Sync)
            {
                PruneExpired(entry, now);
                if (entry.UntilTickByIp.Count > 0)
                {
                    var list = new List<uint>(entry.UntilTickByIp.Count);
                    foreach (var ip in entry.UntilTickByIp.Keys)
                    {
                        if (ip != 0) list.Add(ip);
                    }
                    return list.ToArray();
                }
            }

            // Cold-start seed: DNS resolve цели.
            IPAddress[] resolved;
            try
            {
                resolved = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return Array.Empty<uint>();
            }

            var found = new List<uint>();
            foreach (var ip in resolved)
            {
                var v4 = TryToIpv4Int(ip);
                if (v4 == null) continue;
                var value = v4.Value;
                if (value == 0) continue;
                if (found.Contains(value)) continue;
                found.Add(value);
                if (found.Count >= Udp443DropTargetIpCap) break;
            }

            if (found.Count == 0) return Array.Empty<uint>();

            var until = now + (long)Udp443DropTargetIpTtl.TotalMilliseconds;
            lock (entry.Sync)
            {
                PruneExpired(entry, now);

                foreach (var ip in found)
                {
                    entry.UntilTickByIp[ip] = until;
                }

                // Cap: если каким-то образом разрослось — урежем.
                if (entry.UntilTickByIp.Count > Udp443DropTargetIpCap)
                {
                    // Удаляем самые "старые" (раньше истекающие).
                    var ordered = new List<KeyValuePair<uint, long>>(entry.UntilTickByIp);
                    ordered.Sort((a, b) => a.Value.CompareTo(b.Value));
                    var extra = ordered.Count - Udp443DropTargetIpCap;
                    for (var i = 0; i < extra; i++)
                    {
                        entry.UntilTickByIp.Remove(ordered[i].Key);
                    }
                }

                var result = new List<uint>(entry.UntilTickByIp.Count);
                foreach (var ip in entry.UntilTickByIp.Keys)
                {
                    if (ip != 0) result.Add(ip);
                }
                return result.ToArray();
            }
        }
    }
}
