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
