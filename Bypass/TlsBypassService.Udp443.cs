using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using IspAudit.Core.Traffic.Filters;

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
