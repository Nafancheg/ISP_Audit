using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter
    {
        // Реестр «служебных» (tagged) соединений, которые не должны попадать в пользовательские метрики.
        // Используется для outcome-probe (HTTPS), чтобы не было ложной активации/эффекта только из-за probe.
        private readonly ConcurrentDictionary<ConnectionKey, long> _probeFlowsUntilTick = new();

        /// <summary>
        /// Зарегистрировать 5-tuple соединения, которое следует исключить из пользовательских метрик.
        /// Важно: обход/модификация трафика сохраняется, исключаются только счётчики/план/вердикт.
        /// </summary>
        internal void RegisterProbeFlow(uint srcIp, uint dstIp, ushort srcPort, ushort dstPort, TimeSpan ttl)
        {
            if (ttl <= TimeSpan.Zero) ttl = TimeSpan.FromSeconds(30);
            var until = Environment.TickCount64 + (long)ttl.TotalMilliseconds;
            _probeFlowsUntilTick[new ConnectionKey(srcIp, dstIp, srcPort, dstPort)] = until;
        }

        private bool IsProbeFlow(PacketInfo info)
        {
            if (!info.IsIpv4) return false;

            if (_probeFlowsUntilTick.IsEmpty) return false;

            var now = Environment.TickCount64;
            var key = new ConnectionKey(info.SrcIpInt, info.DstIpInt, info.SrcPort, info.DstPort);

            if (_probeFlowsUntilTick.TryGetValue(key, out var until))
            {
                if (now <= until)
                {
                    return true;
                }

                _probeFlowsUntilTick.TryRemove(key, out _);
                return false;
            }

            // Ленивая чистка: если словарь разросся (редко), удаляем просроченные записи.
            if (_probeFlowsUntilTick.Count > 64)
            {
                List<ConnectionKey>? expiredKeys = null;
                foreach (var kv in _probeFlowsUntilTick)
                {
                    if (now > kv.Value)
                    {
                        expiredKeys ??= new List<ConnectionKey>();
                        expiredKeys.Add(kv.Key);
                    }
                }

                if (expiredKeys != null)
                {
                    foreach (var key in expiredKeys)
                    {
                        _probeFlowsUntilTick.TryRemove(key, out _);
                    }
                }
            }

            return false;
        }
    }
}
