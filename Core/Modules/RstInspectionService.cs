using System;
using System.Collections.Concurrent;
using System.Net;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Traffic.Filters;

namespace IspAudit.Core.Modules
{
    /// <summary>
    /// Сервис инспекции TCP RST пакетов для выявления DPI-инжекций.
    /// Анализирует TTL входящих пакетов и ищет аномалии в RST.
    /// </summary>
    public sealed class RstInspectionService
    {
        // Храним статистику TTL для каждого IP: (MinTTL, MaxTTL, LastTTL)
        // Используем простой подход: если RST TTL сильно отличается от обычного трафика с этого IP, это подозрительно.
        private readonly ConcurrentDictionary<IPAddress, TtlStats> _ttlStats = new();

        // Храним статистику IPv4 Identification (IPID) для каждого IP.
        // Это дополнительная эвристика: если IPID в RST сильно выбивается относительно «обычного» трафика,
        // то RST может быть инжектирован (не от реального сервера).
        private readonly ConcurrentDictionary<IPAddress, IpIdStats> _ipIdStats = new();
        
        // Храним подозрительные RST события
        private readonly ConcurrentDictionary<IPAddress, RstEvent> _suspiciousRstEvents = new();

        private readonly record struct TtlStats(byte Min, byte Max, byte Last, int SampleCount);
        private readonly record struct IpIdStats(ushort Min, ushort Max, ushort Last, int SampleCount);
        private readonly record struct RstEvent(string Details, DateTime Timestamp);

        public void Attach(TrafficMonitorFilter filter)
        {
            if (filter == null) throw new ArgumentNullException(nameof(filter));
            filter.OnPacketReceived += OnPacketReceived;
        }

        private void OnPacketReceived(PacketData packet)
        {
            // Работаем только с входящими IPv4 TCP пакетами
            if (packet.IsOutbound || packet.IsLoopback) return;
            if (packet.Buffer is not { Length: > 20 }) return;

            var buffer = packet.Buffer;

            // IPv4 check
            var version = (buffer[0] & 0xF0) >> 4;
            if (version != 4) return;

            var ihl = buffer[0] & 0x0F;
            var ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || packet.Length < ipHeaderLen + 20) return;

            var protocol = buffer[9];
            if (protocol != 6) return; // Not TCP

            var ttl = buffer[8];
            var srcIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 12, 4));

            // IPv4 Identification (bytes 4-5)
            ushort ipId = (ushort)((buffer[4] << 8) | buffer[5]);

            // TCP Header parsing
            var tcpOffset = ipHeaderLen;
            if (packet.Length < tcpOffset + 20) return;

            // Flags are at offset 13 in TCP header
            var flags = buffer[tcpOffset + 13];
            bool isRst = (flags & 0x04) != 0;
            bool isSynAck = (flags & 0x12) == 0x12; // SYN+ACK
            bool isAck = (flags & 0x10) != 0;       // ACK

            if (isRst)
            {
                AnalyzeRst(srcIp, ttl, ipId);
            }
            else if (isSynAck || isAck) // Обычный трафик (SYN-ACK или данные)
            {
                UpdateTtlStats(srcIp, ttl);
                UpdateIpIdStats(srcIp, ipId);
            }
        }

        private void UpdateTtlStats(IPAddress ip, byte ttl)
        {
            _ttlStats.AddOrUpdate(ip,
                _ => new TtlStats(ttl, ttl, ttl, 1),
                (_, stats) =>
                {
                    // Обновляем статистику. Игнорируем выбросы, если они редкие, но пока просто Min/Max.
                    // DPI часто шлет RST с TTL=64 или 128, а сервер может быть далеко (TTL=50).
                    // Или наоборот: сервер близко (CDN), а DPI далеко.
                    // Важно накопить базу "нормальных" пакетов.
                    return new TtlStats(
                        Math.Min(stats.Min, ttl),
                        Math.Max(stats.Max, ttl),
                        ttl,
                        stats.SampleCount + 1
                    );
                });
        }

        private void UpdateIpIdStats(IPAddress ip, ushort ipId)
        {
            _ipIdStats.AddOrUpdate(ip,
                _ => new IpIdStats(ipId, ipId, ipId, 1),
                (_, stats) =>
                {
                    return new IpIdStats(
                        Math.Min(stats.Min, ipId),
                        Math.Max(stats.Max, ipId),
                        ipId,
                        stats.SampleCount + 1);
                });
        }

        private void AnalyzeRst(IPAddress ip, byte rstTtl, ushort rstIpId)
        {
            var now = DateTime.UtcNow;

            bool ttlSuspicious = false;
            string? ttlDetails = null;
            if (_ttlStats.TryGetValue(ip, out var ttlStats) && ttlStats.SampleCount >= 3)
            {
                // Эвристика:
                // Если у нас есть статистика (хотя бы 3 пакета)
                // И RST TTL отличается от диапазона [Min, Max] более чем на порог (например, 5 хопов)
                // То это подозрительно.
                int diffMin = Math.Abs(rstTtl - ttlStats.Min);
                int diffMax = Math.Abs(rstTtl - ttlStats.Max);
                int minDiff = Math.Min(diffMin, diffMax);
                if (minDiff > 5)
                {
                    ttlSuspicious = true;
                    ttlDetails = $"TTL={rstTtl} (обычный={ttlStats.Min}-{ttlStats.Max})";
                }
            }

            bool ipIdSuspicious = false;
            string? ipIdDetails = null;
            if (_ipIdStats.TryGetValue(ip, out var idStats) && idStats.SampleCount >= 3)
            {
                // Эвристика по IPID:
                // - сравниваем с диапазоном «обычных» IPID и с последним наблюдаемым.
                // - порог намеренно консервативный, чтобы избежать случайных коллизий.
                var diffToMin = Math.Abs((int)rstIpId - idStats.Min);
                var diffToMax = Math.Abs((int)rstIpId - idStats.Max);
                var diffToLast = Math.Abs((int)rstIpId - idStats.Last);

                // «Сильно отличается» — в пределах одного потока/маршрута IPID обычно близок (инкремент/паттерн).
                // 1000 — достаточно большой отрыв для smoke-сценария без wrap-around.
                if (Math.Min(diffToMin, diffToMax) > 1000 && diffToLast > 1000)
                {
                    ipIdSuspicious = true;
                    ipIdDetails = $"IPID={rstIpId} (обычный={idStats.Min}-{idStats.Max}, last={idStats.Last})";
                }
            }

            if (ttlSuspicious || ipIdSuspicious)
            {
                var details = ttlDetails ?? string.Empty;
                if (ipIdDetails != null)
                {
                    details = string.IsNullOrWhiteSpace(details) ? ipIdDetails : $"{details}; {ipIdDetails}";
                }

                // Фолбэк: если по какой-то причине деталей нет — всё равно фиксируем факт.
                if (string.IsNullOrWhiteSpace(details))
                {
                    details = $"RST подозрительный: TTL={rstTtl}, IPID={rstIpId}";
                }

                _suspiciousRstEvents[ip] = new RstEvent(details, now);
            }
        }

        /// <summary>
        /// Проверяет, был ли зафиксирован подозрительный RST от указанного IP.
        /// </summary>
        public bool HasSuspiciousRst(IPAddress ip, out string details)
        {
            if (ip != null && _suspiciousRstEvents.TryGetValue(ip, out var evt))
            {
                // Считаем событие актуальным, если оно было недавно (например, 60 сек)
                if ((DateTime.UtcNow - evt.Timestamp).TotalSeconds < 60)
                {
                    details = evt.Details;
                    return true;
                }
            }
            details = string.Empty;
            return false;
        }
    }
}
