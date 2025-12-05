using System;
using System.Collections.Concurrent;
using System.Net;
using IspAudit.Core.Models;
using IspAudit.Utils;

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
        
        // Храним подозрительные RST события
        private readonly ConcurrentDictionary<IPAddress, RstEvent> _suspiciousRstEvents = new();

        private readonly record struct TtlStats(byte Min, byte Max, byte Last, int SampleCount);
        private readonly record struct RstEvent(byte RstTtl, byte ExpectedMin, byte ExpectedMax, DateTime Timestamp);

        public void Attach(NetworkMonitorService networkMonitor)
        {
            if (networkMonitor == null) throw new ArgumentNullException(nameof(networkMonitor));
            networkMonitor.OnPacketReceived += OnPacketReceived;
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
                AnalyzeRst(srcIp, ttl);
            }
            else if (isSynAck || isAck) // Обычный трафик (SYN-ACK или данные)
            {
                UpdateTtlStats(srcIp, ttl);
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

        private void AnalyzeRst(IPAddress ip, byte rstTtl)
        {
            if (_ttlStats.TryGetValue(ip, out var stats))
            {
                // Эвристика:
                // Если у нас есть статистика (хотя бы 3 пакета)
                // И RST TTL отличается от диапазона [Min, Max] более чем на порог (например, 5 хопов)
                // То это подозрительно.
                
                // Часто DPI инжектит пакеты с дефолтным TTL своей ОС (Linux=64, Cisco=255 и т.д.),
                // тогда как реальный пакет от сервера прошел много хопов и имеет другой TTL.
                
                if (stats.SampleCount >= 3)
                {
                    int diffMin = Math.Abs(rstTtl - stats.Min);
                    int diffMax = Math.Abs(rstTtl - stats.Max);
                    int minDiff = Math.Min(diffMin, diffMax);

                    // Порог 5 хопов - достаточно консервативно, чтобы не ловить джиттер маршрутов,
                    // но достаточно чувствительно для инжекций.
                    if (minDiff > 5)
                    {
                        _suspiciousRstEvents[ip] = new RstEvent(rstTtl, stats.Min, stats.Max, DateTime.UtcNow);
                    }
                }
            }
            else
            {
                // Если статистики нет, мы не можем судить (первый пакет - RST).
                // Можно было бы сравнивать с "типичными" TTL (64, 128, 255), но это ненадежно.
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
                    details = $"RST TTL={evt.RstTtl} (обычный={evt.ExpectedMin}-{evt.ExpectedMax})";
                    return true;
                }
            }
            details = string.Empty;
            return false;
        }
    }
}
