using System;
using System.Net;
using IspAudit.Bypass; // For TransportProtocol

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Хост обнаружен снифером
    /// </summary>
    public record HostDiscovered(
        string Key,                    // IP:Port:Protocol
        IPAddress RemoteIp,
        int RemotePort,
        TransportProtocol Protocol,
        DateTime DiscoveredAt
    )
    {
        public string? Hostname { get; init; }

        /// <summary>
        /// SNI (TLS ClientHello), если удалось извлечь
        /// </summary>
        public string? SniHostname { get; init; }
    }

    /// <summary>
    /// Результат тестирования хоста
    /// </summary>
    public record HostTested(
        HostDiscovered Host,
        bool DnsOk,
        bool TcpOk,
        bool TlsOk,
        string? DnsStatus,             // OK, DNS_FILTERED, DNS_BOGUS, DNS_BYPASS
        string? Hostname,              // Резолвленное имя
        string? SniHostname,           // SNI из трафика (если был)
        string? ReverseDnsHostname,     // PTR / reverse DNS (если делали)
        int? TcpLatencyMs,
        string? BlockageType,          // null, TCP_CONNECTION_RESET (legacy: TCP_RST), TCP_CONNECT_TIMEOUT (legacy: TCP_TIMEOUT), TLS_HANDSHAKE_TIMEOUT (legacy: TLS_TIMEOUT), TLS_AUTH_FAILURE (legacy: TLS_DPI), UDP_DROP
        DateTime TestedAt,

        // HTTP/3 (QUIC) — отдельный канал от TCP/TLS.
        // null = тест не выполнялся (нет hostname или отключено/не поддерживается платформой).
        bool? Http3Ok = null,
        string? Http3Status = null,     // H3_OK | H3_FAILED | H3_TIMEOUT | H3_NOT_SUPPORTED | H3_NOT_ATTEMPTED
        int? Http3LatencyMs = null,
        string? Http3Error = null
    );

    /// <summary>
    /// Хост с блокировкой, требуется bypass
    /// </summary>
    public record HostBlocked(
        HostTested TestResult,
        string BypassStrategy,         // TLS_FRAGMENT, TCP_TTL, UDP_FAKE
        string RecommendedAction       // "Применить TLS fragmentation", "Заблокировать RST пакеты"
    );

    /// <summary>
    /// Конфигурация pipeline
    /// </summary>
    public class PipelineConfig
    {
        public bool EnableLiveTesting { get; set; } = true;
        public bool EnableAutoBypass { get; set; } = true; // Автоматическое применение bypass включено по умолчанию
        public int MaxConcurrentTests { get; set; } = 5;
        public TimeSpan TestTimeout { get; set; } = TimeSpan.FromSeconds(3);
    }
}