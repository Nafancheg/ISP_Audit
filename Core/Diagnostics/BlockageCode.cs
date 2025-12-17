using System;
using System.Collections.Generic;

namespace IspAudit.Core.Diagnostics;

/// <summary>
/// Нормализация кодов проблем (BlockageType).
///
/// Цель: держать алиасы/legacy в одном месте, а в остальном коде работать только
/// с каноническими "фактовыми" кодами.
/// </summary>
public static class BlockageCode
{
    // Канонические коды (фактура)
    public const string TcpConnectTimeout = "TCP_CONNECT_TIMEOUT";
    public const string TcpConnectTimeoutConfirmed = "TCP_CONNECT_TIMEOUT_CONFIRMED";
    public const string TcpConnectionReset = "TCP_CONNECTION_RESET";

    public const string TlsHandshakeTimeout = "TLS_HANDSHAKE_TIMEOUT";
    public const string TlsAuthFailure = "TLS_AUTH_FAILURE";

    // Остальные коды (пока без переименований)
    public const string TcpRstInjection = "TCP_RST_INJECTION";
    public const string TcpRetryHeavy = "TCP_RETRY_HEAVY";
    public const string HttpRedirectDpi = "HTTP_REDIRECT_DPI";
    public const string HttpTimeout = "HTTP_TIMEOUT";
    public const string UdpBlockage = "UDP_BLOCKAGE";
    public const string PortClosed = "PORT_CLOSED";
    public const string FakeIp = "FAKE_IP";

    // Технические/внутренние коды ошибок (не обязательно свидетельствуют о блокировке)
    public const string TcpError = "TCP_ERROR";
    public const string TlsError = "TLS_ERROR";

    // DNS статусы (DnsStatus)
    public const string DnsFiltered = "DNS_FILTERED";
    public const string DnsBogus = "DNS_BOGUS";
    public const string DnsError = "DNS_ERROR";
    public const string DnsBypass = "DNS_BYPASS";

    // Legacy алиасы → канон
    private static readonly Dictionary<string, string> LegacyToCanonical = new(StringComparer.Ordinal)
    {
        // TCP
        ["TCP_TIMEOUT"] = TcpConnectTimeout,
        ["TCP_TIMEOUT_CONFIRMED"] = TcpConnectTimeoutConfirmed,
        ["TCP_RST"] = TcpConnectionReset,

        // TLS
        ["TLS_TIMEOUT"] = TlsHandshakeTimeout,
        ["TLS_DPI"] = TlsAuthFailure,
    };

    // Канон → набор токенов (канон + legacy алиасы)
    private static readonly Dictionary<string, string[]> CanonicalToTokens = new(StringComparer.Ordinal)
    {
        [TcpConnectTimeout] = [TcpConnectTimeout, "TCP_TIMEOUT"],
        [TcpConnectTimeoutConfirmed] = [TcpConnectTimeoutConfirmed, "TCP_TIMEOUT_CONFIRMED"],
        [TcpConnectionReset] = [TcpConnectionReset, "TCP_RST"],

        [TlsHandshakeTimeout] = [TlsHandshakeTimeout, "TLS_TIMEOUT"],
        [TlsAuthFailure] = [TlsAuthFailure, "TLS_DPI"],
    };

    /// <summary>
    /// Приводит код к каноническому виду. Если код неизвестен — возвращает как есть.
    /// </summary>
    public static string? Normalize(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return code;

        var trimmed = code.Trim();
        return LegacyToCanonical.TryGetValue(trimmed, out var canonical) ? canonical : trimmed;
    }

    /// <summary>
    /// Возвращает все текстовые токены для кода: канонический + legacy алиасы.
    /// Удобно для поиска по строкам логов.
    /// </summary>
    public static IReadOnlyList<string> GetTokens(string canonicalCode)
    {
        if (CanonicalToTokens.TryGetValue(canonicalCode, out var tokens))
        {
            return tokens;
        }

        return new[] { canonicalCode };
    }

    /// <summary>
    /// Проверяет, содержит ли строка любой из токенов (канон/алиасы) для заданного кода.
    /// </summary>
    public static bool ContainsCode(string? text, string canonicalCode)
    {
        if (string.IsNullOrEmpty(text)) return false;

        foreach (var token in GetTokens(canonicalCode))
        {
            if (text.Contains(token, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
