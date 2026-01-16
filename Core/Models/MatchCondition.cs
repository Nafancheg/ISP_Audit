using System;
using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace IspAudit.Core.Models
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum FlowTransportProtocol
    {
        Tcp,
        Udp
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TlsStage
    {
        ClientHello,
        Handshake,
        ApplicationData,
        NoSni
    }

    /// <summary>
    /// Условие мэтча для политики. На Этапе 0 используется как декларативная модель и для валидации конфликтов.
    /// </summary>
    public sealed record MatchCondition
    {
        /// <summary>
        /// Набор IP-адресов назначения (селективный режим). null/пусто = любое.
        /// Представлено строками, чтобы быть JSON-дружелюбным (IPv4/IPv6 по строке).
        /// </summary>
        public ImmutableHashSet<string>? DstIpSet { get; init; }

        /// <summary>
        /// Runtime-only набор IPv4 адресов назначения в виде uint (network-order), чтобы быстро мэтчить пакеты.
        /// На Этапе 1 P0.2 используется для UDP/443 (QUIC→TCP) и не предназначен для JSON экспорта.
        /// </summary>
        [JsonIgnore]
        public ImmutableHashSet<uint>? DstIpv4Set { get; init; }

        /// <summary>
        /// Протокол (TCP/UDP). null = любой.
        /// </summary>
        public FlowTransportProtocol? Proto { get; init; }

        /// <summary>
        /// Порт назначения. null = любой.
        /// </summary>
        public int? Port { get; init; }

        /// <summary>
        /// TLS-стадия (например, ClientHello). null = любая.
        /// </summary>
        public TlsStage? TlsStage { get; init; }

        /// <summary>
        /// Паттерн SNI/hostname. На Этапе 0 допускается простая маска ("*" и "*.example.com") или точное совпадение.
        /// null = любой.
        /// </summary>
        public string? SniPattern { get; init; }

        public override string ToString()
        {
            var proto = Proto?.ToString().ToUpperInvariant() ?? "ANY";
            var port = Port?.ToString() ?? "*";
            var tls = TlsStage?.ToString() ?? "*";
            var sni = string.IsNullOrWhiteSpace(SniPattern) ? "*" : SniPattern;
            var ip = DstIpSet is { Count: > 0 } ? $"ipset[{DstIpSet.Count}]" : "ipset[*]";
            return $"{proto}:{port} tls={tls} sni={sni} {ip}";
        }

        internal static bool Overlaps(MatchCondition a, MatchCondition b)
        {
            if (a is null) throw new ArgumentNullException(nameof(a));
            if (b is null) throw new ArgumentNullException(nameof(b));

            if (a.Proto.HasValue && b.Proto.HasValue && a.Proto.Value != b.Proto.Value) return false;
            if (a.Port.HasValue && b.Port.HasValue && a.Port.Value != b.Port.Value) return false;
            if (a.TlsStage.HasValue && b.TlsStage.HasValue && a.TlsStage.Value != b.TlsStage.Value) return false;

            if (!IpSetOverlaps(a.DstIpSet, b.DstIpSet)) return false;
            if (!Ipv4SetOverlaps(a.DstIpv4Set, b.DstIpv4Set)) return false;
            if (!SniOverlaps(a.SniPattern, b.SniPattern)) return false;

            return true;
        }

        private static bool IpSetOverlaps(ImmutableHashSet<string>? a, ImmutableHashSet<string>? b)
        {
            if (a is null || a.Count == 0) return true;
            if (b is null || b.Count == 0) return true;
            foreach (var ip in a)
            {
                if (b.Contains(ip)) return true;
            }
            return false;
        }

        private static bool Ipv4SetOverlaps(ImmutableHashSet<uint>? a, ImmutableHashSet<uint>? b)
        {
            // Семантика для runtime-only набора:
            // - null => ANY
            // - empty => NONE (никогда не мэтчится)
            if (a is { Count: 0 }) return false;
            if (b is { Count: 0 }) return false;
            if (a is null) return true;
            if (b is null) return true;
            foreach (var ip in a)
            {
                if (b.Contains(ip)) return true;
            }
            return false;
        }

        internal bool MatchesUdp443Packet(uint dstIpv4Int, bool isIpv4, bool isIpv6)
        {
            // Протокол/порт проверяются выше через индекс/кандидаты.
            // IPv6: селективность пока недоступна, считаем мэтчем только если нет ipv4-селективного условия.
            if (isIpv6)
            {
                return DstIpv4Set is null;
            }

            if (!isIpv4)
            {
                return false;
            }

            if (DstIpv4Set is null) return true;
            if (DstIpv4Set.Count == 0) return false;
            return DstIpv4Set.Contains(dstIpv4Int);
        }

        private static bool SniOverlaps(string? a, string? b)
        {
            if (string.IsNullOrWhiteSpace(a) || a == "*") return true;
            if (string.IsNullOrWhiteSpace(b) || b == "*") return true;

            // Самый детерминированный случай для hard-conflict валидации (Этап 0): точное совпадение.
            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;

            // Консервативная поддержка простых масок вида "*.example.com".
            if (LooksLikeWildcard(a) && !LooksLikeWildcard(b))
            {
                return WildcardMatches(a, b);
            }

            if (LooksLikeWildcard(b) && !LooksLikeWildcard(a))
            {
                return WildcardMatches(b, a);
            }

            // Если оба паттерна wildcard и они разные, пересечение определить сложно — считаем, что может пересекаться.
            if (LooksLikeWildcard(a) && LooksLikeWildcard(b)) return true;

            return false;
        }

        private static bool LooksLikeWildcard(string s) => s.Contains('*', StringComparison.Ordinal);

        private static bool WildcardMatches(string pattern, string value)
        {
            // Поддерживаем "*" и "*.suffix".
            if (pattern == "*") return true;
            if (pattern.StartsWith("*.", StringComparison.Ordinal) && pattern.Length > 2)
            {
                var suffix = pattern[1..]; // ".example.com"
                return value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
            }

            // Прочие wildcard-паттерны считаем невалидными для мэтча на Этапе 0.
            return false;
        }
    }
}
