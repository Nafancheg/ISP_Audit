using System;
using System.Collections.Generic;
using IspAudit.Core.Diagnostics;

namespace IspAudit.Utils
{
    /// <summary>
    /// Маппинг «сырых» кодов блокировок/ошибок (например TLS_AUTH_FAILURE)
    /// в человекочитаемые тексты для Operator UI.
    /// </summary>
    public static class OperatorTextMapper
    {
        private sealed record OperatorText(string Title, string Recommendation);

        private static readonly IReadOnlyDictionary<string, OperatorText> CanonicalCodeToText
            = new Dictionary<string, OperatorText>(StringComparer.Ordinal)
            {
                // DNS
                [BlockageCode.DnsError] = new OperatorText(
                    Title: "Ошибка DNS (не удаётся получить IP)",
                    Recommendation: "Проверьте DNS/DoH, попробуйте безопасный DNS-профиль."),
                [BlockageCode.DnsTimeout] = new OperatorText(
                    Title: "Таймаут DNS",
                    Recommendation: "Проверьте доступ к DNS-серверам или смените DNS-профиль."),
                [BlockageCode.DnsFiltered] = new OperatorText(
                    Title: "DNS отфильтрован",
                    Recommendation: "Попробуйте другой DNS/DoH или профиль обхода."),

                // TCP
                [BlockageCode.TcpConnectionReset] = new OperatorText(
                    Title: "Сброс соединения (TCP RST)",
                    Recommendation: "Вероятна инъекция RST/DPI: попробуйте Drop RST и/или фрагментацию TLS."),
                [BlockageCode.TcpConnectTimeout] = new OperatorText(
                    Title: "Таймаут TCP соединения",
                    Recommendation: "Проверьте доступ к порту/маршрут; при блокировке попробуйте обход."),
                [BlockageCode.TcpConnectTimeoutConfirmed] = new OperatorText(
                    Title: "Таймаут TCP (подтверждён)",
                    Recommendation: "Вероятна фильтрация/блокировка: попробуйте обход и альтернативный DNS."),

                // TLS
                [BlockageCode.TlsHandshakeTimeout] = new OperatorText(
                    Title: "Таймаут TLS рукопожатия",
                    Recommendation: "Попробуйте фрагментацию TLS и/или смену DNS."),
                [BlockageCode.TlsAuthFailure] = new OperatorText(
                    Title: "Ошибка TLS аутентификации",
                    Recommendation: "Возможен DPI по SNI: попробуйте TLS Fragment/Disorder или AllowNoSNI."),

                // HTTP/UDP
                [BlockageCode.HttpRedirectDpi] = new OperatorText(
                    Title: "HTTP редирект (возможная блок-страница)",
                    Recommendation: "Проверьте редирект и попробуйте HTTP Host tricks/HTTPS-only."),
                [BlockageCode.UdpBlockage] = new OperatorText(
                    Title: "Блокировка UDP/QUIC",
                    Recommendation: "Отключите QUIC или включите QUIC fallback (глушить UDP/443)."),
            };

        private static readonly IReadOnlyDictionary<string, string> TokenToCanonical
            = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                // Явно поддерживаем дополнительные legacy-токены, встречающиеся в логах/моделях.
                ["TCP_RESET"] = BlockageCode.TcpConnectionReset,
                ["UDP_DROP"] = BlockageCode.UdpBlockage,
            };

        /// <summary>
        /// Возвращает человекочитаемый заголовок для кода. Если код неизвестен — возвращает исходное значение.
        /// </summary>
        public static string MapCodeToTitle(string? code)
        {
            if (string.IsNullOrWhiteSpace(code)) return string.Empty;

            var normalized = BlockageCode.Normalize(code) ?? string.Empty;
            if (CanonicalCodeToText.TryGetValue(normalized, out var t)) return t.Title;

            if (TokenToCanonical.TryGetValue(code.Trim(), out var canonical)
                && CanonicalCodeToText.TryGetValue(canonical, out var tt))
            {
                return tt.Title;
            }

            return code.Trim();
        }

        /// <summary>
        /// Возвращает короткую рекомендацию для кода. Если код неизвестен — пустая строка.
        /// </summary>
        public static string MapCodeToRecommendation(string? code)
        {
            if (string.IsNullOrWhiteSpace(code)) return string.Empty;

            var normalized = BlockageCode.Normalize(code) ?? string.Empty;
            if (CanonicalCodeToText.TryGetValue(normalized, out var t)) return t.Recommendation;

            if (TokenToCanonical.TryGetValue(code.Trim(), out var canonical)
                && CanonicalCodeToText.TryGetValue(canonical, out var tt))
            {
                return tt.Recommendation;
            }

            return string.Empty;
        }

        /// <summary>
        /// Best-effort: заменяет известные кодовые токены в произвольном тексте на локализованные формулировки,
        /// чтобы Operator UI не показывал raw-коды типа TLS_AUTH_FAILURE.
        /// </summary>
        public static string LocalizeCodesInText(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return string.Empty;

            var result = text;

            // 1) Канонические коды + legacy-токены из BlockageCode.
            foreach (var canonical in CanonicalCodeToText.Keys)
            {
                var title = CanonicalCodeToText[canonical].Title;

                foreach (var token in GetTokensBestEffort(canonical))
                {
                    if (string.IsNullOrWhiteSpace(token)) continue;

                    result = result.Replace(token, title, StringComparison.Ordinal);
                    result = result.Replace(token, title, StringComparison.OrdinalIgnoreCase);
                }
            }

            // 2) Доп. legacy-токены (которые не входят в BlockageCode.GetTokens).
            foreach (var kv in TokenToCanonical)
            {
                if (!CanonicalCodeToText.TryGetValue(kv.Value, out var t)) continue;
                result = result.Replace(kv.Key, t.Title, StringComparison.Ordinal);
                result = result.Replace(kv.Key, t.Title, StringComparison.OrdinalIgnoreCase);
            }

            return result;
        }

        private static IReadOnlyList<string> GetTokensBestEffort(string canonicalCode)
        {
            try
            {
                return BlockageCode.GetTokens(canonicalCode);
            }
            catch
            {
                return new[] { canonicalCode };
            }
        }
    }
}
