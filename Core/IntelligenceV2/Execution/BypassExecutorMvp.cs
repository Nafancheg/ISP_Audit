using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using IspAudit.Core.Diagnostics;

namespace IspAudit.Core.IntelligenceV2.Execution;

/// <summary>
/// MVP-исполнитель intel-рекомендаций: ТОЛЬКО форматирование и логирование.
/// ВАЖНО: не вызывает TrafficEngine/BypassController и не применяет техники.
/// </summary>
public sealed class BypassExecutorMvp
{
    public const string IntelLogPrefix = "[INTEL]";

    private static readonly TimeSpan DefaultDedupInterval = TimeSpan.FromSeconds(60);

    // Hostname (SNI) регистронезависим. В частности, без этого возможен "спам" одной и той же рекомендацией
    // при разных вариантах регистра/нормализации ключа.
    private readonly ConcurrentDictionary<string, (DateTimeOffset LastEmitUtc, string Signature)> _emitCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Преобразовать технический хвост вида "(intel:SilentDrop conf=78; ... )" в читаемый для пользователя.
    /// </summary>
    public bool TryFormatDiagnosisSuffix(string? tailWithParens, out string formatted)
    {
        formatted = string.Empty;

        if (string.IsNullOrWhiteSpace(tailWithParens))
        {
            return false;
        }

        var tail = tailWithParens.Trim();
        if (!tail.Contains("intel:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Снимаем внешние скобки, если они есть.
        var inner = tail;
        if (inner.StartsWith("(", StringComparison.Ordinal) && inner.EndsWith(")", StringComparison.Ordinal) && inner.Length >= 2)
        {
            inner = inner.Substring(1, inner.Length - 2);
        }

        // Ожидаемый формат: "intel:<DiagnosisId> conf=<N>; <note1>; <note2>".
        var intelIndex = inner.IndexOf("intel:", StringComparison.OrdinalIgnoreCase);
        var prefixIndex = intelIndex;
        var prefixLen = 6;
        if (prefixIndex < 0)
        {
            return false;
        }

        var after = inner.Substring(prefixIndex + prefixLen).Trim();
        if (after.Length == 0)
        {
            return false;
        }

        var diagnosisId = ReadTokenUntil(after, c => char.IsWhiteSpace(c) || c == ';');
        if (string.IsNullOrWhiteSpace(diagnosisId))
        {
            return false;
        }

        var conf = TryParseConfidence(inner);

        var explanation = TryExtractFirstNote(inner);
        if (!string.IsNullOrWhiteSpace(explanation))
        {
            explanation = Compact(explanation!, 90);
        }

        formatted = string.IsNullOrWhiteSpace(explanation)
            ? $"({IntelLogPrefix} диагноз={diagnosisId} уверенность={conf}%)"
            : $"({IntelLogPrefix} диагноз={diagnosisId} уверенность={conf}%: {explanation})";

        return true;
    }

    /// <summary>
    /// Построить одну строку рекомендаций (1 строка на хост) в формате, который парсится UI.
    /// </summary>
    public bool TryBuildRecommendationLine(string hostKey, string? bypassStrategyRaw, out string line)
    {
        return TryBuildRecommendationLine(hostKey, bypassStrategyRaw, contextSuffix: null, out line);
    }

    /// <summary>
    /// Построить одну строку рекомендаций (1 строка на хост) + опциональный хвост контекста цели.
    /// Пример контекста: "host=1.2.3.4:443 SNI=example.com RDNS=-".
    /// Важно: контекст добавляется после "|", чтобы UI мог обрезать его при разборе токенов.
    /// </summary>
    public bool TryBuildRecommendationLine(string hostKey, string? bypassStrategyRaw, string? contextSuffix, out string line)
    {
        line = string.Empty;

        var strategies = ExtractStrategyTokens(bypassStrategyRaw);
        if (strategies.Count == 0)
        {
            return false;
        }

        // Дедупликация: не спамим одинаковой рекомендацией по одному хосту.
        var signature = string.Join(",", strategies);
        if (!ShouldEmit(hostKey, signature, DefaultDedupInterval))
        {
            return false;
        }

        line = $"{IntelLogPrefix} 💡 Рекомендация: {string.Join(", ", strategies)}";

        if (!string.IsNullOrWhiteSpace(contextSuffix))
        {
            var suffix = contextSuffix.Trim();
            if (suffix.Length > 0)
            {
                line += $" | {suffix}";
            }
        }

        return true;
    }

    private bool ShouldEmit(string hostKey, string signature, TimeSpan minInterval)
    {
        var nowUtc = DateTimeOffset.UtcNow;

        if (_emitCache.TryGetValue(hostKey, out var prev))
        {
            if (string.Equals(prev.Signature, signature, StringComparison.Ordinal) && (nowUtc - prev.LastEmitUtc) < minInterval)
            {
                return false;
            }
        }

        _emitCache[hostKey] = (nowUtc, signature);
        return true;
    }

    private static int TryParseConfidence(string inner)
    {
        // Ищем "conf=NN" и пытаемся распарсить.
        var idx = inner.IndexOf("conf=", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return 0;

        idx += "conf=".Length;
        var digits = ReadTokenUntil(inner.Substring(idx), c => !char.IsDigit(c));
        if (int.TryParse(digits, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
        {
            return Math.Clamp(value, 0, 100);
        }

        return 0;
    }

    private static string? TryExtractFirstNote(string inner)
    {
        // После "conf=..." ожидаем "; <note>".
        var semicolon = inner.IndexOf(';');
        if (semicolon < 0) return null;

        var after = inner.Substring(semicolon + 1).Trim();
        if (after.Length == 0) return null;

        // Берём только первую ноту.
        var second = after.IndexOf(';');
        return second < 0 ? after : after.Substring(0, second).Trim();
    }

    private static List<string> ExtractStrategyTokens(string? bypassStrategyRaw)
    {
        if (string.IsNullOrWhiteSpace(bypassStrategyRaw)) return [];

        var raw = bypassStrategyRaw.Trim();
        if (raw.Equals(PipelineContract.BypassNone, StringComparison.OrdinalIgnoreCase) || raw.Equals(PipelineContract.BypassUnknown, StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        // Формат pipeline: "plan:TlsFragment + DropRst (conf=78)".
        if (raw.StartsWith("plan:", StringComparison.OrdinalIgnoreCase))
        {
            raw = raw.Substring(5);
        }

        var parenIndex = raw.IndexOf('(');
        if (parenIndex > 0)
        {
            raw = raw.Substring(0, parenIndex).Trim();
        }

        var tokens = raw
            .Split(new[] { ',', '+', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(MapToLegacyStrategyToken)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return tokens;
    }

    private static string MapToLegacyStrategyToken(string token)
    {
        var t = token.Trim();
        if (string.IsNullOrWhiteSpace(t)) return string.Empty;

        // Поддерживаем и enum-названия, и уже-нормализованные токены.
        // Новые assist-токены:
        // - DropUdp443 => DROP_UDP_443
        // - AllowNoSni => ALLOW_NO_SNI
        return t switch
        {
            "TlsFragment" => "TLS_FRAGMENT",
            "TlsDisorder" => "TLS_DISORDER",
            "TlsFakeTtl" => "TLS_FAKE",
            "DropRst" => "DROP_RST",
            "UseDoh" => "DOH",
            "DropUdp443" => "DROP_UDP_443",
            "AllowNoSni" => "ALLOW_NO_SNI",
            _ => t.ToUpperInvariant()
        };
    }

    private static string ReadTokenUntil(string s, Func<char, bool> stop)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;

        var i = 0;
        while (i < s.Length && !stop(s[i]))
        {
            i++;
        }

        return s.Substring(0, i).Trim();
    }

    private static string Compact(string s, int maxLen)
    {
        var trimmed = s.Replace("\r", " ").Replace("\n", " ").Trim();
        while (trimmed.Contains("  ", StringComparison.Ordinal))
        {
            trimmed = trimmed.Replace("  ", " ", StringComparison.Ordinal);
        }

        if (trimmed.Length <= maxLen) return trimmed;
        return trimmed.Substring(0, Math.Max(0, maxLen - 1)).TrimEnd() + "…";
    }
}
