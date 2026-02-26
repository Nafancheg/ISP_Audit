using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace IspAudit.ViewModels.Orchestrator;

internal sealed class RecommendationEngine
{
    public bool IsIntelMessage(string msg)
    {
        if (string.IsNullOrWhiteSpace(msg)) return false;

        var trimmed = msg.TrimStart();
        return trimmed.StartsWith("[INTEL]", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("plan:", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("intel:", StringComparison.OrdinalIgnoreCase);
    }

    public string? TryExtractAfterMarker(string msg, string marker)
    {
        if (string.IsNullOrWhiteSpace(msg) || string.IsNullOrWhiteSpace(marker)) return null;

        var idx = msg.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        idx += marker.Length;
        if (idx >= msg.Length) return null;

        return msg.Substring(idx);
    }

    public string? TryExtractInlineToken(string msg, string token)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(msg) || string.IsNullOrWhiteSpace(token)) return null;
            var m = Regex.Match(msg, $@"\b{Regex.Escape(token)}=([^\s\|]+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    public IReadOnlyList<string> ParseStrategyTokens(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return Array.Empty<string>();

        var normalized = raw.Trim();
        if (normalized.StartsWith("plan:", StringComparison.OrdinalIgnoreCase)) normalized = normalized.Substring(5);
        else if (normalized.StartsWith("intel:", StringComparison.OrdinalIgnoreCase)) normalized = normalized.Substring(6);

        var tokens = normalized
            .Split(new[] { ',', '+', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(MapStrategyToken)
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return tokens;
    }

    public string FormatStrategyTokenForUi(string token)
    {
        return (token ?? string.Empty).ToUpperInvariant() switch
        {
            "TLS_FRAGMENT" => "Frag",
            "TLS_DISORDER" => "Frag+Rev",
            "TLS_FAKE" => "TLS Fake",
            "DROP_RST" => "Drop RST",
            "DROP_UDP_443" => "QUIC→TCP",
            "ALLOW_NO_SNI" => "No SNI",
            "QUIC_TO_TCP" => "QUIC→TCP",
            "NO_SNI" => "No SNI",
            "DOH" => "🔒 DoH",
            _ => token ?? string.Empty
        };
    }

    public string MapStrategyToken(string token)
    {
        var t = token?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(t)) return string.Empty;

        return t switch
        {
            "TlsFragment" => "TLS_FRAGMENT",
            "TlsDisorder" => "TLS_DISORDER",
            "TlsFakeTtl" => "TLS_FAKE",
            "DropRst" => "DROP_RST",
            "UseDoh" => "DOH",
            "DropUdp443" => "DROP_UDP_443",
            "AllowNoSni" => "ALLOW_NO_SNI",
            "QUIC_TO_TCP" => "DROP_UDP_443",
            "NO_SNI" => "ALLOW_NO_SNI",
            _ => t.ToUpperInvariant()
        };
    }
}
