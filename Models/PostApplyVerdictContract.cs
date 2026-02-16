using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Models
{
    public enum VerdictStatus
    {
        Ok,
        Fail,
        Unknown
    }

    public enum UnknownReason
    {
        None,
        InsufficientDns,
        InsufficientIps,
        ProbeTimeoutBudget,
        NoBaseline,
        NoBaselineFresh,
        Cancelled,
        ConcurrentApply
    }

    /// <summary>
    /// Контракт вердикта post-apply проверки в структурированном виде (v2.3).
    /// </summary>
    public sealed record PostApplyVerdictContract
    {
        public VerdictStatus Status { get; init; } = VerdictStatus.Unknown;
        public UnknownReason UnknownReason { get; init; } = UnknownReason.None;
        public string VerdictCode { get; init; } = "UNKNOWN";

        public static PostApplyVerdictContract FromLegacy(string? verdict, string? details)
        {
            var v = (verdict ?? string.Empty).Trim();

            if (v.Equals("OK", StringComparison.OrdinalIgnoreCase) || v.Equals("SUCCESS", StringComparison.OrdinalIgnoreCase))
            {
                return new PostApplyVerdictContract
                {
                    Status = VerdictStatus.Ok,
                    UnknownReason = UnknownReason.None,
                    VerdictCode = "OK"
                };
            }

            if (v.Equals("FAIL", StringComparison.OrdinalIgnoreCase) || v.Equals("FAILED", StringComparison.OrdinalIgnoreCase))
            {
                return new PostApplyVerdictContract
                {
                    Status = VerdictStatus.Fail,
                    UnknownReason = UnknownReason.None,
                    VerdictCode = "FAIL"
                };
            }

            var reason = ResolveUnknownReason(v, details);
            return new PostApplyVerdictContract
            {
                Status = VerdictStatus.Unknown,
                UnknownReason = reason,
                VerdictCode = reason == UnknownReason.None ? "UNKNOWN" : reason.ToString().ToUpperInvariant()
            };
        }

        public static UnknownReason ResolveUnknownReason(string? verdictCode, string? details)
        {
            var text = (details ?? string.Empty).Trim();
            var code = (verdictCode ?? string.Empty).Trim();

            var candidates = new HashSet<UnknownReason>();

            if (!string.IsNullOrWhiteSpace(code)
                && Enum.TryParse<UnknownReason>(code, ignoreCase: true, out var parsedCodeReason)
                && parsedCodeReason != UnknownReason.None)
            {
                candidates.Add(parsedCodeReason);
            }

            if (string.IsNullOrWhiteSpace(text))
            {
                return PickByPriority(candidates);
            }

            if (text.Contains("reason=", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var token in ExtractReasonTokens(text))
                {
                    if (Enum.TryParse<UnknownReason>(token, ignoreCase: true, out var parsedTokenReason)
                        && parsedTokenReason != UnknownReason.None)
                    {
                        candidates.Add(parsedTokenReason);
                    }
                }
            }

            if (text.Contains("cancelled", StringComparison.OrdinalIgnoreCase)) candidates.Add(UnknownReason.Cancelled);
            if (text.Contains("concurrent", StringComparison.OrdinalIgnoreCase)) candidates.Add(UnknownReason.ConcurrentApply);
            if (text.Contains("insufficientdns", StringComparison.OrdinalIgnoreCase) || text.Contains("dns", StringComparison.OrdinalIgnoreCase)) candidates.Add(UnknownReason.InsufficientDns);
            if (text.Contains("insufficientips", StringComparison.OrdinalIgnoreCase) || text.Contains("no_targets_resolved", StringComparison.OrdinalIgnoreCase)) candidates.Add(UnknownReason.InsufficientIps);
            if (text.Contains("nobaselinefresh", StringComparison.OrdinalIgnoreCase) || text.Contains("baseline stale", StringComparison.OrdinalIgnoreCase) || text.Contains("baseline fresh", StringComparison.OrdinalIgnoreCase)) candidates.Add(UnknownReason.NoBaselineFresh);
            if (text.Contains("nobaseline", StringComparison.OrdinalIgnoreCase) || text.Contains("no baseline", StringComparison.OrdinalIgnoreCase)) candidates.Add(UnknownReason.NoBaseline);
            if (text.Contains("probetimeoutbudget", StringComparison.OrdinalIgnoreCase) || text.Contains("timeout", StringComparison.OrdinalIgnoreCase) || text.Contains("pipeline_not_ready", StringComparison.OrdinalIgnoreCase)) candidates.Add(UnknownReason.ProbeTimeoutBudget);

            return PickByPriority(candidates);
        }

        private static IEnumerable<string> ExtractReasonTokens(string details)
        {
            var text = details ?? string.Empty;
            var parts = text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                var p = part.Trim();
                if (!p.StartsWith("reason=", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var value = p.Substring("reason=".Length).Trim();
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                var values = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (var item in values)
                {
                    if (!string.IsNullOrWhiteSpace(item))
                    {
                        yield return item;
                    }
                }
            }
        }

        private static UnknownReason PickByPriority(HashSet<UnknownReason> candidates)
        {
            if (candidates == null || candidates.Count == 0)
            {
                return UnknownReason.None;
            }

            var priority = new[]
            {
                UnknownReason.ConcurrentApply,
                UnknownReason.Cancelled,
                UnknownReason.NoBaselineFresh,
                UnknownReason.NoBaseline,
                UnknownReason.InsufficientIps,
                UnknownReason.InsufficientDns,
                UnknownReason.ProbeTimeoutBudget,
                UnknownReason.None,
            };

            return priority.FirstOrDefault(candidates.Contains);
        }
    }
}
