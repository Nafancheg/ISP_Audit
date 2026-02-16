using System;

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

            var reason = ParseUnknownReason(details);
            return new PostApplyVerdictContract
            {
                Status = VerdictStatus.Unknown,
                UnknownReason = reason,
                VerdictCode = reason == UnknownReason.None ? "UNKNOWN" : reason.ToString().ToUpperInvariant()
            };
        }

        private static UnknownReason ParseUnknownReason(string? details)
        {
            var text = (details ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(text)) return UnknownReason.None;

            if (text.Contains("cancelled", StringComparison.OrdinalIgnoreCase)) return UnknownReason.Cancelled;
            if (text.Contains("concurrent", StringComparison.OrdinalIgnoreCase)) return UnknownReason.ConcurrentApply;
            if (text.Contains("no_targets_resolved", StringComparison.OrdinalIgnoreCase)) return UnknownReason.InsufficientIps;
            if (text.Contains("no baseline", StringComparison.OrdinalIgnoreCase)) return UnknownReason.NoBaseline;
            if (text.Contains("baseline stale", StringComparison.OrdinalIgnoreCase) || text.Contains("baseline fresh", StringComparison.OrdinalIgnoreCase)) return UnknownReason.NoBaselineFresh;
            if (text.Contains("timeout", StringComparison.OrdinalIgnoreCase) || text.Contains("pipeline_not_ready", StringComparison.OrdinalIgnoreCase)) return UnknownReason.ProbeTimeoutBudget;

            return UnknownReason.None;
        }
    }
}
