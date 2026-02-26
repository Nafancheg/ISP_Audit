using System;
using System.Collections.Generic;
using IspAudit.Core.Intelligence.Contracts;

namespace IspAudit.Models
{
    /// <summary>
    /// P1.9: «win» — сохранённый план обхода, который был применён и после этого
    /// подтвердил доступность на post-apply ретесте (verdict=OK).
    /// </summary>
    public sealed record WinsEntry
    {
        public string HostKey { get; init; } = string.Empty;

        /// <summary>
        /// Для доменных целей обычно совпадает с HostKey.
        /// Для IP может быть пустым.
        /// </summary>
        public string SniHostname { get; init; } = string.Empty;

        /// <summary>
        /// CorrelationId/txId, связывает Apply и PostApplyRetest.
        /// </summary>
        public string CorrelationId { get; init; } = string.Empty;

        public string AppliedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();
        public string VerifiedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();

        public string VerifiedVerdict { get; init; } = string.Empty; // OK/FAIL/PARTIAL/UNKNOWN
        public string VerifiedMode { get; init; } = string.Empty; // enqueue/local
        public string VerifiedDetails { get; init; } = string.Empty;
        public int SemanticsVersion { get; init; } = 0;

        public string AppliedStrategyText { get; init; } = string.Empty;
        public string PlanText { get; init; } = string.Empty;

        public BypassPlan Plan { get; init; } = new();

        public IReadOnlyList<string> CandidateIpEndpoints { get; init; } = Array.Empty<string>();
    }
}
