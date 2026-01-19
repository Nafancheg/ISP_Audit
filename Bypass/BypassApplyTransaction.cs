using System;
using System.Collections.Generic;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Транзакция «применения обхода» (P0.1 MVP): фиксирует что применили, к какой цели,
    /// и какой snapshot policy-driven состояния был виден на момент применения.
    /// 
    /// Важно: это не «источник истины» для policy bundle (это будет на следующих шагах P0.1),
    /// а наблюдаемость/репортинг текущего ручного apply.
    /// </summary>
    public sealed record BypassApplyTransaction
    {
        public string Version { get; init; } = "v1";

        public string TransactionId { get; init; } = Guid.NewGuid().ToString("N");
        public string CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();

        /// <summary>
        /// Цель/карточка, из которой инициировали применение (hostKey).
        /// </summary>
        public string InitiatorHostKey { get; init; } = string.Empty;

        /// <summary>
        /// Человекочитаемый текст «что применили» для UI (например: "TLS Fragment + DROP UDP/443").
        /// </summary>
        public string AppliedStrategyText { get; init; } = string.Empty;

        /// <summary>
        /// Текстовый план (токены из плана) — для лога/репорта.
        /// </summary>
        public string PlanText { get; init; } = string.Empty;

        /// <summary>
        /// Reasoning из v2 плана (best-effort).
        /// </summary>
        public string Reasoning { get; init; } = string.Empty;

        /// <summary>
        /// ActivationStatusSnapshot.Text на момент записи транзакции.
        /// </summary>
        public string ActivationStatusText { get; init; } = string.Empty;

        /// <summary>
        /// ActivationStatusSnapshot.Details на момент записи транзакции.
        /// </summary>
        public string ActivationStatusDetails { get; init; } = string.Empty;

        /// <summary>
        /// Снимок таблицы активных политик (P0.2 Stage 6) на момент записи транзакции.
        /// </summary>
        public IReadOnlyList<ActiveFlowPolicyRow> ActivePolicies { get; init; } = Array.Empty<ActiveFlowPolicyRow>();

        /// <summary>
        /// JSON snapshot decision graph/policies (P0.2 Stage 6) на момент записи транзакции.
        /// Может быть пусто, если policy-driven ветка не активна.
        /// </summary>
        public string PolicySnapshotJson { get; init; } = string.Empty;
    }
}
