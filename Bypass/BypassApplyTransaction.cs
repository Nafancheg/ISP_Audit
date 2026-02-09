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

        /// <summary>
        /// Кто инициировал транзакцию: user | autopilot.
        /// Нужен для разруливания конфликтов Autopilot vs ручные действия (P1.11).
        /// </summary>
        public string AppliedBy { get; init; } = "user";

        /// <summary>
        /// Область действия: group | target.
        /// </summary>
        public string Scope { get; init; } = "group";

        /// <summary>
        /// Ключ области действия: для group обычно GroupKey, для target — hostKey цели.
        /// </summary>
        public string ScopeKey { get; init; } = string.Empty;

        public string TransactionId { get; init; } = Guid.NewGuid().ToString("N");
        public string CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();

        /// <summary>
        /// Цель/карточка, из которой инициировали применение (hostKey).
        /// </summary>
        public string InitiatorHostKey { get; init; } = string.Empty;

        /// <summary>
        /// Групповой ключ для агрегации (доменный suffix, если применимо; иначе hostKey).
        /// Используется для репортинга: «что применили к какой группе целей».
        /// </summary>
        public string GroupKey { get; init; } = string.Empty;

        /// <summary>
        /// Снимок candidate endpoints (IP) для цели на момент применения.
        /// Best-effort: берётся из DNS/SNI кешей и/или короткого DNS resolve.
        /// </summary>
        public IReadOnlyList<string> CandidateIpEndpoints { get; init; } = Array.Empty<string>();

        /// <summary>
        /// Ожидаемые эффекты/инварианты после транзакции (для репорта и самодиагностики).
        /// Пример: «при QUIC→TCP должен расти Udp443Dropped при трафике».
        /// </summary>
        public IReadOnlyList<string> ExpectedEffects { get; init; } = Array.Empty<string>();

        /// <summary>
        /// Предупреждения (почему транзакция может не дать эффекта) — best-effort эвристики.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

        /// <summary>
        /// Человекочитаемый текст «что применили» для UI (например: "TLS Fragment + DROP UDP/443").
        /// </summary>
        public string AppliedStrategyText { get; init; } = string.Empty;

        /// <summary>
        /// Текстовый план (токены из плана) — для лога/репорта.
        /// </summary>
        public string PlanText { get; init; } = string.Empty;

        /// <summary>
        /// Reasoning из INTEL-плана (best-effort).
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

        // P0.1 Step 2 (контракт наблюдаемости): формализованные секции транзакции.
        // Важно: оставляем v1 поля выше для обратной совместимости persisted JSON и UI.

        /// <summary>
        /// Request-секция: что именно запросили применить (план/цель/группа).
        /// </summary>
        public BypassApplyRequest? Request { get; init; }

        /// <summary>
        /// Snapshot-секция: снимок состояния обхода/политик в момент записи транзакции.
        /// </summary>
        public BypassApplySnapshot? Snapshot { get; init; }

        /// <summary>
        /// Result-секция: итог применения (best-effort, так как apply выполняется отдельно).
        /// </summary>
        public BypassApplyResult? Result { get; init; }

        /// <summary>
        /// Contributions: детализированный список вкладов/изменений (для репорта и объяснимости).
        /// </summary>
        public IReadOnlyList<BypassApplyContribution> Contributions { get; init; } = Array.Empty<BypassApplyContribution>();
    }
}
