using System;
using System.Collections.Generic;

namespace IspAudit.Bypass
{
    /// <summary>
    /// P0.2: фазовая диагностика apply. Нужна для расследования таймаутов/подвисаний:
    /// какая стадия заняла время и где была отмена.
    /// </summary>
    public sealed record BypassApplyPhaseTiming
    {
        public string Name { get; init; } = string.Empty;

        // Примеры: START / OK / FAILED / CANCELED.
        public string Status { get; init; } = string.Empty;

        public long ElapsedMs { get; init; }

        public string Details { get; init; } = string.Empty;
    }

    /// <summary>
    /// P0.1 Step 2: контракт данных для транзакции применения обхода.
    ///
    /// Цель: фиксировать единый, расширяемый формат Request/Snapshot/Result и список Contributions,
    /// чтобы UI/репорты могли детерминированно объяснять: что запросили, какое состояние было на момент записи,
    /// и что именно в итоге было (или должно было быть) активировано.
    ///
    /// Важно: это контракт наблюдаемости, а не «источник истины» для policy bundle.
    /// </summary>
    public sealed record BypassApplyRequest
    {
        public string InitiatorHostKey { get; init; } = string.Empty;
        public string GroupKey { get; init; } = string.Empty;
        public IReadOnlyList<string> CandidateIpEndpoints { get; init; } = Array.Empty<string>();
        public string PlanText { get; init; } = string.Empty;
        public string Reasoning { get; init; } = string.Empty;
    }

    public sealed record BypassApplySnapshot
    {
        public string ActivationStatusText { get; init; } = string.Empty;
        public string ActivationStatusDetails { get; init; } = string.Empty;

        public TlsBypassOptions OptionsSnapshot { get; init; } = new();
        public bool DoHEnabled { get; init; }
        public string SelectedDnsPreset { get; init; } = string.Empty;

        public int Udp443DropTargetIpCount { get; init; }

        public IReadOnlyList<BypassStateManager.ActiveTargetPolicy> ActiveTargetPolicies { get; init; }
            = Array.Empty<BypassStateManager.ActiveTargetPolicy>();

        public IReadOnlyList<ActiveFlowPolicyRow> ActivePolicies { get; init; } = Array.Empty<ActiveFlowPolicyRow>();

        /// <summary>
        /// JSON snapshot decision graph/policies (P0.2 Stage 6). Храним как строку и при экспорте
        /// стараемся встроить как JSON, чтобы не было двойного экранирования.
        /// </summary>
        public string PolicySnapshotJson { get; init; } = string.Empty;
    }

    public sealed record BypassApplyResult
    {
        public string Status { get; init; } = "RECORDED";

        // Наблюдаемость: почему транзакция не завершилась успешно (best-effort).
        public string Error { get; init; } = string.Empty;

        // Наблюдаемость: был ли откат и чем закончился (best-effort).
        // Примеры: NOT_NEEDED / DONE / FAILED.
        public string RollbackStatus { get; init; } = string.Empty;

        // P0.2: если apply был отменён, почему.
        // Примеры: timeout / cancel.
        public string CancelReason { get; init; } = string.Empty;

        // P0.2: в какой фазе apply находились в момент отмены/ошибки.
        public string ApplyCurrentPhase { get; init; } = string.Empty;

        // P0.2: суммарное время apply (best-effort).
        public long ApplyTotalElapsedMs { get; init; }

        // P0.2: список фаз и их длительностей.
        public IReadOnlyList<BypassApplyPhaseTiming> ApplyPhases { get; init; } = Array.Empty<BypassApplyPhaseTiming>();

        public string AppliedStrategyText { get; init; } = string.Empty;
        public string PlanText { get; init; } = string.Empty;
        public string Reasoning { get; init; } = string.Empty;

        public string OutcomeTargetHost { get; init; } = string.Empty;
        public OutcomeStatusSnapshot OutcomeStatus { get; init; } = new(global::IspAudit.Bypass.OutcomeStatus.Unknown, "UNKNOWN", "нет данных");
    }

    public sealed record BypassApplyContribution
    {
        public string Kind { get; init; } = string.Empty;
        public string Key { get; init; } = string.Empty;
        public string Value { get; init; } = string.Empty;
        public string Details { get; init; } = string.Empty;

        public static BypassApplyContribution Create(string kind, string key, string value, string details = "")
            => new()
            {
                Kind = kind ?? string.Empty,
                Key = key ?? string.Empty,
                Value = value ?? string.Empty,
                Details = details ?? string.Empty
            };
    }
}
