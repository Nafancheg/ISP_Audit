using System;

namespace IspAudit.Core.IntelligenceV2.Feedback;

/// <summary>
/// Опции для feedback store и ранжирования.
/// </summary>
public sealed class FeedbackStoreOptions
{
    /// <summary>
    /// TTL записи (по LastUpdatedUtc). 0/отрицательное значение отключает TTL.
    /// </summary>
    public TimeSpan EntryTtl { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Максимальное число ключей (DiagnosisId + StrategyId). 0/отрицательное значение отключает лимит.
    /// </summary>
    public int MaxEntries { get; set; } = 512;

    /// <summary>
    /// Минимальное число наблюдений, после которого feedback начинает влиять на ранжирование.
    /// </summary>
    public int MinSamplesToAffectRanking { get; set; } = 5;

    /// <summary>
    /// Максимальный модуль бонуса к BasePriority (в обе стороны).
    /// Пример: 15 позволяет "перевернуть" разницу в 10 пунктов basePriority при устойчивом успехе.
    /// </summary>
    public int MaxPriorityBoostAbs { get; set; } = 15;
}
