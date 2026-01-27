using System;
using IspAudit.Core.Intelligence.Contracts;

namespace IspAudit.Core.Intelligence.Feedback;

/// <summary>
/// Исход одного применения стратегии (для обучения ранжирования).
/// </summary>
public enum StrategyOutcome
{
    Unknown = 0,
    Success = 1,
    Failure = 2,
}

/// <summary>
/// Ключ обратной связи: пара (диагноз + стратегия).
/// </summary>
public readonly record struct FeedbackKey(DiagnosisId DiagnosisId, StrategyId StrategyId);

/// <summary>
/// Накопленная статистика по паре (диагноз + стратегия).
/// </summary>
public sealed class StrategyFeedbackStats
{
    public int SuccessCount { get; set; }
    public int FailureCount { get; set; }
    public DateTimeOffset LastUpdatedUtc { get; set; }

    public int TotalCount => SuccessCount + FailureCount;

    public double SuccessRate => TotalCount <= 0 ? 0.0 : (double)SuccessCount / TotalCount;
}

/// <summary>
/// Хранилище обратной связи для ранжирования стратегий.
/// MVP: in-memory + (опционально) сохранение в файл.
/// </summary>
public interface IFeedbackStore
{
    bool TryGetStats(FeedbackKey key, out StrategyFeedbackStats stats);

    void Record(FeedbackKey key, StrategyOutcome outcome, DateTimeOffset observedAtUtc);

    /// <summary>
    /// Очистка по TTL и лимитам (выполняется без таймеров по инициативе вызывающего кода).
    /// </summary>
    void Prune(DateTimeOffset nowUtc);
}
