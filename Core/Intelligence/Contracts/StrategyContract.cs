using System;
using System.Collections.Generic;

namespace IspAudit.Core.Intelligence.Contracts;

/// <summary>
/// Уровень риска стратегии. Используется только для фильтрации/ранжирования.
/// </summary>
public enum RiskLevel
{
    Low,
    Medium,
    High,
}

/// <summary>
/// Ограничения и пороги контракта стратегий INTEL.
/// </summary>
public static class StrategyContractConstraints
{
    /// <summary>
    /// Контрактное правило: стратегии с <see cref="RiskLevel.High"/> запрещено рекомендовать,
    /// если уверенность диагноза <c>&lt; 70</c>.
    /// Фильтрация должна выполняться в StrategySelector.
    /// </summary>
    public const int MinConfidenceForHighRiskStrategies = 70;
}

/// <summary>
/// Описание одной рекомендуемой стратегии (без привязки к реальному исполнению байпаса).
/// </summary>
public sealed class BypassStrategy
{
    /// <summary>
    /// Идентификатор стратегии.
    /// </summary>
    public required StrategyId Id { get; init; }

    /// <summary>
    /// Базовый приоритет из таблицы маппинга (чем выше, тем раньше пробовать).
    /// </summary>
    public int BasePriority { get; init; }

    /// <summary>
    /// Параметры стратегии (ключ → значение). В контракте допускаются произвольные параметры.
    /// </summary>
    public Dictionary<string, object?> Parameters { get; init; } = new();

    /// <summary>
    /// Уровень риска.
    /// </summary>
    public RiskLevel Risk { get; init; }
}

/// <summary>
/// Отложенная рекомендация: стратегия известна, но пока не может быть применена автоматически
/// (нет реализации, есть блокер на уровне движка или требуется ручная настройка).
/// </summary>
public sealed class DeferredBypassStrategy
{
    /// <summary>
    /// Идентификатор стратегии.
    /// </summary>
    public required StrategyId Id { get; init; }

    /// <summary>
    /// Почему стратегия отложена.
    /// </summary>
    public string Reason { get; init; } = string.Empty;

    /// <summary>
    /// Уровень риска (для UI/сортировки). На исполнение не влияет.
    /// </summary>
    public RiskLevel Risk { get; init; }
}

/// <summary>
/// План рекомендаций (список стратегий), сформированный на основе диагноза.
/// </summary>
public sealed class BypassPlan
{
    /// <summary>
    /// Список стратегий в порядке применения/проб.
    /// </summary>
    public List<BypassStrategy> Strategies { get; init; } = new();

    /// <summary>
    /// Список отложенных стратегий (не применяется автоматически в текущем MVP).
    /// Используется для UI/логов и как «вектор» будущих улучшений.
    /// </summary>
    public List<DeferredBypassStrategy> DeferredStrategies { get; init; } = new();

    /// <summary>
    /// Для какого диагноза построен план.
    /// </summary>
    public DiagnosisId ForDiagnosis { get; init; }

    /// <summary>
    /// Итоговая уверенность плана (как правило, равна уверенности диагноза после фильтраций).
    /// </summary>
    public int PlanConfidence { get; init; }

    /// <summary>
    /// Короткое объяснение, почему выбран такой план (для UI/логов).
    /// </summary>
    public string Reasoning { get; init; } = string.Empty;

    /// <summary>
    /// (Assist) Рекомендовать QUIC fallback: подавлять UDP/443, чтобы клиент откатился на TCP/HTTPS.
    /// </summary>
    public bool DropUdp443 { get; init; }

    /// <summary>
    /// (Assist) Рекомендовать разрешить обход даже при отсутствии распознанного SNI.
    /// Полезно при ECH/ESNI или если SNI не удаётся извлечь в текущем окружении.
    /// </summary>
    public bool AllowNoSni { get; init; }

    /// <summary>
    /// Время формирования плана (UTC).
    /// </summary>
    public DateTimeOffset PlannedAtUtc { get; init; }
}
