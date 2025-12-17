namespace IspAudit.Core.IntelligenceV2.Contracts;

/// <summary>
/// Идентификатор стратегии обхода (логический). Контракт не привязан к реализации байпаса.
/// </summary>
public enum StrategyId
{
    None,

    TlsDisorder,
    TlsFragment,
    TlsFakeTtl,

    DropRst,

    /// <summary>
    /// Будущая стратегия. В MVP НЕ добавлять в маппинг (реализация может отсутствовать).
    /// </summary>
    UseDoh,

    AggressiveFragment,
}
