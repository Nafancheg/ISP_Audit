namespace IspAudit.Core.Intelligence.Contracts;

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

    // Phase 3 техники: реализованы в рантайме и применяются через BypassApplyService/BypassFilter.
    HttpHostTricks,
    QuicObfuscation,
    BadChecksum,

    /// <summary>
    /// Будущая стратегия. В MVP НЕ добавлять в маппинг (реализация может отсутствовать).
    /// </summary>
    UseDoh,

    AggressiveFragment,
}
