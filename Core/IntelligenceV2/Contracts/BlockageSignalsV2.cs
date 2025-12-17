using System;

namespace IspAudit.Core.IntelligenceV2.Contracts;

/// <summary>
/// Агрегированный срез сигналов v2 по окну времени поверх <see cref="SignalSequence"/>.
/// Используется DiagnosisEngine и не содержит параметров стратегий/обхода.
/// </summary>
public sealed class BlockageSignalsV2
{
    /// <summary>
    /// Ключ хоста, для которого построен срез.
    /// </summary>
    public required string HostKey { get; init; }

    /// <summary>
    /// Время построения среза (UTC).
    /// </summary>
    public DateTimeOffset CapturedAtUtc { get; init; }

    /// <summary>
    /// Окно агрегации, по которому построен срез.
    /// Контракт: типовые значения — 30/60 секунд (см. <see cref="IntelligenceV2ContractDefaults"/>).
    /// </summary>
    public TimeSpan AggregationWindow { get; init; }

    // TCP уровень

    /// <summary>
    /// Наблюдался TCP RST в окне агрегации.
    /// </summary>
    public bool HasTcpReset { get; init; }

    /// <summary>
    /// Наблюдался TCP timeout (например, connect timeout) в окне агрегации.
    /// </summary>
    public bool HasTcpTimeout { get; init; }

    /// <summary>
    /// Доля ретрансмиссий TCP (0..1). <see langword="null"/> означает, что данных недостаточно.
    /// </summary>
    public double? RetransmissionRate { get; init; }

    // RST анализ

    /// <summary>
    /// Аномалия TTL для RST (дельта относительно ожидаемого). <see langword="null"/>, если RST не наблюдался.
    /// </summary>
    public int? RstTtlDelta { get; init; }

    /// <summary>
    /// Латентность до RST. <see langword="null"/>, если RST не наблюдался.
    /// </summary>
    public TimeSpan? RstLatency { get; init; }

    // DNS уровень

    /// <summary>
    /// Есть признаки проблем резолва DNS.
    /// </summary>
    public bool HasDnsFailure { get; init; }

    /// <summary>
    /// Подозрение на "fake IP" (например, диапазон 198.18.x.x). В MVP допускается как флаг.
    /// </summary>
    public bool HasFakeIp { get; init; }

    // HTTP уровень

    /// <summary>
    /// Наблюдался подозрительный HTTP редирект/заглушка.
    /// </summary>
    public bool HasHttpRedirect { get; init; }

    // TLS уровень

    /// <summary>
    /// Наблюдался TLS timeout.
    /// </summary>
    public bool HasTlsTimeout { get; init; }

    /// <summary>
    /// Наблюдался TLS reset.
    /// </summary>
    public bool HasTlsReset { get; init; }

    // Метаданные/качество

    /// <summary>
    /// Кол-во событий, попавших в окно (после фильтрации по HostKey и окну).
    /// </summary>
    public int SampleSize { get; init; }

    /// <summary>
    /// Служебный флаг качества данных (например: мало событий, флапающие признаки, неизвестные источники).
    /// </summary>
    public bool IsUnreliable { get; init; }
}
