using System;
using System.Collections.Generic;

namespace IspAudit.Core.IntelligenceV2.Contracts;

/// <summary>
/// Идентификатор диагноза v2.
/// </summary>
public enum DiagnosisId
{
    /// <summary>
    /// Техническое значение по умолчанию (например, до вызова Diagnose). Diagnose не должен возвращать его как результат.
    /// </summary>
    None,

    /// <summary>
    /// Недостаточно данных / не сработало ни одно правило.
    /// </summary>
    Unknown,

    /// <summary>
    /// Быстрый RST с TTL-аномалией.
    /// </summary>
    ActiveDpiEdge,

    /// <summary>
    /// Медленный RST, stateful-инспекция.
    /// </summary>
    StatefulDpi,

    /// <summary>
    /// Timeout + высокая доля ретрансмиссий.
    /// </summary>
    SilentDrop,

    /// <summary>
    /// DNS подмена/перехват.
    /// </summary>
    DnsHijack,

    /// <summary>
    /// HTTP заглушка/редирект.
    /// </summary>
    HttpRedirect,

    /// <summary>
    /// DNS + DPI одновременно.
    /// </summary>
    MultiLayerBlock,

    /// <summary>
    /// Проблема на уровне TLS рукопожатия (timeout/auth failure/reset) без достаточных дополнительных улик.
    /// Это не доказательство DPI, но практический сигнал «TLS-обход может помочь».
    /// </summary>
    TlsInterference,

    /// <summary>
    /// Легитимная недоступность (не блокировка).
    /// </summary>
    NoBlockage,
}

/// <summary>
/// Результат интерпретации <see cref="BlockageSignalsV2"/>.
/// </summary>
public sealed class DiagnosisResult
{
    /// <summary>
    /// Идентификатор диагноза.
    /// </summary>
    public required DiagnosisId DiagnosisId { get; init; }

    /// <summary>
    /// Уверенность (0..100).
    /// </summary>
    public required int Confidence { get; init; }

    /// <summary>
    /// Какое правило/эвристика сработало (опционально, но желательно заполнять).
    /// </summary>
    public string? MatchedRuleName { get; init; }

    /// <summary>
    /// Короткие пояснения (строки для UI/лога). Должны ссылаться на наблюдаемые факты.
    /// </summary>
    public IReadOnlyList<string> ExplanationNotes { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Минимальные улики/факты (ключ → значение). Используется для отладки и QA.
    /// </summary>
    public IReadOnlyDictionary<string, string> Evidence { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// Входные сигналы, по которым был поставлен диагноз.
    /// </summary>
    public required BlockageSignalsV2 InputSignals { get; init; }

    /// <summary>
    /// Время постановки диагноза (UTC).
    /// </summary>
    public DateTimeOffset DiagnosedAtUtc { get; init; }
}
