using System;

namespace IspAudit.Core.Intelligence.Contracts;

/// <summary>
/// Агрегированный срез сигналов INTEL по окну времени поверх <see cref="SignalSequence"/>.
/// Используется DiagnosisEngine и не содержит параметров стратегий/обхода.
/// </summary>
public sealed class BlockageSignals
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
    /// Контракт: типовые значения — 30/60 секунд (см. <see cref="IntelligenceContractDefaults"/>).
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
    /// Аномалия IPv4 Identification (IPID) для RST (оценка дельты относительно «обычного» диапазона/последнего).
    /// <see langword="null"/> означает, что данных нет или строка инспектора не содержит IPID.
    /// </summary>
    public int? RstIpIdDelta { get; init; }

    /// <summary>
    /// Количество событий «подозрительный RST» в окне.
    /// Используется как признак устойчивости улик (чтобы не ставить уверенный DPI-диагноз по единичному событию).
    /// </summary>
    public int SuspiciousRstCount { get; init; }

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

    /// <summary>
    /// Целевой хост HTTP редиректа (из Location), если удалось извлечь.
    /// Может быть полезен для различения заглушки провайдера и «обычного» редиректа (captive portal/роутер).
    /// </summary>
    public string? RedirectToHost { get; init; }

    // UDP/QUIC уровень

    /// <summary>
    /// Количество безответных UDP рукопожатий (DTLS/QUIC) в окне.
    /// Используется для рекомендаций QUIC fallback (DropUdp443).
    /// </summary>
    public int UdpUnansweredHandshakes { get; init; }

    // HTTP/3 (QUIC) уровень (из HostTested)

    /// <summary>
    /// Количество попыток HTTP/3 (QUIC) в окне.
    /// </summary>
    public int Http3AttemptCount { get; init; }

    /// <summary>
    /// Количество успешных HTTP/3 (QUIC) попыток в окне.
    /// </summary>
    public int Http3SuccessCount { get; init; }

    /// <summary>
    /// Количество неуспешных HTTP/3 (QUIC) попыток (ошибка/исключение) в окне.
    /// </summary>
    public int Http3FailureCount { get; init; }

    /// <summary>
    /// Количество таймаутов HTTP/3 (QUIC) в окне.
    /// </summary>
    public int Http3TimeoutCount { get; init; }

    /// <summary>
    /// Количество попыток, которые завершились "не поддерживается" (платформа/рантайм без HTTP/3).
    /// Это не признак блокировки провайдера.
    /// </summary>
    public int Http3NotSupportedCount { get; init; }

    // SNI/качество имени (из HostTested)

    /// <summary>
    /// Количество событий HostTested в окне агрегации.
    /// </summary>
    public int HostTestedCount { get; init; }

    /// <summary>
    /// Количество HostTested без SNI (пусто/не извлечено).
    /// </summary>
    public int HostTestedNoSniCount { get; init; }

    /// <summary>
    /// Количество HostTested с структурированным VerdictStatus=Unknown в окне.
    /// </summary>
    public int HostVerdictUnknownCount { get; init; }

    /// <summary>
    /// Последний ненулевой UnknownReason из HostTested в окне (best-effort).
    /// </summary>
    public string? LastUnknownReason { get; init; }

    // TLS уровень

    /// <summary>
    /// Наблюдался TLS timeout.
    /// </summary>
    public bool HasTlsTimeout { get; init; }

    /// <summary>
    /// Наблюдался TLS auth failure (например, TLS handshake завершился ошибкой аутентификации).
    /// Важно: это наблюдаемый факт, а не доказательство DPI.
    /// </summary>
    public bool HasTlsAuthFailure { get; init; }

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
