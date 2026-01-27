using System;
using System.Collections.Generic;

namespace IspAudit.Core.Intelligence.Contracts;

/// <summary>
/// Общие константы контракта DPI Intelligence.
/// Важно: это именно контракт. Значения фиксированы и используются всеми слоями INTEL.
/// </summary>
public static class IntelligenceContractDefaults
{
    /// <summary>
    /// TTL для событий в <see cref="SignalSequence"/>.
    /// События старше этого времени должны удаляться при <c>Append(...)</c> в сторе.
    /// </summary>
    public const int EventTtlMinutes = 10;

    /// <summary>
    /// Окно агрегации по умолчанию для построения <c>BlockageSignals</c>.
    /// </summary>
    public const int DefaultAggregationWindowSeconds = 30;

    /// <summary>
    /// Расширенное окно агрегации (для потенциально "медленных" сценариев).
    /// </summary>
    public const int ExtendedAggregationWindowSeconds = 60;

    /// <summary>
    /// TTL событий в виде <see cref="TimeSpan"/>.
    /// </summary>
    public static TimeSpan EventTtl => TimeSpan.FromMinutes(EventTtlMinutes);

    /// <summary>
    /// Окно агрегации по умолчанию в виде <see cref="TimeSpan"/>.
    /// </summary>
    public static TimeSpan DefaultAggregationWindow => TimeSpan.FromSeconds(DefaultAggregationWindowSeconds);

    /// <summary>
    /// Расширенное окно агрегации в виде <see cref="TimeSpan"/>.
    /// </summary>
    public static TimeSpan ExtendedAggregationWindow => TimeSpan.FromSeconds(ExtendedAggregationWindowSeconds);
}

/// <summary>
/// Событие (факт) в потоке сигналов INTEL.
/// Это «сырой» слой фактов: без интерпретации, диагнозов и стратегий.
/// </summary>
public sealed class SignalEvent
{
    /// <summary>
    /// Стабильный технический ключ хоста (например IP:Port:Proto).
    /// Примечание: это не UI-лейбл; человеко‑понятное имя (SNI/hostname) передаётся отдельно.
    /// Контракт: значение должно быть непустым.
    /// </summary>
    public required string HostKey { get; init; }

    /// <summary>
    /// Тип события.
    /// </summary>
    public required SignalEventType Type { get; init; }

    /// <summary>
    /// Наблюдаемое значение (произвольный payload). Может быть <see langword="null"/>.
    /// Примечание: контракт не навязывает конкретные типы payload в MVP.
    /// </summary>
    public object? Value { get; init; }

    /// <summary>
    /// Время наблюдения события (UTC).
    /// </summary>
    public required DateTimeOffset ObservedAtUtc { get; init; }

    /// <summary>
    /// Источник события (например: "HostTester", "TcpRetransmissionTracker").
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Короткое пояснение/причина (опционально).
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Доп. метаданные (опционально). Используется только для логирования/диагностики.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}

/// <summary>
/// Последовательность сигналов (временная цепочка фактов) для конкретного <see cref="HostKey"/>.
/// </summary>
public sealed class SignalSequence
{
    /// <summary>
    /// Ключ хоста. Контракт: значение должно быть непустым.
    /// </summary>
    public required string HostKey { get; init; }

    /// <summary>
    /// Список событий. Наполняется адаптером/стором; очистка по TTL выполняется при Append.
    /// </summary>
    public List<SignalEvent> Events { get; } = new();

    /// <summary>
    /// Когда хост впервые появился в сторе (UTC).
    /// </summary>
    public required DateTimeOffset FirstSeenUtc { get; init; }

    /// <summary>
    /// Когда последовательность в последний раз обновлялась (UTC).
    /// </summary>
    public DateTimeOffset LastUpdatedUtc { get; set; }
}
