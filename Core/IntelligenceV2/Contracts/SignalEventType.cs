using System;

namespace IspAudit.Core.IntelligenceV2.Contracts;

/// <summary>
/// Тип события (факта) в потоке сигналов v2.
/// Это часть контракта: значения должны быть стабильны, т.к. на них завязаны адаптер и агрегация.
/// </summary>
public enum SignalEventType
{
    /// <summary>
    /// Факт завершения активной проверки хоста (DNS/TCP/TLS) в <c>StandardHostTester</c>.
    /// </summary>
    HostTested,

    /// <summary>
    /// Обновление статистики ретрансмиссий TCP.
    /// </summary>
    TcpRetransStats,

    /// <summary>
    /// Наблюдение подозрительного TCP RST (например, на уровне инспектора/перехвата).
    /// </summary>
    SuspiciousRstObserved,

    /// <summary>
    /// Наблюдение DPI-подобного HTTP редиректа/заглушки.
    /// </summary>
    HttpRedirectObserved,

    /// <summary>
    /// (Опционально) UDP "рукопожатие" без ответа.
    /// </summary>
    UdpHandshakeUnanswered,
}
