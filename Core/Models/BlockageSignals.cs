using System;

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Агрегированные сигналы блокировок для конкретного хоста за окно времени.
    /// Это тонкий слой над низкоуровневой статистикой (фейлы, таймауты и т.п.).
    /// </summary>
    public readonly record struct BlockageSignals(
        /// <summary>
        /// Общее количество неуспешных попыток за окно.
        /// </summary>
        int FailCount,

        /// <summary>
        /// Количество "жёстких" фейлов (таймауты, RST, TLS-ошибки и т.п.).
        /// </summary>
        int HardFailCount,

        /// <summary>
        /// Время последнего фейла, если был.
        /// </summary>
        DateTime? LastFailAt,

        /// <summary>
        /// Длина окна, за которое агрегируются сигналы.
        /// </summary>
        TimeSpan Window,

        /// <summary>
        /// Оценка количества TCP-ретрансмиссий для хоста за окно.
        /// Может быть получена из внешнего TcpRetransmissionTracker.
        /// </summary>
        int RetransmissionCount,

        /// <summary>
        /// Был ли замечен HTTP-редирект, подозрительный на DPI.
        /// </summary>
        bool HasHttpRedirectDpi,

        /// <summary>
        /// Целевой хост HTTP-редиректа (если обнаружен).
        /// </summary>
        string? RedirectToHost,

        /// <summary>
        /// Обнаружен ли подозрительный RST пакет (с аномальным TTL).
        /// </summary>
        bool HasSuspiciousRst,

        /// <summary>
        /// Детали подозрительного RST (например, "TTL=64 (expected 50-55)").
        /// </summary>
        string? SuspiciousRstDetails,

        /// <summary>
        /// Количество безответных UDP рукопожатий (DTLS/QUIC).
        /// </summary>
        int UdpUnansweredHandshakes)
    {
        /// <summary>
        /// Есть ли фейлы вообще за окно.
        /// </summary>
        public bool HasFails => FailCount > 0;

        /// <summary>
        /// Есть ли жёсткие фейлы за окно.
        /// </summary>
        public bool HasHardFails => HardFailCount > 0;

        /// <summary>
        /// Есть ли существенные ретрансмиссии за окно.
        /// Порог сейчас примитивный и может быть уточнён.
        /// </summary>
        public bool HasSignificantRetransmissions => RetransmissionCount > 3;

        /// <summary>
        /// Есть ли подозрение на блокировку UDP (DTLS/QUIC).
        /// </summary>
        public bool HasUdpBlockage => UdpUnansweredHandshakes > 2;
    }
}
