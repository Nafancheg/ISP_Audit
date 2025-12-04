using System;
using System.Collections.Generic;
using IspAudit.Core.Models;

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Состояние блокировок для конкретного хоста (IP+порт/hostname) во времени.
    /// Используется только для агрегирования статистики фейлов (fail counter + time window).
    /// </summary>
    public sealed class HostBlockageState
    {
        private readonly List<FailureEvent> _events = new();

        public HostBlockageState(string key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>
        /// Уникальный ключ хоста (обычно IP:port или hostname:port).
        /// </summary>
        public string Key { get; }

        /// <summary>
        /// Зарегистрировать новый результат теста.
        /// </summary>
        public void Register(HostTested tested)
        {
            if (tested == null) throw new ArgumentNullException(nameof(tested));

            var isFail = !tested.DnsOk || !tested.TcpOk || !tested.TlsOk;
            if (!isFail)
            {
                _events.Add(new FailureEvent(tested.TestedAt, tested.BlockageType, false));
                return;
            }

            _events.Add(new FailureEvent(tested.TestedAt, tested.BlockageType, true));
        }

        /// <summary>
        /// Вернуть агрегированную статистику за указанное окно времени.
        /// </summary>
        public FailWindowStats GetStats(TimeSpan window)
        {
            var now = DateTime.UtcNow;
            var threshold = now - window;

            int total = 0;
            int hard = 0;
            DateTime? lastFailAt = null;

            for (int i = _events.Count - 1; i >= 0; i--)
            {
                var ev = _events[i];
                if (ev.TimestampUtc < threshold)
                {
                    break;
                }

                if (ev.IsFail)
                {
                    total++;
                    hard++;
                    lastFailAt ??= ev.TimestampUtc;
                }
            }

            return new FailWindowStats(total, hard, lastFailAt, window);
        }

        private readonly record struct FailureEvent(DateTime TimestampUtc, string? BlockageType, bool IsFail);
    }

    /// <summary>
    /// Агрегированная статистика фейлов за окно времени.
    /// </summary>
    public readonly record struct FailWindowStats(int FailCount, int HardFailCount, DateTime? LastFailAt, TimeSpan Window);
}
