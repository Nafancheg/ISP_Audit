using System;
using IspAudit.Core.Models;

namespace IspAudit.Core.Interfaces
{
    /// <summary>
    /// Хранилище состояния блокировок per-host.
    /// Задача: аккумулировать результаты тестов и предоставлять статистику и агрегированные сигналы за окно времени.
    /// </summary>
    public interface IBlockageStateStore
    {
        /// <summary>
        /// Зарегистрировать результат теста для последующей агрегации.
        /// </summary>
        void RegisterResult(HostTested tested);

        /// <summary>
        /// Получить статистику фейлов для хоста за указанное окно.
        /// Ключ формируется на уровне реализации (обычно IP:port или hostname:port).
        /// </summary>
        FailWindowStats GetFailStats(HostTested tested, TimeSpan window);

        /// <summary>
        /// Получить агрегированные сигналы блокировок для хоста за указанное окно.
        /// Базовая реализация может быть тонкой оболочкой над FailWindowStats.
        /// </summary>
        BlockageSignals GetSignals(HostTested tested, TimeSpan window);
    }
}

