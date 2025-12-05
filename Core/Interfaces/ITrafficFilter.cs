using IspAudit.Core.Models;

namespace IspAudit.Core.Interfaces
{
    public interface ITrafficFilter
    {
        /// <summary>
        /// Решает, нужно ли тестировать обнаруженный хост.
        /// Проверяет дедупликацию и "шумные" хосты.
        /// </summary>
        FilterDecision ShouldTest(HostDiscovered host, string? knownHostname = null);

        /// <summary>
        /// Решает, нужно ли показывать результат пользователю (отправлять в UI).
        /// Проверяет статус блокировки и настройки отображения.
        /// </summary>
        FilterDecision ShouldDisplay(HostBlocked result);

        /// <summary>
        /// Проверяет, является ли хост "шумным" (для генерации профилей).
        /// </summary>
        bool IsNoise(string? hostname);

        /// <summary>
        /// Сбрасывает состояние фильтра (кеш проверенных хостов).
        /// </summary>
        void Reset();

        /// <summary>
        /// Принудительно удаляет хост из кеша проверенных, позволяя протестировать его снова.
        /// </summary>
        void Invalidate(string ip);
    }
}
