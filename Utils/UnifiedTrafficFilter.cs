using System;
using System.Collections.Concurrent;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;

namespace IspAudit.Utils
{
    /// <summary>
    /// Единая точка принятия решений о фильтрации трафика.
    /// Объединяет логику дедупликации, фильтрации шума и правил отображения UI.
    /// </summary>
    public class UnifiedTrafficFilter : ITrafficFilter
    {
        private readonly ConcurrentDictionary<string, byte> _testedKeys = new();
        
        // Не кешируем Instance, так как он может быть пересоздан при Initialize
        // private readonly NoiseHostFilter _noiseFilter = NoiseHostFilter.Instance;

        public FilterDecision ShouldTest(HostDiscovered host, string? knownHostname = null)
        {
            // 1. Проверка на шум (если hostname известен)
            if (!string.IsNullOrEmpty(knownHostname) && NoiseHostFilter.Instance.IsNoiseHost(knownHostname))
            {
                return new FilterDecision(FilterAction.Drop, "Noise host (pre-check)");
            }

            // 2. Дедупликация
            // Если знаем hostname - дедуплицируем по нему (чтобы не тестировать 10 IP одного домена)
            // Если не знаем - дедуплицируем по IP:Port
            string key;
            if (!string.IsNullOrEmpty(knownHostname))
            {
                key = $"host:{knownHostname.ToLowerInvariant()}";
            }
            else
            {
                key = $"ip:{host.RemoteIp}:{host.RemotePort}";
            }

            if (!_testedKeys.TryAdd(key, 1))
            {
                return new FilterDecision(FilterAction.Drop, $"Duplicate ({key})");
            }

            return new FilterDecision(FilterAction.Process, "New target");
        }

        public FilterDecision ShouldDisplay(HostBlocked result)
        {
            // 1. Проверка на шум (теперь hostname точно известен после теста)
            var hostname = result.TestResult.Hostname;
            
            if (NoiseHostFilter.Instance.IsNoiseHost(hostname))
            {
                return new FilterDecision(FilterAction.Drop, "Noise host (post-check)");
            }

            // 2. Логика отображения в UI
            // Если стратегии нет и статус OK - это успешный тест, не засоряем UI карточками
            if (result.BypassStrategy == "NONE" && result.RecommendedAction == "OK")
            {
                return new FilterDecision(FilterAction.LogOnly, "Status OK");
            }

            // 3. Всё остальное (блокировки, ошибки, закрытые порты) показываем
            return new FilterDecision(FilterAction.Process, "Issue detected");
        }

        public bool IsNoise(string? hostname)
        {
            return NoiseHostFilter.Instance.IsNoiseHost(hostname);
        }

        public void Reset()
        {
            _testedKeys.Clear();
        }
    }
}
