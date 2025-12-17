using System;
using System.Collections.Concurrent;
using IspAudit.Core.Diagnostics;
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
            // 0. Loopback — почти всегда шум для ISP-диагностики
            if (System.Net.IPAddress.IsLoopback(host.RemoteIp))
            {
                return new FilterDecision(FilterAction.Drop, "Loopback");
            }

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
            // 1. Проверка на шум.
            // Важно: не скрываем проблемы/блокировки только из-за шумового rDNS.
            // Поэтому шум используем только для «успешных»/непроблемных результатов.
            var bestName =
                result.TestResult.SniHostname ??
                result.TestResult.Hostname ??
                result.TestResult.ReverseDnsHostname;

            // 2. Логика отображения в UI
            // Если стратегии нет и статус OK - это успешный тест, не засоряем UI карточками
            if (result.BypassStrategy == PipelineContract.BypassNone && result.RecommendedAction == BlockageCode.StatusOk)
            {
                if (!string.IsNullOrEmpty(bestName) && NoiseHostFilter.Instance.IsNoiseHost(bestName))
                {
                    return new FilterDecision(FilterAction.Drop, "Noise host (post-check, OK)");
                }
                return new FilterDecision(FilterAction.LogOnly, "Status OK");
            }

            // 3. Всё остальное (блокировки, ошибки, закрытые порты) показываем
            return new FilterDecision(FilterAction.Process, "Issue detected");
        }

        public bool IsNoise(string? hostname)
        {
            return NoiseHostFilter.Instance.IsNoiseHost(hostname);
        }

        public void Invalidate(string ip)
        {
            // Удаляем ключи, связанные с этим IP
            // Так как мы не знаем порт, удаляем все ключи, содержащие этот IP
            // Это не очень эффективно, но редко вызывается
            var keysToRemove = new System.Collections.Generic.List<string>();
            foreach (var key in _testedKeys.Keys)
            {
                if (key.Contains(ip))
                {
                    keysToRemove.Add(key);
                }
            }

            foreach (var key in keysToRemove)
            {
                _testedKeys.TryRemove(key, out _);
            }
        }

        public void Reset()
        {
            _testedKeys.Clear();
        }
    }
}
