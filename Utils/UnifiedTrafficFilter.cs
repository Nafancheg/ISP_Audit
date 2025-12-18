using System;
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
        // Уровень-2 дедупликации отключён намеренно.
        // Дедупликация на уровне цели выполняется в TrafficCollector по ключу RemoteIp:RemotePort:Protocol.

        public FilterDecision ShouldTest(HostDiscovered host, string? knownHostname = null)
        {
            // 0. Loopback — почти всегда шум для ISP-диагностики
            if (System.Net.IPAddress.IsLoopback(host.RemoteIp))
            {
                return new FilterDecision(FilterAction.Drop, "Loopback");
            }

            // 2. Дедупликация на уровне цели отключена.
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
            // Уровень-2 дедупликации отключён — инвалидировать нечего.
        }

        public void Reset()
        {
            // Уровень-2 дедупликации отключён — сбрасывать нечего.
        }
    }
}
