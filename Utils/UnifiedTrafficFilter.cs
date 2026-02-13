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

        private readonly NoiseHostFilter _noiseHostFilter;

        public UnifiedTrafficFilter()
            : this(NoiseHostFilter.Instance)
        {
        }

        public UnifiedTrafficFilter(NoiseHostFilter noiseHostFilter)
        {
            _noiseHostFilter = noiseHostFilter ?? throw new ArgumentNullException(nameof(noiseHostFilter));
        }

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
                if (!string.IsNullOrEmpty(bestName) && _noiseHostFilter.IsNoiseHost(bestName))
                {
                    return new FilterDecision(FilterAction.Drop, "Noise host (post-check, OK)");
                }
                return new FilterDecision(FilterAction.LogOnly, "Status OK");
            }

            // 2.1 Intel: не считаем проблемой ситуацию, когда тесты формально OK (DNS/TCP/TLS ✓),
            // а в хвосте только «неуверенный» диагноз/недостаточно данных.
            // Иначе UI превращается в «всё красное», хотя фактических отказов нет.
            if (result.BypassStrategy == PipelineContract.BypassNone
                && result.TestResult.DnsOk
                && result.TestResult.TcpOk
                && result.TestResult.TlsOk)
            {
                var tail = result.RecommendedAction ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(tail)
                    && (tail.Contains("intel:", StringComparison.OrdinalIgnoreCase)
                        || tail.Contains("[INTEL]", StringComparison.OrdinalIgnoreCase)
                        ))
                {
                    // Для шумовых имён — дропаем, для остальных — логируем без карточки.
                    if (!string.IsNullOrEmpty(bestName) && _noiseHostFilter.IsNoiseHost(bestName))
                    {
                        return new FilterDecision(FilterAction.Drop, "Noise host (post-check, intel tail, OK)");
                    }
                    return new FilterDecision(FilterAction.LogOnly, "Intel tail, but checks OK");
                }
            }

            // 3. Всё остальное (блокировки, ошибки, закрытые порты) показываем
            return new FilterDecision(FilterAction.Process, "Issue detected");
        }

        public bool IsNoise(string? hostname)
        {
            return _noiseHostFilter.IsNoiseHost(hostname);
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
