using System;
using IspAudit.Utils;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
        private static readonly TimeSpan ActivationDefaultWarmup = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan ActivationDefaultNoTraffic = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan ActivationDefaultStale = TimeSpan.FromSeconds(120);

        public ActivationStatusSnapshot GetActivationStatusSnapshot()
        {
            var options = _tlsService.GetOptionsSnapshot();
            if (!options.IsAnyEnabled())
            {
                return new ActivationStatusSnapshot(ActivationStatus.Unknown, "BYPASS OFF", "bypass отключён");
            }

            var nowUtc = DateTime.UtcNow;

            var engineGraceMs = ReadMsEnvAllowZero(EnvKeys.ActivationEngineGraceMs, (int)ActivationDefaultWarmup.TotalMilliseconds);
            var warmupMs = ReadMsEnvAllowZero(EnvKeys.ActivationWarmupMs, (int)ActivationDefaultWarmup.TotalMilliseconds);
            var noTrafficMs = ReadMsEnvAllowZero(EnvKeys.ActivationNoTrafficMs, (int)ActivationDefaultNoTraffic.TotalMilliseconds);
            var staleMs = ReadMsEnvAllowZero(EnvKeys.ActivationStaleMs, (int)ActivationDefaultStale.TotalMilliseconds);

            var engineGrace = TimeSpan.FromMilliseconds(engineGraceMs);
            var warmup = TimeSpan.FromMilliseconds(warmupMs);
            var noTraffic = TimeSpan.FromMilliseconds(noTrafficMs);
            var stale = TimeSpan.FromMilliseconds(staleMs);

            // ENGINE_DEAD: движок не запущен после grace.
            if (!_trafficEngine.IsRunning && _lastEngineNotRunningUtc != DateTime.MinValue && (nowUtc - _lastEngineNotRunningUtc) >= engineGrace)
            {
                return new ActivationStatusSnapshot(ActivationStatus.EngineDead, "ENGINE_DEAD", "TrafficEngine не запущен");
            }

            // Если метрики не обновлялись слишком долго — считаем, что движок/фильтр не жив.
            if (_lastMetricsSnapshotUtc != DateTime.MinValue && (nowUtc - _lastMetricsSnapshotUtc) >= stale)
            {
                return new ActivationStatusSnapshot(ActivationStatus.EngineDead, "ENGINE_DEAD", $"нет обновлений метрик {(nowUtc - _lastMetricsSnapshotUtc).TotalSeconds:F0}с");
            }

            var metrics = _lastMetricsSnapshot;
            if (metrics == null)
            {
                return new ActivationStatusSnapshot(ActivationStatus.Unknown, "UNKNOWN", "нет снимка метрик");
            }

            // NO_TRAFFIC: пользователь не генерирует релевантный трафик (TLS@443).
            if (metrics.ClientHellosObserved == 0)
            {
                if (_lastBypassActivatedUtc != DateTime.MinValue && (nowUtc - _lastBypassActivatedUtc) >= noTraffic)
                {
                    return new ActivationStatusSnapshot(ActivationStatus.NoTraffic, "NO_TRAFFIC", "нет ClientHello@443 — откройте HTTPS/игру");
                }

                return new ActivationStatusSnapshot(ActivationStatus.Unknown, "UNKNOWN", "нет TLS@443 (ожидание трафика)");
            }

            // ACTIVATED: видим любые признаки работы фильтра на релевантном трафике.
            var hasEffect =
                metrics.TlsHandled > 0 ||
                metrics.ClientHellosFragmented > 0 ||
                metrics.Udp443Dropped > 0 ||
                metrics.RstDroppedRelevant > 0 ||
                metrics.RstDropped > 0;

            if (hasEffect)
            {
                return new ActivationStatusSnapshot(ActivationStatus.Activated, "ACTIVATED",
                    $"tlsHandled={metrics.TlsHandled}, fragmented={metrics.ClientHellosFragmented}, udp443Drop={metrics.Udp443Dropped}, rst443={metrics.RstDroppedRelevant}");
            }

            // NOT_ACTIVATED: трафик есть, но эффекта нет после warmup.
            if (_lastBypassActivatedUtc != DateTime.MinValue && (nowUtc - _lastBypassActivatedUtc) >= warmup)
            {
                return new ActivationStatusSnapshot(ActivationStatus.NotActivated, "NOT_ACTIVATED", "трафик есть, но нет эффекта по метрикам");
            }

            return new ActivationStatusSnapshot(ActivationStatus.Unknown, "UNKNOWN", "ожидание эффекта (warmup)");
        }

        internal void SetMetricsSnapshotForSmoke(TlsBypassMetrics metrics, DateTime? atUtc = null)
        {
            _lastMetricsSnapshot = metrics;
            _lastMetricsSnapshotUtc = atUtc ?? DateTime.UtcNow;
        }
    }
}
