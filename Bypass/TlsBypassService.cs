using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Core.Models;

using Timer = System.Timers.Timer;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Сервис управления TLS bypass (фрагментация/дезорганизация/FAKE) без привязки к UI.
    /// Отвечает за применение профиля, сбор метрик и вычисление вердикта.
    /// </summary>
    public partial class TlsBypassService : IDisposable
    {
        private readonly TrafficEngine _trafficEngine;
        private readonly BypassProfile _baseProfile;
        private readonly Action<string>? _log;
        private readonly Func<DateTime> _now;
        private readonly bool _useTrafficEngine;
        private readonly object _sync = new();
        private readonly Timer _metricsTimer;

        private BypassFilter? _filter;
        private TlsBypassOptions _options;
        private DateTime _metricsSince = DateTime.MinValue;
        private readonly AggressiveAutoAdjustStrategy _autoAdjust;
        private readonly AutoTtlAdjustStrategy _autoTtl;
        private readonly IReadOnlyList<TlsFragmentPreset> _presets;

        // Селективный QUIC fallback (DROP UDP/443): observed IPv4 адреса (dst ip) текущей цели.
        // Хранится в сервисе, чтобы переживать пересоздание фильтра при Apply.
        private uint[] _udp443DropTargetIps = Array.Empty<uint>();

        // Policy-driven execution plane (P0.2 Stage 1): snapshot decision graph для runtime lookup.
        // Хранится в сервисе, чтобы переживать пересоздание фильтра при Apply.
        private DecisionGraphSnapshot? _decisionGraphSnapshot;

        public event Action<TlsBypassMetrics>? MetricsUpdated;
        public event Action<TlsBypassVerdict>? VerdictChanged;
        public event Action<TlsBypassState>? StateChanged;

        public IReadOnlyList<TlsFragmentPreset> FragmentPresets => _presets;

        /// <summary>
        /// Внутренний доступ для BypassStateManager (smoke/тестовый путь).
        /// </summary>
        internal TrafficEngine TrafficEngineForManager => _trafficEngine;

        public TlsBypassService(TrafficEngine trafficEngine, BypassProfile baseProfile, Action<string>? log = null)
            : this(trafficEngine, baseProfile, log, startMetricsTimer: true, useTrafficEngine: true, nowProvider: null)
        {
        }

        internal TlsBypassService(TrafficEngine trafficEngine, BypassProfile baseProfile, Action<string>? log, bool startMetricsTimer)
            : this(trafficEngine, baseProfile, log, startMetricsTimer, useTrafficEngine: true, nowProvider: null)
        {
        }

        internal TlsBypassService(
            TrafficEngine trafficEngine,
            BypassProfile baseProfile,
            Action<string>? log,
            bool startMetricsTimer,
            bool useTrafficEngine,
            Func<DateTime>? nowProvider)
        {
            _trafficEngine = trafficEngine;
            _baseProfile = baseProfile;
            _log = log;
            _useTrafficEngine = useTrafficEngine;
            _now = nowProvider ?? (() => DateTime.Now);
            _options = TlsBypassOptions.CreateDefault(_baseProfile);
            _presets = BuildPresets(_baseProfile);
            _autoAdjust = new AggressiveAutoAdjustStrategy(_now);
            _autoTtl = new AutoTtlAdjustStrategy(_log, _now);

            _metricsTimer = new Timer
            {
                AutoReset = true,
                Interval = 2000
            };
            _metricsTimer.Elapsed += (_, _) => _ = PullMetricsAsync();
            if (startMetricsTimer)
            {
                _metricsTimer.Start();
            }
        }

        public void Dispose()
        {
            _metricsTimer.Stop();
            _metricsTimer.Dispose();
        }
    }
}
