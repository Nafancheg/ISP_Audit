using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Traffic;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Внутренний guard: позволяет логировать попытки управлять bypass/TrafficEngine
    /// в обход единого менеджера состояния.
    /// </summary>
    internal static class BypassStateManagerGuard
    {
        internal static bool EnforceManagerUsage;

        private static readonly AsyncLocal<int> Depth = new();

        internal static bool IsInManagerScope => Depth.Value > 0;

        internal static IDisposable EnterScope()
        {
            Depth.Value = Depth.Value + 1;
            return new Scope();
        }

        internal static void WarnIfBypassed(Action<string>? log, string action)
        {
            if (!EnforceManagerUsage) return;
            if (IsInManagerScope) return;
            log?.Invoke($"[Bypass][ERROR] {action}: вызов в обход BypassStateManager");
        }

        internal static void WarnIfBypassed(IProgress<string>? progress, string action)
        {
            if (!EnforceManagerUsage) return;
            if (IsInManagerScope) return;
            progress?.Report($"[TrafficEngine][ERROR] {action}: вызов в обход BypassStateManager");
        }

        private sealed class Scope : IDisposable
        {
            public void Dispose()
            {
                var current = Depth.Value;
                Depth.Value = current > 0 ? current - 1 : 0;
            }
        }
    }

    /// <summary>
    /// Единый владелец состояния bypass и операций над TrafficEngine.
    /// Все изменения фильтров/старт/стоп движка, а также Apply/Disable TLS-bypass
    /// должны проходить через этот менеджер.
    /// </summary>
    public sealed class BypassStateManager : IDisposable
    {
        private static readonly ConditionalWeakTable<TrafficEngine, BypassStateManager> Instances = new();
        private static readonly object InstancesSync = new();

        public static BypassStateManager GetOrCreate(
            TrafficEngine trafficEngine,
            BypassProfile? baseProfile = null,
            Action<string>? log = null)
        {
            if (trafficEngine == null) throw new ArgumentNullException(nameof(trafficEngine));

            lock (InstancesSync)
            {
                if (Instances.TryGetValue(trafficEngine, out var existing))
                {
                    return existing;
                }

                var created = new BypassStateManager(
                    trafficEngine,
                    baseProfile ?? BypassProfile.CreateDefault(),
                    log);

                Instances.Add(trafficEngine, created);
                return created;
            }
        }

        internal static BypassStateManager GetOrCreateFromService(
            TlsBypassService tlsService,
            BypassProfile baseProfile,
            Action<string>? log = null)
        {
            if (tlsService == null) throw new ArgumentNullException(nameof(tlsService));
            if (baseProfile == null) throw new ArgumentNullException(nameof(baseProfile));

            var engine = tlsService.TrafficEngineForManager;
            lock (InstancesSync)
            {
                if (Instances.TryGetValue(engine, out var existing))
                {
                    return existing;
                }

                var created = new BypassStateManager(engine, tlsService, baseProfile, log);
                Instances.Add(engine, created);
                return created;
            }
        }

        private readonly TrafficEngine _trafficEngine;
        private readonly TlsBypassService _tlsService;
        private readonly Action<string>? _log;
        private readonly SemaphoreSlim _applyGate = new(1, 1);

        public TrafficEngine TrafficEngine => _trafficEngine;
        public BypassProfile BaseProfile { get; }

        public TlsBypassService TlsService => _tlsService;

        public IReadOnlyList<TlsFragmentPreset> FragmentPresets => _tlsService.FragmentPresets;

        public event Action<TlsBypassMetrics>? MetricsUpdated
        {
            add => _tlsService.MetricsUpdated += value;
            remove => _tlsService.MetricsUpdated -= value;
        }

        public event Action<TlsBypassVerdict>? VerdictChanged
        {
            add => _tlsService.VerdictChanged += value;
            remove => _tlsService.VerdictChanged -= value;
        }

        public event Action<TlsBypassState>? StateChanged
        {
            add => _tlsService.StateChanged += value;
            remove => _tlsService.StateChanged -= value;
        }

        private BypassStateManager(TrafficEngine trafficEngine, BypassProfile baseProfile, Action<string>? log)
        {
            _trafficEngine = trafficEngine;
            BaseProfile = baseProfile;
            _log = log;

            // Важно: лог прокидываем на самый нижний уровень, чтобы любые проблемы
            // в обходе (метрики/вердикт/движок) были видны пользователю.
            _tlsService = new TlsBypassService(_trafficEngine, BaseProfile, _log);

            // Включаем guard: все последующие вызовы к TrafficEngine/TlsBypassService,
            // сделанные не из менеджера, будут логироваться как ошибка.
            BypassStateManagerGuard.EnforceManagerUsage = true;
        }

        private BypassStateManager(TrafficEngine trafficEngine, TlsBypassService tlsService, BypassProfile baseProfile, Action<string>? log)
        {
            _trafficEngine = trafficEngine;
            _tlsService = tlsService;
            BaseProfile = baseProfile;
            _log = log;

            BypassStateManagerGuard.EnforceManagerUsage = true;
        }

        public TlsBypassOptions GetOptionsSnapshot() => _tlsService.GetOptionsSnapshot();

        public void RegisterEngineFilter(IspAudit.Core.Traffic.IPacketFilter filter)
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            _trafficEngine.RegisterFilter(filter);
        }

        public void RemoveEngineFilter(string filterName)
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            _trafficEngine.RemoveFilter(filterName);
        }

        public Task StartEngineAsync(CancellationToken cancellationToken = default)
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            return _trafficEngine.StartAsync(cancellationToken);
        }

        public Task StopEngineAsync()
        {
            using var scope = BypassStateManagerGuard.EnterScope();
            return _trafficEngine.StopAsync();
        }

        public async Task ApplyTlsOptionsAsync(TlsBypassOptions options, CancellationToken cancellationToken = default)
        {
            await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var scope = BypassStateManagerGuard.EnterScope();
                await _tlsService.ApplyAsync(options, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _applyGate.Release();
            }
        }

        public async Task DisableTlsAsync(CancellationToken cancellationToken = default)
        {
            await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var scope = BypassStateManagerGuard.EnterScope();
                await _tlsService.DisableAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _applyGate.Release();
            }
        }

        public async Task ApplyPreemptiveAsync(CancellationToken cancellationToken = default)
        {
            await _applyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var scope = BypassStateManagerGuard.EnterScope();
                await _tlsService.ApplyPreemptiveAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _applyGate.Release();
            }
        }

        public void Dispose()
        {
            _tlsService.Dispose();
            _applyGate.Dispose();
        }
    }
}
