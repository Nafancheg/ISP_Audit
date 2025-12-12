using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;

using Timer = System.Timers.Timer;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Сервис управления TLS bypass (фрагментация/дезорганизация/FAKE) без привязки к UI.
    /// Отвечает за применение профиля, сбор метрик и вычисление вердикта.
    /// </summary>
    public class TlsBypassService : IDisposable
    {
        private readonly TrafficEngine _trafficEngine;
        private readonly BypassProfile _baseProfile;
        private readonly Action<string>? _log;
        private readonly object _sync = new();
        private readonly Timer _metricsTimer;

        private BypassFilter? _filter;
        private TlsBypassOptions _options;
        private DateTime _metricsSince = DateTime.MinValue;
        private readonly AggressiveAutoAdjustStrategy _autoAdjust = new();
        private readonly IReadOnlyList<TlsFragmentPreset> _presets;

        public event Action<TlsBypassMetrics>? MetricsUpdated;
        public event Action<TlsBypassVerdict>? VerdictChanged;
        public event Action<TlsBypassState>? StateChanged;

        public IReadOnlyList<TlsFragmentPreset> FragmentPresets => _presets;

        public TlsBypassService(TrafficEngine trafficEngine, BypassProfile baseProfile, Action<string>? log = null)
        {
            _trafficEngine = trafficEngine;
            _baseProfile = baseProfile;
            _log = log;
            _options = TlsBypassOptions.CreateDefault(_baseProfile);
            _presets = BuildPresets(_baseProfile);

            _metricsTimer = new Timer
            {
                AutoReset = true,
                Interval = 2000
            };
            _metricsTimer.Elapsed += (_, _) => _ = PullMetricsAsync();
            _metricsTimer.Start();
        }

        /// <summary>
        /// Текущий снимок опций (без повторного построения профиля).
        /// </summary>
        public TlsBypassOptions GetOptionsSnapshot()
        {
            lock (_sync)
            {
                return _options;
            }
        }

        /// <summary>
        /// Применить новый набор опций TLS bypass.
        /// </summary>
        public async Task ApplyAsync(TlsBypassOptions options, CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                _options = options.Normalize();
            }

            await ApplyInternalAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Применить преподготовленный профиль (используется для преимптивного включения).
        /// </summary>
        public Task ApplyPreemptiveAsync(CancellationToken cancellationToken = default)
        {
            var preset = _options with
            {
                FragmentEnabled = false,
                DisorderEnabled = true,
                FakeEnabled = false,
                DropRstEnabled = true
            };

            return ApplyAsync(preset, cancellationToken);
        }

        /// <summary>
        /// Отключить bypass и удалить фильтр.
        /// </summary>
        public Task DisableAsync(CancellationToken cancellationToken = default)
        {
            return ApplyAsync(_options with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false
            }, cancellationToken);
        }

        private async Task ApplyInternalAsync(CancellationToken cancellationToken)
        {
            try
            {
                _trafficEngine.RemoveFilter("BypassFilter");

                TlsBypassOptions optionsSnapshot;
                lock (_sync)
                {
                    optionsSnapshot = _options;
                }

                if (!optionsSnapshot.IsAnyEnabled())
                {
                    _filter = null;
                    _metricsSince = DateTime.MinValue;
                    StateChanged?.Invoke(new TlsBypassState(false, "-", "-"));
                    MetricsUpdated?.Invoke(TlsBypassMetrics.Empty);
                    VerdictChanged?.Invoke(TlsBypassVerdict.CreateInactive());
                    _log?.Invoke("[Bypass] Все опции отключены");
                    return;
                }

                var profile = BuildProfile(optionsSnapshot);
                var filter = new BypassFilter(profile, _log, optionsSnapshot.PresetName);
                _trafficEngine.RegisterFilter(filter);

                if (!_trafficEngine.IsRunning)
                {
                    await _trafficEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                }

                lock (_sync)
                {
                    _filter = filter;
                    _metricsSince = DateTime.Now;
                }

                StateChanged?.Invoke(new TlsBypassState(true, "-", _metricsSince.ToString("HH:mm:ss")));
                _log?.Invoke($"[Bypass] Применены опции: {optionsSnapshot.ToReadableStrategy()} | TLS chunks: {optionsSnapshot.FragmentSizesAsText()}, threshold: {profile.TlsFragmentThreshold}");
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass] Ошибка применения опций: {ex.Message}");
            }
        }

        private BypassProfile BuildProfile(TlsBypassOptions options)
        {
            var tlsStrategy = TlsBypassStrategy.None;

            if (options.DisorderEnabled && options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.FakeDisorder;
            else if (options.FragmentEnabled && options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.FakeFragment;
            else if (options.DisorderEnabled)
                tlsStrategy = TlsBypassStrategy.Disorder;
            else if (options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.Fake;
            else if (options.FragmentEnabled)
                tlsStrategy = TlsBypassStrategy.Fragment;

            return new BypassProfile
            {
                DropTcpRst = options.DropRstEnabled,
                FragmentTlsClientHello = options.FragmentEnabled || options.DisorderEnabled || options.FakeEnabled,
                TlsStrategy = tlsStrategy,
                TlsFirstFragmentSize = _baseProfile.TlsFirstFragmentSize,
                TlsFragmentThreshold = _baseProfile.TlsFragmentThreshold,
                TlsFragmentSizes = options.FragmentSizes,
                TtlTrick = _baseProfile.TtlTrick,
                TtlTrickValue = _baseProfile.TtlTrickValue,
                RedirectRules = _baseProfile.RedirectRules
            };
        }

        private static IReadOnlyList<TlsFragmentPreset> BuildPresets(BypassProfile baseProfile)
        {
            var profileSizes = baseProfile.TlsFragmentSizes ?? new List<int> { baseProfile.TlsFirstFragmentSize };
            var safeProfileSizes = profileSizes.Select(v => Math.Max(4, v)).ToList();

            return new List<TlsFragmentPreset>
            {
                new("Стандарт", new List<int> { 64 }, "Баланс: один фрагмент 64 байта"),
                new("Умеренный", new List<int> { 96 }, "Чуть крупнее фрагмент для совместимости"),
                new("Агрессивный", new List<int> { 32, 32 }.Select(v => Math.Max(4, v)).ToList(), "Два мелких фрагмента для сложных DPI"),
                new("Профиль", safeProfileSizes, "Размеры из bypass_profile.json")
            };
        }

        private async Task PullMetricsAsync()
        {
            try
            {
                BypassFilter? filter;
                TlsBypassOptions options;
                DateTime since;

                lock (_sync)
                {
                    filter = _filter;
                    options = _options;
                    since = _metricsSince;
                }

                if (filter == null)
                {
                    MetricsUpdated?.Invoke(TlsBypassMetrics.Empty);
                    VerdictChanged?.Invoke(TlsBypassVerdict.CreateInactive());
                    return;
                }

                var snapshot = filter.GetMetrics();
                var metrics = new TlsBypassMetrics
                {
                    TlsHandled = snapshot.TlsHandled,
                    ClientHellosFragmented = snapshot.ClientHellosFragmented,
                    RstDroppedRelevant = snapshot.RstDroppedRelevant,
                    RstDropped = snapshot.RstDropped,
                    Plan = string.IsNullOrWhiteSpace(snapshot.LastFragmentPlan) ? "-" : snapshot.LastFragmentPlan,
                    Since = since == DateTime.MinValue ? "-" : since.ToString("HH:mm:ss"),
                    ClientHellosObserved = snapshot.ClientHellosObserved,
                    ClientHellosShort = snapshot.ClientHellosShort,
                    ClientHellosNon443 = snapshot.ClientHellosNon443,
                    PresetName = options.PresetName,
                    FragmentThreshold = _baseProfile.TlsFragmentThreshold,
                    MinChunk = (options.FragmentSizes ?? Array.Empty<int>()).DefaultIfEmpty(0).Min()
                };

                var verdict = CalculateVerdict(metrics, options);

                var adjustedSizes = _autoAdjust.TryAdjust(options, metrics, verdict);
                if (adjustedSizes != null)
                {
                    await ApplyAsync(options with { FragmentSizes = adjustedSizes }, CancellationToken.None).ConfigureAwait(false);
                    return;
                }

                MetricsUpdated?.Invoke(metrics);
                VerdictChanged?.Invoke(verdict);
                StateChanged?.Invoke(new TlsBypassState(true, metrics.Plan, metrics.Since));
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass] Ошибка чтения метрик: {ex.Message}");
            }
        }

        private TlsBypassVerdict CalculateVerdict(TlsBypassMetrics metrics, TlsBypassOptions options)
        {
            var fragmentsRaw = metrics.ClientHellosFragmented;
            var fragments = Math.Max(1, fragmentsRaw);
            var rstEffective = Math.Max(0, metrics.RstDroppedRelevant - 5);
            var ratio = fragmentsRaw == 0 ? double.PositiveInfinity : (double)rstEffective / fragments;

            var observedTotal = metrics.ClientHellosObserved;
            var observedNon443 = metrics.ClientHellosNon443;
            var observed443 = Math.Max(0, observedTotal - observedNon443);
            var shortHellos = metrics.ClientHellosShort;
            var threshold = _baseProfile.TlsFragmentThreshold;

            if (fragmentsRaw == 0 && observedTotal == 0)
            {
                return new TlsBypassVerdict(VerdictColor.Gray, "Нет TLS 443 в трафике", "ClientHello не замечены — откройте HTTPS/игру и повторите");
            }

            if (observed443 == 0 && observedNon443 > 0)
            {
                return new TlsBypassVerdict(VerdictColor.Gray, "TLS идёт не на 443", "Обход работает только на 443 — отключите прокси/VPN или проверьте настройки");
            }

            if (fragmentsRaw == 0 && shortHellos > 0 && observed443 > 0)
            {
                return new TlsBypassVerdict(VerdictColor.Yellow, "ClientHello короче порога", $"Payload < threshold ({threshold}) — снизьте порог/выберите агрессивный пресет");
            }

            if (fragmentsRaw == 0)
            {
                var strategy = options.ToReadableStrategy();
                return new TlsBypassVerdict(VerdictColor.Red, "Обход активен, но не применён", $"Стратегия: {strategy}. Включите Fragment/Disorder или смените пресет");
            }

            if (fragmentsRaw < 10)
            {
                return new TlsBypassVerdict(VerdictColor.Gray, "Мало данных по TLS", "Фрагментаций <10 — дайте больше трафика или подождите");
            }

            if (ratio > 4.0)
            {
                return new TlsBypassVerdict(VerdictColor.Red, "Обход не помогает: много RST", $"ratio={ratio:F2} > 4 — усилите фрагментацию или включите Drop RST");
            }

            if (ratio > 1.5)
            {
                return new TlsBypassVerdict(VerdictColor.Yellow, "Обход работает частично", $"ratio={ratio:F2} > 1.5 — попробуйте пресет 'Агрессивный'");
            }

            return new TlsBypassVerdict(VerdictColor.Green, "Обход работает", $"ratio={ratio:F2} — RST под контролем");
        }

        public void Dispose()
        {
            _metricsTimer.Stop();
            _metricsTimer.Dispose();
        }
    }

    /// <summary>
    /// Описание пресета фрагментации TLS.
    /// </summary>
    public record TlsFragmentPreset(string Name, IReadOnlyList<int> Sizes, string Description);

    /// <summary>
    /// DTO с опциями TLS bypass.
    /// </summary>
    public record TlsBypassOptions
    {
        public bool FragmentEnabled { get; init; }
        public bool DisorderEnabled { get; init; }
        public bool FakeEnabled { get; init; }
        public bool DropRstEnabled { get; init; }
        public IReadOnlyList<int> FragmentSizes { get; init; } = Array.Empty<int>();
        public string PresetName { get; init; } = string.Empty;
        public bool AutoAdjustAggressive { get; init; }

        public static TlsBypassOptions CreateDefault(BypassProfile baseProfile)
        {
            var fragments = baseProfile.TlsFragmentSizes ?? new List<int> { baseProfile.TlsFirstFragmentSize };
            fragments = fragments.Select(v => Math.Max(4, v)).ToList();
            return new TlsBypassOptions
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = baseProfile.DropTcpRst,
                FragmentSizes = fragments,
                PresetName = string.IsNullOrWhiteSpace(baseProfile.FragmentPresetName) ? "Профиль" : baseProfile.FragmentPresetName,
                AutoAdjustAggressive = baseProfile.AutoAdjustAggressive
            };
        }

        public bool IsAnyEnabled()
        {
            return FragmentEnabled || DisorderEnabled || FakeEnabled || DropRstEnabled;
        }

        public string FragmentSizesAsText()
        {
            return FragmentSizes.Any() ? string.Join('/', FragmentSizes) : "default";
        }

        public TlsBypassOptions Normalize()
        {
            var safe = FragmentSizes.Where(v => v > 0).Select(v => Math.Max(4, v)).Take(4).ToList();
            if (!safe.Any())
            {
                safe.Add(64);
            }

            return this with { FragmentSizes = safe };
        }

        public string ToReadableStrategy()
        {
            var parts = new List<string>();
            if (FragmentEnabled) parts.Add("Fragment");
            if (DisorderEnabled) parts.Add("Disorder");
            if (FakeEnabled) parts.Add("Fake");
            if (DropRstEnabled) parts.Add("DROP RST");
            return parts.Count > 0 ? string.Join(" + ", parts) : "Выключен";
        }
    }

    /// <summary>
    /// Метрики TLS bypass.
    /// </summary>
    public record TlsBypassMetrics
    {
        public long TlsHandled { get; init; }
        public long ClientHellosFragmented { get; init; }
        public long RstDroppedRelevant { get; init; }
        public long RstDropped { get; init; }
        public string Plan { get; init; } = "-";
        public string Since { get; init; } = "-";
        public long ClientHellosObserved { get; init; }
        public long ClientHellosShort { get; init; }
        public long ClientHellosNon443 { get; init; }
        public string PresetName { get; init; } = "-";
        public int FragmentThreshold { get; init; }
        public int MinChunk { get; init; }

        public static TlsBypassMetrics Empty => new();
    }

    /// <summary>
    /// Вердикт по состоянию обхода.
    /// </summary>
    public record TlsBypassVerdict(VerdictColor Color, string Text, string Reason)
    {
        public static TlsBypassVerdict CreateInactive()
        {
            return new TlsBypassVerdict(VerdictColor.Gray, "Bypass выключен", "Нет активного фильтра");
        }
    }

    public enum VerdictColor
    {
        Gray,
        Green,
        Yellow,
        Red
    }

    /// <summary>
    /// Состояние применённого фильтра (для UI badge/таймстампа).
    /// </summary>
    public record TlsBypassState(bool IsActive, string Plan, string Since);

    /// <summary>
    /// Стратегия автокоррекции агрессивного пресета.
    /// </summary>
    internal class AggressiveAutoAdjustStrategy
    {
        private bool _adjustedDown;
        private bool _adjustedUp;
        private DateTime? _greenSince;

        public IReadOnlyList<int>? TryAdjust(TlsBypassOptions options, TlsBypassMetrics metrics, TlsBypassVerdict verdict)
        {
            if (!options.AutoAdjustAggressive)
            {
                Reset();
                return null;
            }

            if (!string.Equals(options.PresetName, "Агрессивный", StringComparison.OrdinalIgnoreCase))
            {
                Reset();
                return null;
            }

            var fragments = metrics.ClientHellosFragmented;
            var rstRelevant = metrics.RstDroppedRelevant;

            // Правило 1: ранние частые RST — ужать минимальный чанк до 4 байт
            if (!_adjustedDown && fragments >= 5 && fragments <= 20 && rstRelevant > 2 * fragments)
            {
                var adjusted = options.FragmentSizes.Select(v => Math.Max(4, v)).ToList();
                var min = adjusted.Min();
                var idx = adjusted.IndexOf(min);
                adjusted[idx] = 4;
                _adjustedDown = true;
                return adjusted;
            }

            // Правило 2: устойчиво зелёный >30с — немного усилить (не ниже 4)
            if (verdict.Color == VerdictColor.Green)
            {
                _greenSince ??= DateTime.Now;
            }
            else
            {
                _greenSince = null;
            }

            if (verdict.Color == VerdictColor.Green && !_adjustedUp && _greenSince.HasValue && DateTime.Now - _greenSince.Value > TimeSpan.FromSeconds(30))
            {
                var adjusted = options.FragmentSizes.Select(v => Math.Max(4, v)).ToList();
                var min = adjusted.Min();
                var idx = adjusted.IndexOf(min);
                var newVal = Math.Max(4, min - 4);
                if (newVal < min)
                {
                    adjusted[idx] = newVal;
                    _adjustedUp = true;
                    return adjusted;
                }
            }

            return null;
        }

        private void Reset()
        {
            _greenSince = null;
            _adjustedDown = false;
            _adjustedUp = false;
        }
    }
}