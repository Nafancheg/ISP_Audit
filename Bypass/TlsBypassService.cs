using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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

        internal void SetFilterForSmoke(BypassFilter filter, DateTime? metricsSince = null, TlsBypassOptions? options = null)
        {
            if (filter == null) throw new ArgumentNullException(nameof(filter));

            lock (_sync)
            {
                _filter = filter;
                if (options != null)
                {
                    _options = options;
                }

                _metricsSince = metricsSince ?? _now();
            }
        }

        internal Task PullMetricsOnceAsyncForSmoke() => PullMetricsAsync();

        /// <summary>
        /// Outcome-probe (HTTPS): зарегистрировать 5-tuple соединения, которое нужно исключить из пользовательских метрик.
        /// Важно: обход сохраняется (пакеты всё ещё обрабатываются фильтром), исключаются только счётчики.
        /// </summary>
        internal void RegisterOutcomeProbeFlow(IPEndPoint local, IPEndPoint remote, TimeSpan ttl)
        {
            try
            {
                if (local == null || remote == null) return;
                if (local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return;
                if (remote.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return;

                var srcIp = BinaryPrimitives.ReadUInt32BigEndian(local.Address.GetAddressBytes());
                var dstIp = BinaryPrimitives.ReadUInt32BigEndian(remote.Address.GetAddressBytes());

                lock (_sync)
                {
                    _filter?.RegisterProbeFlow(srcIp, dstIp, (ushort)local.Port, (ushort)remote.Port, ttl);
                }
            }
            catch
            {
                // Игнорируем: это наблюдаемость, не критический путь.
            }
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
            BypassStateManagerGuard.WarnIfBypassed(_log, "TlsBypassService.ApplyAsync");

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
            BypassStateManagerGuard.WarnIfBypassed(_log, "TlsBypassService.DisableAsync");
            return ApplyAsync(_options with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false,
                AllowNoSni = false,
                DropUdp443 = false,
                // Важно: DisableAsync должен полностью выключать bypass.
                // Иначе TtlTrickEnabled из профиля может оставить IsAnyEnabled()==true
                // и фильтр будет пересоздан/останется в TrafficEngine.
                TtlTrickEnabled = false,
                AutoTtlEnabled = false
            }, cancellationToken);
        }

        private async Task ApplyInternalAsync(CancellationToken cancellationToken)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Smoke-режим (без TrafficEngine) выполняется почти синхронно.
                // Добавляем небольшую отменяемую задержку, чтобы детерминированно тестировать
                // таймаут/Cancel и безопасный откат на верхнем уровне.
                if (!_useTrafficEngine)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken).ConfigureAwait(false);
                }

                if (_useTrafficEngine)
                {
                    _trafficEngine.RemoveFilter("BypassFilter");
                }

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

                if (_useTrafficEngine)
                {
                    _trafficEngine.RegisterFilter(filter);

                    if (!_trafficEngine.IsRunning)
                    {
                        await _trafficEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                    }
                }

                lock (_sync)
                {
                    _filter = filter;
                    _metricsSince = _now();
                }

                StateChanged?.Invoke(new TlsBypassState(true, "-", _metricsSince.ToString("HH:mm:ss")));
                _log?.Invoke($"[Bypass] Применены опции: {optionsSnapshot.ToReadableStrategy()} | TLS chunks: {optionsSnapshot.FragmentSizesAsText()}, threshold: {profile.TlsFragmentThreshold}");
            }
            catch (OperationCanceledException)
            {
                _log?.Invoke("[Bypass] Применение отменено");
                throw;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass] Ошибка применения опций: {ex.Message}");
            }
        }

        /// <summary>
        /// Smoke-хук: запустить логику автонастроек (AutoAdjustAggressive/AutoTTL) на переданных метриках,
        /// без привязки к реальному TrafficEngine. Возвращает true, если опции были изменены и переприменены.
        /// </summary>
        internal async Task<bool> TryAutoAdjustOnceForSmoke(TlsBypassMetrics metrics, TlsBypassVerdict? verdictOverride = null)
        {
            TlsBypassOptions options;
            lock (_sync)
            {
                options = _options;
            }

            var verdict = verdictOverride ?? CalculateVerdict(metrics, options);

            var adjustedSizes = _autoAdjust.TryAdjust(options, metrics, verdict);
            if (adjustedSizes != null)
            {
                await ApplyAsync(options with { FragmentSizes = adjustedSizes }, CancellationToken.None).ConfigureAwait(false);
                return true;
            }

            var adjustedOptions = _autoTtl.TryAdjust(options, metrics, verdict);
            if (adjustedOptions != null)
            {
                await ApplyAsync(adjustedOptions, CancellationToken.None).ConfigureAwait(false);
                return true;
            }

            return false;
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

            // Делаем обход более "липким" при включённом AllowNoSni:
            // - ClientHello часто сегментируется на несколько TCP пакетов
            // - порог 128 может не дать шанса стратегии сработать
            // В этом режиме мы не зависим от успешного парсинга SNI.
            var tlsThreshold = options.AllowNoSni ? 1 : _baseProfile.TlsFragmentThreshold;

            return new BypassProfile
            {
                DropTcpRst = options.DropRstEnabled,
                FragmentTlsClientHello = options.FragmentEnabled || options.DisorderEnabled || options.FakeEnabled,
                TlsStrategy = tlsStrategy,
                TlsFirstFragmentSize = _baseProfile.TlsFirstFragmentSize,
                TlsFragmentThreshold = tlsThreshold,
                TlsFragmentSizes = options.FragmentSizes,
                TtlTrick = options.TtlTrickEnabled,
                TtlTrickValue = options.TtlTrickValue,
                AutoTtl = options.AutoTtlEnabled,
                AllowNoSni = options.AllowNoSni,
                DropUdp443 = options.DropUdp443,
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
                    Udp443Dropped = snapshot.Udp443Dropped,
                    Plan = string.IsNullOrWhiteSpace(snapshot.LastFragmentPlan) ? "-" : snapshot.LastFragmentPlan,
                    Since = since == DateTime.MinValue ? "-" : since.ToString("HH:mm:ss"),
                    ClientHellosObserved = snapshot.ClientHellosObserved,
                    ClientHellosShort = snapshot.ClientHellosShort,
                    ClientHellosNon443 = snapshot.ClientHellosNon443,
                    ClientHellosNoSni = snapshot.ClientHellosNoSni,
                    PresetName = options.PresetName,
                    FragmentThreshold = options.AllowNoSni ? 1 : _baseProfile.TlsFragmentThreshold,
                    MinChunk = (options.FragmentSizes ?? Array.Empty<int>()).DefaultIfEmpty(0).Min()
                };

                var verdict = CalculateVerdict(metrics, options);

                var adjustedSizes = _autoAdjust.TryAdjust(options, metrics, verdict);
                if (adjustedSizes != null)
                {
                    await ApplyAsync(options with { FragmentSizes = adjustedSizes }, CancellationToken.None).ConfigureAwait(false);
                    return;
                }

                var adjustedOptions = _autoTtl.TryAdjust(options, metrics, verdict);
                if (adjustedOptions != null)
                {
                    await ApplyAsync(adjustedOptions, CancellationToken.None).ConfigureAwait(false);
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

        /// <summary>
        /// Разрешить применение TLS-обхода даже когда SNI не распознан/отсутствует.
        /// </summary>
        public bool AllowNoSni { get; init; }

        /// <summary>
        /// QUIC fallback: глушить UDP/443, чтобы клиент откатился на TCP/HTTPS.
        /// </summary>
        public bool DropUdp443 { get; init; }

        public IReadOnlyList<int> FragmentSizes { get; init; } = Array.Empty<int>();
        public string PresetName { get; init; } = string.Empty;
        public bool AutoAdjustAggressive { get; init; }

        public bool TtlTrickEnabled { get; init; }
        public int TtlTrickValue { get; init; } = 3;
        public bool AutoTtlEnabled { get; init; }

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
                AllowNoSni = baseProfile.AllowNoSni,
                DropUdp443 = baseProfile.DropUdp443,
                FragmentSizes = fragments,
                PresetName = string.IsNullOrWhiteSpace(baseProfile.FragmentPresetName) ? "Профиль" : baseProfile.FragmentPresetName,
                AutoAdjustAggressive = baseProfile.AutoAdjustAggressive,
                TtlTrickEnabled = baseProfile.TtlTrick,
                TtlTrickValue = baseProfile.TtlTrickValue,
                AutoTtlEnabled = baseProfile.AutoTtl
            };
        }

        public bool IsAnyEnabled()
        {
            return FragmentEnabled || DisorderEnabled || FakeEnabled || DropRstEnabled || AllowNoSni || DropUdp443 || TtlTrickEnabled;
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

            var ttl = TtlTrickValue;
            if (ttl <= 0) ttl = 3;
            if (ttl > 255) ttl = 255;

            return this with { FragmentSizes = safe, TtlTrickValue = ttl };
        }

        public string ToReadableStrategy()
        {
            var parts = new List<string>();
            if (FragmentEnabled) parts.Add("Fragment");
            if (DisorderEnabled) parts.Add("Disorder");
            if (FakeEnabled) parts.Add("Fake");
            if (DropRstEnabled) parts.Add("DROP RST");
            if (DropUdp443) parts.Add("DROP UDP/443");
            if (AllowNoSni) parts.Add("AllowNoSNI");
            if (TtlTrickEnabled) parts.Add(AutoTtlEnabled ? $"AutoTTL({TtlTrickValue})" : $"TTL({TtlTrickValue})");
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
        public long Udp443Dropped { get; init; }
        public string Plan { get; init; } = "-";
        public string Since { get; init; } = "-";
        public long ClientHellosObserved { get; init; }
        public long ClientHellosShort { get; init; }
        public long ClientHellosNon443 { get; init; }
        public long ClientHellosNoSni { get; init; }
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
        private readonly Func<DateTime> _now;

        public AggressiveAutoAdjustStrategy(Func<DateTime> now)
        {
            _now = now ?? throw new ArgumentNullException(nameof(now));
        }

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
                _greenSince ??= _now();
            }
            else
            {
                _greenSince = null;
            }

            if (verdict.Color == VerdictColor.Green && !_adjustedUp && _greenSince.HasValue && _now() - _greenSince.Value > TimeSpan.FromSeconds(30))
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

    /// <summary>
    /// Автоподбор TTL для TTL Trick по метрикам bypass.
    /// Логика максимально простая: перебор небольшого набора TTL и выбор наилучшего по ratio RST/фрагменты.
    /// </summary>
    internal sealed class AutoTtlAdjustStrategy
    {
        private readonly Action<string>? _log;
        private readonly Func<DateTime> _now;
        private int[]? _candidates;
        private int _index;
        private DateTime _trialSince;
        private double _bestRatio = double.PositiveInfinity;
        private int _bestTtl;
        private bool _completed;

        public AutoTtlAdjustStrategy(Action<string>? log, Func<DateTime> now)
        {
            _log = log;
            _now = now ?? throw new ArgumentNullException(nameof(now));
        }

        public TlsBypassOptions? TryAdjust(TlsBypassOptions options, TlsBypassMetrics metrics, TlsBypassVerdict verdict)
        {
            if (!options.TtlTrickEnabled || !options.AutoTtlEnabled)
            {
                Reset();
                return null;
            }

            if (_completed)
            {
                return null;
            }

            // Ждём появления реального трафика TLS@443, иначе подбирать нечего.
            if (metrics.ClientHellosObserved < 3)
            {
                return null;
            }

            if (_candidates == null)
            {
                _candidates = BuildCandidates(options.TtlTrickValue);
                _index = 0;
                _trialSince = _now();
                _bestTtl = options.TtlTrickValue;
                _bestRatio = double.PositiveInfinity;

                var first = _candidates[0];
                if (options.TtlTrickValue != first)
                {
                    _log?.Invoke($"[Bypass][AutoTTL] Старт подбора: пробуем TTL={first} (текущий={options.TtlTrickValue})");
                    return options with { TtlTrickValue = first };
                }

                _log?.Invoke($"[Bypass][AutoTTL] Старт подбора: пробуем TTL={first}");
            }

            var age = _now() - _trialSince;
            var enoughData = metrics.ClientHellosFragmented >= 5 || metrics.TlsHandled >= 3;
            if (!enoughData && age < TimeSpan.FromSeconds(12))
            {
                return null;
            }

            var fragments = Math.Max(1, metrics.ClientHellosFragmented);
            var rstRelevant = Math.Max(0, metrics.RstDroppedRelevant);
            var ratio = (rstRelevant + 1.0) / (fragments + 1.0);

            if (metrics.ClientHellosFragmented > 0 && ratio < _bestRatio)
            {
                _bestRatio = ratio;
                _bestTtl = options.TtlTrickValue;
            }

            _index++;
            if (_candidates != null && _index < _candidates.Length)
            {
                var next = _candidates[_index];
                _trialSince = _now();
                _log?.Invoke($"[Bypass][AutoTTL] Пробуем TTL={next} (best={_bestTtl}, ratio={_bestRatio:F2})");
                return options with { TtlTrickValue = next };
            }

            // Завершение: применяем лучший TTL и сохраняем в профиль.
            _completed = true;

            _log?.Invoke($"[Bypass][AutoTTL] Подбор завершён: best TTL={_bestTtl} (ratio={_bestRatio:F2})");
            _ = BypassProfile.TryUpdateTtlSettings(ttlTrickEnabled: true, ttlTrickValue: _bestTtl);

            if (options.TtlTrickValue != _bestTtl)
            {
                return options with { TtlTrickValue = _bestTtl };
            }

            return null;
        }

        private static int[] BuildCandidates(int current)
        {
            // Малый набор TTL, чтобы не дестабилизировать соединения.
            // Набор подобран так, чтобы соответствовать smoke-плану и оставаться предсказуемым.
            var baseSet = new[] { 5, 10, 15, 20 };
            if (baseSet.Contains(current))
            {
                return new[] { current }.Concat(baseSet.Where(v => v != current)).ToArray();
            }
            return new[] { Math.Clamp(current, 1, 255) }.Concat(baseSet).Distinct().ToArray();
        }

        private void Reset()
        {
            _candidates = null;
            _index = 0;
            _trialSince = default;
            _bestRatio = double.PositiveInfinity;
            _bestTtl = 0;
            _completed = false;
        }
    }
}