using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Bypass
{
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
