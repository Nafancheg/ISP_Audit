using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Utils
{
    public sealed class DomainGroupLearnerOptions
    {
        // Окно ко-оккурренса: если домены встречаются близко по времени, считаем их связанными.
        public TimeSpan CoOccurrenceWindow { get; set; } = TimeSpan.FromSeconds(8);

        // Порог: сколько раз пара доменов должна встретиться в окне, чтобы мы предложили learned-группу.
        public int PairEvidenceThreshold { get; set; } = 8;

        // Ограничение количества learned-групп на диске (защита от "распухания" state).
        public int MaxLearnedGroups { get; set; } = 24;

        // Минимальный интервал между persist (уменьшаем churn записи state).
        public TimeSpan MinPersistInterval { get; set; } = TimeSpan.FromSeconds(20);
    }

    /// <summary>
    /// Обучение learned-групп доменов (P1.2) на основе co-occurrence в UI-сессии.
    /// Важно:
    /// - Это ТОЛЬКО UX (агрегация карточек/подсказка группового apply).
    /// - Никаких wildcard-правил фильтрации пакетов не создаётся.
    /// - Срабатывает только для доменов (не IP), и игнорирует шумовые хосты.
    /// </summary>
    public sealed class DomainGroupLearner
    {
        private readonly DomainGroupCatalogState _catalog;
        private readonly DomainGroupLearnerOptions _opt;
        private readonly Action<string>? _log;
        private readonly NoiseHostFilter _noiseHostFilter;

        private DateTime _lastPersistUtc;

        // Кольцевой буфер последних наблюдений базовых суффиксов.
        private readonly Queue<(string BaseSuffix, DateTime SeenUtc)> _recent = new();

        // Счётчик доказательств для пары доменов (A|B).
        private readonly Dictionary<string, int> _pairEvidence = new(StringComparer.OrdinalIgnoreCase);

        public DomainGroupLearner(DomainGroupCatalogState catalog, NoiseHostFilter noiseHostFilter, DomainGroupLearnerOptions? options = null, Action<string>? log = null)
        {
            _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
            _noiseHostFilter = noiseHostFilter ?? throw new ArgumentNullException(nameof(noiseHostFilter));
            _opt = options ?? new DomainGroupLearnerOptions();
            _log = log;
            _lastPersistUtc = DateTime.MinValue;
        }

        /// <summary>
        /// Возвращает true, если каталог learned-групп был изменён и его стоит persist'ить.
        /// </summary>
        public bool ObserveHost(string hostKey, DateTime nowUtc)
        {
            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (hk.Length == 0) return false;

                // IP не обучаем.
                if (System.Net.IPAddress.TryParse(hk, out _))
                {
                    return false;
                }

                // Шумовые домены не обучаем.
                if (_noiseHostFilter.IsNoiseHost(hk))
                {
                    return false;
                }

                if (!DomainUtils.TryGetBaseSuffix(hk, out var baseSuffix))
                {
                    return false;
                }

                baseSuffix = (baseSuffix ?? string.Empty).Trim().Trim('.');
                if (baseSuffix.Length == 0) return false;

                // Если домен уже покрыт pinned-группой — не учим поверх (чтобы не плодить дубликаты).
                if (IsBaseSuffixInAnyPinnedGroup(baseSuffix))
                {
                    return false;
                }

                EvictOld(nowUtc);

                // Поддерживаем локальный сигнал: текущий домен ко-оккурирует со всеми доменами в окне.
                bool changed = false;
                foreach (var (prevSuffix, prevUtc) in _recent)
                {
                    if (prevSuffix.Equals(baseSuffix, StringComparison.OrdinalIgnoreCase)) continue;

                    // Внутренний ключ пары (детерминизм).
                    var pairKey = MakePairKey(prevSuffix, baseSuffix);
                    if (!_pairEvidence.TryGetValue(pairKey, out var count)) count = 0;
                    count++;
                    _pairEvidence[pairKey] = count;

                    if (count == _opt.PairEvidenceThreshold)
                    {
                        // Порог достигнут: создаём/обновляем learned-группу.
                        changed |= UpsertLearnedGroupForPair(prevSuffix, baseSuffix, nowUtc);
                    }
                }

                _recent.Enqueue((baseSuffix, nowUtc));
                return changed;
            }
            catch
            {
                return false;
            }
        }

        public bool ShouldPersistNow(DateTime nowUtc)
        {
            try
            {
                if (_lastPersistUtc == DateTime.MinValue) return true;
                return (nowUtc - _lastPersistUtc) >= _opt.MinPersistInterval;
            }
            catch
            {
                return true;
            }
        }

        public void MarkPersisted(DateTime nowUtc)
        {
            _lastPersistUtc = nowUtc;
        }

        private void EvictOld(DateTime nowUtc)
        {
            var cutoff = nowUtc - _opt.CoOccurrenceWindow;
            while (_recent.Count > 0)
            {
                var head = _recent.Peek();
                if (head.SeenUtc >= cutoff) break;
                _recent.Dequeue();
            }

            // Защита от бесконечного роста, если clock скачет.
            while (_recent.Count > 256)
            {
                _recent.Dequeue();
            }
        }

        private bool UpsertLearnedGroupForPair(string a, string b, DateTime nowUtc)
        {
            try
            {
                a = (a ?? string.Empty).Trim().Trim('.');
                b = (b ?? string.Empty).Trim().Trim('.');
                if (a.Length == 0 || b.Length == 0) return false;

                var domains = new[] { a, b }
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var groupKey = ComputeLearnedGroupKey(domains);

                if (!_catalog.LearnedGroups.TryGetValue(groupKey, out var entry))
                {
                    entry = new LearnedDomainGroupEntry
                    {
                        EvidenceCount = 0,
                        Reason = "Co-occurrence (UI session)",
                        FirstSeenUtc = nowUtc,
                        LastSeenUtc = nowUtc,
                        Domains = domains
                    };

                    _catalog.LearnedGroups[groupKey] = entry;
                    TrimLearnedGroupsBestEffort();
                    _log?.Invoke($"[DomainGroups][Learn] New learned group: {groupKey} ({string.Join(", ", domains)})");
                    return true;
                }

                // Обновляем существующую.
                entry.LastSeenUtc = nowUtc;
                entry.EvidenceCount = Math.Max(entry.EvidenceCount, _opt.PairEvidenceThreshold);
                entry.Reason = string.IsNullOrWhiteSpace(entry.Reason) ? "Co-occurrence (UI session)" : entry.Reason;

                // Если домены поменялись (например, вручную), приводим к текущим.
                entry.Domains = domains;

                _catalog.LearnedGroups[groupKey] = entry;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string ComputeLearnedGroupKey(IReadOnlyList<string> domains)
        {
            // Ключ должен быть стабильным и пригодным для использования в качестве groupKey.
            // Используем нормализованный список доменов.
            var normalized = (domains ?? Array.Empty<string>())
                .Select(d => (d ?? string.Empty).Trim().Trim('.').ToLowerInvariant())
                .Where(d => d.Length > 0)
                .Distinct()
                .OrderBy(d => d, StringComparer.Ordinal)
                .ToList();

            if (normalized.Count == 0)
            {
                return "learned-empty";
            }

            var joined = string.Join("+", normalized);

            // Уберём нежелательные символы.
            var safe = joined
                .Replace(".", "_")
                .Replace("/", "_")
                .Replace(":", "_")
                .Replace(" ", "_");

            if (safe.Length > 120)
            {
                safe = safe.Substring(0, 120);
            }

            return "learned-" + safe;
        }

        private static string MakePairKey(string a, string b)
        {
            var aa = (a ?? string.Empty).Trim().Trim('.');
            var bb = (b ?? string.Empty).Trim().Trim('.');

            if (string.Compare(aa, bb, StringComparison.OrdinalIgnoreCase) <= 0)
            {
                return aa + "|" + bb;
            }

            return bb + "|" + aa;
        }

        private bool IsBaseSuffixInAnyPinnedGroup(string baseSuffix)
        {
            try
            {
                foreach (var g in _catalog.PinnedGroups ?? Enumerable.Empty<DomainGroupEntry>())
                {
                    foreach (var d in g.Domains ?? Enumerable.Empty<string>())
                    {
                        if (d.Equals(baseSuffix, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private void TrimLearnedGroupsBestEffort()
        {
            try
            {
                if (_catalog.LearnedGroups.Count <= _opt.MaxLearnedGroups) return;

                // Удаляем самые старые по LastSeenUtc.
                var ordered = _catalog.LearnedGroups
                    .Select(kv => (Key: kv.Key, LastSeenUtc: kv.Value?.LastSeenUtc ?? DateTime.MinValue))
                    .OrderBy(t => t.LastSeenUtc)
                    .ToList();

                while (_catalog.LearnedGroups.Count > _opt.MaxLearnedGroups && ordered.Count > 0)
                {
                    var victim = ordered[0];
                    ordered.RemoveAt(0);
                    _catalog.LearnedGroups.Remove(victim.Key);
                }
            }
            catch
            {
                // best-effort
            }
        }
    }
}
