using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Utils
{
    public sealed record DomainFamilySuggestion(string DomainSuffix, int UniqueSubhosts, int EntropySubhosts);

    /// <summary>
    /// Лёгкий «анализатор доменных семейств» для UX:
    /// - На лету замечает домены, у которых появляется много шардовых/вариативных подхостов.
    /// - Даёт одну «лучшую» подсказку для доменного apply и (опционально) агрегации карточек.
    /// - Поддерживает внешний справочник/кэш через DomainFamilyCatalogState.
    /// </summary>
    public sealed class DomainFamilyAnalyzer
    {
        private sealed class DomainStats
        {
            public readonly ConcurrentDictionary<string, byte> Subhosts = new(StringComparer.OrdinalIgnoreCase);
            public readonly ConcurrentDictionary<string, byte> EntropySubhosts = new(StringComparer.OrdinalIgnoreCase);
            public DateTime LastSeenUtc;
        }

        private readonly DomainFamilyCatalogState _catalog;
        private readonly ConcurrentDictionary<string, DomainStats> _statsBySuffix = new(StringComparer.OrdinalIgnoreCase);
        private readonly Action<string>? _log;

        private DateTime _lastPersistUtc = DateTime.MinValue;
        private readonly TimeSpan _persistMinInterval = TimeSpan.FromSeconds(5);

        public DomainFamilySuggestion? CurrentSuggestion { get; private set; }

        public DomainFamilyAnalyzer(DomainFamilyCatalogState catalog, Action<string>? log = null)
        {
            _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
            _log = log;
        }

        public void Reset()
        {
            _statsBySuffix.Clear();
            CurrentSuggestion = null;
        }

        public bool ObserveHost(string hostKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(hostKey)) return false;

                hostKey = hostKey.Trim().Trim('.');
                if (hostKey.Length == 0) return false;

                // IP не анализируем в доменные семейства.
                if (System.Net.IPAddress.TryParse(hostKey, out _)) return false;

                if (!TryGetBaseSuffix(hostKey, out var suffix)) return false;

                // Нужно, чтобы это был именно подхост (а не сам домен).
                if (!hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)) return false;

                var parts = hostKey.Split('.');
                var suffixParts = suffix.Split('.');
                if (parts.Length <= suffixParts.Length) return false;

                var stats = _statsBySuffix.GetOrAdd(suffix, _ => new DomainStats());
                stats.LastSeenUtc = DateTime.UtcNow;

                // Уникальность подхостов важнее частоты.
                var added = stats.Subhosts.TryAdd(hostKey, 1);
                if (added && LooksLikeShardSubhost(hostKey, suffix))
                {
                    stats.EntropySubhosts.TryAdd(hostKey, 1);
                }

                return RecomputeSuggestionAndPersistIfNeeded();
            }
            catch
            {
                return false;
            }
        }

        public bool IsPinned(string domainSuffix)
        {
            return _catalog.PinnedDomains.Any(d => d.Equals(domainSuffix, StringComparison.OrdinalIgnoreCase));
        }

        private bool RecomputeSuggestionAndPersistIfNeeded()
        {
            var newSuggestion = PickBestSuggestion();

            bool changed = (newSuggestion?.DomainSuffix ?? "").Equals(CurrentSuggestion?.DomainSuffix ?? "", StringComparison.OrdinalIgnoreCase) == false ||
                           (newSuggestion?.UniqueSubhosts ?? 0) != (CurrentSuggestion?.UniqueSubhosts ?? 0);

            CurrentSuggestion = newSuggestion;

            if (newSuggestion == null)
            {
                return changed;
            }

            // Запоминаем/обновляем во внешнем JSON только когда есть реальная подсказка.
            TryUpdateCatalog(newSuggestion);

            return changed;
        }

        private DomainFamilySuggestion? PickBestSuggestion()
        {
            // Порог “не зашумлять”: по умолчанию начинаем предлагать только когда подхостов реально много.
            const int defaultMinSubhosts = 4;
            const int defaultMinEntropy = 2;

            DomainFamilySuggestion? best = null;

            foreach (var kv in _statsBySuffix)
            {
                var suffix = kv.Key;
                var stats = kv.Value;

                int unique = stats.Subhosts.Count;
                int entropy = stats.EntropySubhosts.Count;

                int minSubhosts = IsPinned(suffix) ? 2 : defaultMinSubhosts;
                int minEntropy = IsPinned(suffix) ? 1 : defaultMinEntropy;

                if (unique < minSubhosts) continue;
                if (entropy < minEntropy) continue;

                // Выбираем «самую убедительную» подсказку.
                if (best == null || unique > best.UniqueSubhosts || (unique == best.UniqueSubhosts && entropy > best.EntropySubhosts))
                {
                    best = new DomainFamilySuggestion(suffix, unique, entropy);
                }
            }

            return best;
        }

        private void TryUpdateCatalog(DomainFamilySuggestion suggestion)
        {
            try
            {
                var now = DateTime.UtcNow;

                if (!_catalog.LearnedDomains.TryGetValue(suggestion.DomainSuffix, out var entry))
                {
                    entry = new LearnedDomainEntry
                    {
                        EvidenceCount = suggestion.UniqueSubhosts,
                        EntropyEvidenceCount = suggestion.EntropySubhosts,
                        Reason = "Авто: много вариативных подхостов (CDN/шардинг)",
                        FirstSeenUtc = now,
                        LastSeenUtc = now
                    };
                    _catalog.LearnedDomains[suggestion.DomainSuffix] = entry;
                }
                else
                {
                    entry.EvidenceCount = Math.Max(entry.EvidenceCount, suggestion.UniqueSubhosts);
                    entry.EntropyEvidenceCount = Math.Max(entry.EntropyEvidenceCount, suggestion.EntropySubhosts);
                    entry.LastSeenUtc = now;
                }

                // Не спамим диск.
                if (now - _lastPersistUtc < _persistMinInterval) return;
                _lastPersistUtc = now;

                DomainFamilyCatalog.TryPersist(_catalog, _log);
            }
            catch
            {
                // ignore
            }
        }

        private static bool TryGetBaseSuffix(string host, out string suffix)
        {
            suffix = "";
            try
            {
                var parts = host.Split('.');
                if (parts.Length < 2) return false;

                // MVP: берём последние 2 лейбла как базовый домен.
                // Для CDN/шардовых хостов этого достаточно, а более точный PSL добавим при необходимости.
                suffix = parts[^2] + "." + parts[^1];
                return suffix.Length >= 3;
            }
            catch
            {
                return false;
            }
        }

        private static bool LooksLikeShardSubhost(string host, string suffix)
        {
            try
            {
                // Мы не хардкодим CDN, но нам нужно отличать "www/api" от шардов.
                // Эвристика: у шардов часто есть цифры/дефисы/длинные токены в левых лейблах.
                var left = host;
                if (host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                {
                    left = host.Substring(0, host.Length - suffix.Length - 1);
                }

                // Берём самый левый лейбл (до первой точки) как основной маркер.
                var firstLabel = left.Split('.')[0];
                if (string.IsNullOrWhiteSpace(firstLabel)) return false;

                bool hasDigit = firstLabel.Any(char.IsDigit);
                bool hasDash = firstLabel.Contains('-');
                bool longToken = firstLabel.Length >= 12;

                // Доп. сигнал: если у подхоста много уровней (a.b.c.example.com), это чаще CDN/edge.
                int subdomainLevels = left.Count(c => c == '.') + 1;
                bool manyLevels = subdomainLevels >= 2;

                return (hasDigit || hasDash || longToken) && (manyLevels || firstLabel.Length >= 8);
            }
            catch
            {
                return false;
            }
        }
    }
}
