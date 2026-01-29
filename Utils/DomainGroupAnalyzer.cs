using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Utils
{
    public sealed record DomainGroupSuggestion(
        string GroupKey,
        string DisplayName,
        string AnchorDomain,
        IReadOnlyList<string> Domains,
        string Reason);

    /// <summary>
    /// Анализатор групп доменов (P1.2): объединяет несколько базовых доменов в одну UX-группу.
    /// На этом этапе (Quick Win) поддерживаются pinned-группы из внешнего каталога.
    /// Advanced авто-обучение можно добавить поверх (co-occurrence PID/IP).
    /// </summary>
    public sealed class DomainGroupAnalyzer
    {
        private readonly DomainGroupCatalogState _catalog;
        private readonly Action<string>? _log;
        private readonly Dictionary<string, DomainGroupSuggestion> _suggestionByBaseSuffix;

        public DomainGroupSuggestion? CurrentSuggestion { get; private set; }

        public DomainGroupAnalyzer(DomainGroupCatalogState catalog, Action<string>? log = null)
        {
            _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
            _log = log;
            _suggestionByBaseSuffix = BuildPinnedIndex(_catalog);
        }

        public void Reset()
        {
            CurrentSuggestion = null;
        }

        public bool ObserveHost(string hostKey)
        {
            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (hk.Length == 0) return false;

                if (!DomainUtils.TryGetBaseSuffix(hk, out var baseSuffix))
                {
                    return false;
                }

                var next = PickSuggestionByBaseSuffix(baseSuffix);

                bool changed = !string.Equals(CurrentSuggestion?.GroupKey ?? string.Empty, next?.GroupKey ?? string.Empty, StringComparison.OrdinalIgnoreCase);
                CurrentSuggestion = next;
                return changed;
            }
            catch
            {
                return false;
            }
        }

        public bool IsHostInGroup(string hostKey, DomainGroupEntry group)
        {
            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (hk.Length == 0) return false;

                // Нормализуем до базового суффикса.
                if (!DomainUtils.TryGetBaseSuffix(hk, out var baseSuffix))
                {
                    // Если hostKey уже является базовым доменом, TryGetBaseSuffix вернёт его же.
                    // Но на всякий случай поддержим прямой матч.
                    baseSuffix = hk;
                }

                return (group.Domains ?? new List<string>())
                    .Any(d => d.Equals(baseSuffix, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        public bool TryPickAnchorDomainForHost(string hostKey, DomainGroupSuggestion suggestion, out string anchor)
        {
            anchor = suggestion.AnchorDomain;

            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (hk.Length == 0) return false;

                if (!DomainUtils.TryGetBaseSuffix(hk, out var baseSuffix))
                {
                    baseSuffix = hk;
                }

                var match = suggestion.Domains.FirstOrDefault(d => d.Equals(baseSuffix, StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(match))
                {
                    anchor = match;
                    return true;
                }

                return !string.IsNullOrWhiteSpace(anchor);
            }
            catch
            {
                return !string.IsNullOrWhiteSpace(anchor);
            }
        }

        private DomainGroupSuggestion? PickSuggestionByBaseSuffix(string baseSuffix)
        {
            try
            {
                baseSuffix = (baseSuffix ?? string.Empty).Trim().Trim('.');
                if (baseSuffix.Length == 0) return null;

                // 1) Pinned groups (O(1) lookup)
                if (_suggestionByBaseSuffix.TryGetValue(baseSuffix, out var pinned))
                {
                    return pinned;
                }

                // 2) Learned groups (advanced, не включаем без явной логики/скоринга)
                return null;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[DomainGroups] Ошибка выбора подсказки: {ex.Message}");
                return null;
            }
        }

        private static Dictionary<string, DomainGroupSuggestion> BuildPinnedIndex(DomainGroupCatalogState catalog)
        {
            var index = new Dictionary<string, DomainGroupSuggestion>(StringComparer.OrdinalIgnoreCase);

            try
            {
                foreach (var g in catalog.PinnedGroups ?? Enumerable.Empty<DomainGroupEntry>())
                {
                    var key = (g.Key ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(key)) continue;

                    var domains = (g.Domains ?? new List<string>())
                        .Select(d => (d ?? string.Empty).Trim().Trim('.'))
                        .Where(d => !string.IsNullOrWhiteSpace(d))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
                    if (domains.Count == 0) continue;

                    var display = string.IsNullOrWhiteSpace(g.DisplayName) ? key : g.DisplayName.Trim();
                    var anchor = domains[0];

                    var suggestion = new DomainGroupSuggestion(
                        GroupKey: key,
                        DisplayName: display,
                        AnchorDomain: anchor,
                        Domains: domains,
                        Reason: "Pinned group (каталог)"
                    );

                    // Если один и тот же домен попал в несколько групп — берём первую (детерминизм по порядку в JSON).
                    foreach (var d in domains)
                    {
                        if (!index.ContainsKey(d))
                        {
                            index[d] = suggestion;
                        }
                    }
                }
            }
            catch
            {
                // best-effort
            }

            return index;
        }
    }
}
