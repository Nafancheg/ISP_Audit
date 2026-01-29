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

        public DomainGroupSuggestion? CurrentSuggestion { get; private set; }

        public DomainGroupAnalyzer(DomainGroupCatalogState catalog, Action<string>? log = null)
        {
            _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
            _log = log;
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

                // 1) Pinned groups
                foreach (var g in _catalog.PinnedGroups ?? Enumerable.Empty<DomainGroupEntry>())
                {
                    if (g.Domains == null || g.Domains.Count == 0) continue;
                    if (!g.Domains.Any(d => d.Equals(baseSuffix, StringComparison.OrdinalIgnoreCase))) continue;

                    var display = string.IsNullOrWhiteSpace(g.DisplayName) ? g.Key : g.DisplayName;
                    var anchor = g.Domains[0];
                    return new DomainGroupSuggestion(
                        GroupKey: g.Key,
                        DisplayName: display,
                        AnchorDomain: anchor,
                        Domains: g.Domains,
                        Reason: "Pinned group (каталог)"
                    );
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
    }
}
