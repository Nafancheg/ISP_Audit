using System;
using System.Linq;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        private int _domainPinsVersion;
        public int DomainPinsVersion => _domainPinsVersion;

        public bool IsDomainPinned(string? domainSuffix)
        {
            try
            {
                var s = (domainSuffix ?? string.Empty).Trim().Trim('.');
                if (s.Length == 0) return false;
                return _domainFamilies.IsPinned(s);
            }
            catch
            {
                return false;
            }
        }

        public bool TogglePinnedDomain(string? domainSuffix)
        {
            try
            {
                var s = (domainSuffix ?? string.Empty).Trim().Trim('.');
                if (s.Length == 0) return false;

                bool isPinned = _domainCatalog.PinnedDomains.Any(d => d.Equals(s, StringComparison.OrdinalIgnoreCase));

                if (isPinned)
                {
                    _domainCatalog.PinnedDomains = _domainCatalog.PinnedDomains
                        .Where(d => !d.Equals(s, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                }
                else
                {
                    _domainCatalog.PinnedDomains.Add(s);
                }

                DomainFamilyCatalog.TryPersist(_domainCatalog, Log);

                // При изменении pinned нам важно пересчитать подсказку даже без новых host-событий.
                var changed = _domainFamilies.ForceRecomputeSuggestion();

                _domainPinsVersion++;
                OnPropertyChanged(nameof(DomainPinsVersion));

                if (changed)
                {
                    OnPropertyChanged(nameof(SuggestedDomainSuffix));
                    OnPropertyChanged(nameof(SuggestedDomainSubhostCount));
                    OnPropertyChanged(nameof(CanSuggestDomainAggregation));

                    var suffix = _domainFamilies.CurrentSuggestion?.DomainSuffix;
                    if (!string.IsNullOrWhiteSpace(suffix))
                    {
                        CollapseDomainCards(suffix);
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool TryGetPinCandidateFromHostKey(string? hostKey, out string domainSuffix)
        {
            domainSuffix = string.Empty;

            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (hk.Length == 0) return false;

                if (DomainUtils.TryGetBaseSuffix(hk, out var baseSuffix))
                {
                    domainSuffix = baseSuffix;
                    return !string.IsNullOrWhiteSpace(domainSuffix);
                }

                return false;
            }
            catch
            {
                domainSuffix = string.Empty;
                return false;
            }
        }
    }
}
