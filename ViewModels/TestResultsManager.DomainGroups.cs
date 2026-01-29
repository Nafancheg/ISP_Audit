using System;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        public bool IsHostInSuggestedDomainGroup(string hostKey)
        {
            try
            {
                var sug = _domainGroups.CurrentSuggestion;
                if (sug == null) return false;

                if (!DomainUtils.TryGetBaseSuffix(hostKey, out var baseSuffix))
                {
                    baseSuffix = (hostKey ?? string.Empty).Trim().Trim('.');
                }

                if (string.IsNullOrWhiteSpace(baseSuffix)) return false;
                return sug.Domains.Any(d => d.Equals(baseSuffix, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        public bool TryGetSuggestedGroupAnchorForHostKey(string hostKey, out string anchorDomain)
        {
            anchorDomain = string.Empty;

            try
            {
                var sug = _domainGroups.CurrentSuggestion;
                if (sug == null) return false;

                if (_domainGroups.TryPickAnchorDomainForHost(hostKey, sug, out var picked))
                {
                    anchorDomain = picked;
                    return !string.IsNullOrWhiteSpace(anchorDomain);
                }

                anchorDomain = sug.AnchorDomain;
                return !string.IsNullOrWhiteSpace(anchorDomain);
            }
            catch
            {
                return false;
            }
        }

        private void TrackDomainGroupCandidate(string hostKey)
        {
            try
            {
                var before = _domainGroups.CurrentSuggestion?.GroupKey;
                var changed = _domainGroups.ObserveHost(hostKey);
                var after = _domainGroups.CurrentSuggestion?.GroupKey;

                if (!changed) return;

                OnPropertyChanged(nameof(SuggestedDomainGroupKey));
                OnPropertyChanged(nameof(SuggestedDomainGroupDisplayName));
                OnPropertyChanged(nameof(SuggestedDomainGroupAnchorDomain));
                OnPropertyChanged(nameof(SuggestedDomainGroupDomains));
                OnPropertyChanged(nameof(CanSuggestDomainGroup));

                // Если появилась новая подсказка — схлопнем карточки по группе.
                if (!string.IsNullOrWhiteSpace(after) && !string.Equals(before, after, StringComparison.OrdinalIgnoreCase))
                {
                    CollapseDomainGroupCardsBestEffort();
                }
            }
            catch
            {
                // ignore
            }
        }

        private void CollapseDomainGroupCardsBestEffort()
        {
            try
            {
                var sug = _domainGroups.CurrentSuggestion;
                if (sug == null) return;

                var groupKey = NormalizeHost(sug.GroupKey);
                if (string.IsNullOrWhiteSpace(groupKey)) return;

                var domains = (sug.Domains ?? Array.Empty<string>())
                    .Select(d => NormalizeHost(d))
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (domains.Count == 0) return;

                var anchor = string.IsNullOrWhiteSpace(sug.AnchorDomain) ? domains[0] : NormalizeHost(sug.AnchorDomain);

                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    // Находим/создаём групповую карточку.
                    var groupCard = TestResults.FirstOrDefault(t =>
                        string.Equals(NormalizeHost(t.Target.Name), groupKey, StringComparison.OrdinalIgnoreCase));

                    // Собираем карточки всех доменов группы (по suffix), кроме уже групповой.
                    var toMerge = TestResults
                        .Where(t =>
                        {
                            if (t?.Target == null) return false;
                            if (string.Equals(NormalizeHost(t.Target.Name), groupKey, StringComparison.OrdinalIgnoreCase)) return false;

                            var hk = NormalizeHost(t.Target.Host);
                            if (string.IsNullOrWhiteSpace(hk)) return false;

                            // Матчим либо базовый домен, либо поддомен базового домена.
                            foreach (var d in domains)
                            {
                                if (hk.Equals(d, StringComparison.OrdinalIgnoreCase)) return true;
                                if (hk.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)) return true;
                            }

                            return false;
                        })
                        .ToList();

                    if (toMerge.Count == 0) return;

                    foreach (var src in toMerge)
                    {
                        var srcKey = NormalizeHost(src.Target.Host);
                        MergeOutcomeHistoryKeys(srcKey, groupKey);

                        if (groupCard == null)
                        {
                            // Переименовываем первую карточку в групповую.
                            var old = src.Target;
                            src.Target = new Target
                            {
                                Name = groupKey,
                                Host = anchor,
                                Service = old.Service,
                                Critical = old.Critical,
                                FallbackIp = old.FallbackIp,
                                SniHost = anchor,
                                ReverseDnsHost = old.ReverseDnsHost
                            };
                            groupCard = src;
                            continue;
                        }

                        groupCard.Status = MergeStatus(groupCard.Status, src.Status);

                        if (!string.IsNullOrWhiteSpace(src.Error) && string.IsNullOrWhiteSpace(groupCard.Error))
                        {
                            groupCard.Error = src.Error;
                        }

                        if (!string.IsNullOrWhiteSpace(src.Details) && (string.IsNullOrWhiteSpace(groupCard.Details) || !groupCard.Details.Contains(src.Details, StringComparison.OrdinalIgnoreCase)))
                        {
                            groupCard.Details = string.IsNullOrWhiteSpace(groupCard.Details)
                                ? src.Details
                                : groupCard.Details + "\n" + src.Details;
                        }

                        if (!string.IsNullOrWhiteSpace(src.BypassStrategy) && string.IsNullOrWhiteSpace(groupCard.BypassStrategy))
                        {
                            groupCard.BypassStrategy = src.BypassStrategy;
                            groupCard.IsBypassStrategyFromIntel = src.IsBypassStrategyFromIntel;
                        }
                        else if (src.IsBypassStrategyFromIntel)
                        {
                            groupCard.IsBypassStrategyFromIntel = true;
                        }

                        if (!string.IsNullOrWhiteSpace(src.AppliedBypassStrategy) && string.IsNullOrWhiteSpace(groupCard.AppliedBypassStrategy))
                        {
                            groupCard.AppliedBypassStrategy = src.AppliedBypassStrategy;
                        }

                        TestResults.Remove(src);
                    }

                    NotifyCountersChanged();
                });
            }
            catch
            {
                // ignore
            }
        }
    }
}
