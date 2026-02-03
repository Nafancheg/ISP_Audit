using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Linq;
using System.Net;
using IspAudit.Core.Diagnostics;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        #region Private Methods

        private string NormalizeHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return host;
            host = SanitizeHostnameToken(host);
            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                return host.Substring(4);
            return host;
        }

        private static string SanitizeHostnameToken(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;

            var s = value.Trim();
            if (s.Length > 255) s = s.Substring(0, 255);

            // Срезаем хвост на первом невалидном символе.
            // Разрешаем только ASCII hostname: a-z, 0-9, '.', '-'
            int end = 0;
            for (; end < s.Length; end++)
            {
                char c = s[end];
                bool ok =
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '.' || c == '-';

                if (!ok) break;
            }

            var cleaned = end == s.Length ? s : s.Substring(0, end);
            cleaned = cleaned.Trim('.');

            return string.IsNullOrWhiteSpace(cleaned) ? s : cleaned;
        }

        private string SelectUiKey(string hostFromLine, string msg)
        {
            // 1) Если в сообщении есть SNI/DNS — это приоритетный пользовательский ключ.
            var sni = ExtractToken(msg, "SNI");
            if (!string.IsNullOrWhiteSpace(sni) && sni != "-")
            {
                var key = NormalizeHost(sni);
                TrackDomainCandidate(key);
                var collapsed = TryApplyDomainAggregation(key);
                return TryApplyDomainGroupAggregationAndTrackMembers(collapsed, memberKey: key);
            }

            // 2) Если host из строки — IP, но мы уже знаем сопоставление IP→SNI, используем его.
            if (IPAddress.TryParse(hostFromLine, out _) && _ipToUiKey.TryGetValue(hostFromLine, out var mapped))
            {
                var key = NormalizeHost(mapped);
                TrackDomainCandidate(key);
                var collapsed = TryApplyDomainAggregation(key);
                return TryApplyDomainGroupAggregationAndTrackMembers(collapsed, memberKey: key);
            }

            // 3) Иначе используем то, что пришло.
            var fallback = NormalizeHost(hostFromLine);
            TrackDomainCandidate(fallback);
            var collapsedFallback = TryApplyDomainAggregation(fallback);
            return TryApplyDomainGroupAggregationAndTrackMembers(collapsedFallback, memberKey: fallback);
        }

        private string TryApplyDomainGroupAggregationAndTrackMembers(string hostKey, string memberKey)
        {
            try
            {
                hostKey = NormalizeHost(hostKey);
                memberKey = NormalizeHost(memberKey);

                if (string.IsNullOrWhiteSpace(hostKey)) return hostKey;
                if (string.IsNullOrWhiteSpace(memberKey)) return hostKey;

                // IP адреса не агрегируем.
                if (IPAddress.TryParse(hostKey, out _)) return hostKey;

                // 1) Приоритет: явный pinning hostKey -> groupKey из state/group_participation.json.
                if (GroupBypassAttachmentStore != null && GroupBypassAttachmentStore.TryGetPinnedGroupKey(memberKey, out var pinned) && !string.IsNullOrWhiteSpace(pinned))
                {
                    var gk = NormalizeHost(pinned);
                    TrackAggregationMember(gk, memberKey);
                    TryUpdateAnchorDomainForGroupKeyBestEffort(gk, memberKey);
                    return gk;
                }

                // 2) Fallback: pinned/learned группы из каталога domain_groups.json.
                // Важно: ObserveHost делает O(1) lookup и обновляет CurrentSuggestion детерминированно.
                _ = _domainGroups.ObserveHost(memberKey);
                var sug = _domainGroups.CurrentSuggestion;
                if (sug != null && IsHostInSuggestedDomainGroup(memberKey))
                {
                    var gk = NormalizeHost(sug.GroupKey);
                    if (!string.IsNullOrWhiteSpace(gk))
                    {
                        TrackAggregationMember(gk, memberKey);
                        TryUpdateAnchorDomainForGroupKeyBestEffort(gk, memberKey);
                        return gk;
                    }
                }

                return hostKey;
            }
            catch
            {
                return hostKey;
            }
        }

        private void TrackAggregationMember(string uiKey, string memberKey)
        {
            try
            {
                uiKey = NormalizeHost(uiKey);
                memberKey = NormalizeHost(memberKey);
                if (string.IsNullOrWhiteSpace(uiKey) || string.IsNullOrWhiteSpace(memberKey)) return;

                var members = _aggregatedMembersByUiKey.GetOrAdd(uiKey, _ => new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase));
                _ = members.TryAdd(memberKey, 1);
            }
            catch
            {
                // ignore
            }
        }

        private int GetAggregatedMemberCount(string uiKey)
        {
            try
            {
                uiKey = NormalizeHost(uiKey);
                if (string.IsNullOrWhiteSpace(uiKey)) return 0;
                return _aggregatedMembersByUiKey.TryGetValue(uiKey, out var members) ? members.Count : 0;
            }
            catch
            {
                return 0;
            }
        }

        private void TryUpdateAnchorDomainForGroupKeyBestEffort(string groupKey, string memberKey)
        {
            try
            {
                groupKey = NormalizeHost(groupKey);
                memberKey = NormalizeHost(memberKey);
                if (string.IsNullOrWhiteSpace(groupKey)) return;
                if (string.IsNullOrWhiteSpace(memberKey)) return;

                // Если якорь уже известен — не трогаем.
                if (_groupKeyToAnchorDomain.TryGetValue(groupKey, out var existing) && !string.IsNullOrWhiteSpace(existing))
                {
                    return;
                }

                // 1) Если текущая подсказка совпадает по groupKey — выбираем якорь по memberKey.
                var sug = _domainGroups.CurrentSuggestion;
                if (sug != null && string.Equals(NormalizeHost(sug.GroupKey), groupKey, StringComparison.OrdinalIgnoreCase))
                {
                    if (_domainGroups.TryPickAnchorDomainForHost(memberKey, sug, out var anchor) && !string.IsNullOrWhiteSpace(anchor))
                    {
                        _groupKeyToAnchorDomain[groupKey] = NormalizeHost(anchor);
                        return;
                    }
                }

                // 2) Fallback: базовый суффикс memberKey.
                if (IspAudit.Utils.DomainUtils.TryGetBaseSuffix(memberKey, out var baseSuffix) && !string.IsNullOrWhiteSpace(baseSuffix))
                {
                    _groupKeyToAnchorDomain[groupKey] = NormalizeHost(baseSuffix);
                }
            }
            catch
            {
                // ignore
            }
        }

        private void TrackDomainCandidate(string hostKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(hostKey)) return;

                // P1.2: кросс-доменная группировка (pinned groups) — независима от доменных семейств.
                TrackDomainGroupCandidate(hostKey);

                var before = _domainFamilies.CurrentSuggestion?.DomainSuffix;
                var changed = _domainFamilies.ObserveHost(hostKey);
                var after = _domainFamilies.CurrentSuggestion?.DomainSuffix;

                if (!changed) return;

                OnPropertyChanged(nameof(SuggestedDomainSuffix));
                OnPropertyChanged(nameof(SuggestedDomainSubhostCount));
                OnPropertyChanged(nameof(CanSuggestDomainAggregation));

                // Если появилась новая подсказка (или сменилась) — схлопнем карточки для домена.
                if (!string.IsNullOrWhiteSpace(after) && !string.Equals(before, after, StringComparison.OrdinalIgnoreCase))
                {
                    CollapseDomainCards(after);
                }
            }
            catch
            {
                // ignore
            }
        }

        private string TryApplyDomainAggregation(string hostKey)
        {
            try
            {
                var suffix = _domainFamilies.CurrentSuggestion?.DomainSuffix;
                if (string.IsNullOrWhiteSpace(suffix)) return hostKey;
                if (string.IsNullOrWhiteSpace(hostKey)) return hostKey;

                if (hostKey.Equals(suffix, StringComparison.OrdinalIgnoreCase)) return suffix;

                if (hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                {
                    return suffix;
                }

                return hostKey;
            }
            catch
            {
                return hostKey;
            }
        }

        private void CollapseDomainCards(string domainSuffix)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domainSuffix)) return;

                // ObservableCollection должен меняться в UI потоке.
                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    var domainKey = NormalizeHost(domainSuffix);

                    // Находим/создаём доменную карточку.
                    var domainCard = TestResults.FirstOrDefault(t =>
                        string.Equals(NormalizeHost(t.Target.Host), domainKey, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(NormalizeHost(t.Target.Name), domainKey, StringComparison.OrdinalIgnoreCase));

                    // Собираем все карточки поддомена, кроме уже доменной.
                    var toMerge = TestResults
                        .Where(t =>
                        {
                            var key = NormalizeHost(t.Target.Host);
                            if (string.Equals(key, domainKey, StringComparison.OrdinalIgnoreCase)) return false;
                            return key.EndsWith("." + domainKey, StringComparison.OrdinalIgnoreCase);
                        })
                        .ToList();

                    foreach (var src in toMerge)
                    {
                        var srcKey = NormalizeHost(src.Target.Host);
                        MergeOutcomeHistoryKeys(srcKey, domainKey);

                        if (domainCard == null)
                        {
                            // Переименовываем первую попавшуюся карточку и делаем её доменной.
                            var old = src.Target;
                            src.Target = new Target
                            {
                                Name = domainKey,
                                Host = domainKey,
                                Service = old.Service,
                                Critical = old.Critical,
                                FallbackIp = old.FallbackIp,
                                SniHost = domainKey,
                                ReverseDnsHost = old.ReverseDnsHost
                            };
                            domainCard = src;
                            continue;
                        }

                        // Сливаем статусы/детали/стратегию.
                        domainCard.Status = MergeStatus(domainCard.Status, src.Status);

                        if (!string.IsNullOrWhiteSpace(src.Error) && string.IsNullOrWhiteSpace(domainCard.Error))
                        {
                            domainCard.Error = src.Error;
                        }

                        if (!string.IsNullOrWhiteSpace(src.Details) && (string.IsNullOrWhiteSpace(domainCard.Details) || !domainCard.Details.Contains(src.Details, StringComparison.OrdinalIgnoreCase)))
                        {
                            domainCard.Details = string.IsNullOrWhiteSpace(domainCard.Details)
                                ? src.Details
                                : domainCard.Details + "\n" + src.Details;
                        }

                        if (!string.IsNullOrWhiteSpace(src.BypassStrategy) && string.IsNullOrWhiteSpace(domainCard.BypassStrategy))
                        {
                            domainCard.BypassStrategy = src.BypassStrategy;
                            domainCard.IsBypassStrategyFromIntel = src.IsBypassStrategyFromIntel;
                        }
                        else if (src.IsBypassStrategyFromIntel)
                        {
                            domainCard.IsBypassStrategyFromIntel = true;
                        }

                        if (!string.IsNullOrWhiteSpace(src.AppliedBypassStrategy) && string.IsNullOrWhiteSpace(domainCard.AppliedBypassStrategy))
                        {
                            domainCard.AppliedBypassStrategy = src.AppliedBypassStrategy;
                        }

                        domainCard.PostApplyCheckStatus = MergePostApplyCheckStatus(domainCard.PostApplyCheckStatus, src.PostApplyCheckStatus);

                        if (src.PostApplyCheckAtUtc.HasValue
                            && (!domainCard.PostApplyCheckAtUtc.HasValue || src.PostApplyCheckAtUtc > domainCard.PostApplyCheckAtUtc))
                        {
                            domainCard.PostApplyCheckAtUtc = src.PostApplyCheckAtUtc;
                            domainCard.PostApplyCheckDetails = src.PostApplyCheckDetails;
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

        private TestStatus ApplyUnstableRule(string normalizedKey, TestStatus incoming)
        {
            var now = DateTime.UtcNow;
            var history = _outcomeHistoryByKey.GetOrAdd(normalizedKey, _ => new OutcomeHistory(DateTime.MinValue, DateTime.MinValue));

            var lastPass = history.LastPassUtc;
            var lastProblem = history.LastProblemUtc;

            if (incoming == TestStatus.Pass)
            {
                lastPass = now;
            }

            if (incoming == TestStatus.Fail || incoming == TestStatus.Warn)
            {
                lastProblem = now;
            }

            _outcomeHistoryByKey[normalizedKey] = new OutcomeHistory(lastPass, lastProblem);

            var hasRecentPass = lastPass != DateTime.MinValue && now - lastPass <= UnstableWindow;
            var hasRecentProblem = lastProblem != DateTime.MinValue && now - lastProblem <= UnstableWindow;

            // Детерминированное правило "Нестабильно": если в окне есть и успех, и проблема (Fail/Warn)
            // — показываем Warn, даже если текущий входящий статус Pass.
            if (hasRecentPass && hasRecentProblem)
            {
                return TestStatus.Warn;
            }

            // Если сейчас пришла проблема, но в недавнем окне был успех — это плавающая/частичная проблема.
            if ((incoming == TestStatus.Fail || incoming == TestStatus.Warn) && hasRecentPass)
            {
                return TestStatus.Warn;
            }

            return incoming;
        }

        private static PostApplyCheckStatus MergePostApplyCheckStatus(PostApplyCheckStatus a, PostApplyCheckStatus b)
        {
            if (a == PostApplyCheckStatus.None) return b;
            if (b == PostApplyCheckStatus.None) return a;

            bool IsFinal(PostApplyCheckStatus s)
                => s is PostApplyCheckStatus.Ok or PostApplyCheckStatus.Fail or PostApplyCheckStatus.Partial or PostApplyCheckStatus.Unknown;

            if (IsFinal(a) && IsFinal(b))
            {
                if (a == b) return a;
                if (a == PostApplyCheckStatus.Partial || b == PostApplyCheckStatus.Partial) return PostApplyCheckStatus.Partial;
                if ((a == PostApplyCheckStatus.Ok && b == PostApplyCheckStatus.Fail) || (a == PostApplyCheckStatus.Fail && b == PostApplyCheckStatus.Ok))
                {
                    return PostApplyCheckStatus.Partial;
                }

                // Любая смесь с Unknown считаем частичной картиной.
                return PostApplyCheckStatus.Partial;
            }

            if (IsFinal(a)) return a;
            if (IsFinal(b)) return b;

            // Оба не финальные: Running > Queued > NotChecked
            if (a == PostApplyCheckStatus.Running || b == PostApplyCheckStatus.Running) return PostApplyCheckStatus.Running;
            if (a == PostApplyCheckStatus.Queued || b == PostApplyCheckStatus.Queued) return PostApplyCheckStatus.Queued;
            if (a == PostApplyCheckStatus.NotChecked || b == PostApplyCheckStatus.NotChecked) return PostApplyCheckStatus.NotChecked;
            return PostApplyCheckStatus.Unknown;
        }

        private void TryMigrateIpCardToNameKey(string ip, string nameKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(nameKey)) return;
                if (!IPAddress.TryParse(ip, out _)) return;

                // P1.9: миграция должна учитывать агрегацию по groupKey,
                // иначе возможны дубликаты (youtube.com + group-youtube) и стратегия будет назначаться «не той» карточке.
                nameKey = NormalizeHost(nameKey);
                if (IPAddress.TryParse(nameKey, out _)) return;

                // Вычисляем финальный UI-ключ с учётом доменных семейств и domain groups.
                // Важно: memberKey оставляем исходным user-facing доменом (youtube.com),
                // чтобы можно было подобрать якорь для groupKey.
                TrackDomainCandidate(nameKey);
                var collapsed = TryApplyDomainAggregation(nameKey);
                var uiKey = TryApplyDomainGroupAggregationAndTrackMembers(collapsed, memberKey: nameKey);
                uiKey = NormalizeHost(uiKey);
                if (string.IsNullOrWhiteSpace(uiKey) || IPAddress.TryParse(uiKey, out _))
                {
                    uiKey = nameKey;
                }

                // Переносим историю исходов на человеко‑понятный ключ.
                // Иначе: Fail мог быть записан на IP, а Pass уже придёт на hostname → UI покажет "Доступно" вместо "Нестабильно".
                MergeOutcomeHistoryKeys(ip, uiKey);

                var ipCard = TestResults.FirstOrDefault(t => t.Target.Host == ip || t.Target.FallbackIp == ip);
                if (ipCard == null) return;

                var normalizedName = NormalizeHost(uiKey);
                var nameCard = TestResults.FirstOrDefault(t =>
                    NormalizeHost(t.Target.Host).Equals(normalizedName, StringComparison.OrdinalIgnoreCase) ||
                    NormalizeHost(t.Target.Name).Equals(normalizedName, StringComparison.OrdinalIgnoreCase));

                if (nameCard == null)
                {
                    var anchor = string.Empty;
                    if (_groupKeyToAnchorDomain.TryGetValue(normalizedName, out var cachedAnchor) && !string.IsNullOrWhiteSpace(cachedAnchor))
                    {
                        anchor = NormalizeHost(cachedAnchor);
                    }

                    // Переименовываем существующую карточку (IP → hostname) и сохраняем IP в FallbackIp.
                    var old = ipCard.Target;
                    ipCard.UiKey = normalizedName;
                    ipCard.Target = new Target
                    {
                        // Если uiKey — groupKey, то Name хранит groupKey, а Host/SniHost — якорный домен.
                        Name = uiKey,
                        Host = string.IsNullOrWhiteSpace(anchor) ? uiKey : anchor,
                        Service = old.Service,
                        Critical = old.Critical,
                        FallbackIp = string.IsNullOrWhiteSpace(old.FallbackIp) ? ip : old.FallbackIp,
                        SniHost = string.IsNullOrWhiteSpace(old.SniHost)
                            ? (string.IsNullOrWhiteSpace(anchor) ? uiKey : anchor)
                            : old.SniHost,
                        ReverseDnsHost = old.ReverseDnsHost
                    };
                    return;
                }

                // Если карточка по имени уже существует — сливаем и удаляем IP-карточку.
                if (string.IsNullOrWhiteSpace(nameCard.Target.FallbackIp))
                {
                    var old = nameCard.Target;
                    nameCard.Target = new Target
                    {
                        Name = old.Name,
                        Host = old.Host,
                        Service = old.Service,
                        Critical = old.Critical,
                        FallbackIp = ip,
                        SniHost = old.SniHost,
                        ReverseDnsHost = old.ReverseDnsHost
                    };
                }

                // Берём более «плохой» статус как базовый.
                var mergedStatus = MergeStatus(nameCard.Status, ipCard.Status);
                nameCard.Status = mergedStatus;

                if (!string.IsNullOrWhiteSpace(ipCard.Details) && (string.IsNullOrWhiteSpace(nameCard.Details) || !nameCard.Details.Contains(ipCard.Details, StringComparison.OrdinalIgnoreCase)))
                {
                    nameCard.Details = string.IsNullOrWhiteSpace(nameCard.Details)
                        ? ipCard.Details
                        : nameCard.Details + "\n" + ipCard.Details;
                }

                if (!string.IsNullOrWhiteSpace(ipCard.Error) && string.IsNullOrWhiteSpace(nameCard.Error))
                {
                    nameCard.Error = ipCard.Error;
                }

                TestResults.Remove(ipCard);
                NotifyCountersChanged();
            }
            catch
            {
            }
        }

        private void MergeOutcomeHistoryKeys(string fromKey, string toKey)
        {
            try
            {
                fromKey = NormalizeHost(fromKey);
                toKey = NormalizeHost(toKey);

                if (string.IsNullOrWhiteSpace(fromKey) || string.IsNullOrWhiteSpace(toKey)) return;
                if (fromKey.Equals(toKey, StringComparison.OrdinalIgnoreCase)) return;

                if (!_outcomeHistoryByKey.TryGetValue(fromKey, out var fromHistory))
                {
                    return;
                }

                var toHistory = _outcomeHistoryByKey.GetOrAdd(toKey, _ => new OutcomeHistory(DateTime.MinValue, DateTime.MinValue));

                var merged = new OutcomeHistory(
                    LastPassUtc: fromHistory.LastPassUtc > toHistory.LastPassUtc ? fromHistory.LastPassUtc : toHistory.LastPassUtc,
                    LastProblemUtc: fromHistory.LastProblemUtc > toHistory.LastProblemUtc ? fromHistory.LastProblemUtc : toHistory.LastProblemUtc);

                _outcomeHistoryByKey[toKey] = merged;

                // Удаляем исходный ключ, чтобы не копить мусор.
                _outcomeHistoryByKey.TryRemove(fromKey, out _);
            }
            catch
            {
            }
        }

        private static TestStatus MergeStatus(TestStatus a, TestStatus b)
        {
            // Доменные семейства часто дают смесь успехов и ошибок по подхостам.
            // Pass+Fail трактуем как Warn, чтобы не показывать "полную недоступность" при частичном успехе.
            if ((a == TestStatus.Fail && b == TestStatus.Pass) || (a == TestStatus.Pass && b == TestStatus.Fail))
            {
                return TestStatus.Warn;
            }

            if (a == TestStatus.Fail || b == TestStatus.Fail) return TestStatus.Fail;
            if (a == TestStatus.Warn || b == TestStatus.Warn) return TestStatus.Warn;
            if (a == TestStatus.Running || b == TestStatus.Running) return TestStatus.Running;
            if (a == TestStatus.Pass || b == TestStatus.Pass) return TestStatus.Pass;
            return TestStatus.Idle;
        }

        private void Log(string message)
        {
            OnLog?.Invoke(message);
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
