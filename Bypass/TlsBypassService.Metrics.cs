using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic.Filters;

namespace IspAudit.Bypass
{
    public partial class TlsBypassService
    {
        private async Task PullMetricsAsync()
        {
            try
            {
                BypassFilter? filter;
                TlsBypassOptions options;
                DateTime since;
                DecisionGraphSnapshot? decisionSnapshot;

                lock (_sync)
                {
                    filter = _filter;
                    options = _options;
                    since = _metricsSince;
                    decisionSnapshot = _decisionGraphSnapshot;
                }

                if (filter == null)
                {
                    MetricsUpdated?.Invoke(TlsBypassMetrics.Empty);
                    VerdictChanged?.Invoke(TlsBypassVerdict.CreateInactive());
                    return;
                }

                var snapshot = filter.GetMetrics();

                string semanticGroupsText = string.Empty;
                string semanticGroupsSummary = string.Empty;
                if (decisionSnapshot != null)
                {
                    var matchedCounts = filter.GetPolicyMatchedCountsSnapshot();
                    var sg = BuildSemanticGroupsStatus(decisionSnapshot, matchedCounts);
                    semanticGroupsText = sg.Details;
                    semanticGroupsSummary = sg.Summary;
                }

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
                    MinChunk = (options.FragmentSizes ?? Array.Empty<int>()).DefaultIfEmpty(0).Min(),
                    SemanticGroupsStatusText = semanticGroupsText,
                    SemanticGroupsSummaryText = semanticGroupsSummary
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

        private static (string Summary, string Details) BuildSemanticGroupsStatus(
            DecisionGraphSnapshot snapshot,
            IReadOnlyDictionary<string, long> policyMatchedCounts)
        {
            if (snapshot == null) return (string.Empty, string.Empty);

            // MVP Stage 5.3: дефолтные группы строим из policy-id, которые создаёт BypassStateManager.
            // Это даёт пользователю видимость: есть ли трафик, который вообще попадает в policy-driven ветку.
            var groups = new (string GroupKey, string DisplayName, string[] PolicyIds)[]
            {
                ("tls_tcp443", "TLS@443 (ClientHello)", new[] { "tcp443_tls_clienthello_strategy" }),
                ("udp443", "QUIC→TCP (UDP/443 drop)", new[] { "udp443_quic_fallback_selective" }),
                ("tcp80", "HTTP Host tricks (TCP/80)", new[] { "tcp80_http_host_tricks" })
            };

            var lines = new List<string>();
            var summaryParts = new List<string>();

            foreach (var g in groups)
            {
                var bundle = snapshot.Policies
                    .Where(p => p != null && !string.IsNullOrWhiteSpace(p.Id) && g.PolicyIds.Contains(p.Id, StringComparer.Ordinal))
                    .ToImmutableArray();

                if (bundle.IsDefaultOrEmpty)
                {
                    continue;
                }

                var group = new SemanticGroup
                {
                    GroupKey = g.GroupKey,
                    DisplayName = g.DisplayName,
                    DomainPatterns = ImmutableArray<string>.Empty,
                    PolicyBundle = bundle
                };

                var status = SemanticGroupEvaluator.EvaluateStatus(group, policyMatchedCounts);
                lines.Add($"{g.DisplayName}: {status.Text} ({status.Details})");
                summaryParts.Add($"{g.DisplayName}={status.Text}");
            }

            if (lines.Count == 0)
            {
                return (string.Empty, string.Empty);
            }

            var details = "Semantic Groups:\n" + string.Join("\n", lines);
            var summary = "SG: " + string.Join("; ", summaryParts);
            return (summary, details);
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
    }
}
