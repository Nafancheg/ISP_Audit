using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Windows;
using IspAudit;
using System.Windows.Media;
using System.Net;
using IspAudit.Core.Intelligence.Feedback;
using IspAudit.Models;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Оркестратор диагностики.
    /// Координирует TrafficCollector и LiveTestingPipeline.
    /// Управляет жизненным циклом мониторинговых сервисов.
    /// </summary>
    public partial class DiagnosticOrchestrator : INotifyPropertyChanged
    {
        #region Recommendations (Apply)

        private const int PostApplyBaselineFreshnessTtlSecondsDefault = 60;
        private const int PostApplyBaselineSampleCountDefault = 3;
        private const int PostApplyBaselineProbeTimeoutSeconds = 3;
        private const int PostApplyGuardrailSampleMDefault = 3;
        private const int PostApplyGuardrailSuccessKDefault = 2;
        private const int PostApplyOutcomeProbeTimeoutSecondsDefault = 6;
        private const int PostApplyEnqueueWarmupMsDefault = 350;
        private const int PostApplyLocalDrainTimeoutSecondsDefault = 15;
        private const int PostApplyRetestMaxConcurrentTestsDefault = 5;
        private static readonly TimeSpan BlacklistTtlMin = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan BlacklistTtlMax = TimeSpan.FromHours(6);

        private readonly record struct LatchedPostApplyPolicy(
            int BaselineSampleCount,
            TimeSpan BaselineProbeTimeout,
            TimeSpan BaselineFreshnessTtl,
            int GuardrailSampleM,
            int GuardrailSuccessK,
            TimeSpan OutcomeProbeTimeout,
            TimeSpan EnqueueWarmupDelay,
            TimeSpan LocalDrainTimeout,
            int RetestMaxConcurrentTests,
            string EvaluationOrder,
            DateTime CapturedAtUtc);

        private sealed record PendingFeedbackContext(
            BypassPlan Plan,
            DateTimeOffset AppliedAtUtc,
            string RunId,
            string ScopeKey,
            string PlanSig,
            string DeltaStep,
            string ActionSource,
            DateTimeOffset BaselineCapturedAtUtc,
            int BaselineSuccessCount,
            int BaselineSampleCount,
            LatchedPostApplyPolicy Policy);

        private readonly ConcurrentDictionary<string, PendingFeedbackContext> _pendingFeedbackByHostKey = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string> _activePostApplyRunByScopeKey = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _blacklistSync = new();
        private Dictionary<string, ApplyActionBlacklistStore.BlacklistEntry>? _blacklistByKey;

        private Dictionary<string, ApplyActionBlacklistStore.BlacklistEntry> GetBlacklistSnapshot()
        {
            lock (_blacklistSync)
            {
                if (_blacklistByKey == null)
                {
                    _blacklistByKey = ApplyActionBlacklistStore.LoadByKeyBestEffort(Log);
                }

                return _blacklistByKey;
            }
        }

        private static DateTimeOffset ParseUtcOrMin(string? value)
            => DateTimeOffset.TryParse(value, out var dt) ? dt : DateTimeOffset.MinValue;

        private void LogPolicyEvent(
            string eventName,
            string? runId,
            string? scopeKey,
            string? planSig,
            string? reasonCode,
            string? details = null)
        {
            static string Sanitize(string? value)
            {
                var s = (value ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(s)) return "-";
                return s.Replace(";", ",", StringComparison.Ordinal);
            }

            var evt = Sanitize(eventName);
            var rid = Sanitize(runId);
            var scope = Sanitize(scopeKey);
            var sig = Sanitize(planSig);
            var reason = Sanitize(reasonCode);
            var extra = Sanitize(details);

            Log($"[POLICY_EVT] event={evt}; runId={rid}; scopeKey={scope}; planSig={sig}; reasonCode={reason}; details={extra}");
        }

        private LatchedPostApplyPolicy CaptureLatchedPostApplyPolicy()
        {
            var sampleM = Math.Max(1, PostApplyGuardrailSampleMDefault);
            var successK = Math.Max(1, Math.Min(PostApplyGuardrailSuccessKDefault, sampleM));
            var baselineSampleCount = Math.Max(1, PostApplyBaselineSampleCountDefault);

            var latched = new LatchedPostApplyPolicy(
                BaselineSampleCount: baselineSampleCount,
                BaselineProbeTimeout: TimeSpan.FromSeconds(Math.Max(1, PostApplyBaselineProbeTimeoutSeconds)),
                BaselineFreshnessTtl: TimeSpan.FromSeconds(Math.Max(1, PostApplyBaselineFreshnessTtlSecondsDefault)),
                GuardrailSampleM: sampleM,
                GuardrailSuccessK: successK,
                OutcomeProbeTimeout: TimeSpan.FromSeconds(Math.Max(1, PostApplyOutcomeProbeTimeoutSecondsDefault)),
                EnqueueWarmupDelay: TimeSpan.FromMilliseconds(Math.Max(0, PostApplyEnqueueWarmupMsDefault)),
                LocalDrainTimeout: TimeSpan.FromSeconds(Math.Max(1, PostApplyLocalDrainTimeoutSecondsDefault)),
                RetestMaxConcurrentTests: Math.Max(1, PostApplyRetestMaxConcurrentTestsDefault),
                EvaluationOrder: "sni_first_then_ip_fallback",
                CapturedAtUtc: DateTime.UtcNow);

            Log($"[PostApplyPolicy] Latched: baselineAttempts={latched.BaselineSampleCount}; baselineProbeTimeoutMs={(int)latched.BaselineProbeTimeout.TotalMilliseconds}; baselineFreshTtlMs={(int)latched.BaselineFreshnessTtl.TotalMilliseconds}; guardrail={latched.GuardrailSuccessK}of{latched.GuardrailSampleM}; outcomeProbeTimeoutMs={(int)latched.OutcomeProbeTimeout.TotalMilliseconds}; enqueueWarmupMs={(int)latched.EnqueueWarmupDelay.TotalMilliseconds}; localDrainTimeoutMs={(int)latched.LocalDrainTimeout.TotalMilliseconds}; maxConcurrency={latched.RetestMaxConcurrentTests}; order={latched.EvaluationOrder}; capturedAt={latched.CapturedAtUtc:O}");

            return latched;
        }

        private bool IsBlacklisted(string scopeKey, string planSig, string deltaStep, string reason, out ApplyActionBlacklistStore.BlacklistEntry? entry)
        {
            entry = null;
            var key = ApplyActionBlacklistStore.BuildKey(scopeKey, planSig, deltaStep, reason);
            var now = DateTimeOffset.UtcNow;

            lock (_blacklistSync)
            {
                var map = GetBlacklistSnapshot();
                if (!map.TryGetValue(key, out var found) || found == null)
                {
                    return false;
                }

                var expiresAt = ParseUtcOrMin(found.ExpiresAtUtc);
                if (expiresAt <= now)
                {
                    map.Remove(key);
                    ApplyActionBlacklistStore.PersistByKeyBestEffort(map, Log);
                    return false;
                }

                entry = found;
                return true;
            }
        }

        private void RecordBlacklistHit(string scopeKey, string planSig, string deltaStep, string reason, string source)
        {
            var key = ApplyActionBlacklistStore.BuildKey(scopeKey, planSig, deltaStep, reason);
            var now = DateTimeOffset.UtcNow;

            lock (_blacklistSync)
            {
                var map = GetBlacklistSnapshot();
                if (map.TryGetValue(key, out var existing) && existing != null)
                {
                    var expiresAt = ParseUtcOrMin(existing.ExpiresAtUtc);
                    var extension = BlacklistTtlMin;
                    var candidate = expiresAt > now ? expiresAt + extension : now + extension;
                    var capped = candidate > (now + BlacklistTtlMax) ? now + BlacklistTtlMax : candidate;

                    map[key] = existing with
                    {
                        LastSeenUtc = now.ToString("O"),
                        ExpiresAtUtc = capped.ToString("O"),
                        HitCount = Math.Max(1, existing.HitCount) + 1
                    };
                }
                else
                {
                    map[key] = new ApplyActionBlacklistStore.BlacklistEntry
                    {
                        Key = key,
                        ScopeKey = scopeKey,
                        PlanSig = planSig,
                        DeltaStep = deltaStep,
                        Reason = reason,
                        Source = source,
                        CreatedAtUtc = now.ToString("O"),
                        LastSeenUtc = now.ToString("O"),
                        ExpiresAtUtc = (now + BlacklistTtlMin).ToString("O"),
                        HitCount = 1
                    };
                }

                ApplyActionBlacklistStore.PersistByKeyBestEffort(map, Log);
            }
        }

        public bool TryGetPendingAppliedPlanForHostKey(string? hostKey, out BypassPlan? plan, out DateTimeOffset appliedAtUtc)
        {
            plan = null;
            appliedAtUtc = DateTimeOffset.MinValue;

            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hk)) return false;

                if (_pendingFeedbackByHostKey.TryGetValue(hk, out var pending) && pending != null)
                {
                    plan = pending.Plan;
                    appliedAtUtc = pending.AppliedAtUtc;
                    return plan != null;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        public sealed record ApplyOutcome(string HostKey, string AppliedStrategyText, string PlanText, string? Reasoning)
        {
            public string Status { get; init; } = "APPLIED";
            public string Error { get; init; } = string.Empty;
            public string RollbackStatus { get; init; } = string.Empty;

            // P0.2: диагностика apply timeout/cancel.
            public string CancelReason { get; init; } = string.Empty;
            public string ApplyCurrentPhase { get; init; } = string.Empty;
            public long ApplyTotalElapsedMs { get; init; }
            public IReadOnlyList<BypassApplyPhaseTiming> ApplyPhases { get; init; } = Array.Empty<BypassApplyPhaseTiming>();
        }

        private static bool PlanHasApplicableActions(BypassPlan plan)
            => plan.Strategies.Count > 0 || plan.DropUdp443 || plan.AllowNoSni;

        public Task<ApplyOutcome?> ApplyRecommendationsAsync(BypassController bypassController)
            => ApplyRecommendationsAsync(bypassController, preferredHostKey: null);

        /// <summary>
        /// P1.9: применить уже известный план (wins) без подбора стратегий.
        /// Используется Operator UI для «Применить проверенный обход».
        /// </summary>
        public Task<ApplyOutcome?> ApplyProvidedPlanAsync(BypassController bypassController, BypassPlan plan, string? preferredHostKey)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));
            if (plan == null) throw new ArgumentNullException(nameof(plan));

            var hostKey = ResolveBestHostKeyForApply(preferredHostKey);
            if (string.IsNullOrWhiteSpace(hostKey))
            {
                Log("[APPLY][WIN] Нет цели для применения wins-плана");
                return Task.FromResult<ApplyOutcome?>(null);
            }

            return ApplyPlanInternalAsync(bypassController, hostKey, plan);
        }

        public async Task<ApplyOutcome?> ApplyRecommendationsForDomainAsync(BypassController bypassController, string domainSuffix)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));
            if (string.IsNullOrWhiteSpace(domainSuffix)) return null;

            var domain = domainSuffix.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(domain)) return null;

            // На данном этапе это управляемая "гибридная" логика:
            // - UI может предложить доменный режим (по анализу доменных семейств в UI-слое)
            // - здесь мы берём последний применимый план из поддоменов и применяем его,
            //   но выставляем OutcomeTargetHost именно на домен.
            var candidates = _intelPlansByHost
                .Where(kv =>
                {
                    var k = kv.Key;
                    if (string.IsNullOrWhiteSpace(k)) return false;
                    if (string.Equals(k, domain, StringComparison.OrdinalIgnoreCase)) return true;
                    return k.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
                })
                .Select(kv => (HostKey: kv.Key, Plan: kv.Value))
                .ToList();

            if (candidates.Count == 0)
            {
                Log($"[APPLY] Domain '{domain}': нет сохранённых планов");
                return null;
            }

            // Предпочитаем план от последнего сохранённого плана (если он из этого домена), иначе берём первый применимый.
            BypassPlan? plan = null;
            string? sourceHost = null;

            if (!string.IsNullOrWhiteSpace(_lastIntelPlanHostKey)
                && (_lastIntelPlanHostKey.Equals(domain, StringComparison.OrdinalIgnoreCase)
                    || _lastIntelPlanHostKey.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                && _intelPlansByHost.TryGetValue(_lastIntelPlanHostKey, out var lastPlan)
                && PlanHasApplicableActions(lastPlan))
            {
                plan = lastPlan;
                sourceHost = _lastIntelPlanHostKey;
            }
            else
            {
                foreach (var c in candidates)
                {
                    if (!PlanHasApplicableActions(c.Plan)) continue;
                    plan = c.Plan;
                    sourceHost = c.HostKey;
                    break;
                }
            }

            if (plan == null || !PlanHasApplicableActions(plan))
            {
                Log($"[APPLY] Domain '{domain}': нет применимых действий в планах");
                return null;
            }

            Log($"[APPLY] Domain '{domain}': apply from '{sourceHost}'");
            return await ApplyPlanInternalAsync(bypassController, domain, plan).ConfigureAwait(false);
        }

        public async Task<ApplyOutcome?> ApplyRecommendationsForDomainGroupAsync(
            BypassController bypassController,
            string groupKey,
            string anchorDomain,
            IReadOnlyList<string> domains)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));

            var gk = (groupKey ?? string.Empty).Trim();
            var anchor = (anchorDomain ?? string.Empty).Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(gk)) return null;
            if (string.IsNullOrWhiteSpace(anchor)) return null;
            if (domains == null || domains.Count == 0) return null;

            var normalizedDomains = domains
                .Select(d => (d ?? string.Empty).Trim().Trim('.'))
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (normalizedDomains.Count == 0)
            {
                Log($"[APPLY] Group '{gk}': домены не определены");
                return null;
            }

            // Берём планы только из доменов группы и применяем их к anchor-домену.
            var candidates = _intelPlansByHost
                .Where(kv =>
                {
                    var host = (kv.Key ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(host)) return false;

                    foreach (var d in normalizedDomains)
                    {
                        if (string.Equals(host, d, StringComparison.OrdinalIgnoreCase)) return true;
                        if (host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)) return true;
                    }

                    return false;
                })
                .Select(kv => (HostKey: kv.Key, Plan: kv.Value))
                .ToList();

            if (candidates.Count == 0)
            {
                Log($"[APPLY] Group '{gk}': нет сохранённых планов (anchor='{anchor}')");
                return null;
            }

            BypassPlan? plan = null;
            string? sourceHost = null;

            // Предпочитаем последний план, если он относится к группе.
            if (!string.IsNullOrWhiteSpace(_lastIntelPlanHostKey)
                && candidates.Any(c => string.Equals(c.HostKey, _lastIntelPlanHostKey, StringComparison.OrdinalIgnoreCase))
                && _intelPlansByHost.TryGetValue(_lastIntelPlanHostKey, out var lastPlan)
                && PlanHasApplicableActions(lastPlan))
            {
                plan = lastPlan;
                sourceHost = _lastIntelPlanHostKey;
            }
            else
            {
                foreach (var c in candidates)
                {
                    if (!PlanHasApplicableActions(c.Plan)) continue;
                    plan = c.Plan;
                    sourceHost = c.HostKey;
                    break;
                }
            }

            if (plan == null || !PlanHasApplicableActions(plan))
            {
                Log($"[APPLY] Group '{gk}': нет применимых действий в планах");
                return null;
            }

            Log($"[APPLY] Group '{gk}': apply from '{sourceHost}' (anchor='{anchor}')");
            return await ApplyPlanInternalAsync(bypassController, anchor, plan).ConfigureAwait(false);
        }

        public async Task<ApplyOutcome?> ApplyRecommendationsAsync(BypassController bypassController, string? preferredHostKey)
        {
            // 1) Пытаемся применить план для выбранной цели (если UI передал её).
            if (!string.IsNullOrWhiteSpace(preferredHostKey)
                && _intelPlansByHost.TryGetValue(preferredHostKey.Trim(), out var preferredPlan)
                && PlanHasApplicableActions(preferredPlan))
            {
                return await ApplyPlanInternalAsync(bypassController, preferredHostKey.Trim(), preferredPlan).ConfigureAwait(false);
            }

            // 2) Fallback: старый режим «последний план».
            if (_lastIntelPlan == null || !PlanHasApplicableActions(_lastIntelPlan)) return null;

            // Защита от «устаревшего» плана: применяем только если план относится
            // к последней цели, для которой был показан диагноз (чтобы не применять план «не к той цели»).
            if (!string.IsNullOrWhiteSpace(_lastIntelDiagnosisHostKey)
                && !string.IsNullOrWhiteSpace(_lastIntelPlanHostKey)
                && !string.Equals(_lastIntelPlanHostKey, _lastIntelDiagnosisHostKey, StringComparison.OrdinalIgnoreCase))
            {
                Log($"[APPLY] WARN: planHost={_lastIntelPlanHostKey}; lastDiagHost={_lastIntelDiagnosisHostKey} (план/цель разошлись)");
            }

            var hostKey = !string.IsNullOrWhiteSpace(_lastIntelPlanHostKey)
                ? _lastIntelPlanHostKey
                : _lastIntelDiagnosisHostKey;

            return await ApplyPlanInternalAsync(bypassController, hostKey, _lastIntelPlan).ConfigureAwait(false);
        }

        /// <summary>
        /// P1.11: «Эскалация ступенями» для Operator UX.
        /// Детерминированно усиливает уже применённые обходы, добавляя по одному действию за раз.
        /// Важно: это не auto-bypass, а ручная кнопка «Усилить».
        /// </summary>
        public async Task<ApplyOutcome?> ApplyEscalationAsync(BypassController bypassController, string? preferredHostKey)
        {
            if (bypassController == null) return null;

            // Выбираем план так же, как в обычном Apply: сначала preferredHostKey, затем fallback.
            string? hostKey = null;
            BypassPlan? basePlan = null;

            if (!string.IsNullOrWhiteSpace(preferredHostKey)
                && _intelPlansByHost.TryGetValue(preferredHostKey.Trim(), out var preferredPlan)
                && PlanHasApplicableActions(preferredPlan))
            {
                hostKey = preferredHostKey.Trim();
                basePlan = preferredPlan;
            }
            else if (_lastIntelPlan != null && PlanHasApplicableActions(_lastIntelPlan))
            {
                hostKey = !string.IsNullOrWhiteSpace(_lastIntelPlanHostKey)
                    ? _lastIntelPlanHostKey
                    : _lastIntelDiagnosisHostKey;
                basePlan = _lastIntelPlan;
            }

            hostKey = (hostKey ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(hostKey) || basePlan == null)
            {
                Log("[APPLY][ESCALATE] Skip: нет базового плана/цели");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: hostKey, planSig: null, reasonCode: "NO_BASE_PLAN");
                return null;
            }

            if (!TryBuildEscalationPlan(basePlan, bypassController, out var escalationPlan, out var escalationReason))
            {
                Log($"[APPLY][ESCALATE] Skip: нечего усиливать (host='{hostKey}'; reason='{escalationReason}')");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: hostKey, planSig: null, reasonCode: "ESCALATION_NOT_AVAILABLE", details: escalationReason);
                return null;
            }

            var scopeKey = ResolveAutoApplyTargetHost(hostKey);
            var planSig = BuildPlanSignature(escalationPlan);
            if (IsBlacklisted(scopeKey, planSig, escalationReason, reason: "guardrail_regression", out var blEsc))
            {
                Log($"[APPLY][ESCALATE] Skip: blacklist_hit scope={scopeKey}; step={escalationReason}; planSig={planSig}; expiresAt={blEsc?.ExpiresAtUtc}");
                LogPolicyEvent("blacklist_hit", runId: null, scopeKey: scopeKey, planSig: planSig, reasonCode: "GUARDRAIL_REGRESSION", details: $"step={escalationReason}; expiresAt={blEsc?.ExpiresAtUtc}");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: scopeKey, planSig: planSig, reasonCode: "BLACKLIST_HIT", details: escalationReason);
                return null;
            }

            Log($"[APPLY][ESCALATE] host='{hostKey}'; step='{escalationReason}'");
            LogPolicyEvent("escalate", runId: null, scopeKey: scopeKey, planSig: planSig, reasonCode: "MANUAL_ESCALATE", details: escalationReason);
            return await ApplyPlanInternalAsync(
                bypassController,
                hostKey,
                escalationPlan,
                deltaStep: escalationReason,
                actionSource: "escalation").ConfigureAwait(false);
        }

        private static bool TryBuildEscalationPlan(BypassPlan basePlan, BypassController bypassController, out BypassPlan escalationPlan, out string reason)
        {
            escalationPlan = basePlan;
            reason = string.Empty;

            try
            {
                // Эскалируем только safe-only (без DoH и без high-risk).
                // Шаги (по одному действию за раз):
                // 1) Fragment -> Disorder
                // 2) включить DropRst
                // 3) включить QUIC fallback (DROP UDP/443)
                // 4) включить AllowNoSNI

                var hasFragment = bypassController.IsFragmentEnabled;
                var hasDisorder = bypassController.IsDisorderEnabled;
                var hasDropRst = bypassController.IsDropRstEnabled;
                var hasQuicFallback = bypassController.IsQuicFallbackEnabled;
                var hasAllowNoSni = bypassController.IsAllowNoSniEnabled;

                var plan = new BypassPlan
                {
                    ForDiagnosis = basePlan.ForDiagnosis,
                    PlanConfidence = Math.Clamp(basePlan.PlanConfidence, 0, 100),
                    PlannedAtUtc = DateTimeOffset.UtcNow,
                    Reasoning = string.IsNullOrWhiteSpace(basePlan.Reasoning)
                        ? "усиление"
                        : basePlan.Reasoning + "; усиление",

                    // Не переносим deferred: эскалация должна быть исполнимой.
                    Strategies = new List<BypassStrategy>(),
                    DeferredStrategies = new List<DeferredBypassStrategy>(),

                    DropUdp443 = false,
                    AllowNoSni = false,
                };

                // Шаг 1: если сейчас включён Fragment, но Disorder нет — усиливаем до Disorder.
                if (hasFragment && !hasDisorder)
                {
                    plan.Strategies.Add(new BypassStrategy
                    {
                        Id = StrategyId.TlsDisorder,
                        BasePriority = 100,
                        Risk = RiskLevel.Medium,
                        Parameters = new Dictionary<string, object?>()
                    });

                    escalationPlan = plan;
                    reason = "tls_disorder";
                    return true;
                }

                // Шаг 2: если DropRst ещё не включён — добавляем его.
                if (!hasDropRst)
                {
                    plan.Strategies.Add(new BypassStrategy
                    {
                        Id = StrategyId.DropRst,
                        BasePriority = 50,
                        Risk = RiskLevel.Medium,
                        Parameters = new Dictionary<string, object?>()
                    });

                    escalationPlan = plan;
                    reason = "drop_rst";
                    return true;
                }

                // Шаг 3: если QUIC fallback ещё не включён — включаем (assist-флаг).
                if (!hasQuicFallback)
                {
                    escalationPlan = new BypassPlan
                    {
                        ForDiagnosis = plan.ForDiagnosis,
                        PlanConfidence = plan.PlanConfidence,
                        PlannedAtUtc = plan.PlannedAtUtc,
                        Reasoning = plan.Reasoning,
                        Strategies = plan.Strategies,
                        DeferredStrategies = plan.DeferredStrategies,
                        DropUdp443 = true,
                        AllowNoSni = false,
                    };

                    reason = "drop_udp_443";
                    return true;
                }

                // Шаг 4: последняя ступень — AllowNoSNI.
                if (!hasAllowNoSni)
                {
                    escalationPlan = new BypassPlan
                    {
                        ForDiagnosis = plan.ForDiagnosis,
                        PlanConfidence = plan.PlanConfidence,
                        PlannedAtUtc = plan.PlannedAtUtc,
                        Reasoning = plan.Reasoning,
                        Strategies = plan.Strategies,
                        DeferredStrategies = plan.DeferredStrategies,
                        DropUdp443 = false,
                        AllowNoSni = true,
                    };

                    reason = "allow_no_sni";
                    return true;
                }

                escalationPlan = plan;
                reason = "already_max";
                return false;
            }
            catch (Exception ex)
            {
                escalationPlan = basePlan;
                reason = "error: " + ex.Message;
                return false;
            }
        }

        private async Task<ApplyOutcome?> ApplyPlanInternalAsync(
            BypassController bypassController,
            string hostKey,
            BypassPlan plan,
            string? deltaStep = null,
            string? actionSource = null)
        {
            if (_noiseHostFilter.IsNoiseHost(hostKey))
            {
                Log($"[APPLY] Skip: шумовой хост '{hostKey}'");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: hostKey, planSig: null, reasonCode: "NOISE_HOST");
                return null;
            }

            // P1.1: дедупликация повторного apply по цели.
            // Формируем сигнатуру плана и сравниваем с последним успешным применением.
            var planTokens = plan.Strategies
                .Select(s => MapStrategyToken(s.Id.ToString()))
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .ToList();
            if (plan.DropUdp443) planTokens.Add("DROP_UDP_443");
            if (plan.AllowNoSni) planTokens.Add("ALLOW_NO_SNI");
            var planStrategies = planTokens.Count == 0 ? "(none)" : string.Join(", ", planTokens);

            var appliedUiText = planTokens.Count == 0
                ? string.Empty
                : string.Join(" + ", planTokens.Select(FormatStrategyTokenForUi).Where(t => !string.IsNullOrWhiteSpace(t)));

            var targetKey = ResolveAutoApplyTargetHost(hostKey);
            var planSig = BuildPlanSignature(plan);
            var desiredAlreadyEffective = planTokens.Count > 0 && planTokens.All(t => IsStrategyActive(t, bypassController));
            if (desiredAlreadyEffective
                && !string.IsNullOrWhiteSpace(targetKey)
                && !string.IsNullOrWhiteSpace(planSig)
                && _lastAppliedPlanSignatureByTarget.TryGetValue(targetKey, out var lastSig)
                && (string.Equals(lastSig, planSig, StringComparison.OrdinalIgnoreCase)
                    || IspAudit.Core.Intelligence.Execution.IntelPlanSelector.IsDominated(planSig, lastSig)))
            {
                Log($"[APPLY] Skip: уже применено (dominated by '{lastSig}') (target='{targetKey}'; sig='{planSig}')");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: targetKey, planSig: planSig, reasonCode: "ALREADY_APPLIED", details: $"dominatedBy={lastSig}");
                return new ApplyOutcome(hostKey, appliedUiText, planStrategies, plan.Reasoning)
                {
                    Status = "ALREADY_APPLIED",
                    Error = string.Empty,
                    RollbackStatus = string.Empty
                };
            }

            // P1.5: не допускаем параллельного входа (manual vs auto apply).
            // Это защищает обвязку Orchestrator (cts/UI) даже если ApplyIntelPlanAsync сериализован ниже.
            if (Interlocked.CompareExchange(ref _applyInFlight, 1, 0) != 0)
            {
                Log($"[APPLY] Skip: apply уже выполняется (host='{hostKey}')");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: hostKey, planSig: planSig, reasonCode: "APPLY_IN_FLIGHT");
                return new ApplyOutcome(hostKey, string.Empty, string.Empty, plan.Reasoning)
                {
                    Status = "BUSY",
                    Error = "Применение уже выполняется",
                    RollbackStatus = string.Empty
                };
            }

            void UpdateApplyUi(Action action)
            {
                try
                {
                    var dispatcher = Application.Current?.Dispatcher;
                    if (dispatcher != null && !dispatcher.CheckAccess())
                    {
                        dispatcher.BeginInvoke(action);
                    }
                    else
                    {
                        action();
                    }
                }
                catch
                {
                    // Best-effort: UI обновление не должно ломать apply.
                }
            }

            static string FormatApplyPhaseForUi(string phase)
            {
                var p = (phase ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(p)) return "Применение…";

                return p.ToLowerInvariant() switch
                {
                    "plan_build" => "Подготовка плана",
                    "test_delay" => "Ожидание (test_delay)",
                    "apply_tls_options" => "Применение стратегий",
                    "apply_doh_enable" => "Включение DoH",
                    "apply_doh_disable" => "Отключение DoH",
                    "apply_doh_skipped" => "DoH: пропущено (нужно разрешение)",
                    "rollback_tls_options" => "Откат стратегий",
                    "rollback_dns" => "Откат DNS",
                    _ => $"Фаза: {p}"
                };
            }

            _applyCts?.Dispose();
            _applyCts = new CancellationTokenSource();

            using var linked = _cts != null
                ? CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, _applyCts.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(_applyCts.Token);

            var ct = linked.Token;

            var beforeState = BuildBypassStateSummary(bypassController);
            var scopeKey = !string.IsNullOrWhiteSpace(targetKey) ? targetKey : hostKey;
            var applyRunId = Guid.NewGuid().ToString("N");
            var baselineCapturedAtUtc = DateTimeOffset.UtcNow;
            var baselineSuccessCount = 0;
            var baselineSampleCount = 0;
            var latchedPostApplyPolicy = CaptureLatchedPostApplyPolicy();

            try
            {
                UpdateApplyUi(() =>
                {
                    IsApplyRunning = true;
                    ApplyStatusText = "Применение: подготовка…";
                });

                Log($"[APPLY] host={hostKey}; plan={planStrategies}; before={beforeState}");
                LogPolicyEvent("apply", runId: applyRunId, scopeKey: scopeKey, planSig: planSig, reasonCode: "START", details: $"host={hostKey}");

                if (PlanHasApplicableActions(plan))
                {
                    for (var attempt = 0; attempt < latchedPostApplyPolicy.BaselineSampleCount; attempt++)
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            var probe = await _stateManager.RunOutcomeProbeNowAsync(
                                hostOverride: hostKey,
                                timeoutOverride: latchedPostApplyPolicy.BaselineProbeTimeout,
                                cancellationToken: ct).ConfigureAwait(false);

                            baselineSampleCount++;
                            if (probe.Status == OutcomeStatus.Success)
                            {
                                baselineSuccessCount++;
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch
                        {
                            baselineSampleCount++;
                        }
                    }

                    baselineCapturedAtUtc = DateTimeOffset.UtcNow;
                    Log($"[APPLY][Baseline][run={applyRunId}] scope={scopeKey}; successBefore={baselineSuccessCount}; sampleBefore={baselineSampleCount}");
                }

                void OnPhaseEvent(BypassApplyPhaseTiming e)
                {
                    if (!string.Equals(e.Status, "START", StringComparison.OrdinalIgnoreCase)) return;

                    UpdateApplyUi(() =>
                    {
                        ApplyStatusText = "Применение: " + FormatApplyPhaseForUi(e.Name);
                    });
                }

                await bypassController.ApplyIntelPlanAsync(plan, hostKey, IntelApplyTimeout, ct, OnPhaseEvent).ConfigureAwait(false);

                // Feedback: фиксируем контекст успешного apply, чтобы post-apply ретест мог записать успех/неуспех.
                // Важно: контекст ключуется по hostKey (домен/IP), так как correlationId доступен только на уровне UI.
                if (PlanHasApplicableActions(plan))
                {
                    _pendingFeedbackByHostKey[hostKey] = new PendingFeedbackContext(
                        plan,
                        DateTimeOffset.UtcNow,
                        applyRunId,
                        scopeKey,
                        planSig,
                        string.IsNullOrWhiteSpace(deltaStep) ? string.Empty : deltaStep.Trim(),
                        string.IsNullOrWhiteSpace(actionSource) ? "manual_apply" : actionSource.Trim(),
                        baselineCapturedAtUtc,
                        Math.Max(0, baselineSuccessCount),
                        Math.Max(0, baselineSampleCount),
                        latchedPostApplyPolicy);
                }

                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[APPLY] OK; after={afterState}");
                LogPolicyEvent("apply", runId: applyRunId, scopeKey: scopeKey, planSig: planSig, reasonCode: "APPLIED", details: afterState);
                ResetRecommendations();

                // P1.1: фиксируем сигнатуру последнего успешного применения для дедупликации.
                if (!string.IsNullOrWhiteSpace(targetKey) && !string.IsNullOrWhiteSpace(planSig))
                {
                    _lastAppliedPlanSignatureByTarget[targetKey] = planSig;
                }

                if (!string.IsNullOrWhiteSpace(appliedUiText))
                {
                    return new ApplyOutcome(hostKey, appliedUiText, planStrategies, plan.Reasoning)
                    {
                        Status = "APPLIED",
                        RollbackStatus = "NOT_NEEDED"
                    };
                }

                return new ApplyOutcome(hostKey, "(none)", planStrategies, plan.Reasoning)
                {
                    Status = "APPLIED",
                    RollbackStatus = "NOT_NEEDED"
                };
            }
            catch (OperationCanceledException oce)
            {
                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[APPLY] ROLLBACK (cancel/timeout); after={afterState}");
                LogPolicyEvent("rollback", runId: applyRunId, scopeKey: scopeKey, planSig: planSig, reasonCode: "CANCELED_OR_TIMEOUT", details: afterState);

                if (oce is BypassApplyService.BypassApplyCanceledException ce)
                {
                    return new ApplyOutcome(hostKey, appliedUiText, planStrategies, plan.Reasoning)
                    {
                        Status = ce.Execution.Status,
                        RollbackStatus = ce.Execution.RollbackStatus,
                        CancelReason = ce.Execution.CancelReason,
                        ApplyCurrentPhase = ce.Execution.CurrentPhase,
                        ApplyTotalElapsedMs = ce.Execution.TotalElapsedMs,
                        ApplyPhases = ce.Execution.Phases
                    };
                }

                // Cancel до входа в apply/rollback (или неизвестный источник отмены).
                return new ApplyOutcome(hostKey, appliedUiText, planStrategies, plan.Reasoning)
                {
                    Status = "CANCELED",
                    RollbackStatus = "NOT_NEEDED"
                };
            }
            catch (Exception ex)
            {
                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[APPLY] ROLLBACK (error); after={afterState}; error={ex.Message}");
                LogPolicyEvent("rollback", runId: applyRunId, scopeKey: scopeKey, planSig: planSig, reasonCode: "APPLY_ERROR", details: ex.GetType().Name);

                if (ex is BypassApplyService.BypassApplyFailedException fe)
                {
                    return new ApplyOutcome(hostKey, appliedUiText, planStrategies, plan.Reasoning)
                    {
                        Status = fe.Execution.Status,
                        Error = fe.Execution.Error,
                        RollbackStatus = fe.Execution.RollbackStatus,
                        CancelReason = fe.Execution.CancelReason,
                        ApplyCurrentPhase = fe.Execution.CurrentPhase,
                        ApplyTotalElapsedMs = fe.Execution.TotalElapsedMs,
                        ApplyPhases = fe.Execution.Phases
                    };
                }

                return new ApplyOutcome(hostKey, appliedUiText, planStrategies, plan.Reasoning)
                {
                    Status = "FAILED",
                    Error = ex.Message,
                    RollbackStatus = "DONE"
                };
            }
            finally
            {
                UpdateApplyUi(() =>
                {
                    IsApplyRunning = false;
                    ApplyStatusText = string.Empty;
                });

                Interlocked.Exchange(ref _applyInFlight, 0);

                _applyCts?.Dispose();
                _applyCts = null;
            }
        }

        /// <summary>
        /// Автоматический ретест сразу после Apply (короткий прогон, чтобы увидеть практический эффект обхода).
        /// </summary>
        public Task StartPostApplyRetestAsync(BypassController bypassController, string? preferredHostKey, string? correlationId = null)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));

            void UpdatePostApplyRetestUi(Action action)
            {
                try
                {
                    var dispatcher = Application.Current?.Dispatcher;
                    if (dispatcher != null && !dispatcher.CheckAccess())
                    {
                        dispatcher.BeginInvoke(action);
                    }
                    else
                    {
                        action();
                    }
                }
                catch
                {
                    // Best-effort: наблюдаемость не должна ломать рантайм
                }
            }

            var hostKey = ResolveBestHostKeyForApply(preferredHostKey);
            if (string.IsNullOrWhiteSpace(hostKey))
            {
                PostApplyRetestStatus = "Ретест после Apply: нет цели";
                return Task.CompletedTask;
            }

            var opId = string.IsNullOrWhiteSpace(correlationId)
                ? Guid.NewGuid().ToString("N")
                : correlationId.Trim();

            var scopeKey = ResolveAutoApplyTargetHost(hostKey);
            if (string.IsNullOrWhiteSpace(scopeKey))
            {
                scopeKey = hostKey;
            }

            if (_activePostApplyRunByScopeKey.TryGetValue(scopeKey, out var activeRunId)
                && !string.Equals(activeRunId, opId, StringComparison.OrdinalIgnoreCase))
            {
                var concurrentDetails = BuildUnknownDetails(
                    UnknownReason.ConcurrentApply,
                    $"scopeKey={scopeKey}; activeRunId={activeRunId}; currentRunId={opId}");

                EmitPostApplyVerdict(hostKey, "UNKNOWN", "guard", concurrentDetails);
                PostApplyRetestStatus = "Ретест после Apply: пропущен (concurrent apply)";
                Log($"[PostApplyRetest][op={opId}] Skip: reason=concurrent_apply; scopeKey={scopeKey}; activeRunId={activeRunId}");
                return Task.CompletedTask;
            }

            _activePostApplyRunByScopeKey[scopeKey] = opId;

            void EmitPostApplyVerdict(string hk, string verdict, string mode, string? details)
            {
                try
                {
                    OnPostApplyCheckVerdict?.Invoke(hk, verdict, mode, details);
                    OnPostApplyCheckVerdictV2?.Invoke(hk, verdict, mode, details, opId);
                    OnPostApplyCheckVerdictV3?.Invoke(hk, PostApplyVerdictContract.FromLegacy(verdict, details), mode, details, opId);
                }
                catch
                {
                    // ignore
                }
            }

            static string BuildUnknownDetails(UnknownReason reason, string details)
            {
                var d = (details ?? string.Empty).Trim();
                var prefix = $"reason={reason}";
                if (string.IsNullOrWhiteSpace(d)) return prefix;
                if (d.Contains("reason=", StringComparison.OrdinalIgnoreCase)) return d;
                return $"{prefix}; {d}";
            }

            static (string Verdict, string Details) NormalizeUnknownProbeVerdict(string verdict, string details)
            {
                var v = (verdict ?? string.Empty).Trim();
                var d = (details ?? string.Empty).Trim();

                if (!string.Equals(v, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
                {
                    return (v, d);
                }

                var resolved = PostApplyVerdictContract.ResolveUnknownReason(v, d);
                if (resolved == UnknownReason.None)
                {
                    resolved = UnknownReason.ProbeTimeoutBudget;
                }

                return ("UNKNOWN", BuildUnknownDetails(resolved, d));
            }

            static (string Verdict, string Details) ApplyBaselineFreshnessPolicy(
                string verdict,
                string details,
                bool hasBaseline,
                bool baselineIsFresh,
                TimeSpan baselineAge,
                TimeSpan baselineTtl)
            {
                var v = (verdict ?? string.Empty).Trim();
                var d = (details ?? string.Empty).Trim();

                if (!hasBaseline || baselineIsFresh)
                {
                    return (v, d);
                }

                var existingReason = PostApplyVerdictContract.ResolveUnknownReason(v, d);
                if (existingReason == UnknownReason.Cancelled
                    || existingReason == UnknownReason.ConcurrentApply
                    || existingReason == UnknownReason.InsufficientIps
                    || existingReason == UnknownReason.ProbeTimeoutBudget)
                {
                    return (v, d);
                }

                var staleDetails = BuildUnknownDetails(
                    UnknownReason.NoBaselineFresh,
                    $"baseline stale; baselineAgeSec={(int)Math.Round(baselineAge.TotalSeconds)}; ttlSec={(int)Math.Round(baselineTtl.TotalSeconds)}; out={v}; source={d}");

                return ("UNKNOWN", staleDetails);
            }

            try
            {
                _postApplyRetest.Cancellation?.Cancel();
            }
            catch
            {
            }

            _postApplyRetest.Cancellation = new CancellationTokenSource();
            var ct = _postApplyRetest.Cancellation.Token;

            UpdatePostApplyRetestUi(() =>
            {
                IsPostApplyRetestRunning = true;
                PostApplyRetestStatus = $"Ретест после Apply: запуск ({hostKey})";
            });

            var startedAtUtc = DateTimeOffset.UtcNow;

            Log($"[PostApplyRetest][op={opId}] Start: host={hostKey}");

            return Task.Run(async () =>
            {
                var hasPendingBaseline = _pendingFeedbackByHostKey.TryGetValue(hostKey, out var pendingBaseline) && pendingBaseline != null;
                var latchedPostApplyPolicy = pendingBaseline?.Policy ?? CaptureLatchedPostApplyPolicy();
                var baselineTtl = latchedPostApplyPolicy.BaselineFreshnessTtl;
                var baselineAge = TimeSpan.Zero;
                var baselineSuccessBefore = Math.Max(0, pendingBaseline?.BaselineSuccessCount ?? 0);
                var baselineSampleBefore = Math.Max(0, pendingBaseline?.BaselineSampleCount ?? 0);
                if (hasPendingBaseline && pendingBaseline != null)
                {
                    baselineAge = DateTimeOffset.UtcNow - pendingBaseline.AppliedAtUtc;
                }
                if (baselineAge < TimeSpan.Zero) baselineAge = TimeSpan.Zero;
                var isBaselineFresh = !hasPendingBaseline || baselineAge <= baselineTtl;

                if (hasPendingBaseline)
                {
                    Log($"[PostApplyRetest][op={opId}] Baseline: ageSec={(int)Math.Round(baselineAge.TotalSeconds)}; ttlSec={(int)Math.Round(baselineTtl.TotalSeconds)}; fresh={(isBaselineFresh ? 1 : 0)}; guardrail={latchedPostApplyPolicy.GuardrailSuccessK}of{latchedPostApplyPolicy.GuardrailSampleM}; order={latchedPostApplyPolicy.EvaluationOrder}");
                }
                else
                {
                    Log($"[PostApplyRetest][op={opId}] Baseline: missing pending context");
                }

                static bool IsYouTubeAnchor(string hk)
                    => string.Equals(hk, "youtube.com", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(hk, "www.youtube.com", StringComparison.OrdinalIgnoreCase);

                static bool IsGuardrailRegression(int beforeSuccess, int beforeSample, int afterSuccess, int requiredSampleM, int requiredSuccessK)
                {
                    if (beforeSample <= 0)
                    {
                        return false;
                    }

                    var effectiveM = Math.Max(1, Math.Min(beforeSample, Math.Max(1, requiredSampleM)));
                    var requiredK = Math.Max(1, Math.Min(Math.Max(1, requiredSuccessK), effectiveM));
                    return beforeSuccess >= requiredK && afterSuccess == 0;
                }

                static string? ResolveGuardrailStopReason(
                    bool hasBaseline,
                    bool baselineFresh,
                    string verdict,
                    string details)
                {
                    if (!hasBaseline)
                    {
                        return UnknownReason.NoBaseline.ToString();
                    }

                    if (!baselineFresh)
                    {
                        return UnknownReason.NoBaselineFresh.ToString();
                    }

                    var normalizedVerdict = (verdict ?? string.Empty).Trim();
                    if (string.Equals(normalizedVerdict, "PARTIAL", StringComparison.OrdinalIgnoreCase))
                    {
                        return "ApplyErrorPartial";
                    }

                    if (!string.Equals(normalizedVerdict, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                    var reason = PostApplyVerdictContract.ResolveUnknownReason(normalizedVerdict, details);
                    return reason switch
                    {
                        UnknownReason.InsufficientIps => reason.ToString(),
                        UnknownReason.Cancelled => reason.ToString(),
                        UnknownReason.ConcurrentApply => reason.ToString(),
                        UnknownReason.NoBaseline => reason.ToString(),
                        UnknownReason.NoBaselineFresh => reason.ToString(),
                        _ => null,
                    };
                }

                async Task<(string Verdict, string ProbeDetails)> ComputePostApplyProbeVerdictAsync(string hk, CancellationToken ctt)
                {
                    try
                    {
                        // YouTube: одного "GET /" по youtube.com недостаточно (редирект 301 даёт ложный OK).
                        // Проверяем стабильные 204 эндпоинты: сам YouTube и GoogleVideo redirector.
                        if (IsYouTubeAnchor(hk))
                        {
                            var probeA = await _stateManager.RunOutcomeProbeNowAsync(
                                hostOverride: "www.youtube.com",
                                pathOverride: "/generate_204",
                                expectedHttpStatusCodeOverride: 204,
                                timeoutOverride: latchedPostApplyPolicy.OutcomeProbeTimeout,
                                cancellationToken: ctt).ConfigureAwait(false);

                            var probeB = await _stateManager.RunOutcomeProbeNowAsync(
                                hostOverride: "redirector.googlevideo.com",
                                pathOverride: "/generate_204",
                                expectedHttpStatusCodeOverride: 204,
                                timeoutOverride: latchedPostApplyPolicy.OutcomeProbeTimeout,
                                cancellationToken: ctt).ConfigureAwait(false);

                            var aOk = probeA.Status == OutcomeStatus.Success;
                            var bOk = probeB.Status == OutcomeStatus.Success;

                            var verdict = (aOk, bOk) switch
                            {
                                (true, true) => "OK",
                                (true, false) => "PARTIAL",
                                (false, true) => "PARTIAL",
                                (false, false) => (probeA.Status == OutcomeStatus.Unknown || probeB.Status == OutcomeStatus.Unknown) ? "UNKNOWN" : "FAIL"
                            };

                            var details = $"yt={probeA.Text}:{probeA.Details}; gv={probeB.Text}:{probeB.Details}";
                            return (verdict, details);
                        }

                        // Default: прежний общий probe (TLS+любой HTTP ответ).
                        var probe = await _stateManager.RunOutcomeProbeNowAsync(
                            hostOverride: hk,
                            timeoutOverride: latchedPostApplyPolicy.OutcomeProbeTimeout,
                            cancellationToken: ctt).ConfigureAwait(false);

                        var v = probe.Status switch
                        {
                            OutcomeStatus.Success => "OK",
                            OutcomeStatus.Failed => "FAIL",
                            _ => "UNKNOWN"
                        };

                        return (v, $"{probe.Text}:{probe.Details}");
                    }
                    catch (OperationCanceledException)
                    {
                        return ("UNKNOWN", "cancelled");
                    }
                    catch (Exception ex)
                    {
                        return ("UNKNOWN", $"error: {ex.Message}");
                    }
                }

                // Если диагностика активна, НЕ создаём второй LiveTestingPipeline (делит TrafficEngine и может конфликтовать).
                // Вместо этого добавляем цель в очередь существующего pipeline — так UI получит свежие результаты,
                // даже если диагностика идёт долго или «залипла» на другой цели.
                if (IsDiagnosticRunning)
                {
                    try
                    {
                        UpdatePostApplyRetestUi(() =>
                        {
                            PostApplyRetestStatus = $"Ретест после Apply: добавляю в очередь диагностики ({hostKey})…";
                        });

                        Log($"[PostApplyRetest][op={opId}] Mode=enqueue (diagnostic running)");

                        var pipeline = _testingPipeline;
                        var diagCts = _cts;

                        // Если пайплайн ещё не готов (редкое окно во время старта) — не ждём «окончания диагностики».
                        // Делаем best-effort outcome-probe, чтобы хотя бы OUT статусы обновились.
                        if (pipeline == null || diagCts == null)
                        {
                            var (verdict, probeDetails) = await ComputePostApplyProbeVerdictAsync(hostKey, ct).ConfigureAwait(false);
                            var normalizedProbe = NormalizeUnknownProbeVerdict(verdict, probeDetails);

                            var details = string.Equals(normalizedProbe.Verdict, "UNKNOWN", StringComparison.OrdinalIgnoreCase)
                                ? BuildUnknownDetails(UnknownReason.ProbeTimeoutBudget, $"pipeline_not_ready; out={normalizedProbe.Verdict}; probe={normalizedProbe.Details}")
                                : $"pipeline_not_ready; out={normalizedProbe.Verdict}; probe={normalizedProbe.Details}";

                            var adjusted = ApplyBaselineFreshnessPolicy(normalizedProbe.Verdict, details, hasPendingBaseline, isBaselineFresh, baselineAge, baselineTtl);
                            EmitPostApplyVerdict(hostKey, adjusted.Verdict, "enqueue", adjusted.Details);

                            UpdatePostApplyRetestUi(() =>
                            {
                                PostApplyRetestStatus = $"Ретест после Apply: диагностика активна, pipeline не готов (OUT={adjusted.Verdict})";
                            });

                            Log($"[PostApplyRetest][op={opId}] Skip: reason=pipeline_not_ready; action=outcome_probe; verdict={adjusted.Verdict}");
                            return;
                        }

                        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, diagCts.Token);
                        var linkedCt = linked.Token;

                        // Даем движку короткое время применить правила после Apply.
                        await Task.Delay(latchedPostApplyPolicy.EnqueueWarmupDelay, linkedCt).ConfigureAwait(false);

                        var hosts = await BuildPostApplyRetestHostsAsync(hostKey, port: 443, linkedCt).ConfigureAwait(false);
                        if (hosts.Count == 0)
                        {
                            UpdatePostApplyRetestUi(() =>
                            {
                                PostApplyRetestStatus = $"Ретест после Apply: не удалось определить IP ({hostKey})";
                            });

                            EmitPostApplyVerdict(hostKey, "UNKNOWN", "enqueue", BuildUnknownDetails(UnknownReason.InsufficientIps, "no_targets_resolved"));

                            Log($"[PostApplyRetest][op={opId}] Abort: reason=no_targets_resolved; mode=enqueue; host={hostKey}");
                            return;
                        }

                        foreach (var h in hosts)
                        {
                            await pipeline.EnqueueHostAsync(h, IspAudit.Utils.LiveTestingPipeline.HostPriority.High).ConfigureAwait(false);
                        }

                        // Делаем outcome-probe (усиленный для YouTube) и используем как семантический итог для UI.
                        var (verdictAfterEnqueue, probeDetailsAfterEnqueue) = await ComputePostApplyProbeVerdictAsync(hostKey, linkedCt).ConfigureAwait(false);
                        var normalizedAfterEnqueue = NormalizeUnknownProbeVerdict(verdictAfterEnqueue, probeDetailsAfterEnqueue);

                        var enqueueDetails = $"enqueued; ips={hosts.Count}; out={normalizedAfterEnqueue.Verdict}; probe={normalizedAfterEnqueue.Details}";
                        var adjustedAfterEnqueue = ApplyBaselineFreshnessPolicy(
                            normalizedAfterEnqueue.Verdict,
                            enqueueDetails,
                            hasPendingBaseline,
                            isBaselineFresh,
                            baselineAge,
                            baselineTtl);

                        EmitPostApplyVerdict(hostKey, adjustedAfterEnqueue.Verdict, "enqueue", adjustedAfterEnqueue.Details);

                        UpdatePostApplyRetestUi(() =>
                        {
                            PostApplyRetestStatus = $"Ретест после Apply: добавлено в очередь диагностики (IP={hosts.Count}, OUT={adjustedAfterEnqueue.Verdict})";
                        });

                        Log($"[PostApplyRetest][op={opId}] Enqueued: host={hostKey}; ips={hosts.Count}; verdict={adjustedAfterEnqueue.Verdict}");
                        return;
                    }
                    catch (OperationCanceledException)
                    {
                        EmitPostApplyVerdict(hostKey, "UNKNOWN", "enqueue", BuildUnknownDetails(UnknownReason.Cancelled, "cancelled"));
                        UpdatePostApplyRetestUi(() =>
                        {
                            PostApplyRetestStatus = "Ретест после Apply: отменён";
                        });

                        Log($"[PostApplyRetest][op={opId}] Canceled: mode=enqueue; host={hostKey}");
                        return;
                    }
                    catch (Exception ex)
                    {
                        var reason = UnknownReason.ProbeTimeoutBudget;
                        EmitPostApplyVerdict(hostKey, "UNKNOWN", "enqueue", BuildUnknownDetails(reason, $"error: {ex.Message}"));
                        UpdatePostApplyRetestUi(() =>
                        {
                            PostApplyRetestStatus = $"Ретест после Apply: ошибка ({ex.Message})";
                        });

                        Log($"[PostApplyRetest][op={opId}] Error: mode=enqueue; error={ex.Message}");
                        return;
                    }
                    finally
                    {
                        var elapsedMs = (DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds;
                        UpdatePostApplyRetestUi(() => { IsPostApplyRetestRunning = false; });
                        if (_activePostApplyRunByScopeKey.TryGetValue(scopeKey, out var active)
                            && string.Equals(active, opId, StringComparison.OrdinalIgnoreCase))
                        {
                            _activePostApplyRunByScopeKey.TryRemove(scopeKey, out _);
                        }
                        Log($"[PostApplyRetest][op={opId}] Finish: mode=enqueue; elapsedMs={elapsedMs:0}; host={hostKey}");
                    }
                }

                // Локальная эвристика результата: для всех target IP смотрим, были ли строки ✓/❌.
                // Усиление:
                // - если одновременно есть ✓ и ❌ по цели — outcome=Unknown (не учимся на неоднозначном результате)
                // - если есть хотя бы один ✓ и нет ❌ — Success
                // - если есть хотя бы один ❌ и нет ✓ — Failure
                // - если вообще нет записей — Unknown
                var targetIpStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var anyOk = false;
                var anyFail = false;
                var totalOkCount = 0;
                var totalFailCount = 0;

                // Более точный режим: если в логах ретеста удалось увидеть SNI, совпадающий с hostKey,
                // то считаем outcome только по этим записям. Иначе fallback на все target IP.
                var anySniMatched = false;
                var anyOkSniMatched = false;
                var anyFailSniMatched = false;
                var sniOkCount = 0;
                var sniFailCount = 0;

                try
                {
                    using var op = BypassOperationContext.Enter(opId, "post_apply_retest", hostKey);

                    Log($"[PostApplyRetest][op={opId}] Mode=local (standalone pipeline)");

                    var latchedRunConfig = CaptureLatchedProbeRunConfig(bypassController, maxConcurrentTests: latchedPostApplyPolicy.RetestMaxConcurrentTests);
                    var pipelineConfig = BuildLatchedPipelineConfig(latchedRunConfig, enableAutoBypass: false);

                    // Собираем IP-адреса цели: DNS + локальные кеши.
                    var hosts = await BuildPostApplyRetestHostsAsync(hostKey, port: 443, ct).ConfigureAwait(false);
                    if (hosts.Count == 0)
                    {
                        UpdatePostApplyRetestUi(() =>
                        {
                            PostApplyRetestStatus = $"Ретест после Apply: не удалось определить IP ({hostKey})";
                        });

                        EmitPostApplyVerdict(hostKey, "UNKNOWN", "local", BuildUnknownDetails(UnknownReason.InsufficientIps, "no_targets_resolved"));

                        Log($"[PostApplyRetest][op={opId}] Abort: reason=no_targets_resolved; mode=local; host={hostKey}");
                        return;
                    }

                    foreach (var h in hosts)
                    {
                        if (h.RemoteIp != null)
                        {
                            targetIpStrings.Add(h.RemoteIp.ToString());
                        }
                    }

                    UpdatePostApplyRetestUi(() =>
                    {
                        PostApplyRetestStatus = $"Ретест после Apply: проверяем {hosts.Count} IP…";
                    });

                    Log($"[PostApplyRetest][op={opId}] Targets: ips={hosts.Count}");

                    var progress = new Progress<string>(msg =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.BeginInvoke(() =>
                            {
                                // Парсим ✓/❌ строки и отмечаем статус по target IP.
                                try
                                {
                                    if (!string.IsNullOrWhiteSpace(msg) && (msg.StartsWith("✓ ", StringComparison.Ordinal) || msg.StartsWith("❌ ", StringComparison.Ordinal)))
                                    {
                                        var afterPrefix = msg.Substring(2).TrimStart();
                                        var firstToken = afterPrefix.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                                        var hostPart = string.IsNullOrWhiteSpace(firstToken) ? string.Empty : (firstToken.Split(':').FirstOrDefault() ?? string.Empty);

                                        if (!string.IsNullOrWhiteSpace(hostPart) && targetIpStrings.Contains(hostPart))
                                        {
                                            var isFail = msg.StartsWith("❌ ", StringComparison.Ordinal);
                                            var isOk = msg.StartsWith("✓ ", StringComparison.Ordinal);

                                            if (isFail) anyFail = true;
                                            if (isOk) anyOk = true;
                                            if (isFail) totalFailCount++;
                                            if (isOk) totalOkCount++;

                                            // Учитываем SNI (если есть) как более точную привязку к hostKey.
                                            // Важно: не требуем совпадения всегда, потому что SNI может быть "-".
                                            var sni = TryExtractInlineToken(msg, "SNI");
                                            if (!string.IsNullOrWhiteSpace(sni) && sni != "-"
                                                && !System.Net.IPAddress.TryParse(hostKey, out _))
                                            {
                                                var normalizedHost = (hostKey ?? string.Empty).Trim().Trim('.');
                                                var normalizedSni = (sni ?? string.Empty).Trim().Trim('.');
                                                if (!string.IsNullOrWhiteSpace(normalizedHost)
                                                    && (string.Equals(normalizedSni, normalizedHost, StringComparison.OrdinalIgnoreCase)
                                                        || normalizedSni.EndsWith("." + normalizedHost, StringComparison.OrdinalIgnoreCase)))
                                                {
                                                    anySniMatched = true;
                                                    if (isFail) anyFailSniMatched = true;
                                                    if (isOk) anyOkSniMatched = true;
                                                    if (isFail) sniFailCount++;
                                                    if (isOk) sniOkCount++;
                                                }
                                            }
                                        }
                                    }
                                }
                                catch
                                {
                                }

                                // Важно: обновляем рекомендации/диагнозы так же, как при обычной диагностике.
                                TrackIntelDiagnosisSummary(msg);
                                TrackRecommendation(msg, bypassController);
                                Log($"[PostApplyRetest][op={opId}] {msg}");
                                OnPipelineMessage?.Invoke(msg);
                            });
                        }
                        catch
                        {
                        }
                    });

                    using var pipeline = _pipelineFactory.Create(
                        pipelineConfig,
                        filter: _trafficFilter,
                        progress: progress,
                        trafficEngine: _trafficEngine,
                        dnsParser: _dnsParser,
                        stateStore: null,
                        autoHostlist: bypassController.AutoHostlist);

                    pipeline.OnPlanBuilt += (k, p) =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.BeginInvoke(() => StorePlan(k, p, bypassController));
                        }
                        catch
                        {
                        }
                    };

                    foreach (var h in hosts)
                    {
                        await pipeline.EnqueueHostAsync(h, IspAudit.Utils.LiveTestingPipeline.HostPriority.High).ConfigureAwait(false);
                    }

                    await pipeline.DrainAndCompleteAsync(latchedPostApplyPolicy.LocalDrainTimeout).ConfigureAwait(false);

                    // Итог: даже если outcome неоднозначен — логируем наблюдаемое.
                    var summaryOk = anySniMatched ? anyOkSniMatched : anyOk;
                    var summaryFail = anySniMatched ? anyFailSniMatched : anyFail;
                    var summaryOutcome = (summaryOk && summaryFail)
                        ? "UNKNOWN"
                        : (summaryFail ? "FAILED" : (summaryOk ? "SUCCESS" : "UNKNOWN"));

                    var summaryVerdict = (summaryOk && summaryFail)
                        ? "PARTIAL"
                        : (summaryFail ? "FAIL" : (summaryOk ? "OK" : "UNKNOWN"));

                    var localSummaryDetails = (summaryOk || summaryFail)
                        ? $"summaryOk={summaryOk}; summaryFail={summaryFail}; beforeSuccessCount={baselineSuccessBefore}; beforeSampleCount={baselineSampleBefore}; afterSuccessCount={(anySniMatched ? sniOkCount : totalOkCount)}; afterSampleCount={(anySniMatched ? (sniOkCount + sniFailCount) : (totalOkCount + totalFailCount))}; scopeKey={scopeKey}; runId={opId}"
                        : BuildUnknownDetails(UnknownReason.NoBaseline, $"summaryOk={summaryOk}; summaryFail={summaryFail}; no_summary_signals");

                    var effectiveAfterSuccess = anySniMatched ? sniOkCount : totalOkCount;
                    var effectiveAfterSample = anySniMatched ? (sniOkCount + sniFailCount) : (totalOkCount + totalFailCount);

                    if (effectiveAfterSample > 0)
                    {
                        var regression = IsGuardrailRegression(
                            baselineSuccessBefore,
                            baselineSampleBefore,
                            effectiveAfterSuccess,
                            latchedPostApplyPolicy.GuardrailSampleM,
                            latchedPostApplyPolicy.GuardrailSuccessK);
                        localSummaryDetails += $"; guardrailRegression={(regression ? 1 : 0)}; guardrailPolicy=KofM_{latchedPostApplyPolicy.GuardrailSuccessK}of{latchedPostApplyPolicy.GuardrailSampleM}; evalOrder={latchedPostApplyPolicy.EvaluationOrder}";
                    }

                    var (probeVerdict, probeDetails) = await ComputePostApplyProbeVerdictAsync(hostKey, ct).ConfigureAwait(false);
                    var normalizedProbe = NormalizeUnknownProbeVerdict(probeVerdict, probeDetails);
                    var semanticDetails = $"local_summary={summaryVerdict}; out={normalizedProbe.Verdict}; probe={normalizedProbe.Details}; {localSummaryDetails}";

                    var adjustedLocalSummary = ApplyBaselineFreshnessPolicy(
                        normalizedProbe.Verdict,
                        semanticDetails,
                        hasPendingBaseline,
                        isBaselineFresh,
                        baselineAge,
                        baselineTtl);

                    var guardrailStopReason = ResolveGuardrailStopReason(
                        hasPendingBaseline,
                        isBaselineFresh,
                        adjustedLocalSummary.Verdict,
                        adjustedLocalSummary.Details);

                    var guardrailRegression = hasPendingBaseline
                        && isBaselineFresh
                        && effectiveAfterSample > 0
                        && IsGuardrailRegression(
                            baselineSuccessBefore,
                            baselineSampleBefore,
                            effectiveAfterSuccess,
                            latchedPostApplyPolicy.GuardrailSampleM,
                            latchedPostApplyPolicy.GuardrailSuccessK);

                    var finalVerdict = adjustedLocalSummary.Verdict;
                    var finalDetails = adjustedLocalSummary.Details;

                    if (guardrailRegression)
                    {
                        if (!string.IsNullOrWhiteSpace(guardrailStopReason))
                        {
                            finalDetails = $"{finalDetails}; guardrailRollback=SKIPPED; guardrailStopReason={guardrailStopReason}";
                            Log($"[PostApplyRetest][op={opId}] Guardrail rollback skipped: reason={guardrailStopReason}; scopeKey={scopeKey}");
                            LogPolicyEvent("skip_reason", runId: opId, scopeKey: scopeKey, planSig: pendingBaseline?.PlanSig, reasonCode: $"GUARDRAIL_STOP_{guardrailStopReason}");
                        }
                        else
                        {
                            if (pendingBaseline != null)
                            {
                                RecordBlacklistHit(
                                    pendingBaseline.ScopeKey,
                                    pendingBaseline.PlanSig,
                                    pendingBaseline.DeltaStep,
                                    reason: "guardrail_regression",
                                    source: pendingBaseline.ActionSource);
                            }

                            try
                            {
                                await bypassController.RollbackAutopilotOnlyAsync(ct).ConfigureAwait(false);
                                finalDetails = $"{finalDetails}; guardrailRollback=DONE";
                                Log($"[PostApplyRetest][op={opId}] Guardrail rollback done: scopeKey={scopeKey}; runId={opId}");
                                LogPolicyEvent("rollback", runId: opId, scopeKey: scopeKey, planSig: pendingBaseline?.PlanSig, reasonCode: "GUARDRAIL_ROLLBACK_DONE");
                            }
                            catch (OperationCanceledException)
                            {
                                finalDetails = $"{finalDetails}; guardrailRollback=CANCELED";
                                finalVerdict = "UNKNOWN";
                                LogPolicyEvent("rollback", runId: opId, scopeKey: scopeKey, planSig: pendingBaseline?.PlanSig, reasonCode: "GUARDRAIL_ROLLBACK_CANCELED");
                            }
                            catch (Exception ex)
                            {
                                finalDetails = $"{finalDetails}; guardrailRollback=FAILED; rollbackError={ex.GetType().Name}";
                                Log($"[PostApplyRetest][op={opId}] Guardrail rollback failed: {ex.Message}");
                                LogPolicyEvent("rollback", runId: opId, scopeKey: scopeKey, planSig: pendingBaseline?.PlanSig, reasonCode: "GUARDRAIL_ROLLBACK_FAILED", details: ex.GetType().Name);
                            }
                        }
                    }

                    EmitPostApplyVerdict(hostKey, finalVerdict, "local", finalDetails);

                    UpdatePostApplyRetestUi(() =>
                    {
                        PostApplyRetestStatus = "Ретест после Apply: завершён";
                    });

                    Log($"[PostApplyRetest][op={opId}] Summary: host={hostKey}; outcome={summaryOutcome}; ok={(summaryOk ? 1 : 0)}; fail={(summaryFail ? 1 : 0)}; sniMatched={(anySniMatched ? 1 : 0)}");

                    // Feedback: по результату ретеста записываем исход применённых стратегий.
                    if (_pendingFeedbackByHostKey.TryRemove(hostKey, out var pending))
                    {
                        var store = FeedbackStoreProvider.TryGetStore(msg => Log(msg));
                        if (store != null)
                        {
                            // Если SNI совпадал с hostKey хотя бы раз — считаем outcome по SNI-matched множеству.
                            // Иначе fallback: по всем target IP.
                            var ok = anySniMatched ? anyOkSniMatched : anyOk;
                            var fail = anySniMatched ? anyFailSniMatched : anyFail;

                            var outcome = (ok && fail)
                                ? StrategyOutcome.Unknown
                                : (fail ? StrategyOutcome.Failure : (ok ? StrategyOutcome.Success : StrategyOutcome.Unknown));

                            if (outcome != StrategyOutcome.Unknown)
                            {
                                var now = DateTimeOffset.UtcNow;
                                var ids = pending.Plan.Strategies.Select(s => s.Id).ToList();

                                // DropUdp443 — это реализация техники QuicObfuscation.
                                if (pending.Plan.DropUdp443 && !ids.Contains(StrategyId.QuicObfuscation))
                                {
                                    ids.Add(StrategyId.QuicObfuscation);
                                }

                                foreach (var id in ids)
                                {
                                    store.Record(new FeedbackKey(pending.Plan.ForDiagnosis, id), outcome, now);
                                }

                                Log($"[FEEDBACK][op={opId}] recorded host={hostKey}; diag={pending.Plan.ForDiagnosis}; outcome={outcome}; ids={ids.Count}; sniMatched={(anySniMatched ? 1 : 0)}");
                            }
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    EmitPostApplyVerdict(hostKey, "UNKNOWN", "local", BuildUnknownDetails(UnknownReason.Cancelled, "cancelled"));
                    UpdatePostApplyRetestUi(() =>
                    {
                        PostApplyRetestStatus = "Ретест после Apply: отменён";
                    });

                    Log($"[PostApplyRetest][op={opId}] Canceled: mode=local; host={hostKey}");
                }
                catch (Exception ex)
                {
                    var reason = UnknownReason.ProbeTimeoutBudget;
                    EmitPostApplyVerdict(hostKey, "UNKNOWN", "local", BuildUnknownDetails(reason, $"error: {ex.Message}"));
                    UpdatePostApplyRetestUi(() =>
                    {
                        PostApplyRetestStatus = $"Ретест после Apply: ошибка ({ex.Message})";
                    });

                    Log($"[PostApplyRetest][op={opId}] Error: mode=local; error={ex.Message}");
                }
                finally
                {
                    var elapsedMs = (DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds;
                    UpdatePostApplyRetestUi(() => { IsPostApplyRetestRunning = false; });
                    if (_activePostApplyRunByScopeKey.TryGetValue(scopeKey, out var active)
                        && string.Equals(active, opId, StringComparison.OrdinalIgnoreCase))
                    {
                        _activePostApplyRunByScopeKey.TryRemove(scopeKey, out _);
                    }
                    Log($"[PostApplyRetest][op={opId}] Finish: mode=local; elapsedMs={elapsedMs:0}; host={hostKey}");
                }
            }, ct);
        }

        /// <summary>
        /// «Рестарт коннекта» (мягкий nudge): на короткое время дропаем трафик к целевым IP:443,
        /// чтобы приложение инициировало новое соединение уже под применённым bypass.
        /// </summary>
        public async Task NudgeReconnectAsync(BypassController bypassController, string? preferredHostKey)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));

            var hostKey = ResolveBestHostKeyForApply(preferredHostKey);
            if (string.IsNullOrWhiteSpace(hostKey))
            {
                PostApplyRetestStatus = "Рестарт коннекта: нет цели";
                return;
            }

            // Достаём IP-адреса (IPv4) и делаем короткий drop.
            var ips = await ResolveCandidateIpsAsync(hostKey, ct: CancellationToken.None).ConfigureAwait(false);
            if (ips.Count == 0)
            {
                PostApplyRetestStatus = $"Рестарт коннекта: IP не определены ({hostKey})";
                return;
            }

            if (!_trafficEngine.IsRunning)
            {
                try
                {
                    await _stateManager.StartEngineAsync().ConfigureAwait(false);
                }
                catch
                {
                    // Если движок не стартует (нет прав/драйвера) — просто выходим без падения.
                    PostApplyRetestStatus = "Рестарт коннекта: движок не запущен (нужны права администратора)";
                    return;
                }
            }

            var ttl = TimeSpan.FromSeconds(2);
            var untilLocal = DateTime.Now + ttl;
            var filterName = $"TempReconnectNudge:{DateTime.UtcNow:HHmmss}";
            var filter = new IspAudit.Core.Traffic.Filters.TemporaryEndpointBlockFilter(
                filterName,
                ips,
                ttl,
                port: 443,
                blockTcp: true,
                blockUdp: true);

            EndpointBlockStatus = $"Endpoint заблокирован до {untilLocal:HH:mm:ss} (порт 443, IP={ips.Count})";
            _stateManager.RegisterEngineFilter(filter);

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(ttl + TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
                    _stateManager.RemoveEngineFilter(filterName);

                    // Сбрасываем индикатор TTL-блока (best-effort).
                    try
                    {
                        Application.Current?.Dispatcher.BeginInvoke(() =>
                        {
                            if (!string.IsNullOrWhiteSpace(EndpointBlockStatus))
                            {
                                EndpointBlockStatus = "";
                            }
                        });
                    }
                    catch
                    {
                    }
                }
                catch
                {
                }
            });

            // После nudging — запускаем быстрый ретест, чтобы увидеть эффект.
            _ = StartPostApplyRetestAsync(bypassController, hostKey);
        }

        private string ResolveBestHostKeyForApply(string? preferredHostKey)
        {
            return _cardActionHandler.ResolveBestHostKey(preferredHostKey, _lastIntelPlanHostKey, _lastIntelDiagnosisHostKey);
        }

        private async Task<System.Collections.Generic.List<HostDiscovered>> BuildPostApplyRetestHostsAsync(
            string hostKey,
            int port,
            CancellationToken ct)
        {
            var list = new System.Collections.Generic.List<HostDiscovered>();
            var ips = await ResolveCandidateIpsAsync(hostKey, ct).ConfigureAwait(false);
            foreach (var ip in ips)
            {
                var key = $"{ip}:{port}:TCP";
                // Для домена передаём Hostname/SNI, чтобы TLS проверялся именно с SNI.
                var host = !IPAddress.TryParse(hostKey, out _)
                    ? new HostDiscovered(key, ip, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                    {
                        Hostname = hostKey,
                        SniHostname = hostKey
                    }
                    : new HostDiscovered(key, ip, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow);

                list.Add(host);
            }

            return list;
        }

        private async Task<System.Collections.Generic.List<IPAddress>> ResolveCandidateIpsAsync(string hostKey, CancellationToken ct)
        {
            var result = new System.Collections.Generic.List<IPAddress>();
            var seen = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

            hostKey = (hostKey ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(hostKey)) return result;

            if (IPAddress.TryParse(hostKey, out var directIp))
            {
                result.Add(directIp);
                return result;
            }

            // 1) Локальные кеши DNS/SNI (если сервисы ещё живы)
            try
            {
                if (_dnsParser != null)
                {
                    foreach (var kv in _dnsParser.DnsCache)
                    {
                        if (!IsHostKeyMatch(kv.Value, hostKey)) continue;
                        if (IPAddress.TryParse(kv.Key, out var ip) && seen.Add(ip.ToString()))
                        {
                            result.Add(ip);
                        }
                    }

                    foreach (var kv in _dnsParser.SniCache)
                    {
                        if (!IsHostKeyMatch(kv.Value, hostKey)) continue;
                        if (IPAddress.TryParse(kv.Key, out var ip) && seen.Add(ip.ToString()))
                        {
                            result.Add(ip);
                        }
                    }
                }
            }
            catch
            {
            }

            // 2) DNS resolve (может вернуть несколько IP)
            try
            {
                var dnsTask = System.Net.Dns.GetHostAddressesAsync(hostKey, ct);
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(4), ct);
                var completed = await Task.WhenAny(dnsTask, timeoutTask).ConfigureAwait(false);
                if (completed == dnsTask)
                {
                    var ips = await dnsTask.ConfigureAwait(false);
                    foreach (var ip in ips)
                    {
                        if (ip == null) continue;
                        if (seen.Add(ip.ToString())) result.Add(ip);
                    }
                }
            }
            catch
            {
            }

            return result;
        }

        /// <summary>
        /// Быстрый снимок candidate IP endpoints (для apply-транзакции):
        /// - если hostKey = IP, возвращаем его
        /// - иначе читаем только локальные кеши DNS/SNI (без DNS resolve)
        /// </summary>
        public System.Collections.Generic.IReadOnlyList<string> GetCachedCandidateIpEndpointsSnapshot(string hostKey)
        {
            var result = new System.Collections.Generic.List<string>();
            var seen = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

            hostKey = (hostKey ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(hostKey)) return result;

            if (IPAddress.TryParse(hostKey, out var directIp))
            {
                result.Add(directIp.ToString());
                return result;
            }

            try
            {
                if (_dnsParser != null)
                {
                    foreach (var kv in _dnsParser.DnsCache)
                    {
                        if (!IsHostKeyMatch(kv.Value, hostKey)) continue;
                        if (IPAddress.TryParse(kv.Key, out var ip) && seen.Add(ip.ToString()))
                        {
                            result.Add(ip.ToString());
                        }
                    }

                    foreach (var kv in _dnsParser.SniCache)
                    {
                        if (!IsHostKeyMatch(kv.Value, hostKey)) continue;
                        if (IPAddress.TryParse(kv.Key, out var ip) && seen.Add(ip.ToString()))
                        {
                            result.Add(ip.ToString());
                        }
                    }
                }
            }
            catch
            {
                // ignore
            }

            return result;
        }

        /// <summary>
        /// Best-effort снимок candidate IP endpoints (для apply-транзакции):
        /// кеши + DNS resolve (с таймаутом, задаваемым CancellationToken).
        /// </summary>
        public async Task<System.Collections.Generic.IReadOnlyList<string>> ResolveCandidateIpEndpointsSnapshotAsync(string hostKey, CancellationToken ct)
        {
            try
            {
                var ips = await ResolveCandidateIpsAsync(hostKey, ct).ConfigureAwait(false);
                return ips
                    .Where(ip => ip != null)
                    .Select(ip => ip.ToString())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
            catch
            {
                return Array.Empty<string>();
            }
        }

        private static bool IsHostKeyMatch(string candidate, string hostKey)
        {
            if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(hostKey)) return false;
            candidate = candidate.Trim();
            hostKey = hostKey.Trim();

            if (candidate.Equals(hostKey, StringComparison.OrdinalIgnoreCase)) return true;
            return candidate.EndsWith("." + hostKey, StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildBypassStateSummary(BypassController bypassController)
        {
            // Коротко и стабильно: только ключевые флаги.
            return $"Frag={(bypassController.IsFragmentEnabled ? 1 : 0)},Dis={(bypassController.IsDisorderEnabled ? 1 : 0)},Fake={(bypassController.IsFakeEnabled ? 1 : 0)},DropRst={(bypassController.IsDropRstEnabled ? 1 : 0)},QuicToTcp={(bypassController.IsQuicFallbackEnabled ? 1 : 0)},NoSni={(bypassController.IsAllowNoSniEnabled ? 1 : 0)},DoH={(bypassController.IsDoHEnabled ? 1 : 0)}";
        }

        private void ResetRecommendations()
        {
            _recommendedStrategies.Clear();
            _manualRecommendations.Clear();
            _legacyRecommendedStrategies.Clear();
            _legacyManualRecommendations.Clear();
            _lastIntelDiagnosisSummary = "";
            _lastIntelDiagnosisHostKey = "";
            _lastIntelPlan = null;
            _lastIntelPlanHostKey = "";
            RecommendedStrategiesText = "Нет рекомендаций";
            ManualRecommendationsText = "";
            OnPropertyChanged(nameof(HasRecommendations));
            OnPropertyChanged(nameof(HasAnyRecommendations));
        }

        private void UpdateRecommendationTexts(BypassController bypassController)
        {
            // Убираем рекомендации, если всё уже включено (актуально при ручном переключении)
            _recommendedStrategies.RemoveWhere(s => IsStrategyActive(s, bypassController));

            // Важно для UX: если Intel-слой уже диагностировал проблему/построил план,
            // панель рекомендаций не должна «исчезать» сразу после ручного включения тумблеров.
            var hasAny = _recommendedStrategies.Count > 0
                || _manualRecommendations.Count > 0
                || _lastIntelPlan != null
                || !string.IsNullOrWhiteSpace(_lastIntelDiagnosisSummary);

            if (!hasAny)
            {
                RecommendedStrategiesText = "Нет рекомендаций";
            }
            else if (_recommendedStrategies.Count == 0)
            {
                var header = string.IsNullOrWhiteSpace(_lastIntelDiagnosisSummary)
                    ? "[INTEL] Диагноз определён"
                    : _lastIntelDiagnosisSummary;

                // Если план был, но рекомендации уже включены вручную — объясняем, почему кнопка может быть не нужна.
                RecommendedStrategiesText = _lastIntelPlan != null
                    ? $"{header}\nРекомендации уже применены (вручную или ранее)"
                    : $"{header}\nАвтоматических рекомендаций нет";
            }
            else
            {
                RecommendedStrategiesText = BuildRecommendationPanelText();
            }

            var manualText = _manualRecommendations.Count == 0
                ? null
                : $"Ручные действия: {string.Join(", ", _manualRecommendations)}";

            ManualRecommendationsText = manualText ?? "";

            OnPropertyChanged(nameof(HasRecommendations));
            OnPropertyChanged(nameof(HasAnyRecommendations));

            // Подсказка остаётся статичной, но триггерим обновление, чтобы UI мог показать tooltip
            OnPropertyChanged(nameof(RecommendationHintText));
        }

        private string BuildRecommendationPanelText()
        {
            // Пишем текст так, чтобы пользователь видел «что попробовать», а не только метрики.
            // Важно: Intel — приоритетно; legacy — только справочно.
            var strategies = string.Join(", ", _recommendedStrategies.Select(FormatStrategyTokenForUi));

            var header = string.IsNullOrWhiteSpace(_lastIntelDiagnosisSummary)
                ? "[INTEL] Диагноз определён"
                : _lastIntelDiagnosisSummary;

            var applyHint = $"Что попробовать: нажмите «Применить рекомендации» (включит: {strategies})";

            return $"{header}\n{applyHint}";
        }

        private static bool IsStrategyActive(string strategy, BypassController bypassController)
        {
            return strategy.ToUpperInvariant() switch
            {
                "TLS_FRAGMENT" => bypassController.IsFragmentEnabled,
                "TLS_DISORDER" => bypassController.IsDisorderEnabled,
                "TLS_FAKE" => bypassController.IsFakeEnabled,
                "TLS_FAKE_FRAGMENT" => bypassController.IsFakeEnabled && bypassController.IsFragmentEnabled,
                "DROP_RST" => bypassController.IsDropRstEnabled,
                "DROP_UDP_443" => bypassController.IsQuicFallbackEnabled,
                "ALLOW_NO_SNI" => bypassController.IsAllowNoSniEnabled,
                // Back-compat
                "QUIC_TO_TCP" => bypassController.IsQuicFallbackEnabled,
                "NO_SNI" => bypassController.IsAllowNoSniEnabled,
                "DOH" => bypassController.IsDoHEnabled,
                _ => false
            };
        }


        #endregion
    }
}

