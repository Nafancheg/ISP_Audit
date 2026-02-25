using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class DiagnosticOrchestrator
    {
        // Защиты от «шторма» auto-apply.
        private readonly SemaphoreSlim _autoApplyGate = new(1, 1);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _autoApplyLastAttemptUtcByTarget = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _autoApplyLastSuccessUtcByTarget = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string> _autoApplyLastPlanSignatureByTarget = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTimeOffset>> _autoApplyLowConfidenceHitsByPolicyKey = new(StringComparer.OrdinalIgnoreCase);

        // MVP значения: достаточно, чтобы не «душить» UI/движок.
        private static readonly TimeSpan AutoApplyCooldown = TimeSpan.FromSeconds(45);
        private static readonly TimeSpan AutoApplySuccessCooldown = TimeSpan.FromMinutes(3);
        private static readonly TimeSpan AutoApplyMinInterval = TimeSpan.FromSeconds(5);

        // P1.11: execution policy автопилота.
        // Авто-применение должно быть консервативным: только безопасные/обратимые действия.
        private const int AutoApplyMinConfidenceDefault = 70;
        private const int AutoApplySafeMinConfidenceDefault = 70;
        private const int AutoApplyConfidenceBoostWindowMinutesDefault = 10;
        private const int AutoApplyConfidenceBoostRequiredHitsDefault = 3;
        private const int AutoApplyConfidenceBoostPerHitDefault = 5;
        private const int AutoApplyConfidenceBoostMaxDefault = 20;

        private static readonly HashSet<StrategyId> AutoApplyAllowedStrategyIds = new()
        {
            // TLS стратегии — основной MVP обход DPI; считаем обратимыми.
            StrategyId.TlsFragment,
            StrategyId.TlsDisorder,

            // HTTP host tricks — селективная техника на TCP/80.
            StrategyId.HttpHostTricks,

            // DropRst — обратимая техника (фильтр), но не системное изменение.
            StrategyId.DropRst,
        };

        // Safe-tier: действия с пониженным порогом confidence (при отдельном ENV).
        // В текущем этапе считаем безопасными только TLS fragment + assist DropUdp443.
        private static readonly HashSet<StrategyId> AutoApplySafeStrategyIds = new()
        {
            StrategyId.TlsFragment,
        };

        private void ResetAutoApplyState()
        {
            _autoApplyLastAttemptUtcByTarget.Clear();
            _autoApplyLastSuccessUtcByTarget.Clear();
            _autoApplyLastPlanSignatureByTarget.Clear();
            _autoApplyLowConfidenceHitsByPolicyKey.Clear();
        }

        private static string BuildPlanSignature(BypassPlan? plan)
        {
            if (plan == null) return string.Empty;

            // Сигнатура должна быть стабильной и дешёвой.
            // Порядок стратегий в списке уже является частью смысла (порядок проб/применения).
            var strategies = plan.Strategies.Count == 0
                ? ""
                : string.Join(",", plan.Strategies.ConvertAll(s => s.Id.ToString()));

            return $"{strategies}|U{(plan.DropUdp443 ? 1 : 0)}|N{(plan.AllowNoSni ? 1 : 0)}";
        }

        private bool TryBuildAutoApplyPlan(string hostKey, BypassPlan plan, out BypassPlan autoPlan, out string reason)
        {
            autoPlan = plan;
            reason = string.Empty;

            if (plan == null)
            {
                reason = "plan=null";
                return false;
            }

            var conf = Math.Clamp(plan.PlanConfidence, 0, 100);
            var minConfidence = AutoApplyMinConfidenceDefault;
            if (EnvVar.TryReadInt32(EnvKeys.AutoApplyMinConfidence, out var cfgMinConfidence))
            {
                minConfidence = Math.Clamp(cfgMinConfidence, 0, 100);
            }

            var minConfidenceSafe = AutoApplySafeMinConfidenceDefault;
            if (EnvVar.TryReadInt32(EnvKeys.AutoApplySafeMinConfidence, out var cfgMinConfidenceSafe))
            {
                minConfidenceSafe = Math.Clamp(cfgMinConfidenceSafe, 0, 100);
            }

            var allowDnsDoh = false;
            try
            {
                allowDnsDoh = _stateManager.AllowDnsDohSystemChanges;
            }
            catch
            {
                allowDnsDoh = false;
            }

            var filtered = new List<BypassStrategy>(capacity: plan.Strategies.Count);
            foreach (var s in plan.Strategies)
            {
                if (s == null) continue;

                // DNS/DoH — системное изменение. Автопилот может применять только при явном consent.
                if (s.Id == StrategyId.UseDoh)
                {
                    if (allowDnsDoh)
                    {
                        filtered.Add(s);
                    }
                    continue;
                }

                // Агрессивные/небезопасные стратегии не auto-apply.
                if (!AutoApplyAllowedStrategyIds.Contains(s.Id))
                {
                    continue;
                }

                // High-risk стратегии запрещены в автопилоте (даже если selector их когда-то вернул).
                if (s.Risk == RiskLevel.High)
                {
                    continue;
                }

                filtered.Add(s);
            }

            // Assist-флаги:
            // - DROP_UDP_443 считаем допустимым, т.к. реализован селективно (target IP list).
            // - ALLOW_NO_SNI не включаем автоматически: может расширить охват действия.
            var allowDropUdp443 = plan.DropUdp443;
            var allowNoSni = false;

            if (filtered.Count == 0 && !allowDropUdp443)
            {
                reason = allowDnsDoh
                    ? "no eligible actions"
                    : "no eligible actions (or DoH requires consent)";
                return false;
            }

            var safeOnly = allowDropUdp443
                && filtered.Count == 0
                || (filtered.Count > 0
                    && filtered.All(s => AutoApplySafeStrategyIds.Contains(s.Id))
                    && !allowNoSni);
            var requiredConfidence = safeOnly ? minConfidenceSafe : minConfidence;

            var normalizedTargetHost = ResolveAutoApplyTargetHost(hostKey);
            var planSig = BuildPlanSignature(plan);
            var now = DateTimeOffset.UtcNow;
            var (hits, boost, requiredHits) = GetConfidenceBoost(normalizedTargetHost, planSig, now);
            var effectiveConfidence = Math.Clamp(conf + boost, 0, 100);

            if (effectiveConfidence < requiredConfidence)
            {
                RegisterLowConfidenceHit(normalizedTargetHost, planSig, now);
                reason = safeOnly
                    ? $"confidence<{requiredConfidence};tier=safe;raw={conf};effective={effectiveConfidence};hits={hits};requiredHits={requiredHits};boost={boost}"
                    : $"confidence<{requiredConfidence};tier=general;raw={conf};effective={effectiveConfidence};hits={hits};requiredHits={requiredHits};boost={boost}";
                return false;
            }

            // Не мутируем исходный план: создаём “auto plan” со строгими ограничениями.
            autoPlan = new BypassPlan
            {
                ForDiagnosis = plan.ForDiagnosis,
                PlanConfidence = conf,
                PlannedAtUtc = plan.PlannedAtUtc,
                Reasoning = plan.Reasoning,

                Strategies = filtered,
                DeferredStrategies = plan.DeferredStrategies ?? new List<DeferredBypassStrategy>(),

                DropUdp443 = allowDropUdp443,
                AllowNoSni = allowNoSni,
            };

            return true;
        }

        private (int hits, int boost, int requiredHits) GetConfidenceBoost(string targetHost, string planSig, DateTimeOffset nowUtc)
        {
            var requiredHits = ReadClampedEnvInt(
                EnvKeys.AutoApplyConfidenceBoostRequiredHits,
                AutoApplyConfidenceBoostRequiredHitsDefault,
                min: 1,
                max: 20);
            var windowMinutes = ReadClampedEnvInt(
                EnvKeys.AutoApplyConfidenceBoostWindowMinutes,
                AutoApplyConfidenceBoostWindowMinutesDefault,
                min: 1,
                max: 120);
            var boostPerHit = ReadClampedEnvInt(
                EnvKeys.AutoApplyConfidenceBoostPerHit,
                AutoApplyConfidenceBoostPerHitDefault,
                min: 0,
                max: 50);
            var maxBoost = ReadClampedEnvInt(
                EnvKeys.AutoApplyConfidenceBoostMax,
                AutoApplyConfidenceBoostMaxDefault,
                min: 0,
                max: 50);

            if (string.IsNullOrWhiteSpace(targetHost) || string.IsNullOrWhiteSpace(planSig))
            {
                return (hits: 0, boost: 0, requiredHits: requiredHits);
            }

            var key = BuildLowConfidencePolicyKey(targetHost, planSig);
            var queue = _autoApplyLowConfidenceHitsByPolicyKey.GetOrAdd(key, _ => new ConcurrentQueue<DateTimeOffset>());

            var cutoff = nowUtc - TimeSpan.FromMinutes(windowMinutes);
            while (queue.TryPeek(out var head) && head < cutoff)
            {
                queue.TryDequeue(out _);
            }

            var hits = queue.Count;
            if (hits < requiredHits || boostPerHit <= 0 || maxBoost <= 0)
            {
                return (hits: hits, boost: 0, requiredHits: requiredHits);
            }

            var overThreshold = hits - requiredHits + 1;
            var boost = Math.Clamp(overThreshold * boostPerHit, 0, maxBoost);
            return (hits: hits, boost: boost, requiredHits: requiredHits);
        }

        private void RegisterLowConfidenceHit(string targetHost, string planSig, DateTimeOffset nowUtc)
        {
            if (string.IsNullOrWhiteSpace(targetHost) || string.IsNullOrWhiteSpace(planSig))
            {
                return;
            }

            var windowMinutes = ReadClampedEnvInt(
                EnvKeys.AutoApplyConfidenceBoostWindowMinutes,
                AutoApplyConfidenceBoostWindowMinutesDefault,
                min: 1,
                max: 120);

            var key = BuildLowConfidencePolicyKey(targetHost, planSig);
            var queue = _autoApplyLowConfidenceHitsByPolicyKey.GetOrAdd(key, _ => new ConcurrentQueue<DateTimeOffset>());
            queue.Enqueue(nowUtc);

            var cutoff = nowUtc - TimeSpan.FromMinutes(windowMinutes);
            while (queue.TryPeek(out var head) && head < cutoff)
            {
                queue.TryDequeue(out _);
            }
        }

        private static int ReadClampedEnvInt(string envKey, int defaultValue, int min, int max)
        {
            var value = defaultValue;
            if (EnvVar.TryReadInt32(envKey, out var parsed))
            {
                value = parsed;
            }

            return Math.Clamp(value, min, max);
        }

        private static string BuildLowConfidencePolicyKey(string targetHost, string planSig)
            => $"{targetHost}|{planSig}";

        private string ResolveAutoApplyTargetHost(string hostKey)
        {
            var hk = (hostKey ?? string.Empty).Trim().Trim('.');
            if (hk.Length == 0) return string.Empty;

            // Для доменов применяем в более «широком» масштабе: SLD+TLD (или эвристика co.uk из NetUtils).
            // Это уменьшает вероятность «applied but no effect» для шардовых/случайных поддоменов.
            if (!System.Net.IPAddress.TryParse(hk, out _))
            {
                var main = NetUtils.GetMainDomain(hk);
                if (!string.IsNullOrWhiteSpace(main)) return main.Trim().Trim('.');
            }

            return hk;
        }

        private bool IsAutoApplyCooldownActive(string targetHost, bool allowWhenPlanChanged, bool planChanged, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;

            var now = DateTimeOffset.UtcNow;

            // После успеха не спамим повторными apply, но если план поменялся — разрешаем быстрее.
            if (!allowWhenPlanChanged || !planChanged)
            {
                if (_autoApplyLastSuccessUtcByTarget.TryGetValue(targetHost, out var lastSuccessUtc))
                {
                    var age = now - lastSuccessUtc;
                    if (age < AutoApplySuccessCooldown)
                    {
                        remaining = AutoApplySuccessCooldown - age;
                        return true;
                    }
                }
            }

            if (_autoApplyLastAttemptUtcByTarget.TryGetValue(targetHost, out var lastAttemptUtc))
            {
                var age = now - lastAttemptUtc;

                // Минимальный интервал соблюдаем всегда.
                if (age < AutoApplyMinInterval)
                {
                    remaining = AutoApplyMinInterval - age;
                    return true;
                }

                // Если план не менялся — держим более длинный cooldown.
                if ((!allowWhenPlanChanged || !planChanged) && age < AutoApplyCooldown)
                {
                    remaining = AutoApplyCooldown - age;
                    return true;
                }
            }

            return false;
        }

        private void TryStartAutoApplyFromPlan(string hostKey, BypassPlan plan, BypassController bypassController)
        {
            if (bypassController == null) return;

            // Не накапливаем очередь фоновых задач: автопилот «мягкий». Если уже занят — пропускаем.
            if (_autoApplyGate.CurrentCount == 0)
            {
                return;
            }

            if (!TryBuildAutoApplyPlan(hostKey, plan, out var autoPlan, out var policyReason))
            {
                if (!string.IsNullOrWhiteSpace(policyReason))
                {
                    Log($"[AUTO_APPLY] Skip (policy {policyReason}): from={hostKey}");
                    var reasonCode = policyReason.StartsWith("confidence<", StringComparison.OrdinalIgnoreCase)
                        ? "LOW_CONFIDENCE"
                        : policyReason.Contains("DoH requires consent", StringComparison.OrdinalIgnoreCase)
                            ? "DOH_CONSENT_REQUIRED"
                            : policyReason.Contains("no eligible actions", StringComparison.OrdinalIgnoreCase)
                                ? "UNSAFE_OR_NOT_ALLOWED_ACTIONS"
                                : "POLICY_BLOCK";
                    LogPolicyEvent("skip_reason", runId: null, scopeKey: hostKey, planSig: BuildPlanSignature(plan), reasonCode: reasonCode, details: policyReason);
                }

                return;
            }

            if (!PlanHasApplicableActions(autoPlan)) return;

            // Диагностика должна быть активна: auto-apply имеет смысл только в live-сценарии.
            if (!IsDiagnosticRunning) return;

            // Не делаем auto-apply по шумовым/техническим целям.
            if (_noiseHostFilter.IsNoiseHost(hostKey)) return;

            var targetHost = ResolveAutoApplyTargetHost(hostKey);
            if (string.IsNullOrWhiteSpace(targetHost)) return;

            var planSig = BuildPlanSignature(autoPlan);
            if (IsBlacklisted(targetHost, planSig, deltaStep: string.Empty, reason: "guardrail_regression", out var blAuto))
            {
                Log($"[AUTO_APPLY] Skip (blacklist_hit): target={targetHost}; sig={planSig}; expiresAt={blAuto?.ExpiresAtUtc}");
                LogPolicyEvent("blacklist_hit", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "GUARDRAIL_REGRESSION", details: $"expiresAt={blAuto?.ExpiresAtUtc}");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "BLACKLIST_HIT");
                return;
            }

            var planChanged = !_autoApplyLastPlanSignatureByTarget.TryGetValue(targetHost, out var lastSig)
                || !string.Equals(lastSig, planSig, StringComparison.OrdinalIgnoreCase);

            // UI/оркестратор уже показывают рекомендацию — auto-apply должен быть «мягким» и не спамить.
            if (IsAutoApplyCooldownActive(targetHost, allowWhenPlanChanged: true, planChanged: planChanged, out var remaining))
            {
                Log($"[AUTO_APPLY] Skip (cooldown {remaining.TotalSeconds:0}s): target={targetHost}; from={hostKey}");
                LogPolicyEvent("skip_reason", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "AUTO_APPLY_COOLDOWN", details: $"remainingSec={remaining.TotalSeconds:0}");
                return;
            }

            _autoApplyLastAttemptUtcByTarget[targetHost] = DateTimeOffset.UtcNow;
            _autoApplyLastPlanSignatureByTarget[targetHost] = planSig;

            // Fire-and-forget: внутри есть gate + уважение Cancel.
            _ = Task.Run(() => AutoApplyFromPlanAsync(targetHost, hostKey, autoPlan, planSig, bypassController));
        }

        private async Task AutoApplyFromPlanAsync(string targetHost, string sourceHostKey, BypassPlan plan, string planSig, BypassController bypassController)
        {
            // Глобальный gate, чтобы не запускать несколько auto-apply параллельно.
            // Важно: ApplyIntelPlanAsync уже сериализуется внутри BypassController, но нам нужно сдержать UI/лог.
            await _autoApplyGate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_cts?.IsCancellationRequested == true) return;

                // P1.11: enforcement policy (confidence/risk/allowlist/consent) на этапе исполнения.
                if (!TryBuildAutoApplyPlan(targetHost, plan, out var autoPlan, out var policyReason))
                {
                    Log($"[AUTO_APPLY] Skip (policy {policyReason}): target={targetHost}; from={sourceHostKey}");
                    var reasonCode = policyReason.StartsWith("confidence<", StringComparison.OrdinalIgnoreCase)
                        ? "LOW_CONFIDENCE"
                        : policyReason.Contains("DoH requires consent", StringComparison.OrdinalIgnoreCase)
                            ? "DOH_CONSENT_REQUIRED"
                            : policyReason.Contains("no eligible actions", StringComparison.OrdinalIgnoreCase)
                                ? "UNSAFE_OR_NOT_ALLOWED_ACTIONS"
                                : "POLICY_BLOCK";
                    LogPolicyEvent("skip_reason", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: reasonCode, details: policyReason);
                    return;
                }

                // На всякий случай используем сигнатуру auto-плана.
                var effectiveSig = BuildPlanSignature(autoPlan);
                if (string.IsNullOrWhiteSpace(effectiveSig))
                {
                    Log($"[AUTO_APPLY] Skip (empty sig): target={targetHost}; from={sourceHostKey}");
                    return;
                }

                planSig = effectiveSig;
                plan = autoPlan;

                if (IsBlacklisted(targetHost, planSig, deltaStep: string.Empty, reason: "guardrail_regression", out var blAutoRuntime))
                {
                    Log($"[AUTO_APPLY] Skip (blacklist_hit): target={targetHost}; sig={planSig}; expiresAt={blAutoRuntime?.ExpiresAtUtc}");
                    LogPolicyEvent("blacklist_hit", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "GUARDRAIL_REGRESSION", details: $"expiresAt={blAutoRuntime?.ExpiresAtUtc}");
                    LogPolicyEvent("skip_reason", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "BLACKLIST_HIT");
                    return;
                }

                // Если пользователь уже вручную жмёт Apply, не мешаем.
                if (IsApplyRunning)
                {
                    Log($"[AUTO_APPLY] Skip (manual apply running): target={targetHost}; from={sourceHostKey}");
                    LogPolicyEvent("skip_reason", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "MANUAL_APPLY_RUNNING");
                    return;
                }

                var planChanged = !_autoApplyLastPlanSignatureByTarget.TryGetValue(targetHost, out var lastSig)
                    || !string.Equals(lastSig, planSig, StringComparison.OrdinalIgnoreCase);

                if (IsAutoApplyCooldownActive(targetHost, allowWhenPlanChanged: true, planChanged: planChanged, out var remaining))
                {
                    Log($"[AUTO_APPLY] Skip (cooldown {remaining.TotalSeconds:0}s): target={targetHost}; from={sourceHostKey}");
                    LogPolicyEvent("skip_reason", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "AUTO_APPLY_COOLDOWN", details: $"remainingSec={remaining.TotalSeconds:0}");
                    return;
                }

                _autoApplyLastAttemptUtcByTarget[targetHost] = DateTimeOffset.UtcNow;
                _autoApplyLastPlanSignatureByTarget[targetHost] = planSig;

                var txId = Guid.NewGuid().ToString("N");
                using var op = BypassOperationContext.Enter(txId, "auto_apply", targetHost);

                Log($"[AUTO_APPLY] Start: target={targetHost}; source={sourceHostKey}; tx={txId}");
                LogPolicyEvent("apply", runId: txId, scopeKey: targetHost, planSig: planSig, reasonCode: "AUTO_APPLY_START", details: $"source={sourceHostKey}");

                try
                {
                    // Пишем в pipeline прогресс, чтобы пользователь видел причину «само что-то применилось».
                    OnPipelineMessage?.Invoke($"⚙ Auto-apply: {targetHost} (по плану для {sourceHostKey})");
                }
                catch
                {
                }

                // Реальное применение.
                var outcome = await ApplyPlanInternalAsync(
                    bypassController,
                    targetHost,
                    plan,
                    deltaStep: string.Empty,
                    actionSource: "auto_apply").ConfigureAwait(false);
                if (outcome == null)
                {
                    Log($"[AUTO_APPLY] Done: no-op/skip (outcome null): target={targetHost}");
                    return;
                }

                // Наблюдаемость: фиксируем авто-применение как apply-транзакцию,
                // чтобы позже можно было выборочно откатывать только autopilot.
                try
                {
                    var endpoints = GetCachedCandidateIpEndpointsSnapshot(targetHost);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await ResolveCandidateIpEndpointsSnapshotAsync(targetHost, cts.Token).ConfigureAwait(false);
                    }

                    bypassController.RecordApplyTransaction(
                        initiatorHostKey: targetHost,
                        groupKey: targetHost,
                        candidateIpEndpoints: endpoints,
                        appliedStrategyText: outcome.AppliedStrategyText,
                        planText: outcome.PlanText,
                        reasoning: outcome.Reasoning,
                        transactionIdOverride: txId,
                        resultStatus: outcome.Status,
                        error: outcome.Error,
                        rollbackStatus: outcome.RollbackStatus,
                        cancelReason: outcome.CancelReason,
                        applyCurrentPhase: outcome.ApplyCurrentPhase,
                        applyTotalElapsedMs: outcome.ApplyTotalElapsedMs,
                        applyPhases: outcome.ApplyPhases,
                        appliedBy: "autopilot",
                        scope: "target",
                        scopeKey: targetHost);
                }
                catch
                {
                    // best-effort
                }

                if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                {
                    _autoApplyLastSuccessUtcByTarget[targetHost] = DateTimeOffset.UtcNow;
                }

                // После apply:
                // 1) outcome-probe (быстрая проверка целевого hostKey)
                // 2) ретест через enqueue (подхватит новые результаты в UI без остановки диагностики)
                try
                {
                    bypassController.RunOutcomeProbeNowCommand?.Execute(null);
                }
                catch
                {
                }

                _ = Task.Run(() => EnqueueAutoRetestAsync(targetHost));

                Log($"[AUTO_APPLY] Done: target={targetHost}; status={outcome.Status}; applied='{outcome.AppliedStrategyText}'");
                LogPolicyEvent("apply", runId: txId, scopeKey: targetHost, planSig: planSig, reasonCode: $"AUTO_APPLY_{outcome.Status}", details: outcome.AppliedStrategyText);
            }
            catch (Exception ex)
            {
                Log($"[AUTO_APPLY] FAILED: target={targetHost}; error={ex.Message}");
                LogPolicyEvent("apply", runId: null, scopeKey: targetHost, planSig: planSig, reasonCode: "AUTO_APPLY_FAILED", details: ex.GetType().Name);
            }
            finally
            {
                try { _autoApplyGate.Release(); } catch { }
            }
        }

        private async Task EnqueueAutoRetestAsync(string targetHost)
        {
            try
            {
                if (_cts?.IsCancellationRequested == true) return;
                if (_testingPipeline == null) return;

                // Небольшая пауза: даём движку применить правила.
                await Task.Delay(TimeSpan.FromMilliseconds(350)).ConfigureAwait(false);

                var ct = _cts?.Token ?? CancellationToken.None;
                var hosts = await BuildPostApplyRetestHostsAsync(targetHost, port: 443, ct).ConfigureAwait(false);
                if (hosts.Count == 0)
                {
                    Log($"[AUTO_RETEST] No targets resolved: {targetHost}");
                    return;
                }

                Log($"[AUTO_RETEST] Enqueue: target={targetHost}; ips={hosts.Count}");

                foreach (var h in hosts)
                {
                    if (_cts?.IsCancellationRequested == true) break;
                    await _testingPipeline.EnqueueHostAsync(h, IspAudit.Utils.LiveTestingPipeline.HostPriority.High).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                Log($"[AUTO_RETEST] FAILED: target={targetHost}; error={ex.Message}");
            }
        }
    }
}
