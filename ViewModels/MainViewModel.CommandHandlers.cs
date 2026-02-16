using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Bypass;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Models;
using IspAudit.Utils;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region Command Handlers

        public bool TryGetVerifiedWinForHostKey(string? hostKey, out WinsEntry? win)
        {
            win = null;
            try
            {
                lock (_winsSync)
                {
                    return WinsStore.TryGetBestMatch(_winsByHostKey, hostKey, out win);
                }
            }
            catch
            {
                win = null;
                return false;
            }
        }

        private string GetStableApplyGroupKeyForHostKey(string? hostKey)
        {
            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hk)) return string.Empty;

                if (_groupBypassAttachmentStore.TryGetPinnedGroupKey(hk, out var pinned))
                {
                    var pk = (pinned ?? string.Empty).Trim().Trim('.');
                    if (!string.IsNullOrWhiteSpace(pk))
                    {
                        return pk;
                    }
                }

                return ComputeApplyGroupKey(hk, Results.SuggestedDomainSuffix);
            }
            catch
            {
                return string.Empty;
            }
        }

        private void PinHostKeyToGroupKeyBestEffort(string? hostKey, string? groupKey)
        {
            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                var gk = (groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hk) || string.IsNullOrWhiteSpace(gk)) return;

                _groupBypassAttachmentStore.PinHostKeyToGroupKey(hk, gk);
            }
            catch
            {
                // ignore
            }
        }

        private void ToggleParticipationFromResult(TestResult? test)
        {
            try
            {
                if (test == null) return;

                var hostKey = GetPreferredHostKey(test);
                if (string.IsNullOrWhiteSpace(hostKey))
                {
                    test.ActionStatusText = "Участие: нет цели";
                    return;
                }

                // Не даём управлять участием для шумовых хостов.
                if (!IPAddress.TryParse(hostKey, out _) && _noiseHostFilter.IsNoiseHost(hostKey))
                {
                    test.ActionStatusText = "Участие: шумовой хост (EXCLUDED)";
                    return;
                }

                var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                var normalizedGroupKey = (groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(normalizedGroupKey))
                {
                    test.ActionStatusText = "Участие: группа не определена";
                    return;
                }

                var normalizedHostKey = hostKey.Trim().Trim('.');

                var nowExcluded = _groupBypassAttachmentStore.ToggleExcluded(normalizedGroupKey, normalizedHostKey);

                // Step 11: как только пользователь явно управляет участием, пиним groupKey для hostKey.
                PinHostKeyToGroupKeyBestEffort(normalizedHostKey, normalizedGroupKey);

                PersistManualParticipationBestEffort();

                UpdateManualParticipationMarkersForGroupKey(normalizedGroupKey);
                UpdateSelectedResultApplyTransactionDetails();

                test.ActionStatusText = nowExcluded
                    ? "Участие: исключено из группы"
                    : "Участие: возвращено в группу";
            }
            catch (Exception ex)
            {
                Log($"[P0.1][Participation] Error: {ex.Message}");
            }
        }

        private async Task ApplyRecommendationsAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                var txId = Guid.NewGuid().ToString("N");
                using var op = BypassOperationContext.Enter(txId, "ui_apply_recommendations", preferredHostKey);

                var outcome = await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey).ConfigureAwait(false);

                // Практический UX: сразу запускаем короткий пост-Apply ретест по цели.
                if (outcome != null && string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                {
                    var groupKeyForCheck = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    SetPostApplyCheckStatusForGroupKey(groupKeyForCheck, IsRunning ? PostApplyCheckStatus.Queued : PostApplyCheckStatus.Running);
                }
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey, txId);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                        MarkAppliedBypassTargetsForGroupKey(groupKey);

                        // Step 11: user-initiated apply фиксирует groupKey для этой цели.
                        PinHostKeyToGroupKeyBestEffort(outcome.HostKey, groupKey);
                        PersistManualParticipationBestEffort();
                    }

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        _groupBypassAttachmentStore.UpdateAttachmentFromApply(groupKey, outcome.HostKey, endpoints, outcome.PlanText);
                        PersistManualParticipationBestEffort();
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning,
                        transactionIdOverride: txId,
                        resultStatus: outcome.Status,
                        error: outcome.Error,
                        rollbackStatus: outcome.RollbackStatus,
                        cancelReason: outcome.CancelReason,
                        applyCurrentPhase: outcome.ApplyCurrentPhase,
                        applyTotalElapsedMs: outcome.ApplyTotalElapsedMs,
                        applyPhases: outcome.ApplyPhases);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[APPLY] Отмена применения рекомендаций");
            }
            catch (Exception ex)
            {
                Log($"[APPLY] Ошибка применения рекомендаций: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ApplyVerifiedWinAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[APPLY][WIN] Bypass недоступен (нужны права администратора)");
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                if (!TryGetVerifiedWinForHostKey(preferredHostKey, out var win) || win == null)
                {
                    Log("[APPLY][WIN] Нет сохранённого wins-плана для цели");
                    return;
                }

                var plan = TryBuildBypassPlanFromWin(win);
                if (!PlanHasApplicableActions(plan))
                {
                    Log("[APPLY][WIN] Wins-план пустой (нет применимых действий)");
                    return;
                }

                var txId = Guid.NewGuid().ToString("N");
                using var op = BypassOperationContext.Enter(txId, "ui_apply_verified_win", preferredHostKey);

                var outcome = await Orchestrator.ApplyProvidedPlanAsync(Bypass, plan, preferredHostKey).ConfigureAwait(false);

                // Практический UX: сразу запускаем короткий пост-Apply ретест по цели.
                if (outcome != null && string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                {
                    var groupKeyForCheck = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    SetPostApplyCheckStatusForGroupKey(groupKeyForCheck, IsRunning ? PostApplyCheckStatus.Queued : PostApplyCheckStatus.Running);
                }
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey, txId);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                        MarkAppliedBypassTargetsForGroupKey(groupKey);

                        // user-initiated apply фиксирует groupKey для этой цели.
                        PinHostKeyToGroupKeyBestEffort(outcome.HostKey, groupKey);
                        PersistManualParticipationBestEffort();
                    }

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        _groupBypassAttachmentStore.UpdateAttachmentFromApply(groupKey, outcome.HostKey, endpoints, outcome.PlanText);
                        PersistManualParticipationBestEffort();
                    }

                    var winRef = string.IsNullOrWhiteSpace(win.CorrelationId) ? string.Empty : $"win_tx={win.CorrelationId}";
                    var reasoning = string.IsNullOrWhiteSpace(winRef)
                        ? (plan.Reasoning ?? string.Empty)
                        : $"{winRef}; {plan.Reasoning}";

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, reasoning,
                        transactionIdOverride: txId,
                        resultStatus: outcome.Status,
                        error: outcome.Error,
                        rollbackStatus: outcome.RollbackStatus,
                        cancelReason: outcome.CancelReason,
                        applyCurrentPhase: outcome.ApplyCurrentPhase,
                        applyTotalElapsedMs: outcome.ApplyTotalElapsedMs,
                        applyPhases: outcome.ApplyPhases);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[APPLY][WIN] Отмена применения wins-плана");
            }
            catch (Exception ex)
            {
                Log($"[APPLY][WIN] Ошибка применения wins-плана: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private static bool PlanHasApplicableActions(BypassPlan plan)
            => plan.Strategies.Count > 0 || plan.DropUdp443 || plan.AllowNoSni;

        private static BypassPlan TryBuildBypassPlanFromWin(WinsEntry win)
        {
            try
            {
                if (win.Plan != null && PlanHasApplicableActions(win.Plan))
                {
                    return win.Plan;
                }

                var tokens = SplitPlanTokens(win.PlanText ?? string.Empty);

                var dropUdp443 = tokens.Contains("DROP_UDP_443") || tokens.Contains("QUIC_TO_TCP");
                var allowNoSni = tokens.Contains("ALLOW_NO_SNI") || tokens.Contains("NO_SNI");

                var plan = new BypassPlan
                {
                    PlannedAtUtc = DateTimeOffset.UtcNow,
                    PlanConfidence = 100,
                    Reasoning = "wins_store",
                    ForDiagnosis = default,
                    DropUdp443 = dropUdp443,
                    AllowNoSni = allowNoSni,
                };

                if (tokens.Contains("TLS_FRAGMENT"))
                {
                    plan.Strategies.Add(new BypassStrategy { Id = StrategyId.TlsFragment, BasePriority = 0, Risk = RiskLevel.Low });
                }
                if (tokens.Contains("TLS_DISORDER"))
                {
                    plan.Strategies.Add(new BypassStrategy { Id = StrategyId.TlsDisorder, BasePriority = 0, Risk = RiskLevel.Low });
                }
                if (tokens.Contains("TLS_FAKE") || tokens.Contains("TLS_FAKE_FRAGMENT"))
                {
                    plan.Strategies.Add(new BypassStrategy { Id = StrategyId.TlsFakeTtl, BasePriority = 0, Risk = RiskLevel.Medium });
                }
                if (tokens.Contains("DROP_RST"))
                {
                    plan.Strategies.Add(new BypassStrategy { Id = StrategyId.DropRst, BasePriority = 0, Risk = RiskLevel.Medium });
                }

                return plan;
            }
            catch
            {
                return new BypassPlan
                {
                    PlannedAtUtc = DateTimeOffset.UtcNow,
                    PlanConfidence = 0,
                    Reasoning = "wins_store_error"
                };
            }
        }

        private async Task ApplyEscalationAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[APPLY][ESCALATE] Bypass недоступен (нужны права администратора)");
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                var txId = Guid.NewGuid().ToString("N");
                using var op = BypassOperationContext.Enter(txId, "ui_apply_escalation", preferredHostKey);

                var outcome = await Orchestrator.ApplyEscalationAsync(Bypass, preferredHostKey).ConfigureAwait(false);
                if (outcome == null)
                {
                    Log("[APPLY][ESCALATE] Нет доступной ступени усиления");
                    return;
                }

                try
                {
                    var groupKeyForLog = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    var prevTx = Bypass.TryGetLatestApplyTransactionForGroupKey(groupKeyForLog);
                    var from = string.IsNullOrWhiteSpace(prevTx?.AppliedStrategyText) ? "none" : prevTx.AppliedStrategyText.Trim();
                    var to = string.IsNullOrWhiteSpace(outcome.AppliedStrategyText) ? "unknown" : outcome.AppliedStrategyText.Trim();
                    var result = string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase) ? "OK" : "FAIL";
                    Log($"[ESCALATION] group={groupKeyForLog} from={from} to={to} result={result}");
                }
                catch
                {
                    // ignore
                }

                // Практический UX: сразу запускаем короткий пост-Apply ретест по цели.
                if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                {
                    var groupKeyForCheck = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    SetPostApplyCheckStatusForGroupKey(groupKeyForCheck, IsRunning ? PostApplyCheckStatus.Queued : PostApplyCheckStatus.Running);
                }

                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey, txId);

                if (Bypass.IsBypassActive && SelectedTestResult != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                        MarkAppliedBypassTargetsForGroupKey(groupKey);

                        // Step 11: user-initiated apply фиксирует groupKey для этой цели.
                        PinHostKeyToGroupKeyBestEffort(outcome.HostKey, groupKey);
                        PersistManualParticipationBestEffort();
                    }

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        _groupBypassAttachmentStore.UpdateAttachmentFromApply(groupKey, outcome.HostKey, endpoints, outcome.PlanText);
                        PersistManualParticipationBestEffort();
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning,
                        transactionIdOverride: txId,
                        resultStatus: outcome.Status,
                        error: outcome.Error,
                        rollbackStatus: outcome.RollbackStatus,
                        cancelReason: outcome.CancelReason,
                        applyCurrentPhase: outcome.ApplyCurrentPhase,
                        applyTotalElapsedMs: outcome.ApplyTotalElapsedMs,
                        applyPhases: outcome.ApplyPhases);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[APPLY][ESCALATE] Отмена усиления");
            }
            catch (Exception ex)
            {
                Log($"[APPLY][ESCALATE] Ошибка усиления: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ApplyDomainRecommendationsAsync(string? domainOverride = null)
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                // Если домен задан явно (например из кнопки строки) — используем его.
                // Иначе работаем по авто-подсказке семейства.
                if (string.IsNullOrWhiteSpace(domainOverride) && !HasDomainSuggestion)
                {
                    Log("[APPLY] Доменная подсказка недоступна для текущей цели");
                    return;
                }

                var domain = string.IsNullOrWhiteSpace(domainOverride)
                    ? Results.SuggestedDomainSuffix
                    : domainOverride;

                if (string.IsNullOrWhiteSpace(domain))
                {
                    Log("[APPLY] Доменная цель не определена");
                    return;
                }

                if (!string.IsNullOrWhiteSpace(domainOverride))
                {
                    Log($"[APPLY] Доменный apply: domain={domain} (override)");
                }

                var txId = Guid.NewGuid().ToString("N");
                using var op = BypassOperationContext.Enter(txId, "ui_apply_domain", domain, domain);

                var outcome = await Orchestrator.ApplyRecommendationsForDomainAsync(Bypass, domain).ConfigureAwait(false);

                // Практический UX: ретестим доменную цель.
                if (outcome != null && string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                {
                    var groupKeyForCheck = ComputeApplyGroupKey(outcome.HostKey, domain);
                    SetPostApplyCheckStatusForGroupKey(groupKeyForCheck, IsRunning ? PostApplyCheckStatus.Queued : PostApplyCheckStatus.Running);
                }
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, domain, txId);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, domain);

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                        MarkAppliedBypassTargetsForGroupKey(groupKey);

                        // Step 11: domain-apply также фиксирует groupKey (чтобы суффикс не "прыгал").
                        PinHostKeyToGroupKeyBestEffort(outcome.HostKey, groupKey);
                        PersistManualParticipationBestEffort();
                    }

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        _groupBypassAttachmentStore.UpdateAttachmentFromApply(groupKey, outcome.HostKey, endpoints, outcome.PlanText);
                        PersistManualParticipationBestEffort();
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning,
                        transactionIdOverride: txId,
                        resultStatus: outcome.Status,
                        error: outcome.Error,
                        rollbackStatus: outcome.RollbackStatus,
                        cancelReason: outcome.CancelReason,
                        applyCurrentPhase: outcome.ApplyCurrentPhase,
                        applyTotalElapsedMs: outcome.ApplyTotalElapsedMs,
                        applyPhases: outcome.ApplyPhases);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[APPLY] Отмена применения доменной стратегии");
            }
            catch (Exception ex)
            {
                Log($"[APPLY] Ошибка применения доменной стратегии: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ApplyDomainGroupRecommendationsAsync(string? groupKeyOverride = null)
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                if (string.IsNullOrWhiteSpace(groupKeyOverride) && !HasDomainGroupSuggestion)
                {
                    Log("[APPLY] Подсказка доменной группы недоступна для текущей цели");
                    return;
                }

                var groupKey = string.IsNullOrWhiteSpace(groupKeyOverride)
                    ? Results.SuggestedDomainGroupKey
                    : groupKeyOverride;

                groupKey = (groupKey ?? string.Empty).Trim().Trim('.');

                if (string.IsNullOrWhiteSpace(groupKey))
                {
                    Log("[APPLY] GroupKey доменной группы не определён");
                    return;
                }

                var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                if (string.IsNullOrWhiteSpace(preferredHostKey))
                {
                    Log("[APPLY] Нет hostKey для выбранной строки (SNI/Host/Name пуст)");
                    return;
                }

                // Anchor-домен нужен как OutcomeTargetHost (для селективных стратегий).
                string? anchorDomain = null;
                if (Results.TryGetSuggestedGroupAnchorForHostKey(preferredHostKey, out var anchor))
                {
                    anchorDomain = anchor;
                }

                if (string.IsNullOrWhiteSpace(anchorDomain))
                {
                    anchorDomain = Results.SuggestedDomainGroupAnchorDomain;
                }

                var domains = Results.SuggestedDomainGroupDomains;
                if (domains == null || domains.Count == 0)
                {
                    Log("[APPLY] Список доменов группы пуст — применять нечего");
                    return;
                }

                if (string.IsNullOrWhiteSpace(anchorDomain))
                {
                    anchorDomain = domains[0];
                }

                anchorDomain = (anchorDomain ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(anchorDomain))
                {
                    Log("[APPLY] Anchor-домен не определён");
                    return;
                }

                if (!string.IsNullOrWhiteSpace(groupKeyOverride))
                {
                    Log($"[APPLY] Групповой apply: groupKey={groupKey} (override)");
                }

                var txId = Guid.NewGuid().ToString("N");
                using var op = BypassOperationContext.Enter(txId, "ui_apply_domain_group", anchorDomain, anchorDomain);

                var outcome = await Orchestrator.ApplyRecommendationsForDomainGroupAsync(Bypass, groupKey, anchorDomain, domains).ConfigureAwait(false);

                // Практический UX: ретестим anchor-домен (OutcomeTargetHost).
                if (outcome != null && string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                {
                    var groupKeyForCheck = (groupKey ?? string.Empty).Trim().Trim('.');
                    SetPostApplyCheckStatusForGroupKey(groupKeyForCheck, IsRunning ? PostApplyCheckStatus.Queued : PostApplyCheckStatus.Running);
                }
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, anchorDomain, txId);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    // Важно: groupKey для доменных групп — это именно ключ группы, не производный от суффикса.
                    var normalizedGroupKey = groupKey!;

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        ApplyAppliedStrategyToGroupKey(normalizedGroupKey, outcome.AppliedStrategyText);
                        MarkAppliedBypassTargetsForGroupKey(normalizedGroupKey);

                        // Step 11: групповой apply фиксирует groupKey для anchor-домена.
                        PinHostKeyToGroupKeyBestEffort(outcome.HostKey, normalizedGroupKey);
                        PersistManualParticipationBestEffort();
                    }

                    // Для группового ключа нужно объединение endpoint'ов всех доменов группы.
                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1100));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    foreach (var d in domains)
                    {
                        if (endpoints.Count >= 64) break;
                        if (string.IsNullOrWhiteSpace(d)) continue;

                        var extra = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(d);
                        if (extra.Count == 0)
                        {
                            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(600));
                            try
                            {
                                extra = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(d, cts.Token).ConfigureAwait(false);
                            }
                            catch
                            {
                                extra = Array.Empty<string>();
                            }
                        }

                        if (extra.Count == 0) continue;

                        endpoints = endpoints
                            .Concat(extra)
                            .Select(s => (s ?? string.Empty).Trim())
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .Take(64)
                            .ToArray();
                    }

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        _groupBypassAttachmentStore.UpdateAttachmentFromApply(normalizedGroupKey, outcome.HostKey, endpoints, outcome.PlanText);
                        PersistManualParticipationBestEffort();
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, normalizedGroupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning,
                        transactionIdOverride: txId,
                        resultStatus: outcome.Status,
                        error: outcome.Error,
                        rollbackStatus: outcome.RollbackStatus,
                        cancelReason: outcome.CancelReason,
                        applyCurrentPhase: outcome.ApplyCurrentPhase,
                        applyTotalElapsedMs: outcome.ApplyTotalElapsedMs,
                        applyPhases: outcome.ApplyPhases);
                    UpdateLastApplyTransactionTextForGroupKey(normalizedGroupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[APPLY] Отмена применения групповой стратегии");
            }
            catch (Exception ex)
            {
                Log($"[APPLY] Ошибка применения групповой стратегии: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private void IgnoreDomainGroupSuggestionBestEffort()
        {
            try
            {
                if (!HasLearnedDomainGroupSuggestion)
                {
                    Log("[DomainGroups] Ignore: learned-подсказка недоступна");
                    return;
                }

                var hk = GetPreferredHostKey(SelectedTestResult);
                if (string.IsNullOrWhiteSpace(hk))
                {
                    hk = Results.SuggestedDomainGroupAnchorDomain;
                }

                if (!Results.TryIgnoreSuggestedDomainGroupBestEffort(hk))
                {
                    Log("[DomainGroups] Ignore: не удалось скрыть learned-группу");
                }
            }
            catch (Exception ex)
            {
                Log($"[DomainGroups] Ignore: ошибка: {ex.Message}");
            }
        }

        private void PromoteDomainGroupSuggestionBestEffort()
        {
            try
            {
                if (!HasLearnedDomainGroupSuggestion)
                {
                    Log("[DomainGroups] Promote: learned-подсказка недоступна");
                    return;
                }

                var key = Results.SuggestedDomainGroupKey;
                var name = Results.SuggestedDomainGroupDisplayName;
                if (string.IsNullOrWhiteSpace(name)) name = key;

                var res = MessageBox.Show(
                    $"Закрепить learned-группу '{name}' как pinned?\n\n" +
                    "Pinned-группы имеют приоритет и сохраняются в state/domain_groups.json.",
                    "Закрепить группу",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (res != MessageBoxResult.Yes)
                {
                    return;
                }

                var hk = GetPreferredHostKey(SelectedTestResult);
                if (string.IsNullOrWhiteSpace(hk))
                {
                    hk = Results.SuggestedDomainGroupAnchorDomain;
                }

                if (!Results.TryPromoteSuggestedDomainGroupToPinnedBestEffort(hk))
                {
                    Log("[DomainGroups] Promote: не удалось закрепить learned-группу");
                }
            }
            catch (Exception ex)
            {
                Log($"[DomainGroups] Promote: ошибка: {ex.Message}");
            }
        }

        private async Task ConnectFromResultAsync(TestResult? test)
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            if (test == null)
            {
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                // Подсветим выбранную цель + выставим OutcomeTargetHost (селективный QUIC→TCP зависит от этого).
                SelectedTestResult = test;

                var preferredHostKey = GetPreferredHostKey(test);
                if (string.IsNullOrWhiteSpace(preferredHostKey))
                {
                    Log("[APPLY] Нет hostKey для выбранной строки (SNI/Host/Name пуст)");
                    return;
                }

                // Если для этой цели есть INTEL-план — применяем его.
                // Если плана нет, ApplyRecommendationsAsync просто ничего не сделает (и это лучше, чем включать тумблеры вслепую).
                var txId = Guid.NewGuid().ToString("N");
                using var op = BypassOperationContext.Enter(txId, "ui_apply_card", preferredHostKey);

                var outcome = await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey).ConfigureAwait(false);

                // Практический UX: ретестим именно выбранную цель.
                if (outcome != null && string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                {
                    var groupKeyForCheck = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    SetPostApplyCheckStatusForGroupKey(groupKeyForCheck, IsRunning ? PostApplyCheckStatus.Queued : PostApplyCheckStatus.Running);
                }
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey, txId);

                if (Bypass.IsBypassActive && outcome != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                        MarkAppliedBypassTargetsForGroupKey(groupKey);

                        // Step 11: per-card apply фиксирует groupKey для этой цели.
                        PinHostKeyToGroupKeyBestEffort(outcome.HostKey, groupKey);
                        PersistManualParticipationBestEffort();
                    }

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    if (string.Equals(outcome.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        _groupBypassAttachmentStore.UpdateAttachmentFromApply(groupKey, outcome.HostKey, endpoints, outcome.PlanText);
                        PersistManualParticipationBestEffort();
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning,
                        transactionIdOverride: txId,
                        resultStatus: outcome.Status,
                        error: outcome.Error,
                        rollbackStatus: outcome.RollbackStatus,
                        cancelReason: outcome.CancelReason,
                        applyCurrentPhase: outcome.ApplyCurrentPhase,
                        applyTotalElapsedMs: outcome.ApplyTotalElapsedMs,
                        applyPhases: outcome.ApplyPhases);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[APPLY] Отмена применения стратегии из карточки");
            }
            catch (Exception ex)
            {
                Log($"[APPLY] Ошибка применения стратегии из карточки: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ConnectDomainFromResultAsync(TestResult? test)
        {
            if (test == null)
            {
                return;
            }

            // Важно: HasDomainSuggestion вычисляется от SelectedTestResult.
            // Поэтому перед доменным Apply выставляем выбранную строку.
            SelectedTestResult = test;

            var preferredHostKey = GetPreferredHostKey(test) ?? string.Empty;
            string? domainOverride = null;

            // Если строка относится к текущей авто-подсказке семейства — используем её.
            // Иначе fallback: домен этой строки (последние 2 лейбла).
            if (IspAudit.Utils.DomainUtils.IsHostInSuffix(preferredHostKey, Results.SuggestedDomainSuffix) && Results.CanSuggestDomainAggregation)
            {
                domainOverride = Results.SuggestedDomainSuffix;
            }
            else if (IspAudit.Utils.DomainUtils.TryGetBaseSuffix(preferredHostKey, out var baseSuffix))
            {
                domainOverride = baseSuffix;
            }

            await ApplyDomainRecommendationsAsync(domainOverride).ConfigureAwait(false);
        }

        private void TogglePinDomainFromResult(TestResult? test)
        {
            try
            {
                if (test?.Target == null) return;

                var preferredHostKey = GetPreferredHostKey(test);
                if (string.IsNullOrWhiteSpace(preferredHostKey)) return;

                string domainSuffix;

                // 1) Если есть активная подсказка семейства и строка относится к ней — закрепляем именно её.
                if (IspAudit.Utils.DomainUtils.IsHostInSuffix(preferredHostKey, Results.SuggestedDomainSuffix) && Results.CanSuggestDomainAggregation)
                {
                    domainSuffix = Results.SuggestedDomainSuffix ?? string.Empty;
                }
                else if (!Results.TryGetPinCandidateFromHostKey(preferredHostKey, out domainSuffix))
                {
                    return;
                }

                domainSuffix = (domainSuffix ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(domainSuffix)) return;

                var ok = Results.TogglePinnedDomain(domainSuffix);
                if (!ok)
                {
                    Log($"[DomainCatalog] Не удалось изменить pin для '{domainSuffix}'");
                    return;
                }

                var pinned = Results.IsDomainPinned(domainSuffix);
                Log(pinned
                    ? $"[DomainCatalog] Закреплён домен: {domainSuffix}"
                    : $"[DomainCatalog] Снято закрепление домена: {domainSuffix}");
            }
            catch
            {
                // ignore
            }
        }

        private Task RetestFromResultAsync(TestResult? test)
        {
            try
            {
                if (test == null) return Task.CompletedTask;

                var hostKey = GetPreferredHostKey(test);
                if (string.IsNullOrWhiteSpace(hostKey))
                {
                    test.ActionStatusText = "Ретест: нет цели";
                    return Task.CompletedTask;
                }

                // Во время активной диагностики ретест запрещён (Orchestrator.RetestTargetsAsync и PostApplyRetest).
                // UX: позволяем нажать кнопку, но ставим ретест в очередь после завершения.
                if (IsRunning)
                {
                    // Если включён режим "без лимита времени", диагностика может не завершиться сама.
                    // Не ставим ретест в очередь, чтобы он не стартовал неожиданно после Cancel.
                    if (IsUnlimitedTime)
                    {
                        test.ActionStatusText = "Ретест недоступен при непрерывной диагностике — остановите диагностику";
                        Log($"[PerCardRetest] Skip queue during unlimited run: {hostKey}");
                        return Task.CompletedTask;
                    }

                    lock (_pendingManualRetestHostKeys)
                    {
                        _pendingManualRetestHostKeys.Add(hostKey);
                    }

                    test.ActionStatusText = "Ретест запланирован (после диагностики)";
                    Log($"[PerCardRetest] Queued retest after run: {hostKey}");
                    return Task.CompletedTask;
                }

                test.ActionStatusText = "Ретест запущен";
                try
                {
                    var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    SetPostApplyCheckStatusForGroupKey(groupKey, IsRunning ? PostApplyCheckStatus.Queued : PostApplyCheckStatus.Running);
                }
                catch
                {
                    // ignore
                }
                var opId = Guid.NewGuid().ToString("N");
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, hostKey, opId);
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                test!.ActionStatusText = $"Ретест: ошибка: {ex.Message}";
                return Task.CompletedTask;
            }
        }

        private async Task ReconnectFromResultAsync(TestResult? test)
        {
            if (test == null)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                test.ActionStatusText = "Переподключение недоступно (нужны права администратора)";
                return;
            }

            var hostKey = GetPreferredHostKey(test);
            if (string.IsNullOrWhiteSpace(hostKey))
            {
                test.ActionStatusText = "Переподключение: нет цели";
                return;
            }

            try
            {
                test.ActionStatusText = "Переподключаю…";
                await Orchestrator.NudgeReconnectAsync(Bypass, hostKey).ConfigureAwait(false);

                // По UX после переподключения просим быстрый ретест. Если сейчас идёт диагностика — ставим в очередь.
                if (IsRunning)
                {
                    if (IsUnlimitedTime)
                    {
                        test.ActionStatusText = "Переподключено; остановите диагностику для ретеста";
                        Log($"[PerCardRetest] Skip queue after reconnect during unlimited run: {hostKey}");
                        return;
                    }

                    lock (_pendingManualRetestHostKeys)
                    {
                        _pendingManualRetestHostKeys.Add(hostKey);
                    }
                    test.ActionStatusText = "Переподключено; ретест запланирован";
                    try
                    {
                        var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                        SetPostApplyCheckStatusForGroupKey(groupKey, PostApplyCheckStatus.Queued);
                    }
                    catch
                    {
                        // ignore
                    }
                }
                else
                {
                    test.ActionStatusText = "Переподключено; ретест…";
                    try
                    {
                        var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                        SetPostApplyCheckStatusForGroupKey(groupKey, PostApplyCheckStatus.Running);
                    }
                    catch
                    {
                        // ignore
                    }
                    var opId = Guid.NewGuid().ToString("N");
                    _ = Orchestrator.StartPostApplyRetestAsync(Bypass, hostKey, opId);
                }
            }
            catch (Exception ex)
            {
                test.ActionStatusText = $"Переподключение: ошибка: {ex.Message}";
            }
        }

        private async Task RunPendingManualRetestsAfterRunAsync()
        {
            string[] hostKeys;
            lock (_pendingManualRetestHostKeys)
            {
                hostKeys = _pendingManualRetestHostKeys.ToArray();
                _pendingManualRetestHostKeys.Clear();
            }

            foreach (var hostKey in hostKeys)
            {
                try
                {
                    var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    SetActionStatusTextForGroupKey(groupKey, "Ретест запущен (очередь)");
                    SetPostApplyCheckStatusForGroupKey(groupKey, PostApplyCheckStatus.Queued);

                    // Step 12: не блокируем UI/OnDiagnosticComplete ожиданием ретеста.
                    // Ретест запускается асинхронно.
                    var opId = Guid.NewGuid().ToString("N");
                    _ = Orchestrator.StartPostApplyRetestAsync(Bypass, hostKey, opId);
                }
                catch (Exception ex)
                {
                    Log($"[PerCardRetest] Error: {ex.Message}");
                }
            }

            await Task.CompletedTask;
        }

        private void SetActionStatusTextForGroupKey(string groupKey, string text)
        {
            if (string.IsNullOrWhiteSpace(groupKey)) return;
            var key = groupKey.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(key)) return;

            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    var hostKey = GetPreferredHostKey(r);
                    if (string.IsNullOrWhiteSpace(hostKey)) continue;

                    var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    if (string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase))
                    {
                        r.ActionStatusText = text;
                    }
                }
            });
        }

        private void SetPostApplyCheckStatusForGroupKey(string groupKey, PostApplyCheckStatus status)
        {
            SetPostApplyCheckResultForGroupKey(groupKey, status, checkedAtUtc: null, details: null);
        }

        private void SetPostApplyCheckResultForGroupKey(string groupKey, PostApplyCheckStatus status, DateTimeOffset? checkedAtUtc, string? details)
        {
            if (string.IsNullOrWhiteSpace(groupKey)) return;
            var key = groupKey.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(key)) return;

            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    var hostKey = GetPreferredHostKey(r);
                    if (string.IsNullOrWhiteSpace(hostKey)) continue;

                    var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    if (!string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (IsHostManuallyExcludedFromGroupKey(key, hostKey))
                    {
                        continue;
                    }

                    if (IsNoiseHostKey(hostKey))
                    {
                        continue;
                    }

                    r.PostApplyCheckStatus = status;

                    // Для нефинальных состояний сбрасываем контекст, чтобы не показывать старое время/детали.
                    if (status == PostApplyCheckStatus.Queued || status == PostApplyCheckStatus.Running || status == PostApplyCheckStatus.NotChecked)
                    {
                        r.PostApplyCheckAtUtc = null;
                        r.PostApplyCheckDetails = string.Empty;
                    }
                    else if (status == PostApplyCheckStatus.Ok || status == PostApplyCheckStatus.Fail || status == PostApplyCheckStatus.Partial || status == PostApplyCheckStatus.Unknown)
                    {
                        r.PostApplyCheckAtUtc = checkedAtUtc;
                        r.PostApplyCheckDetails = details ?? string.Empty;
                    }
                }
            });
        }

        private void ApplyPostApplyVerdictToHostKey(string hostKey, PostApplyVerdictContract verdictContract, string mode, string? details, string? correlationId)
        {
            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hk)) return;

                var groupKey = GetStableApplyGroupKeyForHostKey(hk);
                if (string.IsNullOrWhiteSpace(groupKey)) return;

                var mapped = verdictContract.Status switch
                {
                    VerdictStatus.Ok => PostApplyCheckStatus.Ok,
                    VerdictStatus.Fail => PostApplyCheckStatus.Fail,
                    _ => PostApplyCheckStatus.Unknown
                };
                var nowUtc = DateTimeOffset.UtcNow;

                var d = (details ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(mode))
                {
                    d = string.IsNullOrWhiteSpace(d) ? $"mode={mode}" : $"mode={mode}; {d}";
                }

                SetPostApplyCheckResultForGroupKey(groupKey, mapped, nowUtc, d);

                // Персистим last-known результат по groupKey.
                var entry = new IspAudit.Utils.PostApplyCheckStore.PostApplyCheckEntry
                {
                    GroupKey = (groupKey ?? string.Empty).Trim().Trim('.'),
                    Verdict = verdictContract.VerdictCode,
                    VerdictStatus = verdictContract.Status.ToString(),
                    UnknownReason = verdictContract.UnknownReason.ToString(),
                    CheckedAtUtc = nowUtc.ToString("u").TrimEnd(),
                    HostKey = hk,
                    Mode = (mode ?? string.Empty).Trim(),
                    Details = (details ?? string.Empty).Trim()
                };

                lock (_postApplyChecksSync)
                {
                    _postApplyChecksByGroupKey[entry.GroupKey] = entry;
                }

                PersistPostApplyChecksBestEffort();

                // P1.9: записываем win только при строгом сигнале успеха post-apply (OK) и наличии txId.
                // Это защищает от «мусора» фоновых соединений.
                TryRecordWinFromPostApplyOkBestEffort(hk, groupKey, verdictContract.VerdictCode, mode, details, correlationId, nowUtc);
            }
            catch
            {
                // ignore
            }
        }

        private void ApplyPostApplyVerdictToHostKey(string hostKey, string verdict, string mode, string? details, string? correlationId)
        {
            ApplyPostApplyVerdictToHostKey(hostKey, PostApplyVerdictContract.FromLegacy(verdict, details), mode, details, correlationId);
        }

        private void TryRecordWinFromPostApplyOkBestEffort(
            string hostKey,
            string? groupKey,
            string? verdict,
            string? mode,
            string? details,
            string? correlationId,
            DateTimeOffset verifiedAtUtc)
        {
            try
            {
                var v = (verdict ?? string.Empty).Trim();
                if (!string.Equals(v, "OK", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                var txId = (correlationId ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(txId))
                {
                    return;
                }

                var tx = Bypass.TryGetApplyTransactionById(txId);
                if (tx == null)
                {
                    return;
                }

                // Дополнительная защита: убеждаемся, что транзакция относится к той же группе.
                var txGroupKey = (tx.GroupKey ?? string.Empty).Trim().Trim('.');
                var gk = (groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(txGroupKey) || string.IsNullOrWhiteSpace(gk)
                    || !string.Equals(txGroupKey, gk, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                // По возможности берём appliedAtUtc из оркестратора (pending feedback), иначе — из транзакции.
                var appliedAtUtc = tx.CreatedAtUtc;
                BypassPlan? appliedPlan = null;
                try
                {
                    if (Orchestrator.TryGetPendingAppliedPlanForHostKey(hostKey, out var plan, out var appliedAt))
                    {
                        appliedPlan = plan;
                        appliedAtUtc = appliedAt.ToString("u").TrimEnd();
                    }
                }
                catch
                {
                    // ignore
                }

                var win = new WinsEntry
                {
                    HostKey = hostKey,
                    SniHostname = hostKey,
                    CorrelationId = txId,
                    AppliedAtUtc = string.IsNullOrWhiteSpace(appliedAtUtc) ? verifiedAtUtc.ToString("u").TrimEnd() : appliedAtUtc,
                    VerifiedAtUtc = verifiedAtUtc.ToString("u").TrimEnd(),
                    VerifiedVerdict = v,
                    VerifiedMode = (mode ?? string.Empty).Trim(),
                    VerifiedDetails = (details ?? string.Empty).Trim(),
                    AppliedStrategyText = (tx.AppliedStrategyText ?? string.Empty).Trim(),
                    PlanText = (tx.PlanText ?? string.Empty).Trim(),
                    Plan = appliedPlan ?? new BypassPlan(),
                    CandidateIpEndpoints = tx.CandidateIpEndpoints ?? Array.Empty<string>()
                };

                lock (_winsSync)
                {
                    _winsByHostKey[(hostKey ?? string.Empty).Trim().Trim('.')] = win;
                }

                PersistWinsBestEffort();
            }
            catch
            {
                // ignore
            }
        }

        private void UpdateLastApplyTransactionTextForGroupKey(string groupKey)
        {
            try
            {
                var tx = Bypass.TryGetLatestApplyTransactionForGroupKey(groupKey);
                if (tx == null) return;

                var localTimeText = tx.CreatedAtUtc;
                try
                {
                    if (DateTimeOffset.TryParse(tx.CreatedAtUtc, out var dto))
                    {
                        localTimeText = dto.ToLocalTime().ToString("HH:mm:ss");
                    }
                }
                catch
                {
                    // ignore
                }

                var activationText = string.IsNullOrWhiteSpace(tx.ActivationStatusText) ? "" : $"; {tx.ActivationStatusText}";
                var policiesText = $"; Policies={tx.ActivePolicies.Count}";
                var summary = $"Последнее применение: {localTimeText}; {tx.AppliedStrategyText}{policiesText}; IP={tx.CandidateIpEndpoints.Count}{activationText}";
                var bundleSummary = BuildBundleSummaryFromTransaction(tx);
                var key = (tx.GroupKey ?? groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(key)) return;

                UiBeginInvoke(() =>
                {
                    foreach (var r in Results.TestResults)
                    {
                        var hostKey = GetPreferredHostKey(r);
                        if (string.IsNullOrWhiteSpace(hostKey)) continue;

                        var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                        if (string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase))
                        {
                            r.LastApplyTransactionText = summary;

                            if (!IsHostManuallyExcludedFromGroupKey(key, hostKey) && !IsNoiseHostKey(hostKey))
                            {
                                r.BundleSummaryText = bundleSummary;
                            }
                            else
                            {
                                r.BundleSummaryText = string.Empty;
                            }

                            r.ParticipationText = GetParticipationTextForHostKey(key, hostKey);
                        }
                    }
                });
            }
            catch
            {
                // ignore
            }
        }

        private static string BuildBundleSummaryFromTransaction(IspAudit.Bypass.BypassApplyTransaction tx)
        {
            try
            {
                // Сводка “policy bundle” на основе факта транзакции.
                // Это MVP-репрезентация: стратегия + флаги + endpoints/policies.
                var tokens = SplitPlanTokens(tx.PlanText ?? string.Empty);

                var flags = new System.Collections.Generic.List<string>();
                if (tokens.Contains("DROP_UDP_443")) flags.Add("QUIC→TCP");
                if (tokens.Contains("ALLOW_NO_SNI")) flags.Add("NoSNI");
                if (tokens.Contains("TLS_FRAGMENT")) flags.Add("Frag");
                if (tokens.Contains("TLS_DISORDER")) flags.Add("Disorder");
                if (tokens.Contains("TLS_FAKE")) flags.Add("FakeTTL");
                if (tokens.Contains("DROP_RST")) flags.Add("DropRST");

                var flagsText = flags.Count == 0 ? "—" : string.Join(",", flags);
                return $"Bundle: {tx.AppliedStrategyText}; Flags={flagsText}; Endpoints={tx.CandidateIpEndpoints.Count}; Policies={tx.ActivePolicies.Count}";
            }
            catch
            {
                return string.Empty;
            }
        }

        private static System.Collections.Generic.HashSet<string> SplitPlanTokens(string planText)
        {
            try
            {
                var set = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (string.IsNullOrWhiteSpace(planText)) return set;

                // План часто содержит токены-метки (например "DROP_UDP_443") — извлекаем все такие подстроки.
                var separators = new[] { ' ', '\t', '\r', '\n', ';', ',', '|', '[', ']', '(', ')', '{', '}', ':' };
                var parts = planText.Split(separators, StringSplitOptions.RemoveEmptyEntries);
                foreach (var p in parts)
                {
                    var t = p.Trim();
                    if (t.Length == 0) continue;
                    if (t.Length > 64) continue;
                    if (t.Any(ch => !(char.IsLetterOrDigit(ch) || ch == '_' || ch == '-'))) continue;
                    set.Add(t);
                }
                return set;
            }
            catch
            {
                return new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private void UpdateSelectedResultApplyTransactionDetails()
        {
            try
            {
                var selected = SelectedTestResult;
                if (selected == null)
                {
                    SelectedResultApplyTransactionTitle = "Детали применения обхода";
                    SelectedResultApplyTransactionJson = string.Empty;
                    return;
                }

                var hostKey = GetPreferredHostKey(selected);
                if (string.IsNullOrWhiteSpace(hostKey))
                {
                    SelectedResultApplyTransactionTitle = "Детали применения обхода";
                    SelectedResultApplyTransactionJson = string.Empty;
                    return;
                }

                var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                var normalized = (groupKey ?? string.Empty).Trim().Trim('.');
                SelectedResultApplyTransactionTitle = string.IsNullOrWhiteSpace(normalized)
                    ? "Детали применения обхода"
                    : $"Детали применения обхода (группа: {normalized})";

                var txJson = Bypass.TryGetLatestApplyTransactionJsonForGroupKey(groupKey);
                SelectedResultApplyTransactionJson = BuildSelectedResultDetailsJson(groupKey, txJson);
            }
            catch
            {
                SelectedResultApplyTransactionTitle = "Детали применения обхода";
                SelectedResultApplyTransactionJson = string.Empty;
            }
        }

        private string BuildSelectedResultDetailsJson(string? groupKey, string txJson)
        {
            try
            {
                var root = new JsonObject
                {
                    ["groupKey"] = (groupKey ?? string.Empty).Trim().Trim('.'),
                    ["participation"] = BuildParticipationSnapshotNode(groupKey)
                };

                if (!string.IsNullOrWhiteSpace(txJson))
                {
                    try
                    {
                        root["applyTransaction"] = JsonNode.Parse(txJson);
                    }
                    catch
                    {
                        root["applyTransactionJson"] = txJson;
                    }
                }

                return root.ToJsonString(new JsonSerializerOptions
                {
                    WriteIndented = true
                });
            }
            catch
            {
                // fallback: просто транзакция
                return txJson ?? string.Empty;
            }
        }

        private JsonNode BuildParticipationSnapshotNode(string? groupKey)
        {
            var normalizedGroupKey = (groupKey ?? string.Empty).Trim().Trim('.');
            var excludedManual = new System.Collections.Generic.List<string>();
            var excludedNoise = new System.Collections.Generic.List<string>();
            var included = new System.Collections.Generic.List<string>();

            JsonNode? storeSnapshot = null;
            try
            {
                storeSnapshot = _groupBypassAttachmentStore.BuildParticipationSnapshotNode(normalizedGroupKey);
            }
            catch
            {
                storeSnapshot = null;
            }

            try
            {
                excludedManual.AddRange(_groupBypassAttachmentStore.GetExcludedHostsSnapshot(normalizedGroupKey));
            }
            catch
            {
                // ignore
            }

            try
            {
                var includedSet = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var excludedNoiseSet = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var r in Results.TestResults)
                {
                    var hostKey = GetPreferredHostKey(r);
                    if (string.IsNullOrWhiteSpace(hostKey)) continue;

                    var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    if (!string.Equals(rowGroupKey, normalizedGroupKey, StringComparison.OrdinalIgnoreCase)) continue;

                    var normalizedHostKey = hostKey.Trim().Trim('.');
                    if (string.IsNullOrWhiteSpace(normalizedHostKey)) continue;

                    if (IsNoiseHostKey(normalizedHostKey))
                    {
                        excludedNoiseSet.Add(normalizedHostKey);
                        continue;
                    }

                    if (IsHostManuallyExcludedFromGroupKey(normalizedGroupKey, normalizedHostKey))
                    {
                        continue;
                    }

                    includedSet.Add(normalizedHostKey);
                }

                excludedNoise.AddRange(excludedNoiseSet.OrderBy(s => s, StringComparer.OrdinalIgnoreCase));
                included.AddRange(includedSet.OrderBy(s => s, StringComparer.OrdinalIgnoreCase));
            }
            catch
            {
                // ignore
            }

            return new JsonObject
            {
                // UI-срез (вычисляется от текущих результатов и NoiseHostFilter)
                ["includedHostKeys"] = JsonSerializer.SerializeToNode(included.ToArray()),
                ["excludedManualHostKeys"] = JsonSerializer.SerializeToNode(excludedManual.ToArray()),
                ["excludedNoiseHostKeys"] = JsonSerializer.SerializeToNode(excludedNoise.ToArray()),

                // Store-срез (SSoT): pinning/excluded + attachments + effective merge
                ["store"] = storeSnapshot
            };
        }

        private void UpdateManualParticipationMarkersForGroupKey(string groupKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(groupKey)) return;
                var key = groupKey.Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(key)) return;

                var excluded = new System.Collections.Generic.HashSet<string>(
                    _groupBypassAttachmentStore.GetExcludedHostsSnapshot(key),
                    StringComparer.OrdinalIgnoreCase);

                UiBeginInvoke(() =>
                {
                    foreach (var r in Results.TestResults)
                    {
                        var hostKey = GetPreferredHostKey(r);
                        if (string.IsNullOrWhiteSpace(hostKey)) continue;

                        var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                        if (!string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase)) continue;

                        var normalizedHostKey = hostKey.Trim().Trim('.');
                        r.IsManuallyExcludedFromApplyGroup = excluded.Contains(normalizedHostKey);
                        r.ParticipationText = GetParticipationTextForHostKey(key, hostKey);
                    }
                });
            }
            catch
            {
                // ignore
            }
        }

        private bool IsNoiseHostKey(string hostKey)
        {
            try
            {
                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hk)) return false;
                if (IPAddress.TryParse(hk, out _)) return false;
                return _noiseHostFilter.IsNoiseHost(hk);
            }
            catch
            {
                return false;
            }
        }

        private string GetParticipationTextForHostKey(string groupKey, string hostKey)
        {
            try
            {
                if (IsNoiseHostKey(hostKey)) return "EXCLUDED";
                if (IsHostManuallyExcludedFromGroupKey(groupKey, hostKey)) return "OUT";
                return "IN";
            }
            catch
            {
                return string.Empty;
            }
        }

        private void RefreshManualParticipationMarkersBestEffort()
        {
            try
            {
                foreach (var r in Results.TestResults)
                {
                    var hostKey = GetPreferredHostKey(r);
                    if (string.IsNullOrWhiteSpace(hostKey)) continue;
                    var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    if (string.IsNullOrWhiteSpace(groupKey)) continue;
                    UpdateManualParticipationMarkersForGroupKey(groupKey);
                }
            }
            catch
            {
                // ignore
            }
        }

        private void CopySelectedResultApplyTransactionJson()
        {
            try
            {
                var json = SelectedResultApplyTransactionJson;
                if (string.IsNullOrWhiteSpace(json))
                {
                    UserMessage = "Буфер обмена: нет данных для копирования";
                    return;
                }

                UiBeginInvoke(() =>
                {
                    try
                    {
                        System.Windows.Clipboard.SetText(json);
                        UserMessage = "Буфер обмена: детали применения скопированы";
                    }
                    catch
                    {
                        UserMessage = "Буфер обмена: ошибка копирования";
                    }
                });
            }
            catch
            {
                // ignore
            }
        }

        private string? GetPreferredHostKey(TestResult? test)
        {
            try
            {
                if (test?.Target == null) return null;

                // Важно: "шумовые" домены (например, *.1e100.net) часто появляются как late-resolve/rDNS.
                // Для применения обхода они бесполезны и могут приводить к впечатлению, что кнопка "Подключить" ничего не делает.
                var candidates = new[]
                {
                    test.Target.SniHost,
                    test.Target.Host,
                    test.Target.Name,
                    test.Target.FallbackIp
                };

                foreach (var c in candidates)
                {
                    if (string.IsNullOrWhiteSpace(c)) continue;
                    var trimmed = c.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;

                    if (System.Net.IPAddress.TryParse(trimmed, out _))
                    {
                        return trimmed;
                    }

                    if (!_noiseHostFilter.IsNoiseHost(trimmed))
                    {
                        return trimmed;
                    }
                }

                // Если все кандидаты оказались шумом — возвращаем хотя бы первый непустой,
                // чтобы UI/лог явно показали, что именно выбрано.
                return candidates.FirstOrDefault(s => !string.IsNullOrWhiteSpace(s))?.Trim();
            }
            catch
            {
                return null;
            }
        }

        private static string ComputeApplyGroupKey(string hostKey, string? suggestedDomainSuffix)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hostKey)) return string.Empty;

                // IP адрес не агрегируем.
                if (IPAddress.TryParse(hostKey, out _)) return hostKey;

                var suffix = (suggestedDomainSuffix ?? string.Empty).Trim().Trim('.');
                if (suffix.Length == 0) return hostKey;

                if (hostKey.Equals(suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                if (hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                return hostKey;
            }
            catch
            {
                return hostKey ?? string.Empty;
            }
        }

        private async Task RestartConnectionAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
            try
            {
                await Orchestrator.NudgeReconnectAsync(Bypass, preferredHostKey).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log($"[APPLY] Ошибка рестарта коннекта: {ex.Message}");
            }
        }

        private static void UiBeginInvoke(Action action)
        {
            try
            {
                var dispatcher = Application.Current?.Dispatcher;
                if (dispatcher == null)
                {
                    action();
                    return;
                }

                if (dispatcher.CheckAccess())
                {
                    action();
                }
                else
                {
                    dispatcher.BeginInvoke(action);
                }
            }
            catch
            {
                // ignore
            }
        }

        private void ClearAppliedBypassMarkers()
        {
            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    if (r.IsAppliedBypassTarget)
                    {
                        r.IsAppliedBypassTarget = false;
                    }

                    if (!string.IsNullOrWhiteSpace(r.AppliedBypassStrategy))
                    {
                        r.AppliedBypassStrategy = null;
                    }

                    if (r.PostApplyCheckStatus != PostApplyCheckStatus.None)
                    {
                        r.PostApplyCheckStatus = PostApplyCheckStatus.None;
                    }

                    if (r.PostApplyCheckAtUtc != null)
                    {
                        r.PostApplyCheckAtUtc = null;
                    }

                    if (!string.IsNullOrWhiteSpace(r.PostApplyCheckDetails))
                    {
                        r.PostApplyCheckDetails = string.Empty;
                    }
                }
            });

            // Сбрасываем persisted контекст, чтобы после Disable/Reset не всплывали старые пост‑проверки.
            try
            {
                lock (_postApplyChecksSync)
                {
                    _postApplyChecksByGroupKey.Clear();
                }

                IspAudit.Utils.PostApplyCheckStore.TryDeletePersistedFileBestEffort(Log);
            }
            catch
            {
                // ignore
            }
        }

        private void ApplyAppliedStrategyToResults(string hostKey, string appliedStrategyText)
        {
            if (string.IsNullOrWhiteSpace(hostKey)) return;
            if (string.IsNullOrWhiteSpace(appliedStrategyText)) return;

            var key = hostKey.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(key)) return;

            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    if (r?.Target == null) continue;

                    var candidates = new[]
                    {
                        r.Target.SniHost,
                        r.Target.Host,
                        r.Target.Name,
                        r.Target.FallbackIp
                    };

                    foreach (var c in candidates)
                    {
                        if (string.IsNullOrWhiteSpace(c)) continue;
                        var cc = c.Trim().Trim('.');
                        if (string.IsNullOrWhiteSpace(cc)) continue;

                        if (System.Net.IPAddress.TryParse(key, out _))
                        {
                            if (string.Equals(cc, key, StringComparison.OrdinalIgnoreCase))
                            {
                                r.AppliedBypassStrategy = appliedStrategyText;
                                break;
                            }
                        }
                        else
                        {
                            if (string.Equals(cc, key, StringComparison.OrdinalIgnoreCase)
                                || cc.EndsWith("." + key, StringComparison.OrdinalIgnoreCase))
                            {
                                r.AppliedBypassStrategy = appliedStrategyText;
                                break;
                            }
                        }
                    }
                }
            });
        }

        private void ApplyAppliedStrategyToGroupKey(string groupKey, string appliedStrategyText)
        {
            if (string.IsNullOrWhiteSpace(groupKey)) return;
            if (string.IsNullOrWhiteSpace(appliedStrategyText)) return;

            var key = groupKey.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(key)) return;

            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    var hostKey = GetPreferredHostKey(r);
                    if (string.IsNullOrWhiteSpace(hostKey)) continue;

                    var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    if (string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase))
                    {
                        if (IsHostManuallyExcludedFromGroupKey(key, hostKey))
                        {
                            continue;
                        }
                        r.AppliedBypassStrategy = appliedStrategyText;
                    }
                }
            });
        }

        private void MarkAppliedBypassTarget(TestResult applied)
        {
            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    r.IsAppliedBypassTarget = ReferenceEquals(r, applied);
                }
            });
        }

        private void MarkAppliedBypassTargetsForGroupKey(string groupKey)
        {
            if (string.IsNullOrWhiteSpace(groupKey)) return;

            var key = groupKey.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(key)) return;

            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    var hostKey = GetPreferredHostKey(r);
                    if (string.IsNullOrWhiteSpace(hostKey))
                    {
                        continue;
                    }

                    var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    if (string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase))
                    {
                        if (IsHostManuallyExcludedFromGroupKey(key, hostKey))
                        {
                            r.IsAppliedBypassTarget = false;
                            continue;
                        }
                        // Аккумулятивная модель: отмечаем группу как применённую, не сбрасывая другие группы.
                        r.IsAppliedBypassTarget = true;
                    }
                }
            });
        }

        private bool IsHostManuallyExcludedFromGroupKey(string groupKey, string hostKey)
        {
            try
            {
                var key = (groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(key)) return false;

                var hk = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hk)) return false;

                return _groupBypassAttachmentStore.IsExcluded(key, hk);
            }
            catch
            {
                return false;
            }
        }

        private async Task StartOrCancelAsync()
        {
            if (IsRunning)
            {
                Log("→ Cancelling diagnostic");
                Orchestrator.Cancel();
            }
            else
            {
                await StartDiagnosticAsync();
            }
        }

        private async Task StartDiagnosticAsync()
        {
            string targetExePath;

            if (IsBasicTestMode)
            {
                targetExePath = GetTestNetworkAppPath() ?? "";
                if (string.IsNullOrEmpty(targetExePath))
                {
                    MessageBox.Show("Не удалось найти TestNetworkApp.exe", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                Log($"[Mode] Basic Test: {targetExePath}");
            }
            else
            {
                if (string.IsNullOrEmpty(ExePath) || !File.Exists(ExePath))
                {
                    MessageBox.Show("Файл не найден.", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                targetExePath = ExePath;
                Log($"[Mode] Normal: {targetExePath}");
            }

            ScreenState = "running";
            Results.Clear();

            Orchestrator.EnableSilenceTimeout = !IsUnlimitedTime;
            await Orchestrator.RunAsync(targetExePath, Bypass, Results, EnableAutoBypass, IsSteamMode);
        }

        private void BrowseExe()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*",
                Title = "Выберите exe файл приложения"
            };

            if (dialog.ShowDialog() == true)
            {
                ExePath = dialog.FileName;
                Log($"[BrowseExe] Selected: {ExePath}");
            }
        }

        private void GenerateReport()
        {
            try
            {
                var report = new
                {
                    Date = DateTime.Now,
                    ExePath = ExePath,
                    Summary = new
                    {
                        Total = TotalTargets,
                        Passed = PassCount,
                        Failed = FailCount,
                        Warnings = WarnCount
                    },
                    Results = TestResults.Select(t => new
                    {
                        Host = t.Target.Host,
                        Name = t.Target.Name,
                        Service = t.Target.Service,
                        Status = t.Status.ToString(),
                        Details = t.Details,
                        Error = t.Error,
                        BypassStrategy = t.BypassStrategy,
                        Flags = new
                        {
                            t.IsRstInjection,
                            t.IsHttpRedirect,
                            t.IsRetransmissionHeavy,
                            t.IsUdpBlockage
                        }
                    }).ToList()
                };

                var json = System.Text.Json.JsonSerializer.Serialize(report,
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                var filename = $"isp_audit_report_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filename);

                File.WriteAllText(path, json);
                Log($"[Report] Saved: {path}");

                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
            }
            catch (Exception ex)
            {
                Log($"[Report] Error: {ex.Message}");
                MessageBox.Show($"Ошибка создания отчета: {ex.Message}", "Ошибка",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowDetailsDialog(TestResult? result)
        {
            if (result == null) return;

            try
            {
                string? applyDetailsJson = null;
                try
                {
                    // Важно: у некоторых карточек «предпочтительный» hostKey может оказаться IP или шумовым rDNS.
                    // Тогда groupKey не совпадает с тем, по которому реально применялся обход, и JSON не находится.
                    // Поэтому пробуем несколько кандидатных ключей в предсказуемом порядке.
                    var suffix = Results.SuggestedDomainSuffix;

                    string? TryGetApplyJsonForGroupKey(string? candidateGroupKey)
                    {
                        var key = (candidateGroupKey ?? string.Empty).Trim().Trim('.');
                        if (string.IsNullOrWhiteSpace(key)) return null;

                        var txJson = Bypass.TryGetLatestApplyTransactionJsonForGroupKey(key);
                        if (string.IsNullOrWhiteSpace(txJson)) return null;
                        return BuildSelectedResultDetailsJson(key, txJson);
                    }

                    // 1) Сначала — groupKey, который сейчас активен в UI (если есть).
                    applyDetailsJson = TryGetApplyJsonForGroupKey(ActiveApplyGroupKey);

                    // 2) Дальше — варианты, вычисленные из разных полей цели.
                    if (string.IsNullOrWhiteSpace(applyDetailsJson) && result.Target != null)
                    {
                        var hostCandidates = new[]
                        {
                            result.Target.SniHost,
                            result.Target.Host,
                            result.Target.Name,
                            result.Target.FallbackIp,
                        };

                        foreach (var c in hostCandidates)
                        {
                            if (string.IsNullOrWhiteSpace(c)) continue;
                            var groupKey = ComputeApplyGroupKey(c, suffix);
                            applyDetailsJson = TryGetApplyJsonForGroupKey(groupKey);
                            if (!string.IsNullOrWhiteSpace(applyDetailsJson)) break;
                        }
                    }

                    // 3) Если есть suggested suffix — пробуем его напрямую (частый кейс для групповых применений).
                    if (string.IsNullOrWhiteSpace(applyDetailsJson))
                    {
                        applyDetailsJson = TryGetApplyJsonForGroupKey(suffix);
                    }
                }
                catch
                {
                    applyDetailsJson = null;
                }

                var window = new IspAudit.Windows.TestDetailsWindow(result, applyDetailsJson)
                {
                    Owner = Application.Current.MainWindow
                };
                window.ShowDialog();
            }
            catch (Exception ex)
            {
                Log($"[ShowDetails] Error: {ex.Message}");
            }
        }

        #endregion
    }
}
