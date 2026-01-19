using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Models;
using IspAudit.Utils;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region Command Handlers

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
                if (!IPAddress.TryParse(hostKey, out _) && NoiseHostFilter.Instance.IsNoiseHost(hostKey))
                {
                    test.ActionStatusText = "Участие: шумовой хост (EXCLUDED)";
                    return;
                }

                var groupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
                var normalizedGroupKey = (groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(normalizedGroupKey))
                {
                    test.ActionStatusText = "Участие: группа не определена";
                    return;
                }

                var normalizedHostKey = hostKey.Trim().Trim('.');

                var nowExcluded = false;
                lock (_manualExcludedHostKeysByGroupKey)
                {
                    if (!_manualExcludedHostKeysByGroupKey.TryGetValue(normalizedGroupKey, out var set))
                    {
                        set = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        _manualExcludedHostKeysByGroupKey[normalizedGroupKey] = set;
                    }

                    if (set.Contains(normalizedHostKey))
                    {
                        set.Remove(normalizedHostKey);
                        if (set.Count == 0)
                        {
                            _manualExcludedHostKeysByGroupKey.Remove(normalizedGroupKey);
                        }
                        nowExcluded = false;
                    }
                    else
                    {
                        set.Add(normalizedHostKey);
                        nowExcluded = true;
                    }
                }

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
                var outcome = await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey).ConfigureAwait(false);

                // Практический UX: сразу запускаем короткий пост-Apply ретест по цели.
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                    MarkAppliedBypassTargetsForGroupKey(groupKey);

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения рекомендаций");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения рекомендаций: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ApplyDomainRecommendationsAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[V2][APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            if (!HasDomainSuggestion)
            {
                Log("[V2][APPLY] Доменная подсказка недоступна для текущей цели");
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                var domain = Results.SuggestedDomainSuffix;
                if (string.IsNullOrWhiteSpace(domain))
                {
                    Log("[V2][APPLY] Доменная цель не определена");
                    return;
                }

                var outcome = await Orchestrator.ApplyRecommendationsForDomainAsync(Bypass, domain).ConfigureAwait(false);

                // Практический UX: ретестим доменную цель.
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, domain);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                    MarkAppliedBypassTargetsForGroupKey(groupKey);

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения доменной стратегии");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения доменной стратегии: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
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
                Log("[V2][APPLY] Bypass недоступен (нужны права администратора)");
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
                    Log("[V2][APPLY] Нет hostKey для выбранной строки (SNI/Host/Name пуст)");
                    return;
                }

                // Если для этой цели есть v2 план — применяем его.
                // Если плана нет, ApplyRecommendationsAsync просто ничего не сделает (и это лучше, чем включать тумблеры вслепую).
                var outcome = await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey).ConfigureAwait(false);

                // Практический UX: ретестим именно выбранную цель.
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey);

                if (Bypass.IsBypassActive && outcome != null)
                {
                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    ApplyAppliedStrategyToGroupKey(groupKey, outcome.AppliedStrategyText);
                    MarkAppliedBypassTargetsForGroupKey(groupKey);

                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning);
                    UpdateLastApplyTransactionTextForGroupKey(groupKey);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения стратегии из карточки");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения стратегии из карточки: {ex.Message}");
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
            await ApplyDomainRecommendationsAsync().ConfigureAwait(false);
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
                    lock (_pendingManualRetestHostKeys)
                    {
                        _pendingManualRetestHostKeys.Add(hostKey);
                    }

                    test.ActionStatusText = "Ретест запланирован (после диагностики)";
                    Log($"[PerCardRetest] Queued retest after run: {hostKey}");
                    return Task.CompletedTask;
                }

                test.ActionStatusText = "Ретест запущен";
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, hostKey);
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
                    lock (_pendingManualRetestHostKeys)
                    {
                        _pendingManualRetestHostKeys.Add(hostKey);
                    }
                    test.ActionStatusText = "Переподключено; ретест запланирован";
                }
                else
                {
                    test.ActionStatusText = "Переподключено; ретест…";
                    _ = Orchestrator.StartPostApplyRetestAsync(Bypass, hostKey);
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
                    var groupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
                    SetActionStatusTextForGroupKey(groupKey, "Ретест запущен (очередь)");
                    await Orchestrator.StartPostApplyRetestAsync(Bypass, hostKey).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Log($"[PerCardRetest] Error: {ex.Message}");
                }
            }
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

                    var rowGroupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
                    if (string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase))
                    {
                        r.ActionStatusText = text;
                    }
                }
            });
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
                var key = (tx.GroupKey ?? groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(key)) return;

                UiBeginInvoke(() =>
                {
                    foreach (var r in Results.TestResults)
                    {
                        var hostKey = GetPreferredHostKey(r);
                        if (string.IsNullOrWhiteSpace(hostKey)) continue;

                        var rowGroupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
                        if (string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase))
                        {
                            r.LastApplyTransactionText = summary;
                        }
                    }
                });
            }
            catch
            {
                // ignore
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

                var groupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
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
            var excluded = new System.Collections.Generic.List<string>();

            try
            {
                lock (_manualExcludedHostKeysByGroupKey)
                {
                    if (_manualExcludedHostKeysByGroupKey.TryGetValue(normalizedGroupKey, out var set))
                    {
                        excluded.AddRange(set.OrderBy(s => s, StringComparer.OrdinalIgnoreCase));
                    }
                }
            }
            catch
            {
                // ignore
            }

            return JsonSerializer.SerializeToNode(new
            {
                excludedHostKeys = excluded.ToArray()
            }, new JsonSerializerOptions
            {
                WriteIndented = true
            }) ?? new JsonObject();
        }

        private void UpdateManualParticipationMarkersForGroupKey(string groupKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(groupKey)) return;
                var key = groupKey.Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(key)) return;

                System.Collections.Generic.HashSet<string>? excluded = null;
                lock (_manualExcludedHostKeysByGroupKey)
                {
                    if (_manualExcludedHostKeysByGroupKey.TryGetValue(key, out var set))
                    {
                        excluded = new System.Collections.Generic.HashSet<string>(set, StringComparer.OrdinalIgnoreCase);
                    }
                }

                UiBeginInvoke(() =>
                {
                    foreach (var r in Results.TestResults)
                    {
                        var hostKey = GetPreferredHostKey(r);
                        if (string.IsNullOrWhiteSpace(hostKey)) continue;

                        var rowGroupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
                        if (!string.Equals(rowGroupKey, key, StringComparison.OrdinalIgnoreCase)) continue;

                        var normalizedHostKey = hostKey.Trim().Trim('.');
                        r.IsManuallyExcludedFromApplyGroup = excluded != null && excluded.Contains(normalizedHostKey);
                    }
                });
            }
            catch
            {
                // ignore
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
                    var groupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
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

        private static string? GetPreferredHostKey(TestResult? test)
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

                    if (!NoiseHostFilter.Instance.IsNoiseHost(trimmed))
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
                Log("[V2][APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
            try
            {
                await Orchestrator.NudgeReconnectAsync(Bypass, preferredHostKey).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка рестарта коннекта: {ex.Message}");
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
                }
            });
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

                    var rowGroupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
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

                    var rowGroupKey = ComputeApplyGroupKey(hostKey, Results.SuggestedDomainSuffix);
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

                lock (_manualExcludedHostKeysByGroupKey)
                {
                    return _manualExcludedHostKeysByGroupKey.TryGetValue(key, out var set) && set.Contains(hk);
                }
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
                var window = new IspAudit.Windows.TestDetailsWindow(result)
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
