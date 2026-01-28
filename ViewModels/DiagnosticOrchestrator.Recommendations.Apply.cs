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

        private sealed record PendingFeedbackContext(BypassPlan Plan, DateTimeOffset AppliedAtUtc);
        private readonly ConcurrentDictionary<string, PendingFeedbackContext> _pendingFeedbackByHostKey = new(StringComparer.OrdinalIgnoreCase);

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

        private async Task<ApplyOutcome?> ApplyPlanInternalAsync(BypassController bypassController, string hostKey, BypassPlan plan)
        {
            if (NoiseHostFilter.Instance.IsNoiseHost(hostKey))
            {
                Log($"[APPLY] Skip: шумовой хост '{hostKey}'");
                return null;
            }

            void UpdateApplyUi(Action action)
            {
                try
                {
                    var dispatcher = Application.Current?.Dispatcher;
                    if (dispatcher != null && !dispatcher.CheckAccess())
                    {
                        dispatcher.Invoke(action);
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

            var beforeState = BuildBypassStateSummary(bypassController);

            try
            {
                UpdateApplyUi(() =>
                {
                    IsApplyRunning = true;
                    ApplyStatusText = "Применение: подготовка…";
                });

                Log($"[APPLY] host={hostKey}; plan={planStrategies}; before={beforeState}");

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
                if (plan.Strategies.Count > 0)
                {
                    _pendingFeedbackByHostKey[hostKey] = new PendingFeedbackContext(plan, DateTimeOffset.UtcNow);
                }

                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[APPLY] OK; after={afterState}");
                ResetRecommendations();

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

            // Не мешаем активной диагностике: там pipeline уже работает и сам обновляет результаты.
            if (IsDiagnosticRunning)
            {
                PostApplyRetestStatus = "Ретест после Apply: пропущен (идёт диагностика)";
                return Task.CompletedTask;
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

            try
            {
                _postApplyRetest.Cancellation?.Cancel();
            }
            catch
            {
            }

            _postApplyRetest.Cancellation = new CancellationTokenSource();
            var ct = _postApplyRetest.Cancellation.Token;

            IsPostApplyRetestRunning = true;
            PostApplyRetestStatus = $"Ретест после Apply: запуск ({hostKey})";

            Log($"[PostApplyRetest][op={opId}] Start: host={hostKey}");

            return Task.Run(async () =>
            {
                // Локальная эвристика результата: для всех target IP смотрим, были ли строки ✓/❌.
                // Усиление:
                // - если одновременно есть ✓ и ❌ по цели — outcome=Unknown (не учимся на неоднозначном результате)
                // - если есть хотя бы один ✓ и нет ❌ — Success
                // - если есть хотя бы один ❌ и нет ✓ — Failure
                // - если вообще нет записей — Unknown
                var targetIpStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var anyOk = false;
                var anyFail = false;

                // Более точный режим: если в логах ретеста удалось увидеть SNI, совпадающий с hostKey,
                // то считаем outcome только по этим записям. Иначе fallback на все target IP.
                var anySniMatched = false;
                var anyOkSniMatched = false;
                var anyFailSniMatched = false;

                try
                {
                    using var op = BypassOperationContext.Enter(opId, "post_apply_retest", hostKey);

                    var effectiveTestTimeout = bypassController.IsVpnDetected
                        ? TimeSpan.FromSeconds(8)
                        : TimeSpan.FromSeconds(3);

                    var pipelineConfig = new PipelineConfig
                    {
                        EnableLiveTesting = true,
                        EnableAutoBypass = false,
                        MaxConcurrentTests = 5,
                        TestTimeout = effectiveTestTimeout
                    };

                    // Собираем IP-адреса цели: DNS + локальные кеши.
                    var hosts = await BuildPostApplyRetestHostsAsync(hostKey, port: 443, ct).ConfigureAwait(false);
                    if (hosts.Count == 0)
                    {
                        PostApplyRetestStatus = $"Ретест после Apply: не удалось определить IP ({hostKey})";
                        Log($"[PostApplyRetest][op={opId}] No targets resolved for host={hostKey}");
                        return;
                    }

                    foreach (var h in hosts)
                    {
                        if (h.RemoteIp != null)
                        {
                            targetIpStrings.Add(h.RemoteIp.ToString());
                        }
                    }

                    PostApplyRetestStatus = $"Ретест после Apply: проверяем {hosts.Count} IP…";

                    var progress = new Progress<string>(msg =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.Invoke(() =>
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

                    using var pipeline = new LiveTestingPipeline(
                        pipelineConfig,
                        progress,
                        _trafficEngine,
                        _dnsParser,
                        new UnifiedTrafficFilter(),
                        null,
                        bypassController.AutoHostlist);

                    pipeline.OnPlanBuilt += (k, p) =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.Invoke(() => StorePlan(k, p, bypassController));
                        }
                        catch
                        {
                        }
                    };

                    foreach (var h in hosts)
                    {
                        await pipeline.EnqueueHostAsync(h).ConfigureAwait(false);
                    }

                    await pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                    PostApplyRetestStatus = "Ретест после Apply: завершён";

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
                    PostApplyRetestStatus = "Ретест после Apply: отменён";
                    Log($"[PostApplyRetest][op={opId}] Canceled: host={hostKey}");
                }
                catch (Exception ex)
                {
                    PostApplyRetestStatus = $"Ретест после Apply: ошибка ({ex.Message})";
                    Log($"[PostApplyRetest][op={opId}] Error: {ex.Message}");
                }
                finally
                {
                    IsPostApplyRetestRunning = false;
                    Log($"[PostApplyRetest][op={opId}] Done: host={hostKey}");
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
                        Application.Current?.Dispatcher.Invoke(() =>
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
            if (!string.IsNullOrWhiteSpace(preferredHostKey)) return preferredHostKey.Trim();
            if (!string.IsNullOrWhiteSpace(_lastIntelPlanHostKey)) return _lastIntelPlanHostKey.Trim();
            if (!string.IsNullOrWhiteSpace(_lastIntelDiagnosisHostKey)) return _lastIntelDiagnosisHostKey.Trim();
            return string.Empty;
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

