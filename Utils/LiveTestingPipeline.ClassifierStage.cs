using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Intelligence.Diagnosis;
using IspAudit.Core.Intelligence.Execution;
using IspAudit.Core.Intelligence.Signals;
using IspAudit.Core.Intelligence.Strategies;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;

namespace IspAudit.Utils
{
    public partial class LiveTestingPipeline
    {
        /// <summary>
        /// Worker 2: Классификация блокировок и выбор bypass стратегии
        /// </summary>
        private async Task ClassifierWorker(CancellationToken ct)
        {
            await foreach (var tested in _testerQueue.Reader.ReadAllAsync(ct))
            {
                Interlocked.Increment(ref _pendingInClassifier);
                Interlocked.Increment(ref _statClassifierDequeued);
                try
                {
                    // Регистрируем результат в сторе, чтобы поддерживать fail counter + time window
                    _stateStore.RegisterResult(tested);

                    // INTEL: снимаем «сенсорные» факты без зависимости от legacy BlockageSignals.
                    // Пока legacy-сигналы остаются для UI/AutoHostlist, но INTEL контур может быть переведён отдельно.
                    var inspection = (_stateStore as IInspectionSignalsProvider)?.GetInspectionSignalsSnapshot(tested)
                        ?? InspectionSignalsSnapshot.Empty;

                    // INTEL: записываем факты в последовательность событий + минимальный Gate-лог.
                    // Окно Gate-логов использует дефолт контракта (30 сек), но сами legacy signals сняты за 60 сек.
                    _signalsAdapter.Observe(tested, inspection, _progress);

                    // INTEL: строим агрегированный срез и ставим диагноз (без стратегий/обхода)
                    var snapshot = _signalsAdapter.BuildSnapshot(tested, inspection, IntelligenceContractDefaults.DefaultAggregationWindow);
                    var diagnosis = _diagnosisEngine.Diagnose(snapshot);

                    // INTEL: формируем план рекомендаций строго по диагнозу.
                    // Важно: не применять автоматически (только показать в UI/логах).
                    var plan = _strategySelector.Select(diagnosis, msg => _progress?.Report(msg));

                    // Готовим INTEL-план для UI/оркестратора, но публикуем ТОЛЬКО если хост реально попал в UI как проблема.
                    // Иначе "последний план" будет перетираться шумом/успешными хостами, и Apply применит не то.
                    var publishIntelPlan = false;
                    var planHostKeyForPublish = string.Empty;
                    try
                    {
                        var hasPlanActions = plan.Strategies.Count > 0 || plan.DropUdp443 || plan.AllowNoSni;
                        var isProblem = !(tested.DnsOk && tested.TcpOk && tested.TlsOk)
                            || diagnosis.DiagnosisId != DiagnosisId.NoBlockage
                            || inspection.UdpUnansweredHandshakes > 2;

                        if (hasPlanActions && isProblem)
                        {
                            // Для UX важно привязывать план к SNI, а не к rDNS:
                            // rDNS может быть "служебным" именем и не подходит как цель для TLS-обхода.
                            var sniForPlan = tested.SniHostname;
                            if (string.IsNullOrWhiteSpace(sniForPlan) && _dnsParser != null)
                            {
                                // SNI мог быть распознан DNS/TLS парсером асинхронно и сохранён в кеше
                                // даже если в объекте HostTested поле SniHostname ещё пустое.
                                var ipKey = tested.Host.RemoteIp?.ToString();
                                if (!string.IsNullOrWhiteSpace(ipKey) && _dnsParser.SniCache.TryGetValue(ipKey, out var cachedSni))
                                {
                                    sniForPlan = cachedSni;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(sniForPlan))
                            {
                                planHostKeyForPublish = sniForPlan;
                            }
                            else
                            {
                                // Если Hostname совпадает с ReverseDnsHostname, это, скорее всего, fallback из rDNS.
                                // Не используем его как ключ цели для Apply.
                                var candidateHostname = tested.Hostname;
                                if (!string.IsNullOrWhiteSpace(candidateHostname)
                                    && !string.IsNullOrWhiteSpace(tested.ReverseDnsHostname)
                                    && string.Equals(candidateHostname, tested.ReverseDnsHostname, StringComparison.OrdinalIgnoreCase))
                                {
                                    candidateHostname = null;
                                }

                                planHostKeyForPublish = !string.IsNullOrWhiteSpace(candidateHostname)
                                    ? candidateHostname
                                    : tested.Host.RemoteIp?.ToString() ?? tested.Host.Key;
                            }

                            publishIntelPlan = true;
                        }
                    }
                    catch
                    {
                        publishIntelPlan = false;
                        planHostKeyForPublish = string.Empty;
                    }

                    var remoteIp = tested.Host.RemoteIp;
                    var remoteIpString = remoteIp?.ToString();

                    // Пытаемся обновить hostname из кеша (мог появиться за время теста)
                    var hostname = tested.SniHostname ?? tested.Hostname;
                    if (string.IsNullOrEmpty(hostname) && _dnsParser != null)
                    {
                        if (!string.IsNullOrEmpty(remoteIpString))
                        {
                            _dnsParser.DnsCache.TryGetValue(remoteIpString, out hostname);
                        }
                    }
                    if (string.IsNullOrEmpty(hostname) && _dnsParser != null)
                    {
                        if (!string.IsNullOrEmpty(remoteIpString))
                        {
                            _dnsParser.SniCache.TryGetValue(remoteIpString, out hostname);
                        }
                    }

                    // Auto-hostlist: добавляем кандидатов только по не-шумовым хостам.
                    if (_autoHostlist != null)
                    {
                        _autoHostlist.Observe(tested, inspection, hostname);

                        // INTEL: добавляем auto-hostlist как источник контекста (evidence/notes).
                        // Важно: это не меняет диагноз напрямую, только делает хвост более информативным.
                        if (_autoHostlist.TryGetCandidateFor(tested, hostname, out var candidate))
                        {
                            diagnosis = EnrichDiagnosisWithAutoHostlist(diagnosis, candidate);
                        }
                    }

                    // Формируем результат для UI/фильтра: стратегия всегда NONE, а в RecommendedAction кладём факты/уверенность.
                    // Важно: делаем это ПОСЛЕ EnrichDiagnosisWithAutoHostlist, чтобы метки autoHL попали в UI хвост.
                    var blocked = BuildHostBlockedForUi(tested, inspection, diagnosis, plan);

                    // Принимаем решение о показе через единый фильтр
                    var decision = _filter.ShouldDisplay(blocked);

                    // В сообщениях пайплайна используем IP как технический якорь.
                    // UI-слой может отображать карточки по человеко‑понятному ключу (SNI/hostname),
                    // сохраняя IP как FallbackIp для корреляции.
                    var displayHost = remoteIpString ?? tested.Host.Key;

                    var sni = tested.SniHostname;
                    if (string.IsNullOrWhiteSpace(sni) && _dnsParser != null)
                    {
                        _dnsParser.SniCache.TryGetValue(displayHost, out sni);
                    }
                    var rdns = tested.ReverseDnsHostname;
                    var namesSuffix = $" SNI={(string.IsNullOrWhiteSpace(sni) ? "-" : sni)} RDNS={(string.IsNullOrWhiteSpace(rdns) ? "-" : rdns)}";

                    // Перепроверяем шум с обновлённым hostname.
                    // Важно: НЕ отбрасываем реальные проблемы/блокировки только из-за шумового rDNS.
                    if (decision.Action != FilterAction.Process && !string.IsNullOrEmpty(hostname) && NoiseHostFilter.Instance.IsNoiseHost(hostname))
                    {
                        _progress?.Report($"[NOISE] Отфильтрован (late): {displayHost}");
                        continue; // Пропускаем только «непроблемные» шумовые хосты
                    }

                    // Важно: публикуем INTEL-план не только для карточек (Process), но и для LogOnly,
                    // иначе пользователь не увидит рекомендацию/Apply для «формально OK, но INTEL видит вмешательство».
                    // При этом мы всё так же публикуем ТОЛЬКО когда есть действия в плане и есть признаки проблемы.
                    if (publishIntelPlan && !string.IsNullOrWhiteSpace(planHostKeyForPublish) && decision.Action != FilterAction.Drop)
                    {
                        try
                        {
                            OnPlanBuilt?.Invoke(planHostKeyForPublish, plan);
                        }
                        catch
                        {
                            // Игнорируем ошибки подписчиков: пайплайн должен быть устойчив.
                        }
                    }

                    if (decision.Action == FilterAction.Process)
                    {
                        // Это блокировка или проблема - отправляем в UI
                        await _bypassQueue.Writer.WriteAsync(blocked, ct).ConfigureAwait(false);
                        Interlocked.Increment(ref _statUiIssuesEnqueued);
                    }
                    else if (decision.Action == FilterAction.LogOnly)
                    {
                        // Хост работает - просто логируем (не отправляем в UI)
                        var port = tested.Host.RemotePort;
                        var latency = tested.TcpLatencyMs > 0 ? $" ({tested.TcpLatencyMs}ms)" : "";
                        _progress?.Report($"✓ {displayHost}:{port}{latency}{namesSuffix}");
                        Interlocked.Increment(ref _statUiLogOnly);

                        // INTEL: если селектор сформировал план действий, показываем рекомендацию и диагноз даже при OK.
                        // Это критично для UX: иначе пользователь видит только "✓", хотя INTEL уже заметил вмешательство.
                        var hasPlanActionsForOk = plan.Strategies.Count > 0 || plan.DropUdp443 || plan.AllowNoSni;
                        if (publishIntelPlan && hasPlanActionsForOk)
                        {
                            try
                            {
                                var rdns2 = tested.ReverseDnsHostname;
                                var context = $"host={displayHost}:{port} SNI={(string.IsNullOrWhiteSpace(sni) ? "-" : sni)} RDNS={(string.IsNullOrWhiteSpace(rdns2) ? "-" : rdns2)}";

                                // Auto-hostlist: делаем принадлежность видимой рядом с рекомендацией.
                                if (!string.IsNullOrWhiteSpace(blocked.RecommendedAction)
                                    && blocked.RecommendedAction.Contains("autoHL hits=", StringComparison.OrdinalIgnoreCase))
                                {
                                    context += " hostlist=auto";
                                }

                                // Ключ для дедуп: SNI предпочтительнее, иначе IP.
                                var dedupKey = !string.IsNullOrWhiteSpace(sni) && sni != "-" ? sni : displayHost;

                                var bypassStrategyText = BuildBypassStrategyText(plan);
                                if (_executor.TryBuildRecommendationLine(dedupKey, bypassStrategyText, context, out var recommendationLine))
                                {
                                    _progress?.Report(recommendationLine);
                                }

                                // Дополнительно: компактная строка INTEL-диагноза.
                                if (_executor.TryFormatDiagnosisSuffix(blocked.RecommendedAction, out var formattedDiag))
                                {
                                    _progress?.Report(formattedDiag);
                                }
                            }
                            catch
                            {
                                // best-effort
                            }
                        }
                    }
                    else if (decision.Action == FilterAction.Drop)
                    {
                        // Шумовой хост - отправляем специальное сообщение для UI (удаления карточки)
                        _progress?.Report($"[NOISE] Отфильтрован: {displayHost}");
                        Interlocked.Increment(ref _statUiDropped);
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[CLASSIFIER] Ошибка классификации: {ex.Message}");
                }
                finally
                {
                    Interlocked.Decrement(ref _pendingInClassifier);
                }
            }
        }

        private static HostBlocked BuildHostBlockedForUi(HostTested tested, InspectionSignalsSnapshot inspectionSignals, DiagnosisResult diagnosis, BypassPlan plan)
        {
            // Для успешных результатов оставляем прежний контракт (фильтр ожидает NONE + OK)
            if (tested.DnsOk && tested.TcpOk && tested.TlsOk)
            {
                // UDP blockage не считаем «ошибкой» для UI (браузер часто откатывается на TCP)
                if (inspectionSignals.UdpUnansweredHandshakes > 2)
                {
                    var udpTested = tested with { BlockageType = BlockageCode.UdpBlockage };
                    return new HostBlocked(udpTested, PipelineContract.BypassNone, BlockageCode.StatusOk);
                }

                if (diagnosis.DiagnosisId == DiagnosisId.NoBlockage)
                {
                    return new HostBlocked(tested, PipelineContract.BypassNone, BlockageCode.StatusOk);
                }

                // Если INTEL увидел флаги, но тесты формально OK — не делаем уверенных выводов.
                return new HostBlocked(tested, PipelineContract.BypassNone, BuildEvidenceTail(diagnosis));
            }

            // Проблема/блокировка: показываем «хвост» из фактов для QA/лога.
            // Если селектор дал план — отображаем краткую рекомендацию.
            var bypassStrategy = (plan.Strategies.Count == 0 && !plan.DropUdp443 && !plan.AllowNoSni)
                ? PipelineContract.BypassNone
                : BuildBypassStrategyText(plan);
            return new HostBlocked(tested, bypassStrategy, BuildEvidenceTail(diagnosis));
        }

        private static string BuildBypassStrategyText(BypassPlan plan)
        {
            // Короткая строка для UI/логов. Не привязана к авто-применению.
            var tokens = new List<string>(capacity: plan.Strategies.Count + 2);
            tokens.AddRange(plan.Strategies.Select(s => s.Id.ToString()));
            if (plan.DropUdp443) tokens.Add("DropUdp443");
            if (plan.AllowNoSni) tokens.Add("AllowNoSni");

            var ids = tokens.Count == 0 ? PipelineContract.BypassNone : string.Join(" + ", tokens);
            return $"plan:{ids} (conf={plan.PlanConfidence})";
        }

        private static DiagnosisResult EnrichDiagnosisWithAutoHostlist(DiagnosisResult diagnosis, AutoHostCandidate candidate)
        {
            var evidence = diagnosis.Evidence.Count == 0
                ? new Dictionary<string, string>(StringComparer.Ordinal)
                : new Dictionary<string, string>(diagnosis.Evidence, StringComparer.Ordinal);

            // Ключи фиксируем с префиксом, чтобы не конфликтовать с другими evidence.
            evidence.TryAdd("autoHL.key", candidate.Host);
            evidence.TryAdd("autoHL.hits", candidate.Hits.ToString());
            evidence.TryAdd("autoHL.score", candidate.Score.ToString());
            evidence.TryAdd("autoHL.lastSeenUtc", candidate.LastSeenUtc.ToString("O"));

            // Важно: UI форматтер берёт только первую ноту из хвоста.
            // Поэтому auto-hostlist добавляем первой строкой.
            var notes = diagnosis.ExplanationNotes.Count == 0
                ? new List<string>(capacity: 1)
                : diagnosis.ExplanationNotes.ToList();

            notes.Insert(0, $"autoHL hits={candidate.Hits} score={candidate.Score}");

            return new DiagnosisResult
            {
                DiagnosisId = diagnosis.DiagnosisId,
                Confidence = diagnosis.Confidence,
                MatchedRuleName = diagnosis.MatchedRuleName,
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = diagnosis.InputSignals,
                DiagnosedAtUtc = diagnosis.DiagnosedAtUtc,
            };
        }

        private static string BuildEvidenceTail(DiagnosisResult diagnosis)
        {
            // Формат специально в круглых скобках — UiWorker вытаскивает хвост и добавляет в строку.
            var header = $"intel:{diagnosis.DiagnosisId} conf={diagnosis.Confidence}";
            if (diagnosis.ExplanationNotes.Count == 0)
            {
                return $"({header})";
            }

            return $"({header}; {string.Join("; ", diagnosis.ExplanationNotes)})";
        }
    }
}
