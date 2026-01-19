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
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Windows;
using IspAudit;
using System.Windows.Media;
using System.Net;

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

        public sealed record V2ApplyOutcome(string HostKey, string AppliedStrategyText, string PlanText, string? Reasoning);

        private static bool PlanHasApplicableActions(BypassPlan plan)
            => plan.Strategies.Count > 0 || plan.DropUdp443 || plan.AllowNoSni;

        public Task<V2ApplyOutcome?> ApplyRecommendationsAsync(BypassController bypassController)
            => ApplyRecommendationsAsync(bypassController, preferredHostKey: null);

        public async Task<V2ApplyOutcome?> ApplyRecommendationsForDomainAsync(BypassController bypassController, string domainSuffix)
        {
            if (bypassController == null) throw new ArgumentNullException(nameof(bypassController));
            if (string.IsNullOrWhiteSpace(domainSuffix)) return null;

            var domain = domainSuffix.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(domain)) return null;

            // На данном этапе это управляемая "гибридная" логика:
            // - UI может предложить доменный режим (по анализу доменных семейств в UI-слое)
            // - здесь мы берём последний применимый v2 план из поддоменов и применяем его,
            //   но выставляем OutcomeTargetHost именно на домен.
            var candidates = _v2PlansByHost
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
                Log($"[V2][APPLY] Domain '{domain}': нет сохранённых планов");
                return null;
            }

            // Предпочитаем план от последнего v2 (если он из этого домена), иначе берём первый применимый.
            BypassPlan? plan = null;
            string? sourceHost = null;

            if (!string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                && (_lastV2PlanHostKey.Equals(domain, StringComparison.OrdinalIgnoreCase)
                    || _lastV2PlanHostKey.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                && _v2PlansByHost.TryGetValue(_lastV2PlanHostKey, out var lastPlan)
                && PlanHasApplicableActions(lastPlan))
            {
                plan = lastPlan;
                sourceHost = _lastV2PlanHostKey;
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
                Log($"[V2][APPLY] Domain '{domain}': нет применимых действий в планах");
                return null;
            }

            Log($"[V2][APPLY] Domain '{domain}': apply from '{sourceHost}'");
            return await ApplyPlanInternalAsync(bypassController, domain, plan).ConfigureAwait(false);
        }

        public async Task<V2ApplyOutcome?> ApplyRecommendationsAsync(BypassController bypassController, string? preferredHostKey)
        {
            // 1) Пытаемся применить план для выбранной цели (если UI передал её).
            if (!string.IsNullOrWhiteSpace(preferredHostKey)
                && _v2PlansByHost.TryGetValue(preferredHostKey.Trim(), out var preferredPlan)
                && PlanHasApplicableActions(preferredPlan))
            {
                return await ApplyPlanInternalAsync(bypassController, preferredHostKey.Trim(), preferredPlan).ConfigureAwait(false);
            }

            // 2) Fallback: старый режим «последний v2 план».
            if (_lastV2Plan == null || !PlanHasApplicableActions(_lastV2Plan)) return null;

            // Защита от «устаревшего» плана: применяем только если план относится
            // к последней цели, для которой был показан v2-диагноз.
            if (!string.IsNullOrWhiteSpace(_lastV2DiagnosisHostKey)
                && !string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                && !string.Equals(_lastV2PlanHostKey, _lastV2DiagnosisHostKey, StringComparison.OrdinalIgnoreCase))
            {
                Log($"[V2][APPLY] WARN: planHost={_lastV2PlanHostKey}; lastDiagHost={_lastV2DiagnosisHostKey} (план/цель разошлись)");
            }

            var hostKey = !string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                ? _lastV2PlanHostKey
                : _lastV2DiagnosisHostKey;

            return await ApplyPlanInternalAsync(bypassController, hostKey, _lastV2Plan).ConfigureAwait(false);
        }

        private async Task<V2ApplyOutcome?> ApplyPlanInternalAsync(BypassController bypassController, string hostKey, BypassPlan plan)
        {
            if (NoiseHostFilter.Instance.IsNoiseHost(hostKey))
            {
                Log($"[V2][APPLY] Skip: шумовой хост '{hostKey}'");
                return null;
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
                Log($"[V2][APPLY] host={hostKey}; plan={planStrategies}; before={beforeState}");
                await bypassController.ApplyV2PlanAsync(plan, hostKey, V2ApplyTimeout, ct).ConfigureAwait(false);

                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[V2][APPLY] OK; after={afterState}");
                ResetRecommendations();

                if (!string.IsNullOrWhiteSpace(appliedUiText))
                {
                    return new V2ApplyOutcome(hostKey, appliedUiText, planStrategies, plan.Reasoning);
                }

                return new V2ApplyOutcome(hostKey, "(none)", planStrategies, plan.Reasoning);
            }
            catch (OperationCanceledException)
            {
                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[V2][APPLY] ROLLBACK (cancel/timeout); after={afterState}");
                return null;
            }
            catch (Exception ex)
            {
                var afterState = BuildBypassStateSummary(bypassController);
                Log($"[V2][APPLY] ROLLBACK (error); after={afterState}; error={ex.Message}");
                return null;
            }
            finally
            {
                _applyCts?.Dispose();
                _applyCts = null;
            }
        }

        /// <summary>
        /// Автоматический ретест сразу после Apply (короткий прогон, чтобы увидеть практический эффект обхода).
        /// </summary>
        public Task StartPostApplyRetestAsync(BypassController bypassController, string? preferredHostKey)
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

            return Task.Run(async () =>
            {
                try
                {
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
                        return;
                    }

                    PostApplyRetestStatus = $"Ретест после Apply: проверяем {hosts.Count} IP…";

                    var progress = new Progress<string>(msg =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.Invoke(() =>
                            {
                                // Важно: обновляем рекомендации/диагнозы так же, как при обычной диагностике.
                                TrackV2DiagnosisSummary(msg);
                                TrackRecommendation(msg, bypassController);
                                Log($"[PostApplyRetest] {msg}");
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

                    pipeline.OnV2PlanBuilt += (k, p) =>
                    {
                        try
                        {
                            Application.Current?.Dispatcher.Invoke(() => StoreV2Plan(k, p, bypassController));
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
                }
                catch (OperationCanceledException)
                {
                    PostApplyRetestStatus = "Ретест после Apply: отменён";
                }
                catch (Exception ex)
                {
                    PostApplyRetestStatus = $"Ретест после Apply: ошибка ({ex.Message})";
                }
                finally
                {
                    IsPostApplyRetestRunning = false;
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
            if (!string.IsNullOrWhiteSpace(_lastV2PlanHostKey)) return _lastV2PlanHostKey.Trim();
            if (!string.IsNullOrWhiteSpace(_lastV2DiagnosisHostKey)) return _lastV2DiagnosisHostKey.Trim();
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
            _lastV2DiagnosisSummary = "";
            _lastV2DiagnosisHostKey = "";
            _lastV2Plan = null;
            _lastV2PlanHostKey = "";
            RecommendedStrategiesText = "Нет рекомендаций";
            ManualRecommendationsText = "";
            OnPropertyChanged(nameof(HasRecommendations));
            OnPropertyChanged(nameof(HasAnyRecommendations));
        }

        private void UpdateRecommendationTexts(BypassController bypassController)
        {
            // Убираем рекомендации, если всё уже включено (актуально при ручном переключении)
            _recommendedStrategies.RemoveWhere(s => IsStrategyActive(s, bypassController));

            // Важно для UX: если v2 уже диагностировал проблему/построил план,
            // панель рекомендаций не должна «исчезать» сразу после ручного включения тумблеров.
            var hasAny = _recommendedStrategies.Count > 0
                || _manualRecommendations.Count > 0
                || _lastV2Plan != null
                || !string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary);

            if (!hasAny)
            {
                RecommendedStrategiesText = "Нет рекомендаций";
            }
            else if (_recommendedStrategies.Count == 0)
            {
                var header = string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary)
                    ? "[V2] Диагноз определён"
                    : _lastV2DiagnosisSummary;

                // Если план был, но рекомендации уже включены вручную — объясняем, почему кнопка может быть не нужна.
                RecommendedStrategiesText = _lastV2Plan != null
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
            // Важно: v2 — приоритетно; legacy — только справочно.
            var strategies = string.Join(", ", _recommendedStrategies.Select(FormatStrategyTokenForUi));

            var header = string.IsNullOrWhiteSpace(_lastV2DiagnosisSummary)
                ? "[V2] Диагноз определён"
                : _lastV2DiagnosisSummary;

            var applyHint = $"Что попробовать: нажмите «Применить рекомендации v2» (включит: {strategies})";

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

