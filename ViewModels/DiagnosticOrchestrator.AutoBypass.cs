using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
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

        // MVP значения: достаточно, чтобы не «душить» UI/движок.
        private static readonly TimeSpan AutoApplyCooldown = TimeSpan.FromSeconds(45);
        private static readonly TimeSpan AutoApplySuccessCooldown = TimeSpan.FromMinutes(3);
        private static readonly TimeSpan AutoApplyMinInterval = TimeSpan.FromSeconds(5);

        private void ResetAutoApplyState()
        {
            _autoApplyLastAttemptUtcByTarget.Clear();
            _autoApplyLastSuccessUtcByTarget.Clear();
            _autoApplyLastPlanSignatureByTarget.Clear();
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
            if (!PlanHasApplicableActions(plan)) return;

            // Диагностика должна быть активна: auto-apply имеет смысл только в live-сценарии.
            if (!IsDiagnosticRunning) return;

            // Не делаем auto-apply по шумовым/техническим целям.
            if (NoiseHostFilter.Instance.IsNoiseHost(hostKey)) return;

            var targetHost = ResolveAutoApplyTargetHost(hostKey);
            if (string.IsNullOrWhiteSpace(targetHost)) return;

            var planSig = BuildPlanSignature(plan);
            var planChanged = !_autoApplyLastPlanSignatureByTarget.TryGetValue(targetHost, out var lastSig)
                || !string.Equals(lastSig, planSig, StringComparison.OrdinalIgnoreCase);

            // UI/оркестратор уже показывают рекомендацию — auto-apply должен быть «мягким» и не спамить.
            if (IsAutoApplyCooldownActive(targetHost, allowWhenPlanChanged: true, planChanged: planChanged, out var remaining))
            {
                Log($"[AUTO_APPLY] Skip (cooldown {remaining.TotalSeconds:0}s): target={targetHost}; from={hostKey}");
                return;
            }

            _autoApplyLastAttemptUtcByTarget[targetHost] = DateTimeOffset.UtcNow;
            _autoApplyLastPlanSignatureByTarget[targetHost] = planSig;

            // Fire-and-forget: внутри есть gate + уважение Cancel.
            _ = Task.Run(() => AutoApplyFromPlanAsync(targetHost, hostKey, plan, planSig, bypassController));
        }

        private async Task AutoApplyFromPlanAsync(string targetHost, string sourceHostKey, BypassPlan plan, string planSig, BypassController bypassController)
        {
            // Глобальный gate, чтобы не запускать несколько auto-apply параллельно.
            // Важно: ApplyIntelPlanAsync уже сериализуется внутри BypassController, но нам нужно сдержать UI/лог.
            await _autoApplyGate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_cts?.IsCancellationRequested == true) return;

                // Если пользователь уже вручную жмёт Apply, не мешаем.
                if (IsApplyRunning)
                {
                    Log($"[AUTO_APPLY] Skip (manual apply running): target={targetHost}; from={sourceHostKey}");
                    return;
                }

                var planChanged = !_autoApplyLastPlanSignatureByTarget.TryGetValue(targetHost, out var lastSig)
                    || !string.Equals(lastSig, planSig, StringComparison.OrdinalIgnoreCase);

                if (IsAutoApplyCooldownActive(targetHost, allowWhenPlanChanged: true, planChanged: planChanged, out var remaining))
                {
                    Log($"[AUTO_APPLY] Skip (cooldown {remaining.TotalSeconds:0}s): target={targetHost}; from={sourceHostKey}");
                    return;
                }

                _autoApplyLastAttemptUtcByTarget[targetHost] = DateTimeOffset.UtcNow;
                _autoApplyLastPlanSignatureByTarget[targetHost] = planSig;

                Log($"[AUTO_APPLY] Start: target={targetHost}; source={sourceHostKey}");

                try
                {
                    // Пишем в pipeline прогресс, чтобы пользователь видел причину «само что-то применилось».
                    OnPipelineMessage?.Invoke($"⚙ Auto-apply: {targetHost} (по плану для {sourceHostKey})");
                }
                catch
                {
                }

                // Реальное применение.
                var outcome = await ApplyPlanInternalAsync(bypassController, targetHost, plan).ConfigureAwait(false);
                if (outcome == null)
                {
                    Log($"[AUTO_APPLY] Done: no-op/skip (outcome null): target={targetHost}");
                    return;
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
            }
            catch (Exception ex)
            {
                Log($"[AUTO_APPLY] FAILED: target={targetHost}; error={ex.Message}");
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
                    await _testingPipeline.EnqueueHostAsync(h).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                Log($"[AUTO_RETEST] FAILED: target={targetHost}; error={ex.Message}");
            }
        }
    }
}
