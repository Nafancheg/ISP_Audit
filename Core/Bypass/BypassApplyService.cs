using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Bypass.Strategies;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Intelligence.Execution;
using IspAudit.Utils;

namespace IspAudit.Core.Bypass
{
    /// <summary>
    /// Сервис применения INTEL bypass-плана.
    /// Выносит apply/rollback/timeout из ViewModel-слоя, не имеет зависимостей от WPF.
    /// </summary>
    public sealed class BypassApplyService
    {
        private readonly BypassStateManager _stateManager;
        private readonly Action<string>? _log;

        public BypassApplyService(BypassStateManager stateManager, Action<string>? log)
        {
            _stateManager = stateManager ?? throw new ArgumentNullException(nameof(stateManager));
            _log = log;
        }

        public sealed record BypassApplyStateSnapshot(TlsBypassOptions Options, bool DoHEnabled, string SelectedDnsPreset);

        public sealed record BypassApplyPlanResult(
            BypassApplyStateSnapshot Before,
            TlsBypassOptions PlannedOptions,
            bool PlannedDoHEnabled,
            string PlannedDnsPreset,
            TlsFragmentPreset? PlannedFragmentPreset,
            bool? PlannedAutoAdjustAggressive);

        public sealed record BypassApplyExecutionResult(
            string Status,
            string Error,
            string RollbackStatus,
            string CancelReason,
            BypassApplyStateSnapshot Before,
            string CurrentPhase,
            IReadOnlyList<BypassApplyPhaseTiming> Phases,
            long TotalElapsedMs);

        private sealed class ApplyPhaseTracker
        {
            private readonly List<BypassApplyPhaseTiming> _phases = new();
            private readonly long _startedAt = Stopwatch.GetTimestamp();
            private long _currentStartedAt;
            private string _current = string.Empty;

            public IReadOnlyList<BypassApplyPhaseTiming> Phases => _phases;
            public string CurrentPhase => _current;

            public void Start(string name, string details = "")
            {
                if (!string.IsNullOrWhiteSpace(_current))
                {
                    FinalizeCurrent("ABANDONED", "phase switched without finalize");
                }

                _current = name ?? string.Empty;
                _currentStartedAt = Stopwatch.GetTimestamp();

                if (!string.IsNullOrWhiteSpace(details))
                {
                    _phases.Add(new BypassApplyPhaseTiming
                    {
                        Name = _current,
                        Status = "START",
                        ElapsedMs = 0,
                        Details = details
                    });
                }
            }

            public void FinalizeCurrent(string status, string details = "")
            {
                if (string.IsNullOrWhiteSpace(_current))
                {
                    return;
                }

                var elapsed = ElapsedMs(_currentStartedAt);
                _phases.Add(new BypassApplyPhaseTiming
                {
                    Name = _current,
                    Status = status ?? string.Empty,
                    ElapsedMs = elapsed,
                    Details = details ?? string.Empty
                });
                _current = string.Empty;
                _currentStartedAt = 0;
            }

            public long TotalElapsedMs => ElapsedMs(_startedAt);

            private static long ElapsedMs(long startedAt)
            {
                if (startedAt <= 0) return 0;
                var ticks = Stopwatch.GetTimestamp() - startedAt;
                if (ticks <= 0) return 0;
                return (long)(ticks * 1000.0 / Stopwatch.Frequency);
            }
        }

        public sealed class BypassApplyCanceledException : OperationCanceledException
        {
            public BypassApplyExecutionResult Execution { get; }

            public BypassApplyCanceledException(BypassApplyExecutionResult execution, CancellationToken token)
                : base("Bypass apply canceled", null, token)
            {
                Execution = execution;
            }
        }

        public sealed class BypassApplyFailedException : Exception
        {
            public BypassApplyExecutionResult Execution { get; }

            public BypassApplyFailedException(BypassApplyExecutionResult execution, Exception inner)
                : base("Bypass apply failed", inner)
            {
                Execution = execution;
            }
        }

        /// <summary>
        /// Применить INTEL-план с таймаутом/отменой и безопасным откатом.
        /// На ошибке/отмене выполняет rollback и пробрасывает исключение дальше.
        /// </summary>
        public async Task<BypassApplyPlanResult> ApplyIntelPlanWithRollbackAsync(
            BypassPlan plan,
            TimeSpan timeout,
            bool currentDoHEnabled,
            string selectedDnsPreset,
            bool allowDnsDohChanges,
            CancellationToken cancellationToken,
            Action<BypassApplyPhaseTiming>? onPhaseEvent = null)
        {
            if (plan == null) throw new ArgumentNullException(nameof(plan));

            cancellationToken.ThrowIfCancellationRequested();

            using var op = BypassOperationContext.EnterIfNone("intel_apply_service");

            var strategiesText = plan.Strategies.Count == 0
                ? "(пусто)"
                : string.Join(", ", plan.Strategies.Select(s => s.Id));

            _log?.Invoke($"[APPLY][Executor] Apply requested: диагноз={plan.ForDiagnosis} conf={plan.PlanConfidence}% стратегии={strategiesText}");
            if (!string.IsNullOrWhiteSpace(plan.Reasoning))
            {
                _log?.Invoke($"[APPLY][Executor] Reasoning: {plan.Reasoning}");
            }

            var optionsBefore = _stateManager.GetOptionsSnapshot();
            var before = new BypassApplyStateSnapshot(optionsBefore, currentDoHEnabled, (selectedDnsPreset ?? string.Empty).Trim());
            _log?.Invoke($"[APPLY][Executor] Timeout={(timeout > TimeSpan.Zero ? timeout.TotalSeconds.ToString("0.##") + "s" : "none")}; before={before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

            var tracker = new ApplyPhaseTracker();
            CancellationTokenSource? timeoutCts = null;
            var tlsOptionsApplied = false;
            var dnsTouched = false;

            void ReportPhaseStart(string name, string details = "")
            {
                try
                {
                    onPhaseEvent?.Invoke(new BypassApplyPhaseTiming
                    {
                        Name = name ?? string.Empty,
                        Status = "START",
                        ElapsedMs = 0,
                        Details = details ?? string.Empty
                    });
                }
                catch
                {
                    // Best-effort: прогресс не должен ломать apply.
                }
            }

            try
            {
                if (timeout > TimeSpan.Zero)
                {
                    timeoutCts = new CancellationTokenSource(timeout);
                }

                using var linked = timeoutCts != null
                    ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
                    : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                linked.Token.ThrowIfCancellationRequested();

                ReportPhaseStart("plan_build", $"strategies={strategiesText}");
                tracker.Start("plan_build", $"strategies={strategiesText}");
                var planned = BuildPlannedState(before, plan);
                tracker.FinalizeCurrent("OK");

                _log?.Invoke($"[APPLY][Executor] Target={planned.PlannedOptions.ToReadableStrategy()}; DoH={(planned.PlannedDoHEnabled ? "on" : "off")}; DNS={planned.PlannedDnsPreset}");

                // Тестовый хук (smoke/regression): искусственная задержка, чтобы можно было
                // детерминированно проверить сериализацию apply (P0.1 Step 13).
                // Важно: только DEBUG, чтобы не допускать «скрытого» влияния на Release.
#if DEBUG
                if (IspAudit.Utils.EnvVar.TryReadInt32(IspAudit.Utils.EnvKeys.TestApplyDelayMs, out var testDelayMs) && testDelayMs > 0)
                {
                    ReportPhaseStart("test_delay", $"delayMs={testDelayMs}");
                    tracker.Start("test_delay", $"delayMs={testDelayMs}");
                    _log?.Invoke($"[APPLY][Executor] Test delay: {testDelayMs}ms");
                    await Task.Delay(testDelayMs, linked.Token).ConfigureAwait(false);
                    tracker.FinalizeCurrent("OK");
                }
#endif

                linked.Token.ThrowIfCancellationRequested();

                ReportPhaseStart("apply_tls_options");
                tracker.Start("apply_tls_options");
                var skipTls = false;
#if DEBUG
                skipTls = IspAudit.Utils.EnvVar.ReadBool(IspAudit.Utils.EnvKeys.TestSkipTlsApply, defaultValue: false);
#endif

                if (skipTls)
                {
                    _log?.Invoke($"[APPLY][Executor] Test hook: TLS apply skipped ({IspAudit.Utils.EnvKeys.TestSkipTlsApply})");
                    tracker.FinalizeCurrent("OK", "test_skip_tls_apply");
                }
                else
                {
                    _log?.Invoke("[APPLY][Executor] Applying bypass options...");
                    await _stateManager.ApplyTlsOptionsAsync(planned.PlannedOptions, linked.Token).ConfigureAwait(false);
                    tlsOptionsApplied = true;
                    _log?.Invoke("[APPLY][Executor] Bypass options applied");
                    tracker.FinalizeCurrent("OK");
                }

                linked.Token.ThrowIfCancellationRequested();

                // DoH/DNS: best-effort, как и раньше (не падаем всем apply при ошибке DNS фиксера).
                var dohAfter = before.DoHEnabled;

                // Важно: DoH/DNS — системное изменение. Без явного согласия пропускаем любые попытки его включить/выключить.
                if (!allowDnsDohChanges && planned.PlannedDoHEnabled != before.DoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();

                    var direction = planned.PlannedDoHEnabled ? "enable" : "disable";
                    var details = planned.PlannedDoHEnabled
                        ? $"reason=no_consent direction={direction} preset={planned.PlannedDnsPreset}"
                        : $"reason=no_consent direction={direction}";

                    ReportPhaseStart("apply_doh_skipped", details);
                    tracker.Start("apply_doh_skipped", details);
                    _log?.Invoke($"[APPLY][Executor] DoH/DNS skipped: no explicit consent (direction={direction})");
                    tracker.FinalizeCurrent("SKIPPED", "no_consent");
                }

                if (allowDnsDohChanges && planned.PlannedDoHEnabled && !before.DoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    ReportPhaseStart("apply_doh_enable", $"preset={planned.PlannedDnsPreset}");
                    tracker.Start("apply_doh_enable", $"preset={planned.PlannedDnsPreset}");
                    _log?.Invoke("[APPLY][Executor] Applying DoH (enable)");

                    dnsTouched = true;
                    var (success, error) = await FixService.ApplyDnsFixAsync(planned.PlannedDnsPreset, reason: $"apply_plan:apply_doh_enable preset={planned.PlannedDnsPreset}", cancellationToken: linked.Token).ConfigureAwait(false);
                    if (success)
                    {
                        dohAfter = true;
                        _log?.Invoke($"[DoH] DoH enabled: {planned.PlannedDnsPreset}");
                        tracker.FinalizeCurrent("OK");
                    }
                    else
                    {
                        dohAfter = false;
                        _log?.Invoke($"[DoH] Failed: {error}");
                        tracker.FinalizeCurrent("FAILED", error);
                    }

                    linked.Token.ThrowIfCancellationRequested();
                }

                if (allowDnsDohChanges && !planned.PlannedDoHEnabled && before.DoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    ReportPhaseStart("apply_doh_disable");
                    tracker.Start("apply_doh_disable");
                    _log?.Invoke("[APPLY][Executor] Applying DoH (disable)");

                    dnsTouched = true;
                    var (success, error) = await FixService.RestoreDnsAsync(reason: "apply_plan:apply_doh_disable", cancellationToken: linked.Token).ConfigureAwait(false);
                    dohAfter = false;
                    _log?.Invoke(success ? "[DoH] DNS settings restored." : $"[DoH] Restore failed: {error}");

                    tracker.FinalizeCurrent(success ? "OK" : "FAILED", success ? string.Empty : error);
                    linked.Token.ThrowIfCancellationRequested();
                }

                _log?.Invoke($"[APPLY][Executor] Apply complete: after={planned.PlannedOptions.ToReadableStrategy()}; DoH={(dohAfter ? "on" : "off")}; DNS={planned.PlannedDnsPreset}");

                return planned with { PlannedDoHEnabled = dohAfter };
            }
            catch (OperationCanceledException)
            {
                var cancelReason = timeoutCts?.IsCancellationRequested == true
                    ? "timeout"
                    : (cancellationToken.IsCancellationRequested ? "cancel" : "cancel");

                var currentPhase = tracker.CurrentPhase;
                tracker.FinalizeCurrent("CANCELED", cancelReason);

                _log?.Invoke($"[APPLY][Executor] Apply {cancelReason} — rollback");
                _log?.Invoke($"[APPLY][Executor] Rollback to: {before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

                string rollbackStatus;
                if (!tlsOptionsApplied && !dnsTouched)
                {
                    rollbackStatus = "NOT_NEEDED";
                    _log?.Invoke("[APPLY][Executor] Rollback skipped: ничего не было применено");
                }
                else
                {
                    var rollbackOk = await RestoreSnapshotAsync(before, tracker, onPhaseEvent).ConfigureAwait(false);
                    rollbackStatus = rollbackOk ? "DONE" : "FAILED";
                }

                _log?.Invoke($"[APPLY][Executor] Rollback complete ({rollbackStatus}): after={before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

                throw new BypassApplyCanceledException(
                    new BypassApplyExecutionResult(
                        Status: "CANCELED",
                        Error: string.Empty,
                        RollbackStatus: rollbackStatus,
                        CancelReason: cancelReason,
                        Before: before,
                        CurrentPhase: currentPhase,
                        Phases: tracker.Phases,
                        TotalElapsedMs: tracker.TotalElapsedMs),
                    cancellationToken);
            }
            catch (Exception ex)
            {
                var currentPhase = tracker.CurrentPhase;
                tracker.FinalizeCurrent("FAILED", ex.Message);
                _log?.Invoke($"[APPLY][Executor] Apply failed: {ex.Message} — rollback");
                _log?.Invoke($"[APPLY][Executor] Rollback to: {before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

                string rollbackStatus;
                if (!tlsOptionsApplied && !dnsTouched)
                {
                    rollbackStatus = "NOT_NEEDED";
                    _log?.Invoke("[APPLY][Executor] Rollback skipped: ничего не было применено");
                }
                else
                {
                    var rollbackOk = await RestoreSnapshotAsync(before, tracker, onPhaseEvent).ConfigureAwait(false);
                    rollbackStatus = rollbackOk ? "DONE" : "FAILED";
                }

                _log?.Invoke($"[APPLY][Executor] Rollback complete ({rollbackStatus}): after={before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

                throw new BypassApplyFailedException(
                    new BypassApplyExecutionResult(
                        Status: "FAILED",
                        Error: ex.Message,
                        RollbackStatus: rollbackStatus,
                        CancelReason: string.Empty,
                        Before: before,
                        CurrentPhase: currentPhase,
                        Phases: tracker.Phases,
                        TotalElapsedMs: tracker.TotalElapsedMs),
                    ex);
            }
            finally
            {
                timeoutCts?.Dispose();
            }
        }

        private async Task<bool> RestoreSnapshotAsync(BypassApplyStateSnapshot snapshot, ApplyPhaseTracker? tracker, Action<BypassApplyPhaseTiming>? onPhaseEvent)
        {
            var ok = true;
            try
            {
                try
                {
                    onPhaseEvent?.Invoke(new BypassApplyPhaseTiming { Name = "rollback_tls_options", Status = "START", ElapsedMs = 0, Details = string.Empty });
                }
                catch
                {
                    // Best-effort.
                }

                tracker?.Start("rollback_tls_options");
                using var op = BypassOperationContext.EnterIfNone("intel_apply_rollback");
                await _stateManager.ApplyTlsOptionsAsync(snapshot.Options, CancellationToken.None).ConfigureAwait(false);
                tracker?.FinalizeCurrent("OK");
            }
            catch
            {
                // best-effort
                ok = false;
                tracker?.FinalizeCurrent("FAILED");
            }

            try
            {
                try
                {
                    onPhaseEvent?.Invoke(new BypassApplyPhaseTiming { Name = "rollback_dns", Status = "START", ElapsedMs = 0, Details = string.Empty });
                }
                catch
                {
                    // Best-effort.
                }

                tracker?.Start("rollback_dns");
                if (snapshot.DoHEnabled)
                {
                    await FixService.ApplyDnsFixAsync(snapshot.SelectedDnsPreset, reason: $"apply_plan:rollback_dns enable preset={snapshot.SelectedDnsPreset}", cancellationToken: CancellationToken.None).ConfigureAwait(false);
                }
                else
                {
                    await FixService.RestoreDnsAsync(reason: "apply_plan:rollback_dns disable", cancellationToken: CancellationToken.None).ConfigureAwait(false);
                }

                tracker?.FinalizeCurrent("OK");
            }
            catch
            {
                // best-effort
                ok = false;
                tracker?.FinalizeCurrent("FAILED");
            }

            return ok;
        }

        private Task<bool> RestoreSnapshotAsync(BypassApplyStateSnapshot snapshot)
            => RestoreSnapshotAsync(snapshot, tracker: null, onPhaseEvent: null);

        private BypassApplyPlanResult BuildPlannedState(BypassApplyStateSnapshot before, BypassPlan plan)
        {
            var updated = before.Options;
            // DoH/DNS — системная настройка. По умолчанию не трогаем текущее состояние,
            // а включение возможно только если план явно рекомендует UseDoh.
            // Фактическое применение/изменение дополнительно gate'ится явным согласием (allowDnsDohChanges).
            var enableDoH = before.DoHEnabled;
            TlsFragmentPreset? requestedPreset = null;
            bool? requestedAutoAdjustAggressive = null;

            var wantFragment = false;
            var wantDisorder = false;
            var wantFake = false;
            var wantQuicFallback = false;
            var wantAllowNoSni = false;
            var wantHttpHostTricks = false;

            foreach (var strategy in plan.Strategies)
            {
                switch (strategy.Id)
                {
                    case StrategyId.TlsFragment:
                        updated = updated with { FragmentEnabled = true, DisorderEnabled = false };
                        wantFragment = true;

                        if (strategy.Parameters != null && strategy.Parameters.Count > 0)
                        {
                            if (TlsFragmentPlanParamsParser.TryParse(strategy.Parameters, out var parsed))
                            {
                                if (parsed.Sizes != null && parsed.Sizes.Count > 0)
                                {
                                    var sizes = parsed.Sizes.ToList();
                                    requestedPreset = ResolveOrCreatePresetBySizes(sizes);
                                    _log?.Invoke($"[APPLY][Executor] TlsFragment param: sizes=[{string.Join(",", sizes)}] → preset='{requestedPreset.Name}'");
                                }
                                else if (!string.IsNullOrWhiteSpace(parsed.PresetName))
                                {
                                    var resolved = ResolvePresetByNameOrAlias(parsed.PresetName);
                                    if (resolved != null)
                                    {
                                        requestedPreset = resolved;
                                        _log?.Invoke($"[APPLY][Executor] TlsFragment param: preset='{parsed.PresetName}' → '{resolved.Name}'");
                                    }
                                    else
                                    {
                                        _log?.Invoke($"[APPLY][Executor] TlsFragment param: preset='{parsed.PresetName}' не распознан — пропуск");
                                    }
                                }

                                if (parsed.AutoAdjustAggressive.HasValue)
                                {
                                    requestedAutoAdjustAggressive = parsed.AutoAdjustAggressive.Value;
                                    _log?.Invoke($"[APPLY][Executor] TlsFragment param: autoAdjustAggressive={(requestedAutoAdjustAggressive.Value ? "true" : "false")}");
                                }
                            }
                        }
                        break;
                    case StrategyId.AggressiveFragment:
                        updated = updated with { FragmentEnabled = true, DisorderEnabled = false };
                        wantFragment = true;
                        requestedPreset = _stateManager.FragmentPresets
                            .FirstOrDefault(p => string.Equals(p.Name, "Агрессивный", StringComparison.OrdinalIgnoreCase));
                        requestedAutoAdjustAggressive = true;
                        break;
                    case StrategyId.TlsDisorder:
                        updated = updated with { DisorderEnabled = true, FragmentEnabled = false };
                        wantDisorder = true;
                        break;
                    case StrategyId.TlsFakeTtl:
                        updated = updated with { FakeEnabled = true };
                        wantFake = true;
                        break;
                    case StrategyId.DropRst:
                        updated = updated with { DropRstEnabled = true };
                        break;
                    case StrategyId.UseDoh:
                        enableDoH = true;
                        _log?.Invoke("[APPLY][Executor] UseDoh: план запрашивает включение DoH (применение требует явного согласия)");
                        break;
                    case StrategyId.QuicObfuscation:
                        updated = QuicObfuscationStrategy.EnableSelective(updated);
                        wantQuicFallback = true;
                        _log?.Invoke(QuicObfuscationStrategy.GetApplyLogLine());
                        break;
                    case StrategyId.HttpHostTricks:
                        updated = updated with { HttpHostTricksEnabled = true };
                        wantHttpHostTricks = true;
                        _log?.Invoke("[APPLY][Executor] HttpHostTricks: включаем HTTP Host tricks");
                        break;
                    case StrategyId.BadChecksum:
                        updated = updated with { BadChecksumEnabled = true };
                        _log?.Invoke("[APPLY][Executor] BadChecksum: включаем bad checksum (только для фейковых пакетов)");
                        break;
                    default:
                        _log?.Invoke($"[APPLY][Executor] Стратегия {strategy.Id} не поддерживается контроллером — пропуск");
                        break;
                }
            }

            if (plan.DropUdp443)
            {
                updated = QuicObfuscationStrategy.EnableSelective(updated);
                wantQuicFallback = true;
                _log?.Invoke("[APPLY][Executor] Assist: включаем QUIC→TCP (DROP UDP/443)");
            }

            if (plan.AllowNoSni)
            {
                updated = updated with { AllowNoSni = true };
                wantAllowNoSni = true;
                _log?.Invoke("[APPLY][Executor] Assist: включаем No SNI (разрешить обход без SNI)");
            }

            // P0.1 Step 1: per-target политика (для decision graph).
            try
            {
                var hostKey = _stateManager.GetOutcomeTargetHost();
                if (!string.IsNullOrWhiteSpace(hostKey))
                {
                    var tlsStrategy = TlsBypassStrategy.None;
                    if (wantDisorder && wantFake) tlsStrategy = TlsBypassStrategy.FakeDisorder;
                    else if (wantFragment && wantFake) tlsStrategy = TlsBypassStrategy.FakeFragment;
                    else if (wantDisorder) tlsStrategy = TlsBypassStrategy.Disorder;
                    else if (wantFake) tlsStrategy = TlsBypassStrategy.Fake;
                    else if (wantFragment) tlsStrategy = TlsBypassStrategy.Fragment;

                    _stateManager.RememberActiveTargetPolicy(new BypassStateManager.ActiveTargetPolicy
                    {
                        HostKey = hostKey,
                        LastAppliedUtc = DateTime.UtcNow,
                        DropUdp443 = wantQuicFallback,
                        AllowNoSni = wantAllowNoSni,
                        HttpHostTricksEnabled = wantHttpHostTricks,
                        TlsStrategy = tlsStrategy
                    });
                }
            }
            catch
            {
                // best-effort
            }

            if (requestedPreset != null)
            {
                updated = updated with
                {
                    FragmentSizes = requestedPreset.Sizes,
                    PresetName = requestedPreset.Name
                };
            }

            if (requestedAutoAdjustAggressive.HasValue)
            {
                updated = updated with { AutoAdjustAggressive = requestedAutoAdjustAggressive.Value };
            }
            else if (requestedPreset != null && string.Equals(requestedPreset.Name, "Агрессивный", StringComparison.OrdinalIgnoreCase))
            {
                updated = updated with { AutoAdjustAggressive = true };
            }

            return new BypassApplyPlanResult(
                Before: before,
                PlannedOptions: updated,
                PlannedDoHEnabled: enableDoH,
                PlannedDnsPreset: before.SelectedDnsPreset,
                PlannedFragmentPreset: requestedPreset,
                PlannedAutoAdjustAggressive: requestedAutoAdjustAggressive);
        }

        private TlsFragmentPreset? ResolvePresetByNameOrAlias(string presetName)
        {
            if (string.IsNullOrWhiteSpace(presetName))
            {
                return null;
            }

            var normalized = presetName.Trim();

            var direct = _stateManager.FragmentPresets.FirstOrDefault(p => string.Equals(p.Name, normalized, StringComparison.OrdinalIgnoreCase));
            if (direct != null)
            {
                return direct;
            }

            var alias = normalized.ToLowerInvariant();
            var mapped = alias switch
            {
                "standard" or "std" => "Стандарт",
                "moderate" or "medium" => "Умеренный",
                "aggressive" or "agg" => "Агрессивный",
                "profile" => "Профиль",
                _ => null
            };

            if (mapped == null)
            {
                return null;
            }

            return _stateManager.FragmentPresets.FirstOrDefault(p => string.Equals(p.Name, mapped, StringComparison.OrdinalIgnoreCase));
        }

        private TlsFragmentPreset ResolveOrCreatePresetBySizes(List<int> sizes)
        {
            var normalized = NormalizeFragmentSizes(sizes);
            if (normalized.Count == 0)
            {
                normalized = new List<int> { 64 };
            }

            var existing = _stateManager.FragmentPresets.FirstOrDefault(p => p.Sizes.SequenceEqual(normalized));
            if (existing != null)
            {
                return existing;
            }

            return new TlsFragmentPreset("План INTEL", normalized, "Сгенерировано из параметров стратегии INTEL");
        }

        private static List<int> NormalizeFragmentSizes(IEnumerable<int> input)
        {
            return input
                .Where(v => v > 0)
                .Select(v => Math.Max(4, v))
                .Take(4)
                .ToList();
        }
    }
}

