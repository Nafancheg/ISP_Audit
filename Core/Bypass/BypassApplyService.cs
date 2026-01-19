using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.IntelligenceV2.Execution;
using IspAudit.Utils;

namespace IspAudit.Core.Bypass
{
    /// <summary>
    /// Сервис применения v2 bypass-плана.
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

        /// <summary>
        /// Применить v2 план с таймаутом/отменой и безопасным откатом.
        /// На ошибке/отмене выполняет rollback и пробрасывает исключение дальше.
        /// </summary>
        public async Task<BypassApplyPlanResult> ApplyV2PlanWithRollbackAsync(
            BypassPlan plan,
            TimeSpan timeout,
            bool currentDoHEnabled,
            string selectedDnsPreset,
            CancellationToken cancellationToken)
        {
            if (plan == null) throw new ArgumentNullException(nameof(plan));

            cancellationToken.ThrowIfCancellationRequested();

            var strategiesText = plan.Strategies.Count == 0
                ? "(пусто)"
                : string.Join(", ", plan.Strategies.Select(s => s.Id));

            _log?.Invoke($"[V2][Executor] Apply requested: диагноз={plan.ForDiagnosis} conf={plan.PlanConfidence}% стратегии={strategiesText}");
            if (!string.IsNullOrWhiteSpace(plan.Reasoning))
            {
                _log?.Invoke($"[V2][Executor] Reasoning: {plan.Reasoning}");
            }

            var optionsBefore = _stateManager.GetOptionsSnapshot();
            var before = new BypassApplyStateSnapshot(optionsBefore, currentDoHEnabled, (selectedDnsPreset ?? string.Empty).Trim());
            _log?.Invoke($"[V2][Executor] Timeout={(timeout > TimeSpan.Zero ? timeout.TotalSeconds.ToString("0.##") + "s" : "none")}; before={before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

            CancellationTokenSource? timeoutCts = null;
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

                var planned = BuildPlannedState(before, plan);

                _log?.Invoke($"[V2][Executor] Target={planned.PlannedOptions.ToReadableStrategy()}; DoH={(planned.PlannedDoHEnabled ? "on" : "off")}; DNS={planned.PlannedDnsPreset}");

                linked.Token.ThrowIfCancellationRequested();

                _log?.Invoke("[V2][Executor] Applying bypass options...");
                await _stateManager.ApplyTlsOptionsAsync(planned.PlannedOptions, linked.Token).ConfigureAwait(false);
                _log?.Invoke("[V2][Executor] Bypass options applied");

                linked.Token.ThrowIfCancellationRequested();

                // DoH/DNS: best-effort, как и раньше (не падаем всем apply при ошибке DNS фиксера).
                var dohAfter = before.DoHEnabled;

                if (planned.PlannedDoHEnabled && !before.DoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    _log?.Invoke("[V2][Executor] Applying DoH (enable)");

                    var (success, error) = await FixService.ApplyDnsFixAsync(planned.PlannedDnsPreset).ConfigureAwait(false);
                    if (success)
                    {
                        dohAfter = true;
                        _log?.Invoke($"[DoH] DoH enabled: {planned.PlannedDnsPreset}");
                    }
                    else
                    {
                        dohAfter = false;
                        _log?.Invoke($"[DoH] Failed: {error}");
                    }
                }

                if (!planned.PlannedDoHEnabled && before.DoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    _log?.Invoke("[V2][Executor] Applying DoH (disable)");

                    var (success, error) = await FixService.RestoreDnsAsync().ConfigureAwait(false);
                    dohAfter = false;
                    _log?.Invoke(success ? "[DoH] DNS settings restored." : $"[DoH] Restore failed: {error}");
                }

                _log?.Invoke($"[V2][Executor] Apply complete: after={planned.PlannedOptions.ToReadableStrategy()}; DoH={(dohAfter ? "on" : "off")}; DNS={planned.PlannedDnsPreset}");

                return planned with { PlannedDoHEnabled = dohAfter };
            }
            catch (OperationCanceledException)
            {
                var cancelReason = timeoutCts?.IsCancellationRequested == true
                    ? "timeout"
                    : (cancellationToken.IsCancellationRequested ? "cancel" : "cancel");

                _log?.Invoke($"[V2][Executor] Apply {cancelReason} — rollback");
                _log?.Invoke($"[V2][Executor] Rollback to: {before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

                await RestoreSnapshotAsync(before).ConfigureAwait(false);

                _log?.Invoke($"[V2][Executor] Rollback complete: after={before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");
                throw;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[V2][Executor] Apply failed: {ex.Message} — rollback");
                _log?.Invoke($"[V2][Executor] Rollback to: {before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");

                await RestoreSnapshotAsync(before).ConfigureAwait(false);

                _log?.Invoke($"[V2][Executor] Rollback complete: after={before.Options.ToReadableStrategy()}; DoH={(before.DoHEnabled ? "on" : "off")}; DNS={before.SelectedDnsPreset}");
                throw;
            }
            finally
            {
                timeoutCts?.Dispose();
            }
        }

        private async Task RestoreSnapshotAsync(BypassApplyStateSnapshot snapshot)
        {
            try
            {
                await _stateManager.ApplyTlsOptionsAsync(snapshot.Options, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // best-effort
            }

            try
            {
                if (snapshot.DoHEnabled)
                {
                    await FixService.ApplyDnsFixAsync(snapshot.SelectedDnsPreset).ConfigureAwait(false);
                }
                else
                {
                    await FixService.RestoreDnsAsync().ConfigureAwait(false);
                }
            }
            catch
            {
                // best-effort
            }
        }

        private BypassApplyPlanResult BuildPlannedState(BypassApplyStateSnapshot before, BypassPlan plan)
        {
            var updated = before.Options;
            var enableDoH = false;
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
                                    _log?.Invoke($"[V2][Executor] TlsFragment param: sizes=[{string.Join(",", sizes)}] → preset='{requestedPreset.Name}'");
                                }
                                else if (!string.IsNullOrWhiteSpace(parsed.PresetName))
                                {
                                    var resolved = ResolvePresetByNameOrAlias(parsed.PresetName);
                                    if (resolved != null)
                                    {
                                        requestedPreset = resolved;
                                        _log?.Invoke($"[V2][Executor] TlsFragment param: preset='{parsed.PresetName}' → '{resolved.Name}'");
                                    }
                                    else
                                    {
                                        _log?.Invoke($"[V2][Executor] TlsFragment param: preset='{parsed.PresetName}' не распознан — пропуск");
                                    }
                                }

                                if (parsed.AutoAdjustAggressive.HasValue)
                                {
                                    requestedAutoAdjustAggressive = parsed.AutoAdjustAggressive.Value;
                                    _log?.Invoke($"[V2][Executor] TlsFragment param: autoAdjustAggressive={(requestedAutoAdjustAggressive.Value ? "true" : "false")}");
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
                        break;
                    case StrategyId.QuicObfuscation:
                        updated = updated with { DropUdp443 = true };
                        wantQuicFallback = true;
                        _log?.Invoke("[V2][Executor] QuicObfuscation: включаем QUIC→TCP (DROP UDP/443)");
                        break;
                    case StrategyId.HttpHostTricks:
                        updated = updated with { HttpHostTricksEnabled = true };
                        wantHttpHostTricks = true;
                        _log?.Invoke("[V2][Executor] HttpHostTricks: включаем HTTP Host tricks");
                        break;
                    case StrategyId.BadChecksum:
                        updated = updated with { BadChecksumEnabled = true };
                        _log?.Invoke("[V2][Executor] BadChecksum: включаем bad checksum (только для фейковых пакетов)");
                        break;
                    default:
                        _log?.Invoke($"[V2][Executor] Стратегия {strategy.Id} не поддерживается контроллером — пропуск");
                        break;
                }
            }

            if (plan.DropUdp443)
            {
                updated = updated with { DropUdp443 = true };
                wantQuicFallback = true;
                _log?.Invoke("[V2][Executor] Assist: включаем QUIC→TCP (DROP UDP/443)");
            }

            if (plan.AllowNoSni)
            {
                updated = updated with { AllowNoSni = true };
                wantAllowNoSni = true;
                _log?.Invoke("[V2][Executor] Assist: включаем No SNI (разрешить обход без SNI)");
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

            return new TlsFragmentPreset("План v2", normalized, "Сгенерировано из параметров стратегии v2");
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
