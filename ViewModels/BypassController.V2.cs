using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.IntelligenceV2.Execution;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        /// <summary>
        /// Применить v2 план рекомендаций (ТОЛЬКО вручную), с таймаутом/отменой и безопасным откатом.
        /// </summary>
        public async Task ApplyV2PlanAsync(BypassPlan plan, TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (plan == null) throw new ArgumentNullException(nameof(plan));

            cancellationToken.ThrowIfCancellationRequested();

            var strategiesText = plan.Strategies.Count == 0
                ? "(пусто)"
                : string.Join(", ", plan.Strategies.Select(s => s.Id));

            Log($"[V2][Executor] Apply requested: диагноз={plan.ForDiagnosis} conf={plan.PlanConfidence}% стратегии={strategiesText}");
            if (!string.IsNullOrWhiteSpace(plan.Reasoning))
            {
                Log($"[V2][Executor] Reasoning: {plan.Reasoning}");
            }

            var snapshot = CaptureStateSnapshot();
            Log($"[V2][Executor] Timeout={(timeout > TimeSpan.Zero ? timeout.TotalSeconds.ToString("0.##") + "s" : "none")}; before={snapshot.Options.ToReadableStrategy()}; DoH={(snapshot.DoHEnabled ? "on" : "off")}; DNS={snapshot.SelectedDnsPreset}");

            using var timeoutCts = timeout > TimeSpan.Zero ? new CancellationTokenSource(timeout) : null;
            using var linked = timeoutCts != null
                ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            try
            {
                linked.Token.ThrowIfCancellationRequested();
                _currentOptions = _stateManager.GetOptionsSnapshot();
                var updated = _currentOptions;
                var enableDoH = false;
                TlsFragmentPreset? requestedPreset = null;
                bool? requestedAutoAdjustAggressive = null;

                foreach (var strategy in plan.Strategies)
                {
                    switch (strategy.Id)
                    {
                        case StrategyId.TlsFragment:
                            updated = updated with { FragmentEnabled = true, DisorderEnabled = false };

                            // Опциональные параметры стратегии: пресет/размеры/auto-adjust.
                            // Если параметров нет — сохраняем текущий выбранный пресет пользователя.
                            if (strategy.Parameters != null && strategy.Parameters.Count > 0)
                            {
                                if (TlsFragmentPlanParamsParser.TryParse(strategy.Parameters, out var parsed))
                                {
                                    if (parsed.Sizes != null && parsed.Sizes.Count > 0)
                                    {
                                        var sizes = parsed.Sizes.ToList();
                                        requestedPreset = ResolveOrCreatePresetBySizes(sizes);
                                        Log($"[V2][Executor] TlsFragment param: sizes=[{string.Join(",", sizes)}] → preset='{requestedPreset.Name}'");
                                    }
                                    else if (!string.IsNullOrWhiteSpace(parsed.PresetName))
                                    {
                                        var resolved = ResolvePresetByNameOrAlias(parsed.PresetName);
                                        if (resolved != null)
                                        {
                                            requestedPreset = resolved;
                                            Log($"[V2][Executor] TlsFragment param: preset='{parsed.PresetName}' → '{resolved.Name}'");
                                        }
                                        else
                                        {
                                            Log($"[V2][Executor] TlsFragment param: preset='{parsed.PresetName}' не распознан — пропуск");
                                        }
                                    }

                                    if (parsed.AutoAdjustAggressive.HasValue)
                                    {
                                        requestedAutoAdjustAggressive = parsed.AutoAdjustAggressive.Value;
                                        Log($"[V2][Executor] TlsFragment param: autoAdjustAggressive={(requestedAutoAdjustAggressive.Value ? "true" : "false")}");
                                    }
                                }
                            }
                            break;
                        case StrategyId.AggressiveFragment:
                            // Агрессивная фрагментация: используем пресет «Агрессивный» + авто-подстройку.
                            updated = updated with { FragmentEnabled = true, DisorderEnabled = false };
                            requestedPreset = FragmentPresets
                                .FirstOrDefault(p => string.Equals(p.Name, "Агрессивный", StringComparison.OrdinalIgnoreCase));
                            requestedAutoAdjustAggressive = true;
                            break;
                        case StrategyId.TlsDisorder:
                            updated = updated with { DisorderEnabled = true, FragmentEnabled = false };
                            break;
                        case StrategyId.TlsFakeTtl:
                            updated = updated with { FakeEnabled = true };
                            break;
                        case StrategyId.DropRst:
                            updated = updated with { DropRstEnabled = true };
                            break;
                        case StrategyId.UseDoh:
                            enableDoH = true;
                            break;
                        case StrategyId.QuicObfuscation:
                            // Реализация MVP: QUIC obfuscation = QUIC→TCP fallback (DROP UDP/443).
                            updated = updated with { DropUdp443 = true };
                            Log("[V2][Executor] QuicObfuscation: включаем QUIC→TCP (DROP UDP/443)");
                            break;
                        case StrategyId.HttpHostTricks:
                            updated = updated with { HttpHostTricksEnabled = true };
                            Log("[V2][Executor] HttpHostTricks: включаем HTTP Host tricks");
                            break;
                        case StrategyId.BadChecksum:
                            updated = updated with { BadChecksumEnabled = true };
                            Log("[V2][Executor] BadChecksum: включаем bad checksum (только для фейковых пакетов)");
                            break;
                        default:
                            // Нереализованные/неподдерживаемые в bypass контроллере стратегии пропускаем.
                            Log($"[V2][Executor] Стратегия {strategy.Id} не поддерживается контроллером — пропуск");
                            break;
                    }
                }

                // Assist-флаги из плана (включаем только если селектор их рекомендовал).
                if (plan.DropUdp443)
                {
                    updated = updated with { DropUdp443 = true };
                    Log("[V2][Executor] Assist: включаем QUIC→TCP (DROP UDP/443)");
                }

                if (plan.AllowNoSni)
                {
                    updated = updated with { AllowNoSni = true };
                    Log("[V2][Executor] Assist: включаем No SNI (разрешить обход без SNI)");
                }

                if (requestedPreset != null)
                {
                    // Если пресет создан из параметров v2 и отсутствует в списке — добавим, чтобы UI мог корректно отобразить выбранный вариант.
                    if (!FragmentPresets.Any(p => string.Equals(p.Name, requestedPreset.Name, StringComparison.OrdinalIgnoreCase)
                        && p.Sizes.SequenceEqual(requestedPreset.Sizes)))
                    {
                        FragmentPresets.Add(requestedPreset);
                    }

                    _selectedPreset = requestedPreset;
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
                    // Если явно выбрали агрессивный пресет (даже через TlsFragment), логично включить авто-подстройку.
                    updated = updated with { AutoAdjustAggressive = true };
                }

                _currentOptions = updated;

                Log($"[V2][Executor] Target={_currentOptions.ToReadableStrategy()}; DoH={(enableDoH ? "on" : "off")}; DNS={SelectedDnsPreset}");

                linked.Token.ThrowIfCancellationRequested();

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                    OnPropertyChanged(nameof(IsFakeEnabled));
                    OnPropertyChanged(nameof(IsDropRstEnabled));
                    OnPropertyChanged(nameof(IsQuicFallbackEnabled));
                    OnPropertyChanged(nameof(IsAllowNoSniEnabled));
                    OnPropertyChanged(nameof(IsAutoAdjustAggressive));
                    OnPropertyChanged(nameof(SelectedFragmentPreset));
                    OnPropertyChanged(nameof(SelectedFragmentPresetLabel));
                    NotifyActiveStatesChanged();
                    CheckCompatibility();
                });

                // Сохраняем параметры фрагментации/пресета и флаг авто-подстройки.
                PersistFragmentPreset();

                // Сохраняем assist-флаги (QUIC→TCP / No SNI) в профиль.
                PersistAssistSettings();

                Log("[V2][Executor] Applying bypass options...");
                await ApplyBypassOptionsAsync(linked.Token).ConfigureAwait(false);
                Log("[V2][Executor] Bypass options applied");

                linked.Token.ThrowIfCancellationRequested();

                if (enableDoH && !_isDoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Log("[V2][Executor] Applying DoH (enable)");
                    _isDoHEnabled = true;
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        OnPropertyChanged(nameof(IsDoHEnabled));
                        OnPropertyChanged(nameof(IsDoHActive));
                    });
                    await ApplyDoHAsync().ConfigureAwait(false);
                }

                if (!enableDoH && _isDoHEnabled)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Log("[V2][Executor] Applying DoH (disable)");
                    await DisableDoHAsync().ConfigureAwait(false);
                }

                Log($"[V2][Executor] Apply complete: after={_currentOptions.ToReadableStrategy()}; DoH={(_isDoHEnabled ? "on" : "off")}; DNS={SelectedDnsPreset}");
            }
            catch (OperationCanceledException)
            {
                var cancelReason = timeoutCts?.IsCancellationRequested == true
                    ? "timeout"
                    : (cancellationToken.IsCancellationRequested ? "cancel" : "cancel");
                Log($"[V2][Executor] Apply {cancelReason} — rollback");
                Log($"[V2][Executor] Rollback to: {snapshot.Options.ToReadableStrategy()}; DoH={(snapshot.DoHEnabled ? "on" : "off")}; DNS={snapshot.SelectedDnsPreset}");
                await RestoreSnapshotAsync(snapshot).ConfigureAwait(false);
                Log($"[V2][Executor] Rollback complete: after={_currentOptions.ToReadableStrategy()}; DoH={(_isDoHEnabled ? "on" : "off")}; DNS={SelectedDnsPreset}");
                throw;
            }
            catch (Exception ex)
            {
                Log($"[V2][Executor] Apply failed: {ex.Message} — rollback");
                Log($"[V2][Executor] Rollback to: {snapshot.Options.ToReadableStrategy()}; DoH={(snapshot.DoHEnabled ? "on" : "off")}; DNS={snapshot.SelectedDnsPreset}");
                await RestoreSnapshotAsync(snapshot).ConfigureAwait(false);
                Log($"[V2][Executor] Rollback complete: after={_currentOptions.ToReadableStrategy()}; DoH={(_isDoHEnabled ? "on" : "off")}; DNS={SelectedDnsPreset}");
                throw;
            }
        }

        /// <summary>
        /// Overload: применить v2 план и одновременно задать цель для HTTPS outcome-check.
        /// </summary>
        public Task ApplyV2PlanAsync(BypassPlan plan, string? outcomeTargetHost, TimeSpan timeout, CancellationToken cancellationToken)
        {
            SetOutcomeTargetHost(outcomeTargetHost);
            return ApplyV2PlanAsync(plan, timeout, cancellationToken);
        }

        private TlsFragmentPreset? ResolvePresetByNameOrAlias(string presetName)
        {
            if (string.IsNullOrWhiteSpace(presetName))
            {
                return null;
            }

            var normalized = presetName.Trim();

            // Поддерживаем русские названия пресетов.
            var direct = FragmentPresets.FirstOrDefault(p => string.Equals(p.Name, normalized, StringComparison.OrdinalIgnoreCase));
            if (direct != null)
            {
                return direct;
            }

            // Алиасы (на будущее / на случай JSON-конфига).
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

            return FragmentPresets.FirstOrDefault(p => string.Equals(p.Name, mapped, StringComparison.OrdinalIgnoreCase));
        }

        private TlsFragmentPreset ResolveOrCreatePresetBySizes(List<int> sizes)
        {
            var normalized = NormalizeFragmentSizes(sizes);
            if (normalized.Count == 0)
            {
                // Фоллбек: не должно случиться (проверяется выше), но держим безопасно.
                normalized = new List<int> { 64 };
            }

            var existing = FragmentPresets.FirstOrDefault(p => p.Sizes.SequenceEqual(normalized));
            if (existing != null)
            {
                return existing;
            }

            // Синтетический пресет только при явных размерах из плана.
            return new TlsFragmentPreset("План v2", normalized, "Сгенерировано из параметров стратегии v2");
        }

        private static List<int> NormalizeFragmentSizes(IEnumerable<int> input)
        {
            var safe = input
                .Where(v => v > 0)
                .Select(v => Math.Max(4, v))
                .Take(4)
                .ToList();

            return safe;
        }

        /// <summary>
        /// Применить рекомендации из классификатора (без повторного включения активных стратегий).
        /// </summary>
        public async Task ApplyRecommendedAsync(IEnumerable<string> strategies)
        {
            if (strategies == null) return;

            var unique = strategies
                .Select(s => s?.Trim())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s!.ToUpperInvariant())
                .Distinct()
                .ToList();

            if (!unique.Any()) return;

            var updated = _currentOptions;
            var enableDoH = false;

            foreach (var strategy in unique)
            {
                switch (strategy)
                {
                    case "TLS_FRAGMENT":
                        updated = updated with { FragmentEnabled = true, DisorderEnabled = false };
                        break;
                    case "TLS_DISORDER":
                        updated = updated with { DisorderEnabled = true, FragmentEnabled = false };
                        break;
                    case "TLS_FAKE":
                        updated = updated with { FakeEnabled = true };
                        break;
                    case "TLS_FAKE_FRAGMENT":
                        updated = updated with { FakeEnabled = true, FragmentEnabled = true, DisorderEnabled = false };
                        break;
                    case "DROP_RST":
                        updated = updated with { DropRstEnabled = true };
                        break;
                    case "DOH":
                        enableDoH = true;
                        break;
                    default:
                        break;
                }
            }

            _currentOptions = updated;

            Application.Current?.Dispatcher.Invoke(() =>
            {
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDisorderEnabled));
                OnPropertyChanged(nameof(IsFakeEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                NotifyActiveStatesChanged();
                CheckCompatibility();
            });

            await ApplyBypassOptionsAsync().ConfigureAwait(false);

            if (enableDoH && !IsDoHEnabled)
            {
                _isDoHEnabled = true;
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OnPropertyChanged(nameof(IsDoHEnabled));
                    OnPropertyChanged(nameof(IsDoHActive));
                });
                await ApplyDoHAsync().ConfigureAwait(false);
            }

            Log($"[Bypass] Применены рекомендации: {string.Join(',', unique)}");
        }

        /// <summary>
        /// Включить преимптивный bypass (вызывается при старте диагностики)
        /// </summary>
        public async Task EnablePreemptiveBypassAsync()
        {
            if (!TrafficEngine.HasAdministratorRights) return;

            Log("[Bypass] Enabling preemptive TLS_DISORDER + DROP_RST...");

            try
            {
                _currentOptions = _currentOptions with
                {
                    FragmentEnabled = false,
                    DisorderEnabled = true,
                    FakeEnabled = false,
                    DropRstEnabled = true
                };

                await _stateManager.ApplyPreemptiveAsync().ConfigureAwait(false);
                _currentOptions = _stateManager.GetOptionsSnapshot();

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    OnPropertyChanged(nameof(IsDisorderEnabled));
                    OnPropertyChanged(nameof(IsFragmentEnabled));
                    OnPropertyChanged(nameof(IsFakeEnabled));
                    OnPropertyChanged(nameof(IsDropRstEnabled));
                    NotifyActiveStatesChanged();
                });

                Log("[Bypass] Preemptive bypass enabled");
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Failed: {ex.Message}");
            }
        }
    }
}
