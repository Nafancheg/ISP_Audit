using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Intelligence.Execution;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        /// <summary>
        /// Применить план рекомендаций (ТОЛЬКО вручную), с таймаутом/отменой и безопасным откатом.
        /// </summary>
        public async Task ApplyIntelPlanAsync(BypassPlan plan, TimeSpan timeout, CancellationToken cancellationToken, Action<BypassApplyPhaseTiming>? onPhaseEvent = null)
        {
            if (plan == null) throw new ArgumentNullException(nameof(plan));

            cancellationToken.ThrowIfCancellationRequested();

            // P0.1 Step 13: сериализуем все ручные apply-операции.
            // Если пользователь (или UI) инициировал несколько apply подряд, они должны отработать строго последовательно.
            if (!await _applyIntelGate.WaitAsync(0, cancellationToken).ConfigureAwait(false))
            {
                Log("[APPLY_GATE] queued (another apply in progress)");
                await _applyIntelGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            Log("[APPLY_GATE] enter");

            try
            {
                using var op = BypassOperationContext.EnterIfNone("intel_apply");

                var applyService = new BypassApplyService(_stateManager, Log);
                var applied = await applyService
                    .ApplyIntelPlanWithRollbackAsync(plan, timeout, _isDoHEnabled, SelectedDnsPreset, allowDnsDohChanges: _stateManager.AllowDnsDohSystemChanges, cancellationToken, onPhaseEvent)
                    .ConfigureAwait(false);

                // Синхронизируем локальное UI-состояние после успешного apply.
                _currentOptions = applied.PlannedOptions;

                if (applied.PlannedFragmentPreset != null)
                {
                    var preset = applied.PlannedFragmentPreset;

                    // Если пресет создан из параметров плана и отсутствует в списке — добавим, чтобы UI мог корректно отобразить выбранный вариант.
                    if (!FragmentPresets.Any(p => string.Equals(p.Name, preset.Name, StringComparison.OrdinalIgnoreCase)
                        && p.Sizes.SequenceEqual(preset.Sizes)))
                    {
                        FragmentPresets.Add(preset);
                    }

                    _selectedPreset = FragmentPresets.FirstOrDefault(p => string.Equals(p.Name, preset.Name, StringComparison.OrdinalIgnoreCase)
                        && p.Sizes.SequenceEqual(preset.Sizes)) ?? preset;
                }

                _isDoHEnabled = applied.PlannedDoHEnabled;
                _selectedDnsPreset = applied.PlannedDnsPreset;

                // P0.5: если UI поток занят/завис — Dispatcher.Invoke может повиснуть.
                // Делаем мягкую синхронизацию: InvokeAsync + таймаут; при таймауте — BeginInvoke.
                var uiSw = Stopwatch.StartNew();
                var dispatcher = Application.Current?.Dispatcher;
                void SyncUiAction()
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
                    OnPropertyChanged(nameof(IsDoHEnabled));
                    OnPropertyChanged(nameof(IsDoHActive));
                    OnPropertyChanged(nameof(SelectedDnsPreset));
                    NotifyActiveStatesChanged();
                    CheckCompatibility();
                }

                if (dispatcher != null && !dispatcher.CheckAccess())
                {
                    try
                    {
                        Log("[APPLY][PHASE] ui_sync: dispatching");
                        var opUi = dispatcher.InvokeAsync(SyncUiAction);
                        var uiTimeout = TimeSpan.FromSeconds(2);
                        var completed = await Task.WhenAny(opUi.Task, Task.Delay(uiTimeout, cancellationToken)).ConfigureAwait(false);
                        if (completed != opUi.Task)
                        {
                            Log($"[APPLY][WARN] ui_sync timeout after {uiTimeout.TotalSeconds:0.#}s; fallback to BeginInvoke");
                            _ = dispatcher.BeginInvoke(SyncUiAction); // намеренно не ждём UI: это fallback при зависании
                        }
                        else
                        {
                            await opUi.Task.ConfigureAwait(false);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        Log($"[APPLY][WARN] ui_sync failed: {ex.Message}");
                    }
                }
                else
                {
                    SyncUiAction();
                }
                uiSw.Stop();
                if (uiSw.ElapsedMilliseconds >= 250)
                {
                    Log($"[APPLY][WARN] ui_sync slow: {uiSw.ElapsedMilliseconds}ms");
                }

                // Сохраняем параметры фрагментации/пресета и флаг авто-подстройки.
                var persistSw = Stopwatch.StartNew();
                PersistFragmentPreset();
                persistSw.Stop();
                if (persistSw.ElapsedMilliseconds >= 250)
                {
                    Log($"[APPLY][WARN] PersistFragmentPreset slow: {persistSw.ElapsedMilliseconds}ms");
                }

                // Сохраняем assist-флаги (QUIC→TCP / No SNI) в профиль.
                persistSw.Restart();
                PersistAssistSettings();
                persistSw.Stop();
                if (persistSw.ElapsedMilliseconds >= 250)
                {
                    Log($"[APPLY][WARN] PersistAssistSettings slow: {persistSw.ElapsedMilliseconds}ms");
                }
            }
            finally
            {
                try
                {
                    _applyIntelGate.Release();
                }
                catch
                {
                    // ignore
                }

                Log("[APPLY_GATE] exit");
            }
        }

        /// <summary>
        /// Overload: применить план и одновременно задать цель для HTTPS outcome-check.
        /// </summary>
        public Task ApplyIntelPlanAsync(BypassPlan plan, string? outcomeTargetHost, TimeSpan timeout, CancellationToken cancellationToken, Action<BypassApplyPhaseTiming>? onPhaseEvent = null)
        {
            SetOutcomeTargetHost(outcomeTargetHost);
            return ApplyIntelPlanAsync(plan, timeout, cancellationToken, onPhaseEvent);
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

            SafeUiInvoke(() =>
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
                SafeUiInvoke(() =>
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

                SafeUiInvoke(() =>
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
