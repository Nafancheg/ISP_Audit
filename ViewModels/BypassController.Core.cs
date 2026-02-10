using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Utils;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        private sealed record BypassStateSnapshot(TlsBypassOptions Options, bool DoHEnabled, string SelectedDnsPreset);

        private static bool IsAppliedBy(BypassApplyTransaction tx, string expected)
        {
            if (tx == null) return false;
            var v = (tx.AppliedBy ?? string.Empty).Trim();
            return string.Equals(v, expected, StringComparison.OrdinalIgnoreCase);
        }

        private BypassStateSnapshot CaptureStateSnapshot()
        {
            return new BypassStateSnapshot(_currentOptions, _isDoHEnabled, SelectedDnsPreset);
        }

        private async Task RestoreSnapshotAsync(BypassStateSnapshot snapshot)
        {
            _currentOptions = snapshot.Options;
            _isDoHEnabled = snapshot.DoHEnabled;
            _selectedDnsPreset = snapshot.SelectedDnsPreset;

            Application.Current?.Dispatcher.Invoke(() =>
            {
                OnPropertyChanged(nameof(IsFragmentEnabled));
                OnPropertyChanged(nameof(IsDisorderEnabled));
                OnPropertyChanged(nameof(IsFakeEnabled));
                OnPropertyChanged(nameof(IsDropRstEnabled));
                OnPropertyChanged(nameof(IsDoHEnabled));
                OnPropertyChanged(nameof(IsDoHActive));
                OnPropertyChanged(nameof(SelectedDnsPreset));
                NotifyActiveStatesChanged();
                CheckCompatibility();
            });

            await ApplyBypassOptionsAsync(CancellationToken.None).ConfigureAwait(false);

            if (_isDoHEnabled)
            {
                await ApplyDoHAsync().ConfigureAwait(false);
            }
            else
            {
                await DisableDoHAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Применить текущие настройки bypass
        /// </summary>
        public Task ApplyBypassOptionsAsync()
        {
            return ApplyBypassOptionsAsync(CancellationToken.None);
        }

        /// <summary>
        /// Применить текущие настройки bypass (с поддержкой отмены)
        /// </summary>
        public async Task ApplyBypassOptionsAsync(CancellationToken cancellationToken)
        {
            try
            {
                using var op = BypassOperationContext.EnterIfNone("manual_apply");
                var normalized = _currentOptions.Normalize();
                _currentOptions = normalized;
                await _stateManager.ApplyTlsOptionsAsync(normalized, cancellationToken).ConfigureAwait(false);

                SafeUiInvoke(NotifyActiveStatesChanged);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log($"[Bypass] Error applying options: {ex.Message}");
            }
        }

        private static void SafeUiInvoke(Action action)
        {
            try
            {
                var dispatcher = Application.Current?.Dispatcher;
                if (dispatcher == null || dispatcher.HasShutdownStarted || dispatcher.HasShutdownFinished)
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

        /// <summary>
        /// Отключить все опции bypass
        /// </summary>
        public Task DisableAllAsync()
        {
            return DisableAllAsync(CancellationToken.None);
        }

        /// <summary>
        /// Отключить все опции bypass (с поддержкой отмены)
        /// </summary>
        public async Task DisableAllAsync(CancellationToken cancellationToken)
        {
            _currentOptions = _currentOptions with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false,
                DropUdp443 = false,
                DropUdp443Global = false,
                AllowNoSni = false,

                // Важно: DisableAll должен быть «жёстким» выключением.
                // Здесь отключаем и «скрытые»/не-UI флаги, чтобы последующий Apply не мог
                // включить обход из текущего _currentOptions при выключенных тумблерах.
                TtlTrickEnabled = false,
                AutoTtlEnabled = false,
                HttpHostTricksEnabled = false,
                BadChecksumEnabled = false,
                AutoAdjustAggressive = false
            };

            OnPropertyChanged(nameof(IsFragmentEnabled));
            OnPropertyChanged(nameof(IsDisorderEnabled));
            OnPropertyChanged(nameof(IsFakeEnabled));
            OnPropertyChanged(nameof(IsDropRstEnabled));
            OnPropertyChanged(nameof(IsQuicFallbackEnabled));
            OnPropertyChanged(nameof(IsQuicFallbackGlobal));
            OnPropertyChanged(nameof(IsAllowNoSniEnabled));
            OnPropertyChanged(nameof(IsAutoAdjustAggressive));
            NotifyActiveStatesChanged();
            CheckCompatibility();

            using var op = BypassOperationContext.EnterIfNone("manual_disable_all");
            // Важно: DisableAll должен быть «жёстким» выключением.
            // ApplyBypassOptionsAsync может снова включить capabilities из remembered active targets (policy-driven union).
            await _stateManager.DisableTlsAsync("manual_disable_all", cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Быстрый «Откатить всё»: выключить bypass и восстановить DNS/DoH,
        /// если приложение ранее создавало backup и меняло системные настройки.
        /// </summary>
        public async Task RollbackAllAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await DisableAllAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // best-effort: даже если TLS disable упал, всё равно пробуем вернуть DNS.
                Log($"[Rollback] DisableAll failed: {ex.Message}");
            }

            try
            {
                // DNS/DoH: если есть backup, значит приложение ранее трогало системные настройки.
                // В этом случае «Откатить» должен попытаться восстановить их независимо от текущей галочки UI.
                if (!FixService.HasBackupFile)
                {
                    // Если backup нет — просто синхронизируем UI-галочку best-effort.
                    if (_isDoHEnabled)
                    {
                        await DisableDoHAsync().ConfigureAwait(false);
                    }

                    return;
                }

                if (!TrafficEngine.HasAdministratorRights)
                {
                    Log("[DoH] Rollback requested, but no admin rights to restore DNS.");
                    return;
                }

                Log("[DoH] Rollback: restoring original DNS settings...");
                var (success, error) = await FixService.RestoreDnsAsync(reason: "rollback_all", cancellationToken: cancellationToken).ConfigureAwait(false);

                if (success)
                {
                    Log("[DoH] Rollback: DNS restored.");

                    _isDoHEnabled = false;
                    SafeUiInvoke(() =>
                    {
                        OnPropertyChanged(nameof(IsDoHEnabled));
                        OnPropertyChanged(nameof(IsDoHActive));
                    });
                }
                else
                {
                    Log($"[DoH] Rollback: restore failed: {error}");
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log($"[DoH] Rollback exception: {ex.Message}");
            }
        }

        /// <summary>
        /// Откатить только то, что включил Autopilot (P1.11):
        /// восстанавливаем последний зафиксированный snapshot от пользователя,
        /// чтобы не ломать ручные настройки из Engineer.
        ///
        /// Важно: здесь НЕ делаем принудительный RestoreDnsAsync по backup-файлу,
        /// потому что Autopilot по умолчанию не имеет права трогать DNS/DoH.
        /// </summary>
        public async Task RollbackAutopilotOnlyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var all = _applyTransactionsJournal.Snapshot();
                if (all == null || all.Count == 0)
                {
                    Log("[Rollback][Autopilot] Нет apply-транзакций: откатывать нечего.");
                    return;
                }

                var latestAuto = all
                    .Where(t => IsAppliedBy(t, "autopilot"))
                    .OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc))
                    .FirstOrDefault();

                if (latestAuto == null)
                {
                    Log("[Rollback][Autopilot] Нет автопилотных apply-транзакций: откатывать нечего.");
                    return;
                }

                var autoAt = ParseCreatedAtUtcOrMin(latestAuto.CreatedAtUtc);

                // Если после последнего автопилота уже был ручной apply, значит пользователь "взял владение".
                // В этом случае откат автопилота ничего не должен менять.
                var manualAfterAuto = all
                    .Where(t => IsAppliedBy(t, "user"))
                    .Where(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc) > autoAt)
                    .OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc))
                    .FirstOrDefault();

                if (manualAfterAuto != null)
                {
                    Log("[Rollback][Autopilot] После автопилота есть ручной apply: откат не требуется.");
                    return;
                }

                var baseline = all
                    .Where(t => IsAppliedBy(t, "user"))
                    .Where(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc) < autoAt)
                    .OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc))
                    .FirstOrDefault();

                if (baseline?.Snapshot != null)
                {
                    // Делаем "жёсткое" выключение, чтобы очистить remembered union,
                    // затем восстанавливаем пользовательский снимок.
                    try
                    {
                        await DisableAllAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        Log($"[Rollback][Autopilot] Prepare DisableAll failed: {ex.Message}");
                    }

                    Log($"[Rollback][Autopilot] Restoring user snapshot (tx={baseline.TransactionId}).");
                    var snap = new BypassStateSnapshot(
                        Options: baseline.Snapshot.OptionsSnapshot,
                        DoHEnabled: baseline.Snapshot.DoHEnabled,
                        SelectedDnsPreset: baseline.Snapshot.SelectedDnsPreset);

                    await RestoreSnapshotAsync(snap).ConfigureAwait(false);
                    Log("[Rollback][Autopilot] Done: user snapshot restored.");
                    return;
                }

                // Нет baseline от пользователя: безопасный откат = просто выключить bypass.
                Log("[Rollback][Autopilot] Нет user-snapshot: выключаю bypass (без DNS отката)." );
                await DisableAllAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log($"[Rollback][Autopilot] Ошибка отката: {ex.Message}");
            }
        }

        public string GetOutcomeTargetHost() => _stateManager.GetOutcomeTargetHost();

        public string OutcomeTargetHost => _stateManager.GetOutcomeTargetHost();

        public void SetOutcomeTargetHost(string? host)
        {
            _stateManager.SetOutcomeTargetHost(host);
            SafeUiInvoke(() => OnPropertyChanged(nameof(OutcomeTargetHost)));
        }
    }
}
