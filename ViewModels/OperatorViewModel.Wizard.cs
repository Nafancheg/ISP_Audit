using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Models;
using IspAudit.Utils;
using IspAudit.Wpf;
using MaterialDesignThemes.Wpf;

namespace IspAudit.ViewModels
{
    public sealed partial class OperatorViewModel
    {
        public string CheckedProblemsLine
        {
            get
            {
                var checkedCount = Math.Max(0, Main.PassCount) + Math.Max(0, Main.WarnCount) + Math.Max(0, Main.FailCount);
                var problemCount = Math.Max(0, Main.WarnCount) + Math.Max(0, Main.FailCount);
                return $"Проверено {checkedCount} / проблемных {problemCount}";
            }
        }

        public string Headline => GetPresentation(Status).Headline;

        public string SummaryLine
        {
            get
            {
                if (Status == OperatorStatus.Checking)
                {
                    return Main.RunningStatusText;
                }

                if (Status == OperatorStatus.Fixing)
                {
                    var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                    if (Main.IsPostApplyRetestRunning && !string.IsNullOrWhiteSpace(post)) return post;

                    var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(apply)
                        ? "Применяю безопасные действия и перепроверяю…"
                        : apply;
                }

                if (Main.IsDone)
                {
                    return $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";
                }

                // Idle
                if (Main.IsBasicTestMode)
                {
                    return "Тестовый режим: быстрая проверка интернета (включено в настройках). Нажмите «Проверить».";
                }

                var exePath = (Main.ExePath ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(exePath))
                {
                    try
                    {
                        return $"Источник: {Path.GetFileName(exePath)}. Нажмите «Проверить».";
                    }
                    catch
                    {
                        return "Источник: выбранное приложение (.exe). Нажмите «Проверить».";
                    }
                }

                return "Выберите приложение (.exe) и нажмите «Проверить».";
            }
        }

        public string UserDetails_Anchor
        {
            get
            {
                try
                {
                    var host = (Main.Bypass.OutcomeTargetHost ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(host) ? "—" : host;
                }
                catch
                {
                    return "—";
                }
            }
        }

        public string UserDetails_Source
        {
            get
            {
                var t = BuildTrafficSourceText();
                return string.IsNullOrWhiteSpace(t) ? "—" : t;
            }
        }

        public string UserDetails_Status => GetPresentation(Status).UserDetailsStatus;

        public string UserDetails_Result
        {
            get
            {
                if (!Main.IsDone)
                {
                    // В процессе/idle показывать счётчики бессмысленно.
                    return "—";
                }

                return $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";
            }
        }

        public string UserDetails_AutoFix => Main.EnableAutoBypass ? "Включено" : "Выключено";

        public string UserDetails_Bypass => Main.IsBypassActive ? "Активен" : "Не активен";

        public string UserDetails_LastAction
        {
            get
            {
                var fix = (Main.ActiveApplySummaryText ?? string.Empty).Trim();
                var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();

                // Выводим самое «человеческое» из доступного.
                if (!string.IsNullOrWhiteSpace(fix)) return fix;

                if (!string.IsNullOrWhiteSpace(apply) && !string.IsNullOrWhiteSpace(post))
                {
                    return $"{apply}; {post}";
                }

                if (!string.IsNullOrWhiteSpace(apply)) return apply;
                if (!string.IsNullOrWhiteSpace(post)) return post;

                return Main.HasAnyRecommendations ? "Доступны рекомендации по исправлению" : "—";
            }
        }

        public bool HasUserDetails_SubHosts
        {
            get
            {
                try
                {
                    return BuildUserDetailsSubHostLines(maxItems: 12).Count > 0;
                }
                catch
                {
                    return false;
                }
            }
        }

        public string UserDetails_SubHosts
        {
            get
            {
                try
                {
                    var lines = BuildUserDetailsSubHostLines(maxItems: 12);
                    return lines.Count == 0 ? "—" : string.Join(Environment.NewLine, lines);
                }
                catch
                {
                    return "—";
                }
            }
        }

        private List<string> BuildUserDetailsSubHostLines(int maxItems)
        {
            maxItems = Math.Clamp(maxItems, 1, 50);

            var groupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(groupKey)) return new List<string>();

            var members = Main.Results.GetGroupMembers(groupKey);
            if (members == null || members.Count == 0) return new List<string>();

            var lines = new List<string>(capacity: Math.Min(maxItems, members.Count));

            foreach (var m in members)
            {
                if (m == null) continue;

                var host = (m.DisplayHost ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(host)) continue;

                var status = (m.PrimaryStatusText ?? m.StatusText ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(status)) status = "—";

                var ip = (m.DisplayIp ?? string.Empty).Trim();
                var ipSuffix = IPAddress.TryParse(ip, out _) ? $" ({ip})" : string.Empty;

                lines.Add($"• {host} — {status}{ipSuffix}");

                if (lines.Count >= maxItems) break;
            }

            return lines;
        }

        public string RawDetailsText
        {
            get
            {
                try
                {
                    var parts = new List<string>(capacity: 6);

                    var diag = (Main.DiagnosticStatus ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(diag)) parts.Add(diag);

                    var abs = (Main.AutoBypassStatus ?? string.Empty).Trim();
                    var abv = (Main.AutoBypassVerdict ?? string.Empty).Trim();
                    var abm = (Main.AutoBypassMetrics ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(abs)) parts.Add(abs);
                    if (!string.IsNullOrWhiteSpace(abv)) parts.Add(abv);
                    if (!string.IsNullOrWhiteSpace(abm)) parts.Add(abm);

                    return parts.Count == 0 ? "—" : string.Join(Environment.NewLine, parts);
                }
                catch
                {
                    return "—";
                }
            }
        }

        public OperatorStatus Status
        {
            get
            {
                if (Main.IsApplyRunning || Main.IsPostApplyRetestRunning) return OperatorStatus.Fixing;
                if (Main.IsRunning) return OperatorStatus.Checking;

                // P1.11: операторский статус должен отражать "первичную семантику" (P1.8),
                // т.е. учитывать пост‑проверку после Apply как главный итог.
                try
                {
                    var results = Main.TestResults;
                    if (results == null || results.Count == 0) return OperatorStatus.Idle;

                    var hasAnyNonIdle = false;
                    var hasFail = false;
                    var hasWarn = false;
                    var hasPass = false;

                    foreach (var tr in results)
                    {
                        if (tr == null) continue;

                        // Если по какой-то карточке идёт post-apply ретест (queued/running),
                        // показываем "Исправляем…" даже если глобальный флаг IsPostApplyRetestRunning не поднят.
                        if (tr.PostApplyCheckStatus == PostApplyCheckStatus.Queued
                            || tr.PostApplyCheckStatus == PostApplyCheckStatus.Running)
                        {
                            return OperatorStatus.Fixing;
                        }

                        var s = tr.PrimaryStatus;
                        if (s == TestStatus.Running) return OperatorStatus.Checking;
                        if (s == TestStatus.Idle) continue;

                        hasAnyNonIdle = true;
                        if (s == TestStatus.Fail)
                        {
                            hasFail = true;
                            break;
                        }
                        if (s == TestStatus.Warn) hasWarn = true;
                        if (s == TestStatus.Pass) hasPass = true;
                    }

                    if (!hasAnyNonIdle) return OperatorStatus.Idle;
                    if (hasFail) return OperatorStatus.Blocked;
                    if (hasWarn) return OperatorStatus.Warn;
                    if (hasPass) return OperatorStatus.Ok;

                    return OperatorStatus.Idle;
                }
                catch
                {
                    // Best-effort fallback на старую семантику (счётчики от пайплайна), если коллекция меняется во время перечисления.
                    if (Main.IsDone)
                    {
                        if (Main.FailCount > 0) return OperatorStatus.Blocked;
                        if (Main.WarnCount > 0) return OperatorStatus.Warn;
                        return OperatorStatus.Ok;
                    }

                    return OperatorStatus.Idle;
                }
            }
        }

        public PackIconKind HeroIconKind => GetPresentation(Status).HeroIconKind;

        public System.Windows.Media.Brush HeroAccentBrush => GetPresentation(Status).HeroAccentBrush;

        private IEnumerable<string> BuildProblemsSnapshotLines(int maxItems)
        {
            try
            {
                var list = Main.TestResults
                    .Where(r => r != null)
                    .Where(r => r.Status == TestStatus.Fail || r.Status == TestStatus.Warn)
                    .OrderBy(r => r.Status == TestStatus.Fail ? 0 : 1)
                    .ThenBy(r => (r.DisplayHost ?? string.Empty), StringComparer.OrdinalIgnoreCase)
                    .Take(Math.Max(1, maxItems))
                    .Select(BuildProblemLine)
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .ToList();

                return list;
            }
            catch
            {
                return Array.Empty<string>();
            }
        }

        private static string BuildProblemLine(TestResult r)
        {
            try
            {
                var host = (r.DisplayHost ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(host)) host = (r.DisplayIp ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(host)) host = "(неизвестная цель)";

                var status = r.Status == TestStatus.Fail ? "FAIL" : "WARN";
                var tags = new List<string>(capacity: 4);
                if (r.IsRstInjection) tags.Add("RST");
                if (r.IsHttpRedirect) tags.Add("Redirect");
                if (r.IsRetransmissionHeavy) tags.Add("Retransmit");
                if (r.IsUdpBlockage) tags.Add("UDP/QUIC");

                var tagText = tags.Count > 0 ? $" ({string.Join(", ", tags)})" : string.Empty;
                var err = (r.Error ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(err))
                {
                    err = OperatorTextMapper.LocalizeCodesInText(err);
                }

                if (!string.IsNullOrWhiteSpace(err))
                {
                    return $"{host} — {status}{tagText}: {err}";
                }

                return $"{host} — {status}{tagText}";
            }
            catch
            {
                return string.Empty;
            }
        }

        private string BuildTrafficSourceText()
        {
            try
            {
                if (Main.IsBasicTestMode)
                {
                    return "Источник: быстрая проверка интернета (тестовый режим)";
                }

                var exePath = (Main.ExePath ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(exePath))
                {
                    return "Источник: приложение (.exe) не выбрано";
                }

                try
                {
                    return $"Источник: {Path.GetFileName(exePath)}";
                }
                catch
                {
                    return "Источник: выбранное приложение (.exe)";
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private string _lastScreenState = string.Empty;
        private bool _lastIsApplyRunning;

        private bool _fixStepLatched;
        private string _lastPostApplyVerdict = string.Empty;
        private string _lastPostApplyDetails = string.Empty;
        private DateTimeOffset _lastPostApplyVerdictAtUtc = DateTimeOffset.MinValue;

        public ICommand PrimaryCommand => new RelayCommand(_ => ExecutePrimary());

        public string FixButtonText
            => Main.IsApplyRunning
                ? "Исправляю…"
                : IsEscalationAvailableNow
                    ? "Усилить"
                    : "Исправить";

        public ICommand FixCommand => new RelayCommand(_ => ExecuteFix());

        private void InitializeWizardTrackingStateBestEffort()
        {
            _lastScreenState = (Main.ScreenState ?? string.Empty).Trim();
            _lastIsApplyRunning = Main.IsApplyRunning;
        }

        public bool IsSourceStepVisible =>
            Status == OperatorStatus.Idle
            || Status == OperatorStatus.Ok
            || Status == OperatorStatus.Warn
            || Status == OperatorStatus.Blocked;

        public bool IsProgressStepVisible => Status == OperatorStatus.Checking;

        public bool IsSummaryStepVisible =>
            Status == OperatorStatus.Ok
            || Status == OperatorStatus.Warn
            || Status == OperatorStatus.Blocked;

        public bool IsFixingStepVisible => Status == OperatorStatus.Fixing;

        public bool IsSourceSelectionEnabled => IsSourceStepVisible && !Main.IsRunning && !Main.IsApplyRunning && !Main.IsPostApplyRetestRunning;

        public bool IsPrimaryActionEnabled => Status != OperatorStatus.Fixing;

        public bool IsFixStepCardVisible
            => Status == OperatorStatus.Fixing
            || _fixStepLatched
            || !string.IsNullOrWhiteSpace(Main.PostApplyRetestStatus)
            || !string.IsNullOrWhiteSpace(_lastPostApplyVerdict);

        public string FixStepTitle
        {
            get
            {
                if (Main.IsApplyRunning) return "Исправление…";
                if (Main.IsPostApplyRetestRunning) return "Перепроверка…";
                return "Итог после исправления";
            }
        }

        public string FixStepStatusText
        {
            get
            {
                if (Main.IsApplyRunning)
                {
                    var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(apply) ? "Применяю рекомендации…" : apply;
                }

                if (Main.IsPostApplyRetestRunning)
                {
                    var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(post) ? "Ретест после исправления: выполняется…" : post;
                }

                var done = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(done)) return done;

                if (_fixStepLatched)
                {
                    return "Ретест после исправления: завершён";
                }

                return "—";
            }
        }

        public bool HasFixStepOutcome => !string.IsNullOrWhiteSpace(_lastPostApplyVerdict);

        private bool IsEscalationAvailableNow
        {
            get
            {
                // «Усилить» показываем только после неуспешного пост-apply ретеста.
                var v = (_lastPostApplyVerdict ?? string.Empty).Trim().ToUpperInvariant();
                if (v != "FAIL" && v != "PARTIAL") return false;

                // В non-admin режиме применить байпас нельзя.
                if (!Main.ShowBypassPanel) return false;

                // Если идёт apply/ретест — не эскалируем.
                if (Main.IsApplyRunning || Main.IsPostApplyRetestRunning) return false;

                // Детерминированная лестница должна совпадать с Orchestrator.TryBuildEscalationPlan:
                // 1) Fragment -> Disorder
                // 2) DropRst
                // 3) QUIC fallback
                // 4) AllowNoSNI
                if (Main.IsFragmentEnabled && !Main.IsDisorderEnabled) return true;
                if (!Main.IsDropRstEnabled) return true;
                if (!Main.IsQuicFallbackEnabled) return true;
                if (!Main.IsAllowNoSniEnabled) return true;

                return false;
            }
        }

        public string FixStepOutcomeText
        {
            get
            {
                var v = (_lastPostApplyVerdict ?? string.Empty).Trim().ToUpperInvariant();
                if (string.IsNullOrWhiteSpace(v)) return string.Empty;

                var headline = v switch
                {
                    "OK" => "Итог: стало лучше",
                    "PARTIAL" => "Итог: частично",
                    "FAIL" => "Итог: не помогло",
                    "UNKNOWN" => "Итог: не удалось проверить",
                    _ => $"Итог: {v}"
                };

                var d = (_lastPostApplyDetails ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(d))
                {
                    d = OperatorTextMapper.LocalizeCodesInText(d);
                }
                if (string.IsNullOrWhiteSpace(d)) return headline;
                return $"{headline} ({d})";
            }
        }

        public bool ShowFixButton =>
            (Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
            && (Main.HasAnyRecommendations || IsEscalationAvailableNow)
            && !Main.IsApplyRunning;

        public bool ShowPrimaryButton => !ShowFixButton;

        public string PrimaryButtonText
        {
            get
            {
                var p = GetPresentation(Status);

                // Единственное исключение из таблицы: если "Исправить" недоступно, предлагаем повторную проверку.
                if ((Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
                    && !Main.HasAnyRecommendations)
                {
                    return "Проверить снова";
                }

                return p.DefaultPrimaryButtonText;
            }
        }

        private void ExecutePrimary()
        {
            if ((Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
                && (Main.HasAnyRecommendations || IsEscalationAvailableNow))
            {
                ExecuteFix();
                return;
            }

            ExecuteStartOrStop();
        }

        private void ExecuteStartOrStop()
        {
            try
            {
                Main.StartLiveTestingCommand.Execute(null);
            }
            catch (Exception ex)
            {
                // Best-effort: фиксируем как «сессию-ошибку», чтобы оператор видел попытку.
                FinalizeSessionAsErrorBestEffort("Ошибка запуска проверки", ex.Message);
                throw;
            }
        }

        private void ExecuteFix()
        {
            try
            {
                _pendingFixTriggeredByUser = true;

                if (IsEscalationAvailableNow)
                {
                    Main.ApplyEscalationCommand.Execute(null);
                }
                else
                {
                    Main.ApplyRecommendationsCommand.Execute(null);
                }
            }
            catch (Exception ex)
            {
                FinalizeSessionAsErrorBestEffort("Ошибка запуска исправления", ex.Message);
                throw;
            }
        }

        private void TrackScreenStateTransition()
        {
            var now = (Main.ScreenState ?? string.Empty).Trim();
            var prev = _lastScreenState;
            if (string.Equals(now, prev, StringComparison.Ordinal)) return;

            _lastScreenState = now;

            if (string.Equals(now, "running", StringComparison.OrdinalIgnoreCase))
            {
                ClearFixWizardStateBestEffort();
                StartNewDraftForCheckBestEffort();
                return;
            }

            if (string.Equals(now, "done", StringComparison.OrdinalIgnoreCase))
            {
                CompleteCheckInDraftBestEffort();
                TryFinalizeActiveSessionBestEffort(preferPostApply: true);
            }
        }

        private void TrackApplyTransition()
        {
            var now = Main.IsApplyRunning;
            var prev = _lastIsApplyRunning;
            if (now == prev) return;

            _lastIsApplyRunning = now;

            if (now)
            {
                _fixStepLatched = true;
                EnsureDraftExistsBestEffort(reason: "apply_start");
                if (_activeSession != null)
                {
                    _activeSession.HadApply = true;
                    var mode = _pendingFixTriggeredByUser ? "ручное" : "авто";
                    _pendingFixTriggeredByUser = false;

                    var detail = (Main.ApplyStatusText ?? string.Empty).Trim();
                    _activeSession.Actions.Add(string.IsNullOrWhiteSpace(detail)
                        ? $"Исправление: запуск ({mode})"
                        : $"Исправление: запуск ({mode}) — {detail}");
                }
                return;
            }

            // Apply закончился.
            _fixStepLatched = true;
            EnsureDraftExistsBestEffort(reason: "apply_end");
            if (_activeSession != null)
            {
                var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                _activeSession.PostApplyStatusText = post;

                if (!string.IsNullOrWhiteSpace(apply) && !string.IsNullOrWhiteSpace(post))
                {
                    _activeSession.Actions.Add($"Исправление: завершено — {apply}; {post}");
                }
                else if (!string.IsNullOrWhiteSpace(apply))
                {
                    _activeSession.Actions.Add($"Исправление: завершено — {apply}");
                }
                else if (!string.IsNullOrWhiteSpace(post))
                {
                    _activeSession.Actions.Add($"Исправление: завершено — {post}");
                }
                else
                {
                    _activeSession.Actions.Add("Исправление: завершено");
                }
            }

            TryFinalizeActiveSessionBestEffort(preferPostApply: true);
        }

        private void OrchestratorOnPostApplyCheckVerdict(string hostKey, string verdict, string mode, string? details)
        {
            try
            {
                EnsureDraftExistsBestEffort(reason: "post_apply_verdict");
                if (_activeSession == null) return;

                _fixStepLatched = true;
                _lastPostApplyVerdict = (verdict ?? string.Empty).Trim();
                _lastPostApplyDetails = (details ?? string.Empty).Trim();
                _lastPostApplyVerdictAtUtc = DateTimeOffset.UtcNow;

                _activeSession.HadApply = true;
                _activeSession.PostApplyVerdict = (verdict ?? string.Empty).Trim();

                var d = (details ?? string.Empty).Trim();
                var hk = (hostKey ?? string.Empty).Trim();
                var m = (mode ?? string.Empty).Trim();

                var line = string.IsNullOrWhiteSpace(d)
                    ? $"Ретест после исправления: {verdict} ({m})"
                    : $"Ретест после исправления: {verdict} ({m}) — {hk}; {d}";

                _activeSession.Actions.Add(line);

                TryFinalizeActiveSessionBestEffort(preferPostApply: true);

                // Событие приходит не через Main.PropertyChanged — обновим UI явно.
                RaiseDerivedProperties();
            }
            catch
            {
                // ignore
            }
        }

        private void TrackPostApplyRetestBestEffort()
        {
            try
            {
                if (Main.IsPostApplyRetestRunning)
                {
                    _fixStepLatched = true;
                    return;
                }

                var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(post))
                {
                    _fixStepLatched = true;
                }
            }
            catch
            {
                // ignore
            }
        }

        private void ClearFixWizardStateBestEffort()
        {
            try
            {
                _fixStepLatched = false;
                _lastPostApplyVerdict = string.Empty;
                _lastPostApplyDetails = string.Empty;
                _lastPostApplyVerdictAtUtc = DateTimeOffset.MinValue;
            }
            catch
            {
                // ignore
            }
        }

        private void AutoCollapseSourceSectionBestEffort()
        {
            try
            {
                if (_didAutoCollapseSourceSection) return;

                // Как только начинается проверка/исправление или появился итог — сворачиваем.
                if (Status != OperatorStatus.Idle)
                {
                    _didAutoCollapseSourceSection = true;
                    IsSourceSectionExpanded = false;
                }
            }
            catch
            {
                // ignore
            }
        }
    }
}
