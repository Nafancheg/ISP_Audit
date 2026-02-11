using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public sealed partial class OperatorViewModel
    {
        private const int MaxSessionsEntries = 128;

        public ObservableCollection<OperatorSessionEntry> Sessions { get; } = new();

        public bool HasSessions => Sessions.Count > 0;

        private sealed class SessionDraft
        {
            public string Id { get; } = Guid.NewGuid().ToString("N");
            public DateTimeOffset StartedAtUtc { get; set; } = DateTimeOffset.UtcNow;
            public string TrafficSource { get; set; } = string.Empty;
            public bool AutoFixEnabledAtStart { get; set; }

            public bool CheckCompleted { get; set; }
            public int PassCount { get; set; }
            public int WarnCount { get; set; }
            public int FailCount { get; set; }
            public string CountsText { get; set; } = string.Empty;
            public List<string> Problems { get; } = new();

            public bool HadApply { get; set; }
            public string PostApplyVerdict { get; set; } = string.Empty;
            public string PostApplyStatusText { get; set; } = string.Empty;
            public List<string> Actions { get; } = new();

            public bool Ended { get; set; }
        }

        private SessionDraft? _activeSession;
        private bool _pendingFixTriggeredByUser;

        private void InitializeSessionsBestEffort()
        {
            try
            {
                var loadedSessions = OperatorSessionStore.LoadBestEffort(log: null);
                foreach (var s in loadedSessions)
                {
                    Sessions.Add(s);
                }

                SortSessionsBestEffort();
            }
            catch
            {
                // ignore
            }
        }

        private void SortSessionsBestEffort()
        {
            try
            {
                if (Sessions.Count <= 1) return;

                var sorted = Sessions
                    .OrderBy(e => GetOutcomeRank(e?.Outcome))
                    .ThenByDescending(e => GetSessionTimeUtc(e))
                    .ToList();

                for (var targetIndex = 0; targetIndex < sorted.Count; targetIndex++)
                {
                    var desired = sorted[targetIndex];
                    var currentIndex = Sessions.IndexOf(desired);
                    if (currentIndex >= 0 && currentIndex != targetIndex)
                    {
                        Sessions.Move(currentIndex, targetIndex);
                    }
                }
            }
            catch
            {
                // ignore
            }
        }

        private static int GetOutcomeRank(string? outcome)
        {
            var v = (outcome ?? string.Empty).Trim().ToUpperInvariant();
            return v switch
            {
                "FAIL" => 0,
                "WARN" => 1,
                "PARTIAL" => 1,
                "UNKNOWN" => 2,
                "OK" => 3,
                "CANCELLED" => 4,
                _ => 2
            };
        }

        private static DateTimeOffset GetSessionTimeUtc(OperatorSessionEntry? entry)
        {
            if (entry == null) return DateTimeOffset.MinValue;

            if (TryParseUtc(entry.EndedAtUtc, out var endedUtc))
            {
                return endedUtc;
            }

            if (TryParseUtc(entry.StartedAtUtc, out var startedUtc))
            {
                return startedUtc;
            }

            return DateTimeOffset.MinValue;
        }

        private void ClearSessionsBestEffort()
        {
            try
            {
                Sessions.Clear();
                OperatorSessionStore.TryDeletePersistedFileBestEffort(log: null);
                OnPropertyChanged(nameof(HasSessions));
            }
            catch
            {
                // ignore
            }
        }

        private void EnsureDraftExistsBestEffort(string reason)
        {
            try
            {
                if (_activeSession != null && !_activeSession.Ended) return;

                _activeSession = new SessionDraft
                {
                    StartedAtUtc = DateTimeOffset.UtcNow,
                    TrafficSource = BuildSessionTrafficDescriptorTextBestEffort(),
                    AutoFixEnabledAtStart = Main.EnableAutoBypass
                };

                if (!string.IsNullOrWhiteSpace(reason))
                {
                    _activeSession.Actions.Add($"Сессия: создана ({reason})");
                }
            }
            catch
            {
                // ignore
            }
        }

        private string BuildSessionTrafficDescriptorTextBestEffort()
        {
            try
            {
                var source = BuildTrafficSourceText();
                return source;
            }
            catch
            {
                return BuildTrafficSourceText();
            }
        }

        private void StartNewDraftForCheckBestEffort()
        {
            try
            {
                // Если предыдущая сессия не была закрыта (например ожидали ретест, но пользователь начал новую проверку)
                // — закрываем best-effort как UNKNOWN.
                if (_activeSession != null && !_activeSession.Ended)
                {
                    _activeSession.Actions.Add("Новая проверка запущена: предыдущая сессия закрыта без итогового ретеста");
                    FinalizeDraftBestEffort(_activeSession, outcomeOverride: "UNKNOWN");
                }

                _activeSession = new SessionDraft
                {
                    StartedAtUtc = DateTimeOffset.UtcNow,
                    TrafficSource = BuildSessionTrafficDescriptorTextBestEffort(),
                    AutoFixEnabledAtStart = Main.EnableAutoBypass
                };
                _activeSession.Actions.Add("Проверка: началась");
            }
            catch
            {
                // ignore
            }
        }

        private void CompleteCheckInDraftBestEffort()
        {
            try
            {
                EnsureDraftExistsBestEffort(reason: "check_done");
                if (_activeSession == null) return;

                _activeSession.CheckCompleted = true;
                _activeSession.PassCount = Main.PassCount;
                _activeSession.WarnCount = Main.WarnCount;
                _activeSession.FailCount = Main.FailCount;
                _activeSession.CountsText = $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";

                _activeSession.Problems.Clear();
                foreach (var line in BuildProblemsSnapshotLines(maxItems: 10))
                {
                    _activeSession.Problems.Add(line);
                }

                var cancelled = Main.Orchestrator.LastRunWasUserCancelled;
                var outcome = cancelled
                    ? "CANCELLED"
                    : (_activeSession.FailCount > 0 ? "FAIL" : (_activeSession.WarnCount > 0 ? "WARN" : "OK"));

                var title = outcome == "OK" ? "Проверка: завершена (норма)"
                    : outcome == "WARN" ? "Проверка: завершена (есть ограничения)"
                    : outcome == "FAIL" ? "Проверка: завершена (есть блокировки)"
                    : "Проверка: завершена";

                _activeSession.Actions.Add($"{title} — {_activeSession.CountsText}");
            }
            catch
            {
                // ignore
            }
        }

        private void TryFinalizeActiveSessionBestEffort(bool preferPostApply)
        {
            try
            {
                if (_activeSession == null || _activeSession.Ended) return;

                // Если был Apply — стараемся закрывать по verdict (семантика P1.8).
                if (preferPostApply && _activeSession.HadApply)
                {
                    if (!string.IsNullOrWhiteSpace(_activeSession.PostApplyVerdict))
                    {
                        FinalizeDraftBestEffort(_activeSession, outcomeOverride: MapVerdictToOutcome(_activeSession.PostApplyVerdict));
                        _activeSession = null;
                        return;
                    }

                    // Fallback: если ретест уже не бежит и статус заполнен — тоже закрываем.
                    if (!Main.IsPostApplyRetestRunning && !string.IsNullOrWhiteSpace(Main.PostApplyRetestStatus))
                    {
                        _activeSession.PostApplyStatusText = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                        FinalizeDraftBestEffort(_activeSession, outcomeOverride: string.Empty);
                        _activeSession = null;
                        return;
                    }

                    // Ждём.
                    return;
                }

                // Без Apply: закрываем по завершению проверки.
                if (_activeSession.CheckCompleted)
                {
                    FinalizeDraftBestEffort(_activeSession, outcomeOverride: string.Empty);
                    _activeSession = null;
                }
            }
            catch
            {
                // ignore
            }
        }

        private void FinalizeSessionAsErrorBestEffort(string title, string details)
        {
            try
            {
                EnsureDraftExistsBestEffort(reason: "error");
                if (_activeSession == null) return;

                _activeSession.Actions.Add($"Ошибка: {title} — {details}");
                FinalizeDraftBestEffort(_activeSession, outcomeOverride: "FAIL");
                _activeSession = null;
            }
            catch
            {
                // ignore
            }
        }

        private static string MapVerdictToOutcome(string verdict)
        {
            var v = (verdict ?? string.Empty).Trim().ToUpperInvariant();
            return v switch
            {
                "OK" => "OK",
                "FAIL" => "FAIL",
                "PARTIAL" => "WARN",
                "UNKNOWN" => "UNKNOWN",
                _ => string.IsNullOrWhiteSpace(v) ? string.Empty : v
            };
        }

        private void FinalizeDraftBestEffort(SessionDraft draft, string outcomeOverride)
        {
            try
            {
                if (draft.Ended) return;
                draft.Ended = true;

                var endUtc = DateTimeOffset.UtcNow;

                var cancelled = Main.Orchestrator.LastRunWasUserCancelled;
                var baseOutcome = cancelled
                    ? "CANCELLED"
                    : (draft.FailCount > 0 ? "FAIL" : (draft.WarnCount > 0 ? "WARN" : "OK"));

                var outcome = string.IsNullOrWhiteSpace(outcomeOverride) ? baseOutcome : outcomeOverride.Trim();

                var problemsText = string.Join("\n", draft.Problems.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => "• " + s));
                var actionsText = string.Join("\n", draft.Actions.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => "• " + s));

                var entry = new OperatorSessionEntry
                {
                    Id = draft.Id,
                    StartedAtUtc = draft.StartedAtUtc.ToString("u").TrimEnd(),
                    EndedAtUtc = endUtc.ToString("u").TrimEnd(),
                    TrafficSource = draft.TrafficSource,
                    AutoFixEnabledAtStart = draft.AutoFixEnabledAtStart,
                    Outcome = outcome,
                    CountsText = draft.CountsText,
                    ProblemsText = problemsText,
                    ActionsText = actionsText,
                    PostApplyVerdict = draft.PostApplyVerdict,
                    PostApplyStatusText = string.IsNullOrWhiteSpace(draft.PostApplyStatusText) ? (Main.PostApplyRetestStatus ?? string.Empty).Trim() : draft.PostApplyStatusText
                };

                // Новые сверху.
                Sessions.Insert(0, entry);
                SortSessionsBestEffort();
                while (Sessions.Count > MaxSessionsEntries)
                {
                    Sessions.RemoveAt(Sessions.Count - 1);
                }
                OnPropertyChanged(nameof(HasSessions));

                var snapshot = Sessions.ToList();
                _ = Task.Run(() =>
                {
                    try
                    {
                        OperatorSessionStore.PersistBestEffort(snapshot, log: null);
                    }
                    catch
                    {
                        // ignore
                    }
                });
            }
            catch
            {
                // ignore
            }
        }
    }
}
