using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Media;
using IspAudit.Models;
using IspAudit.Utils;
using IspAudit.Wpf;
using MaterialDesignThemes.Wpf;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Лёгкая ViewModel для «Операторского» UI.
    /// Оборачивает MainViewModel и предоставляет упрощённые computed-свойства.
    /// </summary>
    public sealed class OperatorViewModel : INotifyPropertyChanged
    {
        public enum OperatorStatus
        {
            Idle,
            Checking,
            Ok,
            Warn,
            Blocked,
            Fixing
        }

        public MainViewModel Main { get; }

        private const int MaxHistoryEntries = 256;
        private const string AllHistoryGroupsKey = "__all__";
        private readonly ObservableCollection<OperatorEventEntry> _historyAll = new();

        public sealed record HistoryGroupOption(string Key, string Title);

        public ObservableCollection<OperatorEventEntry> HistoryEvents { get; } = new();
        public ObservableCollection<HistoryGroupOption> HistoryGroupOptions { get; } = new();

        private OperatorHistoryTimeRange _historyTimeRange = OperatorHistoryTimeRange.Last7Days;
        private OperatorHistoryTypeFilter _historyTypeFilter = OperatorHistoryTypeFilter.All;
        private string _historyGroupKey = AllHistoryGroupsKey;

        private string _lastScreenState = string.Empty;
        private bool _lastIsApplyRunning;

        public ICommand RollbackCommand { get; }
        public ICommand ClearHistoryCommand { get; }

        public OperatorViewModel(MainViewModel main)
        {
            Main = main ?? throw new ArgumentNullException(nameof(main));

            // История активности (best-effort).
            try
            {
                var loaded = OperatorEventStore.LoadBestEffort(log: null);
                foreach (var e in loaded)
                {
                    _historyAll.Add(e);
                }
            }
            catch
            {
                // ignore
            }

            RebuildHistoryGroupOptionsBestEffort();
            ApplyHistoryFilters();

            _lastScreenState = (Main.ScreenState ?? string.Empty).Trim();
            _lastIsApplyRunning = Main.IsApplyRunning;

            RollbackCommand = new RelayCommand(async _ => await RollbackAsync().ConfigureAwait(false));
            ClearHistoryCommand = new RelayCommand(_ => ClearHistoryBestEffort());

            Main.PropertyChanged += MainOnPropertyChanged;
        }

        public OperatorHistoryTimeRange HistoryTimeRange
        {
            get => _historyTimeRange;
            set
            {
                if (_historyTimeRange == value) return;
                _historyTimeRange = value;
                OnPropertyChanged(nameof(HistoryTimeRange));
                ApplyHistoryFilters();
            }
        }

        public OperatorHistoryTypeFilter HistoryTypeFilter
        {
            get => _historyTypeFilter;
            set
            {
                if (_historyTypeFilter == value) return;
                _historyTypeFilter = value;
                OnPropertyChanged(nameof(HistoryTypeFilter));
                ApplyHistoryFilters();
            }
        }

        public string HistoryGroupKey
        {
            get => _historyGroupKey;
            set
            {
                if (string.Equals(_historyGroupKey, value, StringComparison.Ordinal)) return;
                _historyGroupKey = string.IsNullOrWhiteSpace(value) ? AllHistoryGroupsKey : value;
                OnPropertyChanged(nameof(HistoryGroupKey));
                ApplyHistoryFilters();
            }
        }

        public bool HasHistory => _historyAll.Count > 0;

        public string Headline
        {
            get
            {
                return Status switch
                {
                    OperatorStatus.Checking => "Идёт проверка",
                    OperatorStatus.Fixing => "Исправляю…",
                    OperatorStatus.Blocked => "Найдены проблемы",
                    OperatorStatus.Warn => "Есть ограничения",
                    OperatorStatus.Ok => "Всё в порядке",
                    _ => "Готов к проверке"
                };
            }
        }

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
                    return string.IsNullOrWhiteSpace(Main.ApplyStatusText)
                        ? "Применяю безопасные действия и перепроверяю…"
                        : Main.ApplyStatusText;
                }

                if (Main.IsDone)
                {
                    return $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";
                }

                // Idle
                if (Main.IsBasicTestMode)
                {
                    return "Источник: быстрая проверка интернета. Нажмите «Проверить».";
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

                return "Выберите источник трафика и нажмите «Проверить».";
            }
        }

        public OperatorStatus Status
        {
            get
            {
                if (Main.IsApplyRunning) return OperatorStatus.Fixing;
                if (Main.IsRunning) return OperatorStatus.Checking;

                if (Main.IsDone)
                {
                    if (Main.FailCount > 0) return OperatorStatus.Blocked;
                    if (Main.WarnCount > 0) return OperatorStatus.Warn;
                    return OperatorStatus.Ok;
                }

                return OperatorStatus.Idle;
            }
        }

        public PackIconKind HeroIconKind
        {
            get
            {
                return Status switch
                {
                    OperatorStatus.Checking => PackIconKind.Radar,
                    OperatorStatus.Fixing => PackIconKind.Wrench,
                    OperatorStatus.Blocked => PackIconKind.ShieldAlert,
                    OperatorStatus.Warn => PackIconKind.ShieldOutline,
                    OperatorStatus.Ok => PackIconKind.ShieldCheck,
                    _ => PackIconKind.Shield
                };
            }
        }

        public System.Windows.Media.Brush HeroAccentBrush
        {
            get
            {
                return Status switch
                {
                    OperatorStatus.Checking => System.Windows.Media.Brushes.DodgerBlue,
                    OperatorStatus.Fixing => System.Windows.Media.Brushes.DodgerBlue,
                    OperatorStatus.Blocked => System.Windows.Media.Brushes.IndianRed,
                    OperatorStatus.Warn => System.Windows.Media.Brushes.DarkOrange,
                    OperatorStatus.Ok => System.Windows.Media.Brushes.SeaGreen,
                    _ => System.Windows.Media.Brushes.Gray
                };
            }
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

        public bool IsSourceSelectionEnabled => IsSourceStepVisible && !Main.IsRunning && !Main.IsApplyRunning;

        public bool ShowFixButton =>
            (Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
            && Main.HasAnyRecommendations
            && !Main.IsApplyRunning;

        public bool ShowPrimaryButton => !ShowFixButton;

        public string PrimaryButtonText
        {
            get
            {
                if (Status == OperatorStatus.Checking) return "Остановить";
                if (Status == OperatorStatus.Ok) return "Проверить снова";
                if (Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
                {
                    return Main.HasAnyRecommendations ? "Исправить" : "Проверить снова";
                }
                return "Проверить";
            }
        }

        public ICommand PrimaryCommand
        {
            get
            {
                // Всегда возвращаем одну команду, чтобы можно было логировать события.
                return new RelayCommand(_ => ExecutePrimary());
            }
        }

        public string FixButtonText => Main.IsApplyRunning ? "Исправляю…" : "Исправить";
        public ICommand FixCommand => new RelayCommand(_ => ExecuteFix());

        public event PropertyChangedEventHandler? PropertyChanged;

        private void MainOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            try
            {
                RaiseDerivedProperties();

                if (string.Equals(e.PropertyName, nameof(MainViewModel.ScreenState), StringComparison.Ordinal))
                {
                    TrackScreenStateTransition();
                }
                else if (string.Equals(e.PropertyName, nameof(MainViewModel.IsApplyRunning), StringComparison.Ordinal))
                {
                    TrackApplyTransition();
                }
                else if (string.Equals(e.PropertyName, nameof(MainViewModel.FailCount), StringComparison.Ordinal)
                      || string.Equals(e.PropertyName, nameof(MainViewModel.WarnCount), StringComparison.Ordinal)
                      || string.Equals(e.PropertyName, nameof(MainViewModel.PassCount), StringComparison.Ordinal))
                {
                    // На завершении диагностики могут прилетать счётчики отдельно.
                    // Обновим фильтры/derived без логирования.
                }
            }
            catch
            {
                // ignore
            }
        }

        private void RaiseDerivedProperties()
        {
            OnPropertyChanged(nameof(Status));
            OnPropertyChanged(nameof(HeroIconKind));
            OnPropertyChanged(nameof(HeroAccentBrush));
            OnPropertyChanged(nameof(IsSourceStepVisible));
            OnPropertyChanged(nameof(IsProgressStepVisible));
            OnPropertyChanged(nameof(IsSummaryStepVisible));
            OnPropertyChanged(nameof(IsFixingStepVisible));
            OnPropertyChanged(nameof(IsSourceSelectionEnabled));
            OnPropertyChanged(nameof(Headline));
            OnPropertyChanged(nameof(SummaryLine));
            OnPropertyChanged(nameof(ShowFixButton));
            OnPropertyChanged(nameof(ShowPrimaryButton));
            OnPropertyChanged(nameof(PrimaryButtonText));
            OnPropertyChanged(nameof(FixButtonText));
            OnPropertyChanged(nameof(HasHistory));
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void ExecutePrimary()
        {
            if ((Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked) && Main.HasAnyRecommendations)
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
                var wasRunning = Main.IsRunning;
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "check",
                    GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                    Title = wasRunning ? "Проверка: остановка" : "Проверка: запуск",
                    Details = BuildTrafficSourceText(),
                    Outcome = ""
                });

                Main.StartLiveTestingCommand.Execute(null);
            }
            catch (Exception ex)
            {
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "error",
                    Title = "Проверка: ошибка запуска",
                    Details = ex.Message,
                    Outcome = "FAIL"
                });
                throw;
            }
        }

        private void ExecuteFix()
        {
            try
            {
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "fix",
                    GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                    Title = "Исправление: запуск",
                    Details = string.IsNullOrWhiteSpace(Main.ActiveApplySummaryText) ? "" : Main.ActiveApplySummaryText,
                    Outcome = ""
                });

                Main.ApplyRecommendationsCommand.Execute(null);
            }
            catch (Exception ex)
            {
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "error",
                    Title = "Исправление: ошибка запуска",
                    Details = ex.Message,
                    Outcome = "FAIL"
                });
                throw;
            }
        }

        private async Task RollbackAsync()
        {
            AddHistoryEvent(new OperatorEventEntry
            {
                Category = "rollback",
                GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                Title = "Откат: запуск",
                Details = string.IsNullOrWhiteSpace(Main.ActiveApplySummaryText) ? "" : Main.ActiveApplySummaryText,
                Outcome = ""
            });

            try
            {
                await Main.Bypass.DisableAllAsync().ConfigureAwait(false);
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "rollback",
                    GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                    Title = "Откат: выполнено",
                    Details = "Bypass выключен",
                    Outcome = "OK"
                });
            }
            catch (Exception ex)
            {
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "error",
                    Title = "Откат: ошибка",
                    Details = ex.Message,
                    Outcome = "FAIL"
                });
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
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "check",
                    GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                    Title = "Проверка: началась",
                    Details = BuildTrafficSourceText(),
                    Outcome = ""
                });
                return;
            }

            if (string.Equals(now, "done", StringComparison.OrdinalIgnoreCase))
            {
                var outcome = Main.FailCount > 0 ? "FAIL" : (Main.WarnCount > 0 ? "WARN" : "OK");
                var title = outcome == "OK" ? "Проверка: завершена (норма)"
                    : outcome == "WARN" ? "Проверка: завершена (есть ограничения)"
                    : "Проверка: завершена (есть блокировки)";

                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "check",
                    GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                    Title = title,
                    Details = $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}",
                    Outcome = outcome
                });
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
                AddHistoryEvent(new OperatorEventEntry
                {
                    Category = "fix",
                    GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                    Title = "Исправление: выполняется",
                    Details = string.IsNullOrWhiteSpace(Main.ApplyStatusText) ? "" : Main.ApplyStatusText,
                    Outcome = ""
                });
                return;
            }

            // Apply закончился.
            var details = string.IsNullOrWhiteSpace(Main.PostApplyRetestStatus)
                ? (string.IsNullOrWhiteSpace(Main.ApplyStatusText) ? "" : Main.ApplyStatusText)
                : $"{Main.ApplyStatusText}; {Main.PostApplyRetestStatus}";

            AddHistoryEvent(new OperatorEventEntry
            {
                Category = "fix",
                GroupKey = (Main.ActiveApplyGroupKey ?? string.Empty).Trim(),
                Title = "Исправление: завершено",
                Details = details,
                Outcome = ""
            });
        }

        private void AddHistoryEvent(OperatorEventEntry entry)
        {
            try
            {
                if (entry == null) return;

                // Новые сверху.
                _historyAll.Insert(0, entry);

                while (_historyAll.Count > MaxHistoryEntries)
                {
                    _historyAll.RemoveAt(_historyAll.Count - 1);
                }

                RebuildHistoryGroupOptionsBestEffort();
                ApplyHistoryFilters();
                OnPropertyChanged(nameof(HasHistory));

                // Persist best-effort в фоне.
                var snapshot = _historyAll.ToList();
                _ = Task.Run(() =>
                {
                    try
                    {
                        OperatorEventStore.PersistBestEffort(snapshot, log: null);
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

        private void ClearHistoryBestEffort()
        {
            try
            {
                _historyAll.Clear();
                HistoryEvents.Clear();
                OperatorEventStore.TryDeletePersistedFileBestEffort(log: null);
                RebuildHistoryGroupOptionsBestEffort();
                OnPropertyChanged(nameof(HasHistory));
            }
            catch
            {
                // ignore
            }
        }

        private void RebuildHistoryGroupOptionsBestEffort()
        {
            try
            {
                var keys = _historyAll
                    .Where(e => e != null)
                    .Select(e => (e.GroupKey ?? string.Empty).Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(k => string.IsNullOrWhiteSpace(k) ? "" : k, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var options = new List<HistoryGroupOption>(capacity: 1 + keys.Count)
                {
                    new HistoryGroupOption(AllHistoryGroupsKey, "Все")
                };

                foreach (var k in keys)
                {
                    var title = string.IsNullOrWhiteSpace(k) ? "Без группы" : k;
                    options.Add(new HistoryGroupOption(string.IsNullOrWhiteSpace(k) ? string.Empty : k, title));
                }

                var selected = _historyGroupKey;
                HistoryGroupOptions.Clear();
                foreach (var opt in options)
                {
                    HistoryGroupOptions.Add(opt);
                }

                // Если выбранная группа исчезла — откатываемся на "Все".
                var exists = HistoryGroupOptions.Any(o => string.Equals(o.Key, selected, StringComparison.Ordinal));
                if (!exists)
                {
                    _historyGroupKey = AllHistoryGroupsKey;
                    OnPropertyChanged(nameof(HistoryGroupKey));
                }
            }
            catch
            {
                // ignore
            }
        }

        private void ApplyHistoryFilters()
        {
            try
            {
                var nowLocal = DateTimeOffset.Now;
                DateTimeOffset? cutoff = null;

                if (HistoryTimeRange == OperatorHistoryTimeRange.Today)
                {
                    cutoff = new DateTimeOffset(nowLocal.Date, nowLocal.Offset);
                }
                else if (HistoryTimeRange == OperatorHistoryTimeRange.Last7Days)
                {
                    cutoff = nowLocal.AddDays(-7);
                }

                bool IsTypeMatch(OperatorEventEntry e)
                {
                    var cat = (e.Category ?? string.Empty).Trim();
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.All) return true;
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.Checks) return cat.Equals("check", StringComparison.OrdinalIgnoreCase);
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.Fixes) return cat.Equals("fix", StringComparison.OrdinalIgnoreCase) || cat.Equals("rollback", StringComparison.OrdinalIgnoreCase);
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.Errors) return cat.Equals("error", StringComparison.OrdinalIgnoreCase);
                    return true;
                }

                bool IsTimeMatch(OperatorEventEntry e)
                {
                    if (cutoff == null) return true;
                    try
                    {
                        var local = e.OccurredAt.ToLocalTime();
                        return local >= cutoff.Value;
                    }
                    catch
                    {
                        return true;
                    }
                }

                bool IsGroupMatch(OperatorEventEntry e)
                {
                    if (string.Equals(HistoryGroupKey, AllHistoryGroupsKey, StringComparison.Ordinal))
                    {
                        return true;
                    }

                    var g = (e.GroupKey ?? string.Empty).Trim();
                    return string.Equals(g, HistoryGroupKey, StringComparison.OrdinalIgnoreCase);
                }

                var filtered = _historyAll
                    .Where(e => e != null)
                    .Where(IsTypeMatch)
                    .Where(IsTimeMatch)
                    .Where(IsGroupMatch)
                    .OrderByDescending(e => e.OccurredAt)
                    .Take(MaxHistoryEntries)
                    .ToList();

                HistoryEvents.Clear();
                foreach (var e in filtered)
                {
                    HistoryEvents.Add(e);
                }
            }
            catch
            {
                // ignore
            }
        }

        private string BuildTrafficSourceText()
        {
            try
            {
                if (Main.IsBasicTestMode)
                {
                    return "Источник: быстрая проверка интернета";
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
    }
}
