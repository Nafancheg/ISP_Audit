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
        private const int MaxHistoryEntries = 256;
        private const string AllHistoryGroupsKey = "__all__";
        private readonly ObservableCollection<OperatorEventEntry> _historyAll = new();

        public sealed record HistoryGroupOption(string Key, string Title);

        public ObservableCollection<OperatorEventEntry> HistoryEvents { get; } = new();
        public ObservableCollection<HistoryGroupOption> HistoryGroupOptions { get; } = new();

        private OperatorHistoryTimeRange _historyTimeRange = OperatorHistoryTimeRange.Last7Days;
        private OperatorHistoryTypeFilter _historyTypeFilter = OperatorHistoryTypeFilter.All;
        private string _historyGroupKey = AllHistoryGroupsKey;

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

        private void InitializeHistoryBestEffort()
        {
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

        private static bool TryParseUtc(string? text, out DateTimeOffset value)
        {
            value = default;
            if (string.IsNullOrWhiteSpace(text)) return false;

            return DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out value);
        }
    }
}
