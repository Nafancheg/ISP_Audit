using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Core.Intelligence.Feedback;

/// <summary>
/// In-memory реализация feedback store.
/// Важно: никаких таймеров — очистка делается только при вызове <see cref="Prune"/>.
/// </summary>
public sealed class InMemoryFeedbackStore : IFeedbackStore
{
    private readonly object _lock = new();
    private readonly Dictionary<FeedbackKey, StrategyFeedbackStats> _stats = new();

    public InMemoryFeedbackStore(FeedbackStoreOptions? options = null)
    {
        Options = options ?? new FeedbackStoreOptions();
    }

    public FeedbackStoreOptions Options { get; }

    public bool TryGetStats(FeedbackKey key, out StrategyFeedbackStats stats)
    {
        lock (_lock)
        {
            return _stats.TryGetValue(key, out stats!);
        }
    }

    public void Record(FeedbackKey key, StrategyOutcome outcome, DateTimeOffset observedAtUtc)
    {
        if (outcome == StrategyOutcome.Unknown)
        {
            return;
        }

        lock (_lock)
        {
            if (!_stats.TryGetValue(key, out var s))
            {
                s = new StrategyFeedbackStats();
                _stats[key] = s;
            }

            switch (outcome)
            {
                case StrategyOutcome.Success:
                    s.SuccessCount++;
                    break;
                case StrategyOutcome.Failure:
                    s.FailureCount++;
                    break;
            }

            s.LastUpdatedUtc = observedAtUtc;

            // Поддерживаем ограничения без фоновых задач.
            Prune_NoLock(observedAtUtc);
        }
    }

    public void Prune(DateTimeOffset nowUtc)
    {
        lock (_lock)
        {
            Prune_NoLock(nowUtc);
        }
    }

    private void Prune_NoLock(DateTimeOffset nowUtc)
    {
        // 1) TTL
        var ttl = Options.EntryTtl;
        if (ttl > TimeSpan.Zero)
        {
            var threshold = nowUtc - ttl;
            var toRemove = _stats
                .Where(kvp => kvp.Value.LastUpdatedUtc < threshold)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var k in toRemove)
            {
                _stats.Remove(k);
            }
        }

        // 2) Лимит по количеству ключей
        var max = Options.MaxEntries;
        if (max > 0 && _stats.Count > max)
        {
            // Детерминированная очистка: сначала самые старые, при равенстве — по ключу.
            var ordered = _stats
                .OrderBy(kvp => kvp.Value.LastUpdatedUtc)
                .ThenBy(kvp => kvp.Key.DiagnosisId)
                .ThenBy(kvp => kvp.Key.StrategyId)
                .Select(kvp => kvp.Key)
                .ToList();

            var extra = _stats.Count - max;
            for (var i = 0; i < extra; i++)
            {
                _stats.Remove(ordered[i]);
            }
        }
    }

    public IReadOnlyDictionary<FeedbackKey, StrategyFeedbackStats> SnapshotForPersistence()
    {
        lock (_lock)
        {
            // Для сериализации возвращаем копию, чтобы не держать блокировку.
            return _stats.ToDictionary(
                kvp => kvp.Key,
                kvp => new StrategyFeedbackStats
                {
                    SuccessCount = kvp.Value.SuccessCount,
                    FailureCount = kvp.Value.FailureCount,
                    LastUpdatedUtc = kvp.Value.LastUpdatedUtc
                });
        }
    }

    public void ReplaceFromPersistence(IReadOnlyDictionary<FeedbackKey, StrategyFeedbackStats> data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        lock (_lock)
        {
            _stats.Clear();
            foreach (var kvp in data)
            {
                _stats[kvp.Key] = kvp.Value;
            }
        }
    }
}
