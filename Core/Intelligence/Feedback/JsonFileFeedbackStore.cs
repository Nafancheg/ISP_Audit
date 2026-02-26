using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using IspAudit.Utils;

namespace IspAudit.Core.Intelligence.Feedback;

/// <summary>
/// Feedback store с сохранением в JSON файл.
/// MVP: простая реализация без фоновых задач и без сложной синхронизации.
/// </summary>
public sealed class JsonFileFeedbackStore : IFeedbackStore
{
    private readonly InMemoryFeedbackStore _inner;
    private readonly object _fileLock = new();

    public JsonFileFeedbackStore(string filePath, FeedbackStoreOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(filePath)) throw new ArgumentException("filePath is required", nameof(filePath));

        FilePath = filePath;
        _inner = new InMemoryFeedbackStore(options);

        TryLoadFromDisk();
        _inner.Prune(DateTimeOffset.UtcNow);
    }

    public string FilePath { get; }

    public FeedbackStoreOptions Options => _inner.Options;

    public bool TryGetStats(FeedbackKey key, out StrategyFeedbackStats stats)
        => _inner.TryGetStats(key, out stats);

    public void Record(FeedbackKey key, StrategyOutcome outcome, DateTimeOffset observedAtUtc)
    {
        _inner.Record(key, outcome, observedAtUtc);
        TrySaveToDisk();
    }

    public void Prune(DateTimeOffset nowUtc)
    {
        _inner.Prune(nowUtc);
        TrySaveToDisk();
    }

    private void TryLoadFromDisk()
    {
        lock (_fileLock)
        {
            try
            {
                if (!File.Exists(FilePath))
                {
                    return;
                }

                var json = File.ReadAllText(FilePath);
                if (string.IsNullOrWhiteSpace(json))
                {
                    return;
                }

                var data = JsonSerializer.Deserialize<PersistedFeedback>(json, JsonOptions);
                if (data?.Entries == null)
                {
                    return;
                }

                var dict = new Dictionary<FeedbackKey, StrategyFeedbackStats>();
                foreach (var e in data.Entries)
                {
                    var key = new FeedbackKey(e.DiagnosisId, e.StrategyId);
                    dict[key] = new StrategyFeedbackStats
                    {
                        SuccessCount = e.SuccessCount,
                        FailureCount = e.FailureCount,
                        LastUpdatedUtc = e.LastUpdatedUtc
                    };
                }

                _inner.ReplaceFromPersistence(dict);
            }
            catch
            {
                // MVP: любые проблемы с файлом не должны ломать приложение.
            }
        }
    }

    private void TrySaveToDisk()
    {
        lock (_fileLock)
        {
            try
            {
                var snap = _inner.SnapshotForPersistence();

                // Детерминированный порядок в файле.
                var entries = snap
                    .OrderBy(kvp => kvp.Key.DiagnosisId)
                    .ThenBy(kvp => kvp.Key.StrategyId)
                    .Select(kvp => new PersistedEntry
                    {
                        DiagnosisId = kvp.Key.DiagnosisId,
                        StrategyId = kvp.Key.StrategyId,
                        SuccessCount = kvp.Value.SuccessCount,
                        FailureCount = kvp.Value.FailureCount,
                        LastUpdatedUtc = kvp.Value.LastUpdatedUtc
                    })
                    .ToList();

                // Дополнительная страховка по лимиту (на случай если Options сменились между загрузкой/сохранением).
                if (Options.MaxEntries > 0 && entries.Count > Options.MaxEntries)
                {
                    entries = entries
                        .OrderByDescending(e => e.LastUpdatedUtc)
                        .ThenBy(e => e.DiagnosisId)
                        .ThenBy(e => e.StrategyId)
                        .Take(Options.MaxEntries)
                        .OrderBy(e => e.DiagnosisId)
                        .ThenBy(e => e.StrategyId)
                        .ToList();
                }

                var persisted = new PersistedFeedback
                {
                    SchemaVersion = 1,
                    SavedAtUtc = DateTimeOffset.UtcNow,
                    Entries = entries
                };

                var json = JsonSerializer.Serialize(persisted, JsonOptions);

                var dir = Path.GetDirectoryName(FilePath);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                FileAtomicWriter.WriteAllText(FilePath, json, Encoding.UTF8);
            }
            catch
            {
                // MVP: ошибки записи не должны ломать рантайм.
            }
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters =
        {
            new JsonStringEnumConverter()
        }
    };

    private sealed class PersistedFeedback
    {
        public int SchemaVersion { get; set; }
        public DateTimeOffset SavedAtUtc { get; set; }
        public List<PersistedEntry> Entries { get; set; } = new();
    }

    private sealed class PersistedEntry
    {
        public Contracts.DiagnosisId DiagnosisId { get; set; }
        public Contracts.StrategyId StrategyId { get; set; }
        public int SuccessCount { get; set; }
        public int FailureCount { get; set; }
        public DateTimeOffset LastUpdatedUtc { get; set; }
    }
}
