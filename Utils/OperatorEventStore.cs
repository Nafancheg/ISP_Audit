using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using IspAudit.Models;

namespace IspAudit.Utils
{
    /// <summary>
    /// P1.11: best-effort персист истории операторских событий.
    /// Файл: state/operator_events.json (portable).
    /// </summary>
    public static class OperatorEventStore
    {
        private const int MaxEntries = 256;
        private const int MaxJsonBytes = 256 * 1024; // best-effort защита от раздувания
        private const string DefaultFileName = "operator_events.json";

        private const string EnvVarPathOverride = "ISP_AUDIT_OPERATOR_EVENTS_PATH";

        private sealed record PersistedStateV1
        {
            public string Version { get; init; } = "v1";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();
            public IReadOnlyList<OperatorEventEntry> Entries { get; init; } = Array.Empty<OperatorEventEntry>();
        }

        public static string GetPersistPath()
        {
            var overridePath = EnvVar.GetTrimmedNonEmpty(EnvVarPathOverride);
            if (!string.IsNullOrWhiteSpace(overridePath))
            {
                return overridePath;
            }

            return AppPaths.GetStateFilePath(DefaultFileName);
        }

        public static IReadOnlyList<OperatorEventEntry> LoadBestEffort(Action<string>? log)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path))
                {
                    return Array.Empty<OperatorEventEntry>();
                }

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json))
                {
                    return Array.Empty<OperatorEventEntry>();
                }

                if (Encoding.UTF8.GetByteCount(json) > MaxJsonBytes)
                {
                    return Array.Empty<OperatorEventEntry>();
                }

                var state = JsonSerializer.Deserialize<PersistedStateV1>(json);
                var entries = state?.Entries;
                if (entries == null || entries.Count == 0)
                {
                    return Array.Empty<OperatorEventEntry>();
                }

                // Новые сверху.
                return entries
                    .Where(e => e != null)
                    .OrderByDescending(e => ParseUtcOrMin(e.OccurredAtUtc))
                    .Take(MaxEntries)
                    .ToList();
            }
            catch (Exception ex)
            {
                log?.Invoke($"[OperatorEventStore] Load error: {ex.Message}");
                return Array.Empty<OperatorEventEntry>();
            }
        }

        public static void PersistBestEffort(IReadOnlyList<OperatorEventEntry> entries, Action<string>? log)
        {
            try
            {
                _ = AppPaths.EnsureStateDirectoryExists();

                var path = GetPersistPath();
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var safe = (entries ?? Array.Empty<OperatorEventEntry>())
                    .Where(e => e != null && !string.IsNullOrWhiteSpace(e.Id))
                    .OrderByDescending(e => ParseUtcOrMin(e.OccurredAtUtc))
                    .Take(MaxEntries)
                    .ToList();

                var payload = new PersistedStateV1
                {
                    Entries = safe
                };

                var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                if (Encoding.UTF8.GetByteCount(json) > MaxJsonBytes)
                {
                    return;
                }

                File.WriteAllText(path, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[OperatorEventStore] Persist error: {ex.Message}");
            }
        }

        public static void TryDeletePersistedFileBestEffort(Action<string>? log)
        {
            try
            {
                var path = GetPersistPath();
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"[OperatorEventStore] Delete error: {ex.Message}");
            }
        }

        private static DateTimeOffset ParseUtcOrMin(string? utc)
        {
            if (string.IsNullOrWhiteSpace(utc)) return DateTimeOffset.MinValue;
            if (DateTimeOffset.TryParse(utc, out var dto)) return dto;
            return DateTimeOffset.MinValue;
        }
    }
}
