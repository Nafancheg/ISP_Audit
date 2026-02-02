using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace IspAudit.Utils
{
    /// <summary>
    /// P1.7/P1.8: персист последнего результата пост‑проверки после Apply.
    ///
    /// Хранится в state/ рядом с приложением, чтобы работать в portable-режиме.
    /// Цель: после перезапуска UI не теряет контекст «что получилось после Apply».
    /// </summary>
    public static class PostApplyCheckStore
    {
        private const int MaxEntries = 256;
        private const int MaxJsonBytes = 256 * 1024; // best-effort защита от раздувания

        public sealed record PostApplyCheckEntry
        {
            public string GroupKey { get; init; } = string.Empty;
            public string Verdict { get; init; } = string.Empty; // OK/FAIL/PARTIAL/UNKNOWN
            public string CheckedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();

            public string HostKey { get; init; } = string.Empty;
            public string Mode { get; init; } = string.Empty; // enqueue/local
            public string Details { get; init; } = string.Empty;
        }

        private sealed record PersistedStateV1
        {
            public string Version { get; init; } = "v1";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();
            public IReadOnlyList<PostApplyCheckEntry> Entries { get; init; } = Array.Empty<PostApplyCheckEntry>();
        }

        public static string GetPersistPath()
        {
            var overridePath = Environment.GetEnvironmentVariable("ISP_AUDIT_POST_APPLY_CHECKS_PATH");
            if (!string.IsNullOrWhiteSpace(overridePath))
            {
                return overridePath;
            }

            return AppPaths.GetStateFilePath("post_apply_checks.json");
        }

        public static Dictionary<string, PostApplyCheckEntry> LoadByGroupKeyBestEffort(Action<string>? log)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path))
                {
                    return new Dictionary<string, PostApplyCheckEntry>(StringComparer.OrdinalIgnoreCase);
                }

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json))
                {
                    return new Dictionary<string, PostApplyCheckEntry>(StringComparer.OrdinalIgnoreCase);
                }

                if (Encoding.UTF8.GetByteCount(json) > MaxJsonBytes)
                {
                    return new Dictionary<string, PostApplyCheckEntry>(StringComparer.OrdinalIgnoreCase);
                }

                var state = JsonSerializer.Deserialize<PersistedStateV1>(json);
                var entries = state?.Entries;
                if (entries == null || entries.Count == 0)
                {
                    return new Dictionary<string, PostApplyCheckEntry>(StringComparer.OrdinalIgnoreCase);
                }

                // Берём последнюю запись по groupKey по CheckedAtUtc.
                return entries
                    .Where(e => !string.IsNullOrWhiteSpace(e?.GroupKey))
                    .GroupBy(e => NormalizeKey(e.GroupKey), StringComparer.OrdinalIgnoreCase)
                    .Where(g => !string.IsNullOrWhiteSpace(g.Key))
                    .Select(g => g.OrderByDescending(x => ParseUtcOrMin(x.CheckedAtUtc)).First())
                    .Take(MaxEntries)
                    .ToDictionary(e => NormalizeKey(e.GroupKey), e => e, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[PostApplyCheckStore] Load error: {ex.Message}");
                return new Dictionary<string, PostApplyCheckEntry>(StringComparer.OrdinalIgnoreCase);
            }
        }

        public static void PersistByGroupKeyBestEffort(IReadOnlyDictionary<string, PostApplyCheckEntry> byGroupKey, Action<string>? log)
        {
            try
            {
                var path = GetPersistPath();
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var list = (byGroupKey ?? new Dictionary<string, PostApplyCheckEntry>(StringComparer.OrdinalIgnoreCase))
                    .Values
                    .Where(e => e != null && !string.IsNullOrWhiteSpace(e.GroupKey))
                    .OrderByDescending(e => ParseUtcOrMin(e.CheckedAtUtc))
                    .Take(MaxEntries)
                    .ToList();

                var payload = new PersistedStateV1
                {
                    Entries = list
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
                log?.Invoke($"[PostApplyCheckStore] Persist error: {ex.Message}");
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
                log?.Invoke($"[PostApplyCheckStore] Delete error: {ex.Message}");
            }
        }

        private static string NormalizeKey(string? value)
            => (value ?? string.Empty).Trim().Trim('.');

        private static DateTimeOffset ParseUtcOrMin(string? utc)
        {
            if (string.IsNullOrWhiteSpace(utc)) return DateTimeOffset.MinValue;
            if (DateTimeOffset.TryParse(utc, out var dto)) return dto;
            return DateTimeOffset.MinValue;
        }
    }
}
