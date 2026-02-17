using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace IspAudit.Utils
{
    /// <summary>
    /// Blacklist v1 для блокировки повторных авто-действий (auto-apply/escalation) после регрессии.
    /// Ключ дедупликации: scopeKey + planSig + deltaStep + reason.
    /// </summary>
    public static class ApplyActionBlacklistStore
    {
        private const int MaxEntries = 1024;
        private const int MaxJsonBytes = 512 * 1024;

        public sealed record BlacklistEntry
        {
            public string Version { get; init; } = "1";
            public string Key { get; init; } = string.Empty;
            public string ScopeKey { get; init; } = string.Empty;
            public string PlanSig { get; init; } = string.Empty;
            public string DeltaStep { get; init; } = string.Empty;
            public string Reason { get; init; } = string.Empty;
            public string Source { get; init; } = string.Empty;

            public string CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("O");
            public string ExpiresAtUtc { get; init; } = DateTimeOffset.UtcNow.AddMinutes(10).ToString("O");
            public string LastSeenUtc { get; init; } = DateTimeOffset.UtcNow.ToString("O");
            public int HitCount { get; init; } = 1;
        }

        private sealed record PersistedStateV1
        {
            public string Version { get; init; } = "1";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("O");
            public IReadOnlyList<BlacklistEntry> Entries { get; init; } = Array.Empty<BlacklistEntry>();
        }

        public static string GetPersistPath()
            => AppPaths.GetStateFilePath("apply_action_blacklist_v1.json");

        public static string BuildKey(string scopeKey, string planSig, string deltaStep, string reason)
        {
            var s = Normalize(scopeKey);
            var p = Normalize(planSig);
            var d = Normalize(deltaStep);
            var r = Normalize(reason);
            return $"{s}|{p}|{d}|{r}";
        }

        public static Dictionary<string, BlacklistEntry> LoadByKeyBestEffort(Action<string>? log)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path))
                {
                    return new Dictionary<string, BlacklistEntry>(StringComparer.OrdinalIgnoreCase);
                }

                var json = File.ReadAllText(path, Encoding.UTF8);
                if (string.IsNullOrWhiteSpace(json) || Encoding.UTF8.GetByteCount(json) > MaxJsonBytes)
                {
                    return new Dictionary<string, BlacklistEntry>(StringComparer.OrdinalIgnoreCase);
                }

                var state = JsonSerializer.Deserialize<PersistedStateV1>(json);
                var entries = state?.Entries ?? Array.Empty<BlacklistEntry>();

                var now = DateTimeOffset.UtcNow;
                return entries
                    .Where(e => e != null && !string.IsNullOrWhiteSpace(e.Key))
                    .Where(e => ParseUtcOrMin(e.ExpiresAtUtc) > now)
                    .OrderByDescending(e => ParseUtcOrMin(e.LastSeenUtc))
                    .Take(MaxEntries)
                    .ToDictionary(e => e.Key, e => e, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[ApplyActionBlacklistStore] Load error: {ex.Message}");
                return new Dictionary<string, BlacklistEntry>(StringComparer.OrdinalIgnoreCase);
            }
        }

        public static void PersistByKeyBestEffort(IReadOnlyDictionary<string, BlacklistEntry> byKey, Action<string>? log)
        {
            try
            {
                var path = GetPersistPath();
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var now = DateTimeOffset.UtcNow;
                var entries = (byKey ?? new Dictionary<string, BlacklistEntry>(StringComparer.OrdinalIgnoreCase))
                    .Values
                    .Where(e => e != null && !string.IsNullOrWhiteSpace(e.Key))
                    .Where(e => ParseUtcOrMin(e.ExpiresAtUtc) > now)
                    .OrderByDescending(e => ParseUtcOrMin(e.LastSeenUtc))
                    .Take(MaxEntries)
                    .ToList();

                var payload = new PersistedStateV1
                {
                    Entries = entries
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
                log?.Invoke($"[ApplyActionBlacklistStore] Persist error: {ex.Message}");
            }
        }

        private static string Normalize(string? value)
            => (value ?? string.Empty).Trim();

        private static DateTimeOffset ParseUtcOrMin(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return DateTimeOffset.MinValue;
            }

            return DateTimeOffset.TryParse(value, out var dt)
                ? dt
                : DateTimeOffset.MinValue;
        }
    }
}
