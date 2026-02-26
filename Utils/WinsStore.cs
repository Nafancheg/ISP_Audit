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
    /// P1.9: best-effort персист wins-библиотеки.
    /// Файл: state/wins_store.json (portable).
    /// </summary>
    public static class WinsStore
    {
        private const int MaxEntries = 256;
        private const int MaxJsonBytes = 512 * 1024; // best-effort защита от раздувания
        private const string DefaultFileName = "wins_store.json";
        private const int CurrentSemanticsVersion = 2;

        private const string EnvVarPathOverride = EnvKeys.WinsStorePath;

        private sealed record PersistedStateV1
        {
            public string Version { get; init; } = "v1";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();
            public IReadOnlyList<WinsEntry> Entries { get; init; } = Array.Empty<WinsEntry>();
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

        public static Dictionary<string, WinsEntry> LoadByHostKeyBestEffort(Action<string>? log)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path))
                {
                    return new Dictionary<string, WinsEntry>(StringComparer.OrdinalIgnoreCase);
                }

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json))
                {
                    return new Dictionary<string, WinsEntry>(StringComparer.OrdinalIgnoreCase);
                }

                if (Encoding.UTF8.GetByteCount(json) > MaxJsonBytes)
                {
                    return new Dictionary<string, WinsEntry>(StringComparer.OrdinalIgnoreCase);
                }

                var state = JsonSerializer.Deserialize<PersistedStateV1>(json);
                var entries = state?.Entries;
                if (entries == null || entries.Count == 0)
                {
                    return new Dictionary<string, WinsEntry>(StringComparer.OrdinalIgnoreCase);
                }

                var latestByHost = entries
                    .Where(e => e != null && !string.IsNullOrWhiteSpace(e.HostKey))
                    .OrderByDescending(e => ParseUtcOrMin(e.VerifiedAtUtc))
                    .Take(MaxEntries)
                    .GroupBy(e => NormalizeKey(e.HostKey), StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .ToList();

                var droppedLegacyCount = 0;
                var migratedLegacyCount = 0;
                var compatible = new List<WinsEntry>(latestByHost.Count);

                foreach (var entry in latestByHost)
                {
                    if (!IsCompatibleWithCurrentSemantics(entry))
                    {
                        droppedLegacyCount++;
                        continue;
                    }

                    var normalized = NormalizeToCurrentSemantics(entry);
                    if (normalized.SemanticsVersion != entry.SemanticsVersion)
                    {
                        migratedLegacyCount++;
                    }

                    compatible.Add(normalized);
                }

                var result = compatible
                    .ToDictionary(e => NormalizeKey(e.HostKey), e => e, StringComparer.OrdinalIgnoreCase);

                if (droppedLegacyCount > 0 || migratedLegacyCount > 0)
                {
                    log?.Invoke($"[WinsStore] Migration: droppedLegacy={droppedLegacyCount}; migratedLegacy={migratedLegacyCount}");
                    PersistByHostKeyBestEffort(result, log);
                }

                return result;
            }
            catch (Exception ex)
            {
                log?.Invoke($"[WinsStore] Load error: {ex.Message}");
                return new Dictionary<string, WinsEntry>(StringComparer.OrdinalIgnoreCase);
            }
        }

        public static void PersistByHostKeyBestEffort(IReadOnlyDictionary<string, WinsEntry> byHostKey, Action<string>? log)
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

                var list = (byHostKey ?? new Dictionary<string, WinsEntry>(StringComparer.OrdinalIgnoreCase))
                    .Values
                    .Where(e => e != null && !string.IsNullOrWhiteSpace(e.HostKey))
                    .Where(IsCompatibleWithCurrentSemantics)
                    .Select(NormalizeToCurrentSemantics)
                    .OrderByDescending(e => ParseUtcOrMin(e.VerifiedAtUtc))
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
                log?.Invoke($"[WinsStore] Persist error: {ex.Message}");
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
                log?.Invoke($"[WinsStore] Delete error: {ex.Message}");
            }
        }

        public static bool TryGetBestMatch(IReadOnlyDictionary<string, WinsEntry> byHostKey, string? hostKey, out WinsEntry? entry)
        {
            entry = null;

            var hk = NormalizeKey(hostKey);
            if (string.IsNullOrWhiteSpace(hk)) return false;

            if (byHostKey != null && byHostKey.TryGetValue(hk, out var exact) && exact != null)
            {
                entry = exact;
                return true;
            }

            // Для доменных целей допускаем match по суффиксу: sub.example.com → example.com.
            // Выбираем самый длинный ключ (наиболее специфичный).
            if (byHostKey == null || byHostKey.Count == 0) return false;

            WinsEntry? best = null;
            var bestLen = -1;
            foreach (var kv in byHostKey)
            {
                var key = NormalizeKey(kv.Key);
                if (string.IsNullOrWhiteSpace(key)) continue;

                if (string.Equals(hk, key, StringComparison.OrdinalIgnoreCase)
                    || hk.EndsWith("." + key, StringComparison.OrdinalIgnoreCase))
                {
                    if (key.Length > bestLen)
                    {
                        best = kv.Value;
                        bestLen = key.Length;
                    }
                }
            }

            if (best == null) return false;
            entry = best;
            return true;
        }

        private static string NormalizeKey(string? value)
            => (value ?? string.Empty).Trim().Trim('.');

        private static DateTimeOffset ParseUtcOrMin(string? utc)
        {
            if (string.IsNullOrWhiteSpace(utc)) return DateTimeOffset.MinValue;
            if (DateTimeOffset.TryParse(utc, out var dto)) return dto;
            return DateTimeOffset.MinValue;
        }

        private static bool IsCompatibleWithCurrentSemantics(WinsEntry entry)
        {
            if (entry == null)
            {
                return false;
            }

            if (entry.SemanticsVersion >= CurrentSemanticsVersion)
            {
                return true;
            }

            return CanMigrateLegacyEntry(entry);
        }

        private static WinsEntry NormalizeToCurrentSemantics(WinsEntry entry)
        {
            if (entry.SemanticsVersion >= CurrentSemanticsVersion)
            {
                return entry;
            }

            if (!CanMigrateLegacyEntry(entry))
            {
                return entry;
            }

            return entry with { SemanticsVersion = CurrentSemanticsVersion };
        }

        private static bool CanMigrateLegacyEntry(WinsEntry entry)
        {
            var verdict = (entry.VerifiedVerdict ?? string.Empty).Trim();
            if (!string.Equals(verdict, "OK", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var mode = (entry.VerifiedMode ?? string.Empty).Trim();
            if (!string.Equals(mode, "enqueue", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var details = (entry.VerifiedDetails ?? string.Empty).Trim();
            return details.Contains("out=OK", StringComparison.OrdinalIgnoreCase)
                && details.Contains("probe=", StringComparison.OrdinalIgnoreCase);
        }
    }
}
