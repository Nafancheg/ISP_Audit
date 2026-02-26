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
    /// Best-effort хранилище «сессий» Operator UI.
    /// По умолчанию: state/operator_sessions.json.
    /// Можно переопределить env-переменной ISP_AUDIT_OPERATOR_SESSIONS_PATH.
    /// </summary>
    public static class OperatorSessionStore
    {
        private const int DefaultMaxEntries = 128;
        private const int DefaultMaxBytes = 512 * 1024;
        private const string EnvPath = EnvKeys.OperatorSessionsPath;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        public static string GetDefaultPath()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            return Path.Combine(baseDir, "state", "operator_sessions.json");
        }

        private static string ResolvePath()
        {
            try
            {
                var overridePath = EnvVar.GetTrimmedNonEmpty(EnvPath);
                if (!string.IsNullOrWhiteSpace(overridePath)) return overridePath;
            }
            catch
            {
                // ignore
            }

            return GetDefaultPath();
        }

        public static List<OperatorSessionEntry> LoadBestEffort(Action<string>? log)
        {
            try
            {
                var path = ResolvePath();
                if (!File.Exists(path)) return new List<OperatorSessionEntry>();

                var json = File.ReadAllText(path, Encoding.UTF8);
                if (string.IsNullOrWhiteSpace(json)) return new List<OperatorSessionEntry>();

                var data = JsonSerializer.Deserialize<List<OperatorSessionEntry>>(json, JsonOptions);
                return (data ?? new List<OperatorSessionEntry>())
                    .Where(x => x != null)
                    .OrderByDescending(GetStartedAtUtcBestEffort)
                    .ToList();
            }
            catch (Exception ex)
            {
                log?.Invoke($"[OperatorSessionStore] Load error: {ex.Message}");
                return new List<OperatorSessionEntry>();
            }
        }

        public static void PersistBestEffort(IReadOnlyList<OperatorSessionEntry> entries, Action<string>? log)
        {
            try
            {
                var path = ResolvePath();
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                // Нормализуем: новые сверху, ограничиваем количество.
                var normalized = (entries ?? Array.Empty<OperatorSessionEntry>())
                    .Where(x => x != null)
                    .OrderByDescending(GetStartedAtUtcBestEffort)
                    .Take(DefaultMaxEntries)
                    .ToList();

                var json = JsonSerializer.Serialize(normalized, JsonOptions);
                if (Encoding.UTF8.GetByteCount(json) > DefaultMaxBytes)
                {
                    // Если не влезаем — режем хвост, пока не уложимся.
                    while (normalized.Count > 0)
                    {
                        normalized.RemoveAt(normalized.Count - 1);
                        json = JsonSerializer.Serialize(normalized, JsonOptions);
                        if (Encoding.UTF8.GetByteCount(json) <= DefaultMaxBytes) break;
                    }
                }

                FileAtomicWriter.WriteAllText(path, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[OperatorSessionStore] Persist error: {ex.Message}");
            }
        }

        private static DateTimeOffset GetStartedAtUtcBestEffort(OperatorSessionEntry e)
        {
            try
            {
                if (e == null) return DateTimeOffset.MinValue;
                var s = (e.StartedAtUtc ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(s)) return DateTimeOffset.MinValue;
                return DateTimeOffset.TryParse(s, out var dto) ? dto : DateTimeOffset.MinValue;
            }
            catch
            {
                return DateTimeOffset.MinValue;
            }
        }

        public static void TryDeletePersistedFileBestEffort(Action<string>? log)
        {
            try
            {
                var path = ResolvePath();
                if (File.Exists(path)) File.Delete(path);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[OperatorSessionStore] Delete error: {ex.Message}");
            }
        }
    }
}
