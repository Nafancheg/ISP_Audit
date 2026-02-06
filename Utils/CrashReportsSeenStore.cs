using System;
using System.IO;
using System.Text.Json;

namespace IspAudit.Utils
{
    /// <summary>
    /// Персист «последний просмотренный» crash-report timestamp.
    /// Используется для UX: после рестарта показать баннер, если появились новые отчёты.
    /// Файл: state/crash_reports_seen.json
    /// Best-effort: ошибки чтения/записи игнорируются.
    /// </summary>
    public static class CrashReportsSeenStore
    {
        private const string FileName = "crash_reports_seen.json";

        private sealed class SeenState
        {
            public DateTimeOffset? LastSeenUtc { get; set; }
        }

        public static string GetPersistPath() => AppPaths.GetStateFilePath(FileName);

        public static DateTimeOffset LoadLastSeenOrDefault(DateTimeOffset defaultValue)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path)) return defaultValue;

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return defaultValue;

                var state = JsonSerializer.Deserialize<SeenState>(json);
                return state?.LastSeenUtc ?? defaultValue;
            }
            catch
            {
                return defaultValue;
            }
        }

        public static void SaveBestEffort(DateTimeOffset lastSeenUtc)
        {
            try
            {
                _ = AppPaths.EnsureStateDirectoryExists();

                var path = GetPersistPath();
                var state = new SeenState
                {
                    LastSeenUtc = lastSeenUtc
                };

                var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
            }
            catch
            {
                // ignore
            }
        }
    }
}
