using System;
using System.IO;
using System.Text.Json;

namespace IspAudit.Utils
{
    public enum UiMode
    {
        Operator,
        Engineer
    }

    /// <summary>
    /// Персист режима UI (Operator/Engineer) рядом с приложением: state/ui_mode.json
    /// </summary>
    public static class UiModeStore
    {
        private const string FileName = "ui_mode.json";

        private sealed class UiModeState
        {
            public string? Mode { get; set; }
        }

        public static string GetPersistPath() => AppPaths.GetStateFilePath(FileName);

        public static UiMode LoadOrDefault(UiMode defaultMode)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path)) return defaultMode;

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return defaultMode;

                var state = JsonSerializer.Deserialize<UiModeState>(json);
                var raw = (state?.Mode ?? string.Empty).Trim();

                if (raw.Equals("engineer", StringComparison.OrdinalIgnoreCase)) return UiMode.Engineer;
                if (raw.Equals("advanced", StringComparison.OrdinalIgnoreCase)) return UiMode.Engineer;
                if (raw.Equals("operator", StringComparison.OrdinalIgnoreCase)) return UiMode.Operator;

                return defaultMode;
            }
            catch
            {
                return defaultMode;
            }
        }

        public static void SaveBestEffort(UiMode mode)
        {
            try
            {
                _ = AppPaths.EnsureStateDirectoryExists();

                var path = GetPersistPath();
                var state = new UiModeState
                {
                    Mode = mode == UiMode.Engineer ? "engineer" : "operator"
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
