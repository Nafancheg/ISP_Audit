using System;
using System.IO;
using System.Text.Json;

namespace IspAudit.Utils
{
    /// <summary>
    /// Персист выбранной «цели» (сервис/игра) для Operator UI: state/operator_target.json
    /// Best-effort: ошибки чтения/записи игнорируются.
    /// </summary>
    public static class OperatorTargetStore
    {
        private const string FileName = "operator_target.json";

        private sealed class TargetState
        {
            public string SelectedTargetKey { get; set; } = string.Empty;
        }

        public static string GetPersistPath()
        {
            // Тестовый override пути.
            var overridePath = EnvVar.GetTrimmedNonEmpty(EnvKeys.OperatorTargetPath);
            if (!string.IsNullOrWhiteSpace(overridePath)) return overridePath;

            return AppPaths.GetStateFilePath(FileName);
        }

        public static string LoadOrDefault(string defaultValue)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path)) return defaultValue;

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return defaultValue;

                var state = JsonSerializer.Deserialize<TargetState>(json);
                var key = (state?.SelectedTargetKey ?? string.Empty).Trim();
                return string.IsNullOrWhiteSpace(key) ? defaultValue : key;
            }
            catch
            {
                return defaultValue;
            }
        }

        public static void SaveBestEffort(string selectedTargetKey)
        {
            try
            {
                _ = AppPaths.EnsureStateDirectoryExists();

                var path = GetPersistPath();
                var state = new TargetState
                {
                    SelectedTargetKey = (selectedTargetKey ?? string.Empty).Trim()
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
