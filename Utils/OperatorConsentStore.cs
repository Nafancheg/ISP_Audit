using System;
using System.IO;
using System.Text.Json;

namespace IspAudit.Utils
{
    /// <summary>
    /// Персист явного согласия оператора на системные изменения (DNS/DoH): state/operator_consent.json
    /// Best-effort: ошибки чтения/записи игнорируются.
    /// </summary>
    public static class OperatorConsentStore
    {
        private const string FileName = "operator_consent.json";

        private sealed class ConsentState
        {
            public bool AllowDnsDohChanges { get; set; }
        }

        public static string GetPersistPath()
        {
            // Тестовый override пути.
            var overridePath = (Environment.GetEnvironmentVariable("ISP_AUDIT_OPERATOR_CONSENT_PATH") ?? string.Empty).Trim();
            if (!string.IsNullOrWhiteSpace(overridePath)) return overridePath;

            return AppPaths.GetStateFilePath(FileName);
        }

        public static bool LoadOrDefault(bool defaultValue)
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path)) return defaultValue;

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return defaultValue;

                var state = JsonSerializer.Deserialize<ConsentState>(json);
                return state?.AllowDnsDohChanges ?? defaultValue;
            }
            catch
            {
                return defaultValue;
            }
        }

        public static void SaveBestEffort(bool allowDnsDohChanges)
        {
            try
            {
                _ = AppPaths.EnsureStateDirectoryExists();

                var path = GetPersistPath();
                var state = new ConsentState
                {
                    AllowDnsDohChanges = allowDnsDohChanges
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
