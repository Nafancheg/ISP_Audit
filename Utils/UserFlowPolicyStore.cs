using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using IspAudit.Core.Models;

namespace IspAudit.Utils
{
    /// <summary>
    /// Персист пользовательских policy-driven политик: state/user_flow_policies.json
    /// Best-effort: ошибки чтения/записи не должны ломать UI.
    /// </summary>
    public static class UserFlowPolicyStore
    {
        private const string FileName = "user_flow_policies.json";

        public static string GetPersistPath()
        {
            // Тестовый override пути.
            var overridePath = EnvVar.GetTrimmedNonEmpty(EnvKeys.UserFlowPoliciesPath);
            if (!string.IsNullOrWhiteSpace(overridePath)) return overridePath;

            return AppPaths.GetStateFilePath(FileName);
        }

        public static IReadOnlyList<FlowPolicy> LoadOrEmpty()
        {
            try
            {
                var path = GetPersistPath();
                if (!File.Exists(path)) return Array.Empty<FlowPolicy>();

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return Array.Empty<FlowPolicy>();

                var list = JsonSerializer.Deserialize<List<FlowPolicy>>(json);
                return list?.Where(p => p != null).ToArray() ?? Array.Empty<FlowPolicy>();
            }
            catch
            {
                return Array.Empty<FlowPolicy>();
            }
        }

        public static void SaveBestEffort(IEnumerable<FlowPolicy> policies)
        {
            try
            {
                _ = AppPaths.EnsureStateDirectoryExists();

                var path = GetPersistPath();
                var list = (policies ?? Array.Empty<FlowPolicy>()).Where(p => p != null).ToList();
                var json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
            }
            catch
            {
                // ignore
            }
        }
    }
}
