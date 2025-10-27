using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    public class GuiProfileTarget
    {
        public string Name { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
    }

    public class GuiProfileData
    {
        public List<GuiProfileTarget> Targets { get; set; } = new();
        public List<int> Ports { get; set; } = new();
        public int TimeoutSeconds { get; set; } = 12;
        public bool EnableDns { get; set; } = true;
        public bool EnableTcp { get; set; } = true;
        public bool EnableHttp { get; set; } = true;
        public bool EnableTrace { get; set; } = true;
        public bool EnableUdp { get; set; } = true;
        public bool EnableRst { get; set; } = true;
    }

    public static class GuiProfileStorage
    {
        private static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public static async Task SaveAsync(GuiProfileData profile, string path)
        {
            var json = JsonSerializer.Serialize(profile, Options);
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            await File.WriteAllTextAsync(path, json);
        }

        public static async Task<GuiProfileData> LoadAsync(string path)
        {
            var json = await File.ReadAllTextAsync(path);
            var profile = JsonSerializer.Deserialize<GuiProfileData>(json, Options);
            return profile ?? new GuiProfileData();
        }
    }
}
