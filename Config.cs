using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IspAudit
{
    public class Config
    {
        public List<string> Targets { get; set; } = new();
        public Dictionary<string, TargetDefinition> TargetMap { get; set; } = TargetCatalog.CreateDefaultTargetMap();
        public string ReportPath { get; set; } = string.Empty;
        public bool Verbose { get; set; } = false;
        
        // Game profile management
        public static GameProfile? ActiveProfile { get; set; }
        public bool PrintJson { get; set; } = false;
        public bool NoTrace { get; set; } = false;
        public bool ShowHelp { get; set; } = false;
        // Environment profile: normal|vpn (affects classification/thresholds)
        public string Profile { get; set; } = "normal";

        // Timeouts in seconds
        public int HttpTimeoutSeconds { get; set; } = 6;
        public int TcpTimeoutSeconds { get; set; } = 3;
        public int UdpTimeoutSeconds { get; set; } = 2;

        // Ports list for TCP checks
        public List<int> Ports { get; set; } = TargetCatalog.CreateDefaultTcpPorts();
        public List<UdpProbeDefinition> UdpProbes { get; set; } = TargetCatalog.CreateDefaultUdpProbes();

        // Toggle tests (GUI использует)
        public bool EnableDns { get; set; } = true;
        public bool EnableTcp { get; set; } = true;
        public bool EnableHttp { get; set; } = true;
        public bool EnableTrace { get; set; } = false; // Отключено по умолчанию - медленный и редко полезный для пользователей
        public bool EnableUdp { get; set; } = true;
        public bool EnableRst { get; set; } = false; // Отключено по умолчанию - сложная эвристика, мало информативна

        public static Config Default() => new Config();

        public static (Config config, string? error, string help) ParseArgs(string[] args)
        {
            var cfg = Default();
            string? error = null;
            string help = BuildHelp();

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                switch (a)
                {
                    case "--help":
                    case "-h":
                    case "/?":
                        cfg.ShowHelp = true;
                        break;
                    case "--verbose":
                        cfg.Verbose = true;
                        break;
                    case "--json":
                        cfg.PrintJson = true;
                        break;
                    case "--no-trace":
                        cfg.NoTrace = true;
                        break;
                    case "--report":
                        if (i + 1 >= args.Length) { error = "--report requires a path"; break; }
                        cfg.ReportPath = args[++i];
                        break;
                    case "--profile":
                        if (i + 1 >= args.Length) { error = "--profile requires a value (normal|vpn)"; break; }
                        var prof = (args[++i] ?? string.Empty).Trim().ToLowerInvariant();
                        if (prof == "normal" || prof == "vpn") cfg.Profile = prof; else error = "--profile must be 'normal' or 'vpn'";
                        break;
                    case "--targets":
                        if (i + 1 >= args.Length) { error = "--targets requires a value"; break; }
                        var tval = args[++i];
                        LoadTargets(cfg, tval);
                        break;
                    case "--timeout":
                        if (i + 1 >= args.Length) { error = "--timeout requires seconds"; break; }
                        if (int.TryParse(args[++i], out int sec) && sec > 0)
                        {
                            cfg.HttpTimeoutSeconds = Math.Max(1, sec);
                            cfg.TcpTimeoutSeconds = Math.Max(1, Math.Min(sec, 10));
                            cfg.UdpTimeoutSeconds = Math.Max(1, Math.Min(sec, 10));
                        }
                        else { error = "--timeout must be a positive integer"; }
                        break;
                    case "--ports":
                        if (i + 1 >= args.Length) { error = "--ports requires a list"; break; }
                        var pval = args[++i];
                        try
                        {
                            cfg.Ports = pval.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                .Select(s => int.Parse(s.Trim()))
                                .Where(p => p > 0 && p <= 65535)
                                .Distinct()
                                .ToList();
                        }
                        catch { error = "--ports must be comma-separated integers"; }
                        break;
                    default:
                        // ignore unknown or positional
                        break;
                }
                if (error != null) break;
            }

            return (cfg, error, help);
        }

        private static void LoadTargets(Config cfg, string value)
        {
            // Accept: comma-separated list, or a file path to JSON/CSV
            if (File.Exists(value))
            {
                var ext = Path.GetExtension(value).ToLowerInvariant();
                if (ext == ".json")
                {
                    var json = File.ReadAllText(value);
                    if (json.TrimStart().StartsWith("["))
                    {
                        // ["host1", "host2"]
                        var arr = System.Text.Json.JsonSerializer.Deserialize<List<string>>(json) ?? new();
                        cfg.Targets = arr.Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();
                        cfg.TargetMap = TargetCatalog.CreateDefaultTargetMap();
                    }
                    else
                    {
                        // {"Name":"host"} or {"name":"host"}
                        var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();
                        cfg.Targets = dict.Values.Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();
                        cfg.TargetMap = dict
                            .Where(kv => !string.IsNullOrWhiteSpace(kv.Value))
                            .ToDictionary(kv => kv.Key, kv => new TargetDefinition
                            {
                                Name = kv.Key.Trim(),
                                Host = kv.Value.Trim(),
                                Service = "Пользовательский"
                            }, StringComparer.OrdinalIgnoreCase);
                    }
                }
                else
                {
                    // CSV: lines of "name,host" or just "host"
                    var hosts = new List<string>();
                    var map = new Dictionary<string, TargetDefinition>(StringComparer.OrdinalIgnoreCase);
                    foreach (var line in File.ReadAllLines(value))
                    {
                        var l = line.Trim();
                        if (string.IsNullOrEmpty(l) || l.StartsWith("#")) continue;
                        var parts = l.Split(',', StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 1)
                        {
                            var host = parts[0].Trim();
                            if (!string.IsNullOrWhiteSpace(host)) hosts.Add(host);
                        }
                        else if (parts.Length >= 2)
                        {
                            var name = parts[0].Trim();
                            var host = parts[1].Trim();
                            if (!string.IsNullOrWhiteSpace(host))
                            {
                                hosts.Add(host);
                                if (!string.IsNullOrWhiteSpace(name))
                                {
                                    map[name] = new TargetDefinition
                                    {
                                        Name = name,
                                        Host = host,
                                        Service = "Пользовательский"
                                    };
                                }
                            }
                        }
                    }
                    cfg.Targets = hosts.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();
                    if (map.Count > 0) cfg.TargetMap = map;
                }
            }
            else
            {
                cfg.Targets = value.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Distinct()
                    .ToList();
                cfg.TargetMap = TargetCatalog.CreateDefaultTargetMap();
            }
        }

        public List<TargetDefinition> ResolveTargets()
        {
            // Если профиль загружен, используем цели из профиля напрямую
            if (ActiveProfile?.Targets != null && ActiveProfile.Targets.Count > 0)
            {
                System.Diagnostics.Debug.WriteLine($"ResolveTargets: Using ActiveProfile targets ({ActiveProfile.Targets.Count} targets)");
                var result = new List<TargetDefinition>();
                foreach (var profileTarget in ActiveProfile.Targets)
                {
                    // Проверяем есть ли этот хост в Config.Targets (если Targets указаны явно)
                    if (Targets.Count > 0 && !Targets.Any(t => string.Equals(t, profileTarget.Host, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue; // Пропускаем цели не из списка
                    }
                    
                    result.Add(new TargetDefinition
                    {
                        Name = profileTarget.Name,
                        Host = profileTarget.Host,
                        Service = profileTarget.Service ?? "Unknown",
                        Critical = profileTarget.Critical,
                        FallbackIp = profileTarget.FallbackIp
                    });
                    System.Diagnostics.Debug.WriteLine($"  Added from profile: {profileTarget.Name} -> {profileTarget.Host}");
                }
                return result;
            }

            // Fallback: старая логика с TargetCatalog
            System.Diagnostics.Debug.WriteLine($"ResolveTargets: Using TargetCatalog fallback");
            var map = TargetMap.Count > 0
                ? TargetMap
                : TargetCatalog.CreateDefaultTargetMap();

            if (Targets.Count == 0)
            {
                return map.Values.Select(t => t.Copy()).ToList();
            }

            var fallbackResult = new List<TargetDefinition>();
            foreach (var host in Targets)
            {
                var matched = map.Values.FirstOrDefault(t => string.Equals(t.Host, host, StringComparison.OrdinalIgnoreCase));
                if (matched != null)
                {
                    fallbackResult.Add(matched.Copy());
                    continue;
                }

                var catalog = TargetCatalog.TryGetByHost(host);
                if (catalog != null)
                {
                    fallbackResult.Add(catalog);
                    continue;
                }

                fallbackResult.Add(new TargetDefinition
                {
                    Name = host,
                    Host = host,
                    Service = "Пользовательский"
                });
            }
            return fallbackResult;
        }

        private static string BuildHelp()
        {
            return string.Join(Environment.NewLine, new[]
            {
                "Usage:",
                "  ISP_Audit.exe --targets youtube.com,discord.com --report result.json --timeout 12 --verbose",
                "",
                "Options:",
                "  --targets <file|list>   Comma-separated hosts or path to JSON/CSV",
                "  --report <path>         Save JSON report (default isp_report.json)",
                "  --timeout <s>           Global timeout hint (http=12s, tcp/udp=3s by default)",
                "  --ports <list>          TCP ports to test (default 80,443,8000-8020)",
                "  --no-trace              Disable system tracert wrapper",
                "  --verbose               Verbose logging",
                "  --json                  Also print a short JSON summary to stdout",
                "  --help                  Show this help",
            });
        }

        public string[] ToArgsArray()
        {
            var args = new List<string>();
            if (Targets.Count > 0) args.AddRange(new[] { "--targets", string.Join(',', Targets) });
            if (!string.IsNullOrWhiteSpace(ReportPath)) args.AddRange(new[] { "--report", ReportPath });
            if (Verbose) args.Add("--verbose");
            if (PrintJson) args.Add("--json");
            if (NoTrace) args.Add("--no-trace");
            if (HttpTimeoutSeconds != 12) args.AddRange(new[] { "--timeout", HttpTimeoutSeconds.ToString() });
            if (!(Ports.Count == 2 && Ports.Contains(80) && Ports.Contains(443))) args.AddRange(new[] { "--ports", string.Join(',', Ports) });
            return args.ToArray();
        }

        public static void LoadGameProfile(string profileName)
        {
            try
            {
                string profilePath = Path.Combine("Profiles", $"{profileName}.json");
                
                if (!File.Exists(profilePath))
                {
                    throw new FileNotFoundException($"Профиль '{profileName}' не найден по пути: {profilePath}");
                }

                string json = File.ReadAllText(profilePath);
                var profile = System.Text.Json.JsonSerializer.Deserialize<GameProfile>(json);
                
                if (profile == null)
                {
                    throw new InvalidOperationException($"Не удалось десериализовать профиль '{profileName}'");
                }

                ActiveProfile = profile;
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine($"⚠️ Ошибка загрузки профиля: {ex.Message}");
                ActiveProfile = null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Ошибка при загрузке профиля '{profileName}': {ex.Message}");
                ActiveProfile = null;
            }
        }

        public static void SetActiveProfile(string profileName)
        {
            LoadGameProfile(profileName);
            
            // Обновить Program.Targets для совместимости с GUI
            if (ActiveProfile != null && ActiveProfile.Targets.Count > 0)
            {
                Program.Targets = ActiveProfile.Targets.ToDictionary(
                    t => t.Name,
                    t => new TargetDefinition
                    {
                        Name = t.Name,
                        Host = t.Host,
                        Service = t.Service,
                        Critical = t.Critical,
                        FallbackIp = t.FallbackIp
                    },
                    StringComparer.OrdinalIgnoreCase
                );
            }
        }
    }
}
