using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IspAudit
{
    public class Config
    {
        public List<string> Targets { get; set; } = new();
        public string ReportPath { get; set; } = string.Empty;
        public bool Verbose { get; set; } = false;
        public bool PrintJson { get; set; } = false;
        public bool NoTrace { get; set; } = false;
        public bool ShowHelp { get; set; } = false;

        // Timeouts in seconds
        public int HttpTimeoutSeconds { get; set; } = 12;
        public int TcpTimeoutSeconds { get; set; } = 3;
        public int UdpTimeoutSeconds { get; set; } = 3;

        // Ports list for TCP checks
        public List<int> Ports { get; set; } = new() { 80, 443 };

        // Toggle tests (GUI использует)
        public bool EnableDns { get; set; } = true;
        public bool EnableTcp { get; set; } = true;
        public bool EnableHttp { get; set; } = true;
        public bool EnableTrace { get; set; } = true;
        public bool EnableUdp { get; set; } = true;
        public bool EnableRst { get; set; } = true;

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
                    }
                    else
                    {
                        // {"Name":"host"} or {"name":"host"}
                        var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();
                        cfg.Targets = dict.Values.Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();
                    }
                }
                else
                {
                    // CSV: lines of "name,host" or just "host"
                    var hosts = new List<string>();
                    foreach (var line in File.ReadAllLines(value))
                    {
                        var l = line.Trim();
                        if (string.IsNullOrEmpty(l) || l.StartsWith("#")) continue;
                        var parts = l.Split(',', StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 1) hosts.Add(parts[0].Trim());
                        else if (parts.Length >= 2) hosts.Add(parts[1].Trim());
                    }
                    cfg.Targets = hosts.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();
                }
            }
            else
            {
                cfg.Targets = value.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Distinct()
                    .ToList();
            }
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
                "  --ports <list>          TCP ports to test (default 80,443)",
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
    }
}
