using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace IspAudit
{
    public static class TargetCatalog
    {
        private const string CatalogFileName = "game_targets.json";

        public static IReadOnlyList<TargetDefinition> Targets { get; }
        public static IReadOnlyList<int> DefaultTcpPorts { get; }
        public static IReadOnlyList<UdpProbeDefinition> UdpProbes { get; }

        private static readonly Dictionary<string, TargetDefinition> TargetsByHost;

        static TargetCatalog()
        {
            var fallback = BuildFallback();
            TargetCatalogData data = fallback;
            try
            {
                var path = LocateCatalogFile();
                if (path != null && File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    var opts = new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true,
                        ReadCommentHandling = JsonCommentHandling.Skip,
                    };
                    opts.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
                    var loaded = JsonSerializer.Deserialize<TargetCatalogData>(json, opts);
                    if (loaded != null && loaded.Targets.Count > 0)
                    {
                        data = new TargetCatalogData
                        {
                            Targets = loaded.Targets,
                            TcpPorts = loaded.TcpPorts.Count > 0 ? loaded.TcpPorts : fallback.TcpPorts,
                            UdpProbes = loaded.UdpProbes.Count > 0 ? loaded.UdpProbes : fallback.UdpProbes
                        };
                    }
                }
            }
            catch
            {
                data = fallback;
            }

            Targets = data.Targets;
            DefaultTcpPorts = data.TcpPorts.Count > 0 ? data.TcpPorts : fallback.TcpPorts;
            UdpProbes = data.UdpProbes.Count > 0 ? data.UdpProbes : fallback.UdpProbes;
            TargetsByHost = Targets
                .GroupBy(t => t.Host, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Copy(), StringComparer.OrdinalIgnoreCase);
        }

        public static Dictionary<string, TargetDefinition> CreateDefaultTargetMap()
        {
            return Targets.ToDictionary(t => t.Name, t => t.Copy(), StringComparer.OrdinalIgnoreCase);
        }

        public static List<int> CreateDefaultTcpPorts() => new(DefaultTcpPorts);

        public static List<UdpProbeDefinition> CreateDefaultUdpProbes()
        {
            return UdpProbes.Select(p => p.Copy()).ToList();
        }

        public static TargetDefinition? TryGetByHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return null;
            return TargetsByHost.TryGetValue(host, out var def) ? def.Copy() : null;
        }

        private static string? LocateCatalogFile()
        {
            var baseDir = AppContext.BaseDirectory;
            var candidate = Path.Combine(baseDir, CatalogFileName);
            if (File.Exists(candidate)) return candidate;
            var current = Directory.GetCurrentDirectory();
            candidate = Path.Combine(current, CatalogFileName);
            if (File.Exists(candidate)) return candidate;
            return null;
        }

        private static TargetCatalogData BuildFallback()
        {
            var targets = new List<TargetDefinition>
            {
                new() { Name = "RSI Портал", Host = "robertsspaceindustries.com", Service = "Портал" },
                new() { Name = "RSI Аккаунты", Host = "accounts.robertsspaceindustries.com", Service = "Портал" },
                new() { Name = "RSI API", Host = "api.robertsspaceindustries.com", Service = "API" },
                new() { Name = "RSI CDN", Host = "cdn.robertsspaceindustries.com", Service = "CDN" },
                new() { Name = "RSI Установщик", Host = "install.robertsspaceindustries.com", Service = "CDN" }
            };

            var tcpPorts = new List<int> { 80, 443 };
            tcpPorts.AddRange(Enumerable.Range(8000, 21)); // 8000-8020 включительно

            var udp = new List<UdpProbeDefinition>
            {
                new()
                {
                    Name = "Cloudflare DNS", Host = "1.1.1.1", Port = 53,
                    Service = "Базовая сеть", Kind = UdpProbeKind.Dns, ExpectReply = true,
                    Note = "Проверка UDP DNS"
                }
            };

            return new TargetCatalogData
            {
                Targets = targets,
                TcpPorts = tcpPorts,
                UdpProbes = udp
            };
        }
    }
}
