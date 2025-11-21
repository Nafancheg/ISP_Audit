using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Настройки обхода блокировок для WinDivert.
    /// </summary>
    public sealed class BypassProfile
    {
        private const string ProfileFileName = "bypass_profile.json";

        private static readonly Lazy<BypassProfile> _default = new(() =>
        {
            var fromFile = TryLoadFromFile();
            return fromFile ?? BuildFallback();
        });

        public bool DropTcpRst { get; init; } = true;

        public bool FragmentTlsClientHello { get; init; } = true;

        /// <summary>
        /// Размер первой части ClientHello после фрагментации.
        /// </summary>
        public int TlsFirstFragmentSize { get; init; } = 64;

        /// <summary>
        /// Минимальный размер ClientHello, при котором выполняется фрагментация.
        /// </summary>
        public int TlsFragmentThreshold { get; init; } = 128;

        public IReadOnlyList<BypassRedirectRule> RedirectRules { get; init; } = Array.Empty<BypassRedirectRule>();

        public static BypassProfile CreateDefault() => _default.Value;

        private static BypassProfile? TryLoadFromFile()
        {
            try
            {
                var baseDir = AppContext.BaseDirectory;
                var candidate = Path.Combine(baseDir, ProfileFileName);
                if (!File.Exists(candidate))
                {
                    candidate = Path.Combine(Directory.GetCurrentDirectory(), ProfileFileName);
                    if (!File.Exists(candidate)) return null;
                }

                var json = File.ReadAllText(candidate);
                if (string.IsNullOrWhiteSpace(json)) return null;

                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip,
                };
                options.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());

                var doc = JsonSerializer.Deserialize<BypassProfileDocument>(json, options);
                if (doc == null) return null;

                return new BypassProfile
                {
                    DropTcpRst = doc.DropTcpRst,
                    FragmentTlsClientHello = doc.FragmentTlsClientHello,
                    TlsFirstFragmentSize = doc.TlsFirstFragmentSize > 0 ? doc.TlsFirstFragmentSize : 64,
                    TlsFragmentThreshold = doc.TlsFragmentThreshold > 0 ? doc.TlsFragmentThreshold : 128,
                    RedirectRules = doc.RedirectRules?
                        .Select(r => r.ToRule())
                        .Where(r => r != null)!
                        .Cast<BypassRedirectRule>()
                        .ToList()
                        ?? new List<BypassRedirectRule>()
                };
            }
            catch
            {
                return null;
            }
        }

        private static BypassProfile BuildFallback()
        {
            var gameHosts = TargetCatalog.Targets
                .Where(t => t.Service.Contains("Игровые сервера", StringComparison.OrdinalIgnoreCase))
                .Select(t => t.Host)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var defaultRule = new BypassRedirectRule
            {
                Name = "Игровые UDP порты",
                Protocol = TransportProtocol.Udp,
                Port = 64090,
                RedirectIp = "127.0.0.1",
                RedirectPort = 64090,
                Enabled = false,
                Hosts = gameHosts,
            };

            var defaultTcpRule = new BypassRedirectRule
            {
                Name = "Игровые TCP порты",
                Protocol = TransportProtocol.Tcp,
                Port = 64090,
                RedirectIp = "127.0.0.1",
                RedirectPort = 64090,
                Enabled = false,
                Hosts = gameHosts,
            };

            return new BypassProfile
            {
                DropTcpRst = true,
                FragmentTlsClientHello = true,
                TlsFirstFragmentSize = 64,
                TlsFragmentThreshold = 128,
                RedirectRules = new[] { defaultRule, defaultTcpRule }
            };
        }

        private sealed class BypassProfileDocument
        {
            public bool DropTcpRst { get; set; } = true;
            public bool FragmentTlsClientHello { get; set; } = true;
            public int TlsFirstFragmentSize { get; set; } = 64;
            public int TlsFragmentThreshold { get; set; } = 128;
            public List<BypassRedirectRuleDocument>? RedirectRules { get; set; }
        }

        private sealed class BypassRedirectRuleDocument
        {
            public string? Name { get; set; }
            public TransportProtocol Protocol { get; set; } = TransportProtocol.Tcp;
            public ushort Port { get; set; }
            public string? RedirectIp { get; set; }
            public ushort RedirectPort { get; set; }
            public bool Enabled { get; set; } = true;
            public List<string>? Hosts { get; set; }

            public BypassRedirectRule? ToRule()
            {
                if (string.IsNullOrWhiteSpace(RedirectIp) || Port == 0)
                {
                    return null;
                }

                return new BypassRedirectRule
                {
                    Name = string.IsNullOrWhiteSpace(Name) ? $"Rule:{Protocol}:{Port}" : Name!,
                    Protocol = Protocol,
                    Port = Port,
                    RedirectIp = RedirectIp!,
                    RedirectPort = RedirectPort == 0 ? Port : RedirectPort,
                    Enabled = Enabled,
                    Hosts = Hosts?.Where(h => !string.IsNullOrWhiteSpace(h)).Select(h => h.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                        ?? new List<string>()
                };
            }
        }
    }
}
