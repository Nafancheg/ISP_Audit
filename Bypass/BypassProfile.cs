using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace IspAudit.Bypass
{
    public enum TlsBypassStrategy
    {
        None,
        Fragment,
        Disorder,      // Фрагменты в обратном порядке (второй, потом первый)
        Fake,
        FakeFragment,
        FakeDisorder   // Fake + Disorder
    }

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
        /// Стратегия обхода для TLS (HTTPS).
        /// </summary>
        public TlsBypassStrategy TlsStrategy { get; init; } = TlsBypassStrategy.Fragment;

        /// <summary>
        /// Последний выбранный пресет фрагментации (для восстановления UI).
        /// </summary>
        public string FragmentPresetName { get; init; } = "Профиль";

        /// <summary>
        /// Флаг автокоррекции для агрессивного пресета.
        /// </summary>
        public bool AutoAdjustAggressive { get; init; }

        /// <summary>
        /// Размер первой части ClientHello после фрагментации.
        /// </summary>
        public int TlsFirstFragmentSize { get; init; } = 64;

        /// <summary>
        /// Минимальный размер ClientHello, при котором выполняется фрагментация.
        /// </summary>
        public int TlsFragmentThreshold { get; init; } = 128;

        /// <summary>
        /// Набор размеров фрагментов ClientHello (последний фрагмент = остаток).
        /// Первый элемент должен быть > 0, список должен давать хотя бы 2 фрагмента.
        /// </summary>
        public IReadOnlyList<int> TlsFragmentSizes { get; init; } = new List<int> { 64 };

        /// <summary>
        /// Использовать TTL Trick (отправка копии пакета с малым TTL).
        /// </summary>
        public bool TtlTrick { get; init; } = false;

        /// <summary>
        /// Значение TTL для TTL Trick (обычно 3-5).
        /// </summary>
        public int TtlTrickValue { get; init; } = 3;

        public IReadOnlyList<BypassRedirectRule> RedirectRules { get; init; } = Array.Empty<BypassRedirectRule>();

        public static BypassProfile CreateDefault() => _default.Value;

        public static void Save(BypassProfile profile)
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true
                };
                options.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());

                var doc = new BypassProfileDocument
                {
                    DropTcpRst = profile.DropTcpRst,
                    FragmentTlsClientHello = profile.FragmentTlsClientHello,
                    TlsStrategy = profile.TlsStrategy,
                    TlsFirstFragmentSize = profile.TlsFirstFragmentSize,
                    TlsFragmentThreshold = profile.TlsFragmentThreshold,
                    TlsFragmentSizes = profile.TlsFragmentSizes?.ToList() ?? new List<int>(),
                    TtlTrick = profile.TtlTrick,
                    TtlTrickValue = profile.TtlTrickValue,
                    RedirectRules = profile.RedirectRules?
                        .Select(r => new BypassRedirectRuleDocument
                        {
                            Name = r.Name,
                            Protocol = r.Protocol,
                            Port = r.Port,
                            RedirectIp = r.RedirectIp,
                            RedirectPort = r.RedirectPort,
                            Enabled = r.Enabled,
                            Hosts = r.Hosts?.ToList()
                        })
                        .ToList(),
                    FragmentPresetName = profile.FragmentPresetName,
                    AutoAdjustAggressive = profile.AutoAdjustAggressive
                };

                var json = JsonSerializer.Serialize(doc, options);
                var path = GetProfilePath();
                File.WriteAllText(path, json);
            }
            catch
            {
                // Игнорируем ошибки записи, чтобы не падать в GUI сценариях
            }
        }

        private static BypassProfile? TryLoadFromFile()
        {
            try
            {
                var candidate = GetProfilePath();
                if (!File.Exists(candidate)) return null;

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

                var threshold = doc.TlsFragmentThreshold > 0 ? doc.TlsFragmentThreshold : 128;
                var normalizedSizes = NormalizeFragmentSizes(doc.TlsFragmentSizes, doc.TlsFirstFragmentSize, threshold);
                var presetName = string.IsNullOrWhiteSpace(doc.FragmentPresetName) ? "Профиль" : doc.FragmentPresetName;

                return new BypassProfile
                {
                    DropTcpRst = doc.DropTcpRst,
                    FragmentTlsClientHello = doc.FragmentTlsClientHello,
                    TlsStrategy = doc.TlsStrategy,
                    TlsFirstFragmentSize = doc.TlsFirstFragmentSize > 0 ? doc.TlsFirstFragmentSize : 64,
                    TlsFragmentThreshold = threshold,
                    TlsFragmentSizes = normalizedSizes,
                    FragmentPresetName = presetName,
                    AutoAdjustAggressive = doc.AutoAdjustAggressive,
                    TtlTrick = doc.TtlTrick,
                    TtlTrickValue = doc.TtlTrickValue > 0 ? doc.TtlTrickValue : 3,
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

        private static string GetProfilePath()
        {
            var baseDir = AppContext.BaseDirectory;
            var candidate = Path.Combine(baseDir, ProfileFileName);
            if (File.Exists(candidate)) return candidate;
            candidate = Path.Combine(Directory.GetCurrentDirectory(), ProfileFileName);
            return candidate;
        }

        private static BypassProfile BuildFallback()
        {
            // В новой архитектуре список игровых хостов формируется динамически,
            // поэтому fallback-профиль не привязывается к TargetCatalog.
            var gameHosts = new List<string>();

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
                TlsStrategy = TlsBypassStrategy.Fragment,
                TlsFirstFragmentSize = 64,
                TlsFragmentThreshold = 128,
                TlsFragmentSizes = new List<int> { 64 },
                FragmentPresetName = "Профиль",
                AutoAdjustAggressive = false,
                RedirectRules = new[] { defaultRule, defaultTcpRule }
            };
        }

        private static IReadOnlyList<int> NormalizeFragmentSizes(IEnumerable<int>? sizes, int fallbackSize, int minClientHelloSize)
        {
            const int maxTlsRecord = 16384;
            const int minChunk = 4;

            var normalized = sizes?
                .Where(v => v > 0)
                .Select(v => Math.Max(minChunk, v))
                .Take(4) // ограничиваем разумно, чтобы не ломать стабильность
                .ToList();

            if (normalized is { Count: > 0 })
            {
                var sum = normalized.Sum();
                if (sum < minClientHelloSize || sum > maxTlsRecord)
                {
                    return BuildFallbackSizes(fallbackSize);
                }
                return normalized;
            }

            return BuildFallbackSizes(fallbackSize);
        }

        private static IReadOnlyList<int> BuildFallbackSizes(int fallbackSize)
        {
            const int minChunk = 4;
            var safeSize = Math.Max(minChunk, fallbackSize > 0 ? fallbackSize : 64);
            return new List<int> { safeSize };
        }

        private sealed class BypassProfileDocument
        {
            public bool DropTcpRst { get; set; } = true;
            public bool FragmentTlsClientHello { get; set; } = true;
            public TlsBypassStrategy TlsStrategy { get; set; } = TlsBypassStrategy.Fragment;
            public int TlsFirstFragmentSize { get; set; } = 64;
            public int TlsFragmentThreshold { get; set; } = 128;
            public List<int>? TlsFragmentSizes { get; set; }
            public bool TtlTrick { get; set; }
            public int TtlTrickValue { get; set; } = 3;
            public string? FragmentPresetName { get; set; }
            public bool AutoAdjustAggressive { get; set; }
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
