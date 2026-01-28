using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace IspAudit.Utils
{
    public sealed class BlockpageHostsConfig
    {
        public int Version { get; set; } = 1;
        public bool Enabled { get; set; } = true;

        public List<string> ExactHosts { get; set; } = new();
        public List<string> ContainsTokens { get; set; } = new();
        public List<PrefixSuffixRule> PrefixSuffixRules { get; set; } = new();
    }

    public sealed class PrefixSuffixRule
    {
        public string Prefix { get; set; } = string.Empty;
        public string Suffix { get; set; } = string.Empty;
    }

    public static class BlockpageHostCatalog
    {
        private const string EnvVarPathOverride = "ISP_AUDIT_BLOCKPAGE_HOSTS_PATH";
        private const string DefaultFileName = "blockpage_hosts.json";

        private sealed class CachedRules
        {
            public string Path { get; init; } = string.Empty;
            public DateTimeOffset? LastWriteUtc { get; init; }
            public BlockpageHostsConfig Config { get; init; } = new();
        }

        private static readonly object Sync = new();
        private static CachedRules? _cache;

        public static string GetDefaultPath()
            => AppPaths.GetStateFilePath(DefaultFileName);

        public static string GetEffectivePath()
        {
            var overridePath = Environment.GetEnvironmentVariable(EnvVarPathOverride);
            if (!string.IsNullOrWhiteSpace(overridePath))
            {
                return overridePath.Trim();
            }

            return GetDefaultPath();
        }

        public static bool IsLikelyProviderBlockpageHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;

            var normalized = NormalizeHost(host);
            if (string.IsNullOrWhiteSpace(normalized)) return false;

            var cfg = GetConfigBestEffort();
            if (!cfg.Enabled) return false;

            foreach (var exact in cfg.ExactHosts ?? Enumerable.Empty<string>())
            {
                var e = NormalizeHost(exact);
                if (string.IsNullOrWhiteSpace(e)) continue;
                if (string.Equals(normalized, e, StringComparison.OrdinalIgnoreCase)) return true;
            }

            foreach (var token in cfg.ContainsTokens ?? Enumerable.Empty<string>())
            {
                var t = (token ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(t)) continue;
                if (normalized.Contains(t, StringComparison.OrdinalIgnoreCase)) return true;
            }

            foreach (var rule in cfg.PrefixSuffixRules ?? Enumerable.Empty<PrefixSuffixRule>())
            {
                var prefix = (rule?.Prefix ?? string.Empty).Trim();
                var suffix = (rule?.Suffix ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(prefix) || string.IsNullOrWhiteSpace(suffix)) continue;

                if (normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                    normalized.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static BlockpageHostsConfig GetConfigBestEffort()
        {
            var path = GetEffectivePath();

            lock (Sync)
            {
                var lastWriteUtc = TryGetLastWriteUtc(path);

                if (_cache != null &&
                    string.Equals(_cache.Path, path, StringComparison.OrdinalIgnoreCase) &&
                    Nullable.Equals(_cache.LastWriteUtc, lastWriteUtc))
                {
                    return _cache.Config;
                }

                var cfg = TryLoad(path) ?? new BlockpageHostsConfig
                {
                    // Встроенный fallback пустой: справочник поставляется как внешний JSON рядом с приложением.
                    Enabled = true
                };

                _cache = new CachedRules
                {
                    Path = path,
                    LastWriteUtc = lastWriteUtc,
                    Config = cfg
                };

                return cfg;
            }
        }

        private static DateTimeOffset? TryGetLastWriteUtc(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path)) return null;
                if (!File.Exists(path)) return null;
                return File.GetLastWriteTimeUtc(path);
            }
            catch
            {
                return null;
            }
        }

        private static BlockpageHostsConfig? TryLoad(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path)) return null;
                if (!File.Exists(path)) return null;

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return null;

                var cfg = JsonSerializer.Deserialize<BlockpageHostsConfig>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (cfg == null) return null;

                // Нормализация коллекций (best-effort)
                cfg.ExactHosts ??= new List<string>();
                cfg.ContainsTokens ??= new List<string>();
                cfg.PrefixSuffixRules ??= new List<PrefixSuffixRule>();

                return cfg;
            }
            catch
            {
                return null;
            }
        }

        private static string NormalizeHost(string value)
            => (value ?? string.Empty).Trim().TrimEnd('.');
    }
}
