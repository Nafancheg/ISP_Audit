using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit
{
    /// <summary>
    /// Описывает набор проверок для конкретного типа сервиса Star Citizen.
    /// </summary>
    public sealed class ServiceTestProfile
    {
        public string Key { get; }
        public string DisplayName { get; }
        public bool RunDns { get; }
        public bool RunTcp { get; }
        public bool RunHttp { get; }
        public bool RunTrace { get; }
        public IReadOnlyList<int>? PreferredTcpPorts { get; }

        public ServiceTestProfile(
            string key,
            string displayName,
            bool runDns = true,
            bool runTcp = true,
            bool runHttp = true,
            bool runTrace = true,
            IReadOnlyList<int>? preferredTcpPorts = null)
        {
            Key = key;
            DisplayName = displayName;
            RunDns = runDns;
            RunTcp = runTcp;
            RunHttp = runHttp;
            RunTrace = runTrace;
            PreferredTcpPorts = preferredTcpPorts;
        }

        public IReadOnlyList<int> ResolveTcpPorts(IEnumerable<int> fallback)
        {
            if (PreferredTcpPorts != null && PreferredTcpPorts.Count > 0)
            {
                return PreferredTcpPorts;
            }

            return fallback switch
            {
                IReadOnlyList<int> list => list,
                _ => fallback.Distinct().ToList()
            };
        }
    }

    /// <summary>
    /// Централизованный справочник профилей тестирования.
    /// </summary>
    public static class TargetServiceProfiles
    {
        private static readonly ServiceTestProfile DefaultProfile = new(
            "default",
            "Общий сервис",
            runDns: true,
            runTcp: true,
            runHttp: true,
            runTrace: true,
            preferredTcpPorts: TargetCatalog.DefaultTcpPorts);

        private static readonly Dictionary<string, ServiceTestProfile> Profiles = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Портал"] = new ServiceTestProfile(
                "portal",
                "Веб-порталы RSI",
                preferredTcpPorts: new List<int> { 80, 443 }),
            ["Лаунчер"] = new ServiceTestProfile(
                "launcher",
                "Лаунчер Star Citizen",
                preferredTcpPorts: Enumerable.Range(8000, 21).Prepend(443).ToList()),
            ["CDN"] = new ServiceTestProfile(
                "cdn",
                "CDN и загрузчик",
                preferredTcpPorts: new List<int> { 80, 443 }),
            ["Игровые сервера"] = new ServiceTestProfile(
                "game",
                "Игровые сервера Star Citizen",
                runHttp: false,
                preferredTcpPorts: Enumerable.Range(8000, 21).ToList()),
            ["Базовая сеть"] = new ServiceTestProfile(
                "base_network",
                "Базовая сеть",
                preferredTcpPorts: TargetCatalog.DefaultTcpPorts)
        };

        public static ServiceTestProfile Resolve(string? service)
        {
            if (string.IsNullOrWhiteSpace(service))
            {
                return DefaultProfile;
            }

            if (Profiles.TryGetValue(service.Trim(), out var profile))
            {
                return profile;
            }

            if (service.Contains("игров", StringComparison.OrdinalIgnoreCase))
            {
                return Profiles["Игровые сервера"];
            }

            if (service.Contains("лаунч", StringComparison.OrdinalIgnoreCase))
            {
                return Profiles["Лаунчер"];
            }

            if (service.Contains("cdn", StringComparison.OrdinalIgnoreCase))
            {
                return Profiles["CDN"];
            }

            if (service.Contains("портал", StringComparison.OrdinalIgnoreCase) || service.Contains("rsi", StringComparison.OrdinalIgnoreCase))
            {
                return Profiles["Портал"];
            }

            return DefaultProfile;
        }
    }
}

