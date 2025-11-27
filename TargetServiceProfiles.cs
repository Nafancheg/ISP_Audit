using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit
{
    /// <summary>
    /// Описывает набор проверок для конкретного типа игрового сервиса.
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
            "Сервис",
            runDns: true,
            runTcp: true,
            runHttp: true,
            runTrace: true,
            preferredTcpPorts: null); // Порты теперь в JSON

        private static readonly Dictionary<string, ServiceTestProfile> Profiles = new(StringComparer.OrdinalIgnoreCase)
        {
            ["web"] = new ServiceTestProfile("web", "Web-сервис", runDns: true, runTcp: true, runHttp: true, runTrace: false),
            ["game-tcp"] = new ServiceTestProfile("game-tcp", "Игровой сервер (TCP)", runDns: true, runTcp: true, runHttp: false, runTrace: false),
            ["game-udp"] = new ServiceTestProfile("game-udp", "Игровой сервер (UDP)", runDns: true, runTcp: false, runHttp: false, runTrace: false),
            ["voice-tcp"] = new ServiceTestProfile("voice-tcp", "Голосовой чат (TCP)", runDns: true, runTcp: true, runHttp: false, runTrace: false),
            ["voice-udp"] = new ServiceTestProfile("voice-udp", "Голосовой чат (UDP)", runDns: true, runTcp: false, runHttp: false, runTrace: false),
            ["dns"] = new ServiceTestProfile("dns", "DNS", runDns: true, runTcp: false, runHttp: false, runTrace: false),
            // DNS-failed: хосты с неудавшимся DNS резолвом — не тестируем TCP/HTTP (нет IP)
            ["dns-failed"] = new ServiceTestProfile("dns-failed", "DNS не отвечает", runDns: false, runTcp: false, runHttp: false, runTrace: false),
            ["unknown-tcp"] = new ServiceTestProfile("unknown-tcp", "Неизвестный (TCP)", runDns: true, runTcp: true, runHttp: false, runTrace: false),
            ["unknown-udp"] = new ServiceTestProfile("unknown-udp", "Неизвестный (UDP)", runDns: true, runTcp: false, runHttp: false, runTrace: false),
            ["unknown"] = new ServiceTestProfile("unknown", "Неизвестный", runDns: true, runTcp: true, runHttp: false, runTrace: false),
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

            // Для всех остальных случаев - полный набор тестов
            return DefaultProfile;
        }
    }
}

