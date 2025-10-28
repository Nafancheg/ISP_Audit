using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit
{
    public readonly record struct TargetTestProfile(
        bool RunDns,
        bool RunTcp,
        bool RunHttp,
        bool RunTrace,
        IReadOnlyList<int>? TcpPortsOverride
    );

    public readonly record struct TargetTestPlan(
        bool RunDns,
        bool RunTcp,
        bool RunHttp,
        bool RunTrace,
        IReadOnlyList<int> TcpPorts
    );

    public readonly record struct TestUsage(
        bool Dns,
        bool Tcp,
        bool Http,
        bool Trace,
        bool Udp,
        bool Rst
    );

    public static class ServiceTestMatrix
    {
        private static readonly IReadOnlyList<int> GameServerTcpPorts = Enumerable.Range(64090, 11).ToArray();

        private static readonly TargetTestProfile DefaultProfile = new(true, true, true, true, null);

        private static readonly Dictionary<string, TargetTestProfile> Profiles = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Портал"] = DefaultProfile,
            ["Лаунчер"] = DefaultProfile,
            ["CDN"] = DefaultProfile,
            ["Игровые сервера"] = new TargetTestProfile(true, true, false, true, GameServerTcpPorts),
            ["Прочее"] = DefaultProfile,
            ["Пользовательский"] = DefaultProfile,
        };

        public static TargetTestPlan GetPlan(TargetDefinition def, Config cfg)
        {
            if (def == null) throw new ArgumentNullException(nameof(def));
            if (cfg == null) throw new ArgumentNullException(nameof(cfg));

            var profile = GetProfile(def.Service);
            bool runDns = cfg.EnableDns && profile.RunDns;
            bool runTcp = cfg.EnableTcp && profile.RunTcp;
            bool runHttp = cfg.EnableHttp && profile.RunHttp;
            bool runTrace = (cfg.EnableTrace && !cfg.NoTrace) && profile.RunTrace;

            var ports = profile.TcpPortsOverride != null && profile.TcpPortsOverride.Count > 0
                ? profile.TcpPortsOverride
                : cfg.Ports;

            if (runTcp && ports.Count == 0)
            {
                ports = new List<int> { 80, 443 };
            }

            return new TargetTestPlan(runDns, runTcp, runHttp, runTrace, ports);
        }

        public static TestUsage CalculateUsage(IEnumerable<TargetDefinition> targets, Config cfg)
        {
            if (targets == null) throw new ArgumentNullException(nameof(targets));
            if (cfg == null) throw new ArgumentNullException(nameof(cfg));

            bool dns = false;
            bool tcp = false;
            bool http = false;
            bool trace = false;

            foreach (var def in targets)
            {
                var plan = GetPlan(def, cfg);
                dns |= plan.RunDns;
                tcp |= plan.RunTcp;
                http |= plan.RunHttp;
                trace |= plan.RunTrace;
            }

            bool udp = cfg.EnableUdp && cfg.UdpProbes.Count > 0;
            bool rst = cfg.EnableRst;

            return new TestUsage(dns, tcp, http, trace, udp, rst);
        }

        private static TargetTestProfile GetProfile(string? service)
        {
            if (string.IsNullOrWhiteSpace(service)) return DefaultProfile;
            return Profiles.TryGetValue(service.Trim(), out var profile) ? profile : DefaultProfile;
        }
    }
}
