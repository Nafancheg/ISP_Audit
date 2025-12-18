using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static IReadOnlyDictionary<string, Func<CancellationToken, Task<SmokeTestResult>>> GetImplementedTests()
            => new Dictionary<string, Func<CancellationToken, Task<SmokeTestResult>>>(StringComparer.OrdinalIgnoreCase)
            {
                ["INFRA-001"] = Infra_WinDivertDriver,
                ["INFRA-002"] = Infra_FilterRegistration,
                ["INFRA-003"] = Infra_FilterOrder,
                ["INFRA-004"] = Infra_AdminRights,
                ["INFRA-005"] = Infra_EncodingCp866,

                ["UI-011"] = Ui_UiReducerSmoke,

                ["PIPE-005"] = Pipe_UnifiedFilter_LoopbackDropped,
                ["PIPE-006"] = Pipe_UnifiedFilter_NoiseOnlyOnDisplay,
                ["PIPE-007"] = Pipe_TrafficCollector_DedupByRemoteIpPortProto_Polling,
                ["PIPE-008"] = Pipe_Tester_DnsResolve_Google,
                ["PIPE-009"] = Pipe_Tester_TcpHandshake_Google443,
                ["PIPE-010"] = Pipe_Tester_TlsHandshake_Google443_Sni,
                ["PIPE-011"] = Pipe_Tester_ReverseDns_8888,
                ["PIPE-012"] = Pipe_Classifier_DnsBlocked,
                ["PIPE-013"] = Pipe_Classifier_TcpTimeout,
                ["PIPE-014"] = Pipe_Classifier_TcpReset,
                ["PIPE-015"] = Pipe_Classifier_DpiFilter_Tls,
                ["PIPE-016"] = Pipe_Classifier_FakeIpRange,

                ["CFG-001"] = Cfg_BypassProfile_Load,
                ["CFG-002"] = Cfg_BypassProfile_SaveChanges,
                ["CFG-003"] = Cfg_BypassProfile_CorruptJson_Graceful,
                ["CFG-004"] = Cfg_NoiseHostFilter_Singleton,
                ["CFG-005"] = Cfg_NoiseHostFilter_LoadAndMatch,

                ["BYPASS-001"] = Bypass_TlsBypassService_RegistersFilter,
                ["BYPASS-002"] = Bypass_TlsBypassService_RemovesFilter,
                ["BYPASS-005"] = Bypass_TlsBypassService_ProfilePresetPresent,
            };

        public static Task<SmokeTestResult> NotImplemented(string id, string name, CancellationToken ct)
            => Task.FromResult(new SmokeTestResult(
                id,
                string.IsNullOrWhiteSpace(name) ? "Не реализовано" : name,
                SmokeOutcome.Fail,
                TimeSpan.Zero,
                "Тест из плана присутствует, но ещё не реализован в SmokeRunner"));
    }
}
