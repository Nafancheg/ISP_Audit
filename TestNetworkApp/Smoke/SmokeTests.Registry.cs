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
                ["PIPE-001"] = Pipe_ConnectionMonitor_PublishesEvents_OnTcpConnect,
                ["PIPE-002"] = Pipe_TrafficCollector_PidFiltering_IgnoresOtherPid,
                ["PIPE-003"] = Pipe_DnsParser_SniParsing_OneShotAndFragmented,
                ["PIPE-004"] = Pipe_Orchestrator_SniGating_ByRemoteEndpointPid,
                ["PIPE-007"] = Pipe_StateStore_Dedup_SingleSession,
                ["PIPE-008"] = Pipe_Tester_DnsResolve_Google,
                ["PIPE-009"] = Pipe_Tester_TcpHandshake_Google443,
                ["PIPE-010"] = Pipe_Tester_TlsHandshake_Google443_Sni,
                ["PIPE-011"] = Pipe_Tester_ReverseDns_8888,
                ["PIPE-017"] = Pipe_PipelineHealth_EmitsLog_OnActivity,
                ["PIPE-012"] = Pipe_Classifier_DnsBlocked,
                ["PIPE-013"] = Pipe_Classifier_TcpTimeout,
                ["PIPE-014"] = Pipe_Classifier_TcpReset,
                ["PIPE-015"] = Pipe_Classifier_DpiFilter_Tls,
                ["PIPE-016"] = Pipe_Classifier_FakeIpRange,

                ["INSP-001"] = Insp_RstInspection_TtlInjectionDetected,
                ["INSP-002"] = Insp_RstInspection_IpIdAnomalyDetected,
                ["INSP-003"] = Insp_UdpInspection_QuicBlockageDetected,
                ["INSP-004"] = Insp_TcpRetransmissionTracker_DropSuspicion,
                ["INSP-005"] = Insp_HttpRedirectDetector_BlockpageHost,

                ["DPI2-001"] = Dpi2_SignalsAdapter_Observe_AdaptsLegacySignals_ToTtlStore,
                ["DPI2-002"] = Dpi2_SignalStore_Ttl_DeletesEventsOlderThan10Minutes,
                ["DPI2-003"] = Dpi2_Aggregation_BuildSnapshot_RespectsWindow_30s_60s,
                ["DPI2-004"] = Dpi2_DiagnosisEngine_ProducesDiagnosis_WithConfidenceAtLeast50,
                ["DPI2-005"] = Dpi2_DiagnosisEngine_Explanation_IsFactBased_NoStrategiesMentioned,
                ["DPI2-006"] = Dpi2_GateMarkers_Gate1_EmittedInProgressLog,
                ["DPI2-007"] = Dpi2_StrategySelector_BuildsPlan_AndExecutorFormatsRecommendation,
                ["DPI2-008"] = Dpi2_StrategySelector_HighRiskBlocked_WhenConfidenceBelow70,
                ["DPI2-009"] = Dpi2_StrategySelector_EmptyPlan_WhenConfidenceBelow50,
                ["DPI2-010"] = Dpi2_StrategySelector_WarnsAndSkips_UnimplementedStrategies,
                ["DPI2-011"] = Dpi2_ExecutorMvp_FormatsCompactOutput_OneLine,
                ["DPI2-012"] = Dpi2_AllV2Outputs_StartWithPrefix,
                ["DPI2-013"] = Dpi2_ExecutorMvp_DoesNotCallTrafficEngineOrBypassController,

                ["CFG-001"] = Cfg_BypassProfile_Load,
                ["CFG-002"] = Cfg_BypassProfile_SaveChanges,
                ["CFG-003"] = Cfg_BypassProfile_CorruptJson_Graceful,
                ["CFG-004"] = Cfg_NoiseHostFilter_Singleton,
                ["CFG-005"] = Cfg_NoiseHostFilter_LoadAndMatch,

                ["BYPASS-001"] = Bypass_TlsBypassService_RegistersFilter,
                ["BYPASS-002"] = Bypass_TlsBypassService_RemovesFilter,
                ["BYPASS-003"] = Bypass_TlsBypassService_MetricsUpdated_Periodic,
                ["BYPASS-004"] = Bypass_TlsBypassService_VerdictChanged_RatioThresholds,
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
