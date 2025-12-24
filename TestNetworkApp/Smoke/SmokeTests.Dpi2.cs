using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Reflection.Emit;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.IntelligenceV2.Diagnosis;
using IspAudit.Core.IntelligenceV2.Execution;
using IspAudit.Core.IntelligenceV2.Feedback;
using IspAudit.Core.IntelligenceV2.Signals;
using IspAudit.Core.IntelligenceV2.Strategies;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;
using IspAudit.Utils;
using IspAudit.ViewModels;

using BypassTransportProtocol = IspAudit.Bypass.TransportProtocol;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> Dpi2_SignalsAdapter_Observe_AdaptsLegacySignals_ToTtlStore(CancellationToken ct)
            => RunAsync("DPI2-001", "SignalsAdapterV2 адаптирует legacy сигналы и пишет в TTL-store", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapterV2(store);

                var tested = CreateHostTested(
                    remoteIp: IPAddress.Parse("203.0.113.10"),
                    blockageType: BlockageCode.TcpConnectionReset);

                var legacy = new BlockageSignals(
                    FailCount: 1,
                    HardFailCount: 1,
                    LastFailAt: DateTime.UtcNow,
                    Window: TimeSpan.FromSeconds(30),
                    RetransmissionCount: 0,
                    TotalPackets: 0,
                    HasHttpRedirectDpi: false,
                    RedirectToHost: null,
                    HasSuspiciousRst: true,
                    SuspiciousRstDetails: "TTL=5 (expected 50-55)",
                    UdpUnansweredHandshakes: 0);

                adapter.Observe(tested, legacy);

                var hostKey = SignalsAdapterV2.BuildStableHostKey(tested);
                var events = store.ReadWindow(hostKey, DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1), DateTimeOffset.UtcNow + TimeSpan.FromSeconds(1));

                if (!events.Any(e => e.Type == SignalEventType.HostTested))
                {
                    return new SmokeTestResult("DPI2-001", "SignalsAdapterV2 адаптирует legacy сигналы и пишет в TTL-store", SmokeOutcome.Fail, TimeSpan.Zero,
                        "В сторе нет события HostTested после Observe(...)");
                }

                if (!events.Any(e => e.Type == SignalEventType.SuspiciousRstObserved))
                {
                    return new SmokeTestResult("DPI2-001", "SignalsAdapterV2 адаптирует legacy сигналы и пишет в TTL-store", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали событие SuspiciousRstObserved из legacy сигналов, но его нет");
                }

                return new SmokeTestResult("DPI2-001", "SignalsAdapterV2 адаптирует legacy сигналы и пишет в TTL-store", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: events={events.Count}, hostKey={hostKey}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_SignalStore_Ttl_DeletesEventsOlderThan10Minutes(CancellationToken ct)
            => RunAsync("DPI2-002", "TTL событий v2: старше 10 минут удаляются при Append", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var hostKey = "203.0.113.20";

                var old = new SignalEvent
                {
                    HostKey = hostKey,
                    Type = SignalEventType.HostTested,
                    ObservedAtUtc = DateTimeOffset.UtcNow - IntelligenceV2ContractDefaults.EventTtl - TimeSpan.FromMinutes(1),
                    Source = "Smoke",
                    Value = null,
                    Reason = "old"
                };

                store.Append(old);

                var fresh = new SignalEvent
                {
                    HostKey = hostKey,
                    Type = SignalEventType.TcpRetransStats,
                    ObservedAtUtc = DateTimeOffset.UtcNow,
                    Source = "Smoke",
                    Value = null,
                    Reason = "fresh"
                };

                store.Append(fresh);

                var events = store.ReadWindow(hostKey, DateTimeOffset.UtcNow - TimeSpan.FromHours(1), DateTimeOffset.UtcNow + TimeSpan.FromSeconds(1));

                if (events.Any(e => e.Reason == "old"))
                {
                    return new SmokeTestResult("DPI2-002", "TTL событий v2: старше 10 минут удаляются при Append", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что старое событие будет удалено, но оно осталось. events={events.Count}");
                }

                if (!events.Any(e => e.Reason == "fresh"))
                {
                    return new SmokeTestResult("DPI2-002", "TTL событий v2: старше 10 минут удаляются при Append", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что свежее событие останется, но его нет");
                }

                return new SmokeTestResult("DPI2-002", "TTL событий v2: старше 10 минут удаляются при Append", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: старые события удаляются только при Append (без таймеров)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Aggregation_BuildSnapshot_RespectsWindow_30s_60s(CancellationToken ct)
            => RunAsync("DPI2-003", "Агрегация v2: BuildSnapshot корректно считает окно 30s/60s", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapterV2(store);

                var tested = CreateHostTested(remoteIp: IPAddress.Parse("203.0.113.30"), blockageType: BlockageCode.TcpConnectTimeout);
                var hostKey = SignalsAdapterV2.BuildStableHostKey(tested);

                var now = DateTimeOffset.UtcNow;

                // 5 событий в пределах 30 секунд
                for (var i = 0; i < 5; i++)
                {
                    store.Append(new SignalEvent
                    {
                        HostKey = hostKey,
                        Type = i == 0 ? SignalEventType.SuspiciousRstObserved : SignalEventType.TcpRetransStats,
                        ObservedAtUtc = now - TimeSpan.FromSeconds(25) + TimeSpan.FromMilliseconds(i),
                        Source = "Smoke",
                        Value = null,
                        Reason = "in30"
                    });
                }

                // 5 событий только в extended окне (старше 30s, но младше 60s)
                for (var i = 0; i < 5; i++)
                {
                    store.Append(new SignalEvent
                    {
                        HostKey = hostKey,
                        Type = SignalEventType.TcpRetransStats,
                        ObservedAtUtc = now - TimeSpan.FromSeconds(40) + TimeSpan.FromMilliseconds(i),
                        Source = "Smoke",
                        Value = null,
                        Reason = "in60"
                    });
                }

                var legacy = new BlockageSignals(
                    FailCount: 2,
                    HardFailCount: 2,
                    LastFailAt: DateTime.UtcNow,
                    Window: TimeSpan.FromSeconds(30),
                    RetransmissionCount: 3,
                    TotalPackets: 10,
                    HasHttpRedirectDpi: false,
                    RedirectToHost: null,
                    HasSuspiciousRst: false,
                    SuspiciousRstDetails: null,
                    UdpUnansweredHandshakes: 0);

                var snap30 = adapter.BuildSnapshot(tested, legacy, IntelligenceV2ContractDefaults.DefaultAggregationWindow);
                var snap60 = adapter.BuildSnapshot(tested, legacy, IntelligenceV2ContractDefaults.ExtendedAggregationWindow);

                if (snap30.SampleSize < 5 || snap30.SampleSize > 7)
                {
                    return new SmokeTestResult("DPI2-003", "Агрегация v2: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали ~5 событий в 30s окне, получили sampleSize={snap30.SampleSize}");
                }

                if (snap60.SampleSize < 10)
                {
                    return new SmokeTestResult("DPI2-003", "Агрегация v2: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали >=10 событий в 60s окне, получили sampleSize={snap60.SampleSize}");
                }

                if (!snap30.HasTcpReset)
                {
                    return new SmokeTestResult("DPI2-003", "Агрегация v2: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что HasTcpReset будет true из-за события SuspiciousRstObserved в окне");
                }

                return new SmokeTestResult("DPI2-003", "Агрегация v2: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: sampleSize30={snap30.SampleSize}, sampleSize60={snap60.SampleSize}, hostKey={hostKey}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Aggregation_BuildSnapshot_ExtractsRstTtlDelta_AndLatency(CancellationToken ct)
            => RunAsync("DPI2-016", "Агрегация v2: BuildSnapshot извлекает RST TTL delta + latency", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapterV2(store);

                var tested = CreateHostTested(remoteIp: IPAddress.Parse("203.0.113.31"), blockageType: BlockageCode.TcpConnectionReset) with
                {
                    TcpLatencyMs = 120
                };

                var legacy = new BlockageSignals(
                    FailCount: 1,
                    HardFailCount: 1,
                    LastFailAt: DateTime.UtcNow,
                    Window: TimeSpan.FromSeconds(30),
                    RetransmissionCount: 0,
                    TotalPackets: 0,
                    HasHttpRedirectDpi: false,
                    RedirectToHost: null,
                    HasSuspiciousRst: true,
                    SuspiciousRstDetails: "TTL=64 (обычный=50-55)",
                    UdpUnansweredHandshakes: 0);

                var snap = adapter.BuildSnapshot(tested, legacy, IntelligenceV2ContractDefaults.DefaultAggregationWindow);

                if (!snap.HasTcpReset)
                {
                    return new SmokeTestResult("DPI2-016", "Агрегация v2: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали HasTcpReset=true (TCP_CONNECTION_RESET + HasSuspiciousRst)");
                }

                if (snap.RstTtlDelta != 9)
                {
                    return new SmokeTestResult("DPI2-016", "Агрегация v2: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали RstTtlDelta=9 (TTL=64 vs 50-55), получили {snap.RstTtlDelta}");
                }

                if (snap.RstLatency is null || Math.Abs(snap.RstLatency.Value.TotalMilliseconds - 120) > 1)
                {
                    return new SmokeTestResult("DPI2-016", "Агрегация v2: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали RstLatency≈120ms, получили {snap.RstLatency}");
                }

                return new SmokeTestResult("DPI2-016", "Агрегация v2: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: rstTtlDelta={snap.RstTtlDelta}, rstLatencyMs={(int)snap.RstLatency.Value.TotalMilliseconds}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_ProducesDiagnosis_WithConfidenceAtLeast50(CancellationToken ct)
            => RunAsync("DPI2-004", "DiagnosisEngine v2 формирует диагноз с confidence >= 50", () =>
            {
                var engine = new StandardDiagnosisEngineV2();

                var signals = new BlockageSignalsV2
                {
                    HostKey = "203.0.113.40",
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    AggregationWindow = TimeSpan.FromSeconds(30),
                    SampleSize = 5,
                    IsUnreliable = false,

                    HasDnsFailure = false,
                    HasFakeIp = false,
                    HasHttpRedirect = false,

                    HasTcpTimeout = true,
                    HasTcpReset = false,
                    RetransmissionRate = 0.30,

                    RstTtlDelta = null,
                    RstLatency = null,

                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false
                };

                var result = engine.Diagnose(signals);

                if (result.Confidence < 50)
                {
                    return new SmokeTestResult("DPI2-004", "DiagnosisEngine v2 формирует диагноз с confidence >= 50", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали confidence >= 50, получили {result.Confidence} (diagnosis={result.DiagnosisId})");
                }

                if (result.DiagnosisId != DiagnosisId.SilentDrop)
                {
                    return new SmokeTestResult("DPI2-004", "DiagnosisEngine v2 формирует диагноз с confidence >= 50", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали DiagnosisId.SilentDrop для timeout+high retx-rate, получили {result.DiagnosisId}");
                }

                return new SmokeTestResult("DPI2-004", "DiagnosisEngine v2 формирует диагноз с confidence >= 50", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {result.DiagnosisId} ({result.Confidence}%)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_RstTtlDelta_FastClassifiesAsActiveDpiEdge(CancellationToken ct)
            => RunAsync("DPI2-017", "DiagnosisEngine v2: RST TTL delta + быстрый reset => ActiveDpiEdge", () =>
            {
                var engine = new StandardDiagnosisEngineV2();

                var signals = new BlockageSignalsV2
                {
                    HostKey = "203.0.113.41",
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    AggregationWindow = TimeSpan.FromSeconds(30),
                    SampleSize = 5,
                    IsUnreliable = false,

                    HasDnsFailure = false,
                    HasFakeIp = false,
                    HasHttpRedirect = false,

                    HasTcpTimeout = false,
                    HasTcpReset = true,
                    RetransmissionRate = null,

                    RstTtlDelta = 10,
                    RstLatency = TimeSpan.FromMilliseconds(120),

                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false
                };

                var result = engine.Diagnose(signals);

                if (result.DiagnosisId != DiagnosisId.ActiveDpiEdge)
                {
                    return new SmokeTestResult("DPI2-017", "DiagnosisEngine v2: RST TTL delta + быстрый reset => ActiveDpiEdge", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали ActiveDpiEdge, получили {result.DiagnosisId} (conf={result.Confidence})");
                }

                if (result.Confidence < 60)
                {
                    return new SmokeTestResult("DPI2-017", "DiagnosisEngine v2: RST TTL delta + быстрый reset => ActiveDpiEdge", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали confidence >= 60, получили {result.Confidence}");
                }

                return new SmokeTestResult("DPI2-017", "DiagnosisEngine v2: RST TTL delta + быстрый reset => ActiveDpiEdge", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {result.DiagnosisId} ({result.Confidence}%)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_RstTtlDelta_SlowClassifiesAsStatefulDpi(CancellationToken ct)
            => RunAsync("DPI2-018", "DiagnosisEngine v2: RST TTL delta + медленный reset => StatefulDpi", () =>
            {
                var engine = new StandardDiagnosisEngineV2();

                var signals = new BlockageSignalsV2
                {
                    HostKey = "203.0.113.42",
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    AggregationWindow = TimeSpan.FromSeconds(30),
                    SampleSize = 5,
                    IsUnreliable = false,

                    HasDnsFailure = false,
                    HasFakeIp = false,
                    HasHttpRedirect = false,

                    HasTcpTimeout = false,
                    HasTcpReset = true,
                    RetransmissionRate = null,

                    RstTtlDelta = 10,
                    RstLatency = TimeSpan.FromMilliseconds(900),

                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false
                };

                var result = engine.Diagnose(signals);

                if (result.DiagnosisId != DiagnosisId.StatefulDpi)
                {
                    return new SmokeTestResult("DPI2-018", "DiagnosisEngine v2: RST TTL delta + медленный reset => StatefulDpi", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали StatefulDpi, получили {result.DiagnosisId} (conf={result.Confidence})");
                }

                if (result.Confidence < 60)
                {
                    return new SmokeTestResult("DPI2-018", "DiagnosisEngine v2: RST TTL delta + медленный reset => StatefulDpi", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали confidence >= 60, получили {result.Confidence}");
                }

                return new SmokeTestResult("DPI2-018", "DiagnosisEngine v2: RST TTL delta + медленный reset => StatefulDpi", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {result.DiagnosisId} ({result.Confidence}%)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_Explanation_IsFactBased_NoStrategiesMentioned(CancellationToken ct)
            => RunAsync("DPI2-005", "DiagnosisEngine v2: пояснение содержит факты, но не упоминает стратегии", () =>
            {
                var engine = new StandardDiagnosisEngineV2();

                var signals = new BlockageSignalsV2
                {
                    HostKey = "203.0.113.50",
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    AggregationWindow = TimeSpan.FromSeconds(30),
                    SampleSize = 3,
                    IsUnreliable = false,

                    HasDnsFailure = false,
                    HasFakeIp = false,
                    HasHttpRedirect = false,

                    HasTcpTimeout = false,
                    HasTcpReset = false,
                    RetransmissionRate = null,

                    RstTtlDelta = null,
                    RstLatency = null,

                    HasTlsTimeout = true,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false
                };

                var result = engine.Diagnose(signals);

                var text = string.Join(" | ", result.ExplanationNotes);
                var forbidden = new[]
                {
                    "TLS_FRAGMENT", "TLS_DISORDER", "DROP_RST", "DOH",
                    "TlsFragment", "TlsDisorder", "DropRst", "UseDoh",
                    "Fragment", "Disorder", "стратег"
                };

                if (forbidden.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase)))
                {
                    return new SmokeTestResult("DPI2-005", "DiagnosisEngine v2: пояснение содержит факты, но не упоминает стратегии", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Пояснение содержит упоминание стратегий/обхода: {text}");
                }

                if (!text.Contains("TLS", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("DPI2-005", "DiagnosisEngine v2: пояснение содержит факты, но не упоминает стратегии", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что пояснение содержит факт про TLS, получили: {text}");
                }

                return new SmokeTestResult("DPI2-005", "DiagnosisEngine v2: пояснение содержит факты, но не упоминает стратегии", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: пояснение фактологическое и без рекомендаций");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_GateMarkers_Gate1_EmittedInProgressLog(CancellationToken ct)
            => RunAsync("DPI2-006", "Gate 1→2: в логе появляется маркер [V2][GATE1]", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapterV2(store);

                var tested = CreateHostTested(remoteIp: IPAddress.Parse("203.0.113.60"), blockageType: BlockageCode.TcpConnectionReset);

                var legacy = new BlockageSignals(
                    FailCount: 1,
                    HardFailCount: 1,
                    LastFailAt: DateTime.UtcNow,
                    Window: TimeSpan.FromSeconds(30),
                    RetransmissionCount: 2,
                    TotalPackets: 10,
                    HasHttpRedirectDpi: true,
                    RedirectToHost: "example.org",
                    HasSuspiciousRst: false,
                    SuspiciousRstDetails: null,
                    UdpUnansweredHandshakes: 0);

                var lines = new List<string>();
                var progress = new ImmediateProgress(lines);

                adapter.Observe(tested, legacy, progress);

                if (!lines.Any(s => s.Contains("[V2][GATE1]", StringComparison.Ordinal)))
                {
                    return new SmokeTestResult("DPI2-006", "Gate 1→2: в логе появляется маркер [V2][GATE1]", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не нашли строку [V2][GATE1] после Observe(...). Ожидали, что 3 разных типа событий (HostTested + ретранс/редирект) достаточно для Gate 1→2");
                }

                var line = lines.First(s => s.Contains("[V2][GATE1]", StringComparison.Ordinal));
                if (!line.Contains("timeline=", StringComparison.Ordinal) || !line.Contains("recentCount=", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-006", "Gate 1→2: в логе появляется маркер [V2][GATE1]", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Маркер найден, но формат не совпал ожиданию (timeline/recentCount): {line}");
                }

                return new SmokeTestResult("DPI2-006", "Gate 1→2: в логе появляется маркер [V2][GATE1]", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: Gate 1→2 логируется");
            }, ct);

        private sealed class ImmediateProgress : IProgress<string>
        {
            private readonly List<string> _lines;

            public ImmediateProgress(List<string> lines)
            {
                _lines = lines ?? throw new ArgumentNullException(nameof(lines));
            }

            public void Report(string value)
            {
                _lines.Add(value);
            }
        }

        public static Task<SmokeTestResult> Dpi2_StrategySelector_BuildsPlan_AndExecutorFormatsRecommendation(CancellationToken ct)
            => RunAsync("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", () =>
            {
                var selector = new StandardStrategySelectorV2();
                var executor = new BypassExecutorMvp();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 80,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = new[] { "TLS: timeout" },
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new BlockageSignalsV2
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 3,
                        IsUnreliable = false
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis);
                if (plan.Strategies.Count == 0)
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали непустой план стратегий для ActiveDpiEdge/conf=80");
                }

                var bypassText = InvokePrivateBuildBypassStrategyText(plan);
                if (string.IsNullOrWhiteSpace(bypassText))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось получить текст bypass-стратегий (v2:...)");
                }

                if (!executor.TryBuildRecommendationLine("example.com", bypassText, out var line))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Executor не смог построить строку рекомендации из: {bypassText}");
                }

                if (!line.Contains(BypassExecutorMvp.V2LogPrefix, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"В строке рекомендации нет префикса {BypassExecutorMvp.V2LogPrefix}: {line}");
                }

                var hasFragment = line.Contains("TLS_FRAGMENT", StringComparison.Ordinal);
                var hasDisorder = line.Contains("TLS_DISORDER", StringComparison.Ordinal);
                if (!hasFragment && !hasDisorder)
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали одну TLS-стратегию (TLS_FRAGMENT или TLS_DISORDER), но не нашли ни одной: {line}");
                }

                if (hasFragment && hasDisorder)
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что селектор выберет ровно одну TLS-стратегию, но нашли обе: {line}");
                }

                return new SmokeTestResult("DPI2-007", "StrategySelector v2 формирует план и даёт v2-рекомендацию", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {line}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_HighRiskBlocked_WhenConfidenceBelow70(CancellationToken ct)
            => RunAsync("DPI2-008", "High-risk стратегии запрещены при confidence < 70", () =>
            {
                var selector = new StandardStrategySelectorV2();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 60,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new BlockageSignalsV2
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 3,
                        IsUnreliable = false
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis);

                if (plan.Strategies.Any(s => s.Risk == RiskLevel.High))
                {
                    return new SmokeTestResult("DPI2-008", "High-risk стратегии запрещены при confidence < 70", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Нашли RiskLevel.High стратегию в плане при confidence=60");
                }

                return new SmokeTestResult("DPI2-008", "High-risk стратегии запрещены при confidence < 70", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: strategies={plan.Strategies.Count}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_EmptyPlan_WhenConfidenceBelow50(CancellationToken ct)
            => RunAsync("DPI2-009", "Пустой план при confidence < 50", () =>
            {
                var selector = new StandardStrategySelectorV2();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 40,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new BlockageSignalsV2
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 3,
                        IsUnreliable = false
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis);

                if (plan.Strategies.Count != 0)
                {
                    return new SmokeTestResult("DPI2-009", "Пустой план при confidence < 50", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали пустой план, получили strategies={plan.Strategies.Count}");
                }

                return new SmokeTestResult("DPI2-009", "Пустой план при confidence < 50", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_WarnsAndSkips_UnimplementedStrategies(CancellationToken ct)
            => RunAsync("DPI2-010", "Warning при нереализованных стратегиях (warning + skip)", () =>
            {
                var selector = new StandardStrategySelectorV2();

                var warnings = new List<string>();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 80,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new BlockageSignalsV2
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 3,
                        IsUnreliable = false
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis, warningLog: s => warnings.Add(s));

                if (!warnings.Any(w => w.Contains("не реализована", StringComparison.OrdinalIgnoreCase)))
                {
                    return new SmokeTestResult("DPI2-010", "Warning при нереализованных стратегиях (warning + skip)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не получили warning для нереализованной стратегии (ожидали AggressiveFragment)");
                }

                if (plan.Strategies.Any(s => s.Id == StrategyId.AggressiveFragment))
                {
                    return new SmokeTestResult("DPI2-010", "Warning при нереализованных стратегиях (warning + skip)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Нереализованная стратегия AggressiveFragment попала в план (ожидали skip)");
                }

                return new SmokeTestResult("DPI2-010", "Warning при нереализованных стратегиях (warning + skip)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: warnings={warnings.Count}, strategies={plan.Strategies.Count}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_Feedback_AffectsOrdering_WhenEnoughSamples(CancellationToken ct)
            => RunAsync("DPI2-014", "Feedback влияет на ранжирование (достаточно выборок, детерминизм)", () =>
            {
                var options = new FeedbackStoreOptions
                {
                    MinSamplesToAffectRanking = 5,
                    MaxPriorityBoostAbs = 15,
                    MaxEntries = 128,
                    EntryTtl = TimeSpan.FromDays(30)
                };

                var store = new InMemoryFeedbackStoreV2(options);
                var selector = new StandardStrategySelectorV2(store, options);

                var now = DateTimeOffset.UtcNow;
                for (var i = 0; i < 5; i++)
                {
                    store.Record(new FeedbackKey(DiagnosisId.ActiveDpiEdge, StrategyId.TlsFragment), StrategyOutcome.Success, now);
                    store.Record(new FeedbackKey(DiagnosisId.ActiveDpiEdge, StrategyId.TlsDisorder), StrategyOutcome.Failure, now);
                }

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 80,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new BlockageSignalsV2
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 3,
                        IsUnreliable = false
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var p1 = selector.Select(diagnosis);
                var p2 = selector.Select(diagnosis);

                if (p1.Strategies.Count == 0)
                {
                    return new SmokeTestResult("DPI2-014", "Feedback влияет на ранжирование (достаточно выборок, детерминизм)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали непустой план для ActiveDpiEdge/conf=80");
                }

                var first = p1.Strategies[0].Id;
                if (first != StrategyId.TlsFragment)
                {
                    return new SmokeTestResult("DPI2-014", "Feedback влияет на ранжирование (достаточно выборок, детерминизм)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что feedback поднимет TlsFragment на первое место, получили first={first}");
                }

                var seq1 = string.Join(",", p1.Strategies.Select(s => s.Id));
                var seq2 = string.Join(",", p2.Strategies.Select(s => s.Id));

                if (!string.Equals(seq1, seq2, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-014", "Feedback влияет на ранжирование (достаточно выборок, детерминизм)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Нарушен детерминизм: seq1={seq1} seq2={seq2}");
                }

                return new SmokeTestResult("DPI2-014", "Feedback влияет на ранжирование (достаточно выборок, детерминизм)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: order={seq1}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_Feedback_DoesNotAffect_WhenNotEnoughSamples(CancellationToken ct)
            => RunAsync("DPI2-015", "Feedback не влияет на ранжирование при малой выборке", () =>
            {
                var options = new FeedbackStoreOptions
                {
                    MinSamplesToAffectRanking = 5,
                    MaxPriorityBoostAbs = 15,
                    MaxEntries = 128,
                    EntryTtl = TimeSpan.FromDays(30)
                };

                var store = new InMemoryFeedbackStoreV2(options);
                var selector = new StandardStrategySelectorV2(store, options);

                var now = DateTimeOffset.UtcNow;
                for (var i = 0; i < 4; i++)
                {
                    store.Record(new FeedbackKey(DiagnosisId.ActiveDpiEdge, StrategyId.TlsFragment), StrategyOutcome.Success, now);
                }

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 80,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new BlockageSignalsV2
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 3,
                        IsUnreliable = false
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis);
                if (plan.Strategies.Count == 0)
                {
                    return new SmokeTestResult("DPI2-015", "Feedback не влияет на ранжирование при малой выборке", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали непустой план для ActiveDpiEdge/conf=80");
                }

                // При отсутствии влияния feedback первый остаётся TlsDisorder (basePriority=90).
                if (plan.Strategies[0].Id != StrategyId.TlsDisorder)
                {
                    return new SmokeTestResult("DPI2-015", "Feedback не влияет на ранжирование при малой выборке", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали first=TlsDisorder без влияния feedback, получили first={plan.Strategies[0].Id}");
                }

                return new SmokeTestResult("DPI2-015", "Feedback не влияет на ранжирование при малой выборке", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: first={plan.Strategies[0].Id}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_ExecutorMvp_FormatsCompactOutput_OneLine(CancellationToken ct)
            => RunAsync("DPI2-011", "Executor MVP форматирует компактный вывод (1 строка)", () =>
            {
                var executor = new BypassExecutorMvp();

                var tail = "(v2:SilentDrop conf=78; TCP: timeout; TCP: retx-rate=0.30)";
                if (!executor.TryFormatDiagnosisSuffix(tail, out var formatted))
                {
                    return new SmokeTestResult("DPI2-011", "Executor MVP форматирует компактный вывод (1 строка)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"TryFormatDiagnosisSuffix не смог распарсить: {tail}");
                }

                if (formatted.Contains("\n", StringComparison.Ordinal) || formatted.Contains("\r", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-011", "Executor MVP форматирует компактный вывод (1 строка)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали одну строку без переводов строк");
                }

                if (!formatted.Contains("диагноз=SilentDrop", StringComparison.Ordinal) || !formatted.Contains("уверенность=78%", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-011", "Executor MVP форматирует компактный вывод (1 строка)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"В форматировании нет диагноза/уверенности: {formatted}");
                }

                // Также проверим, что рекомендация строится как 1 строка.
                var bypass = "v2:TlsFragment + DropRst (conf=78)";
                if (!executor.TryBuildRecommendationLine("example.com", bypass, out var line))
                {
                    return new SmokeTestResult("DPI2-011", "Executor MVP форматирует компактный вывод (1 строка)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось построить строку рекомендации"
                    );
                }

                if (line.Contains("\n", StringComparison.Ordinal) || line.Contains("\r", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-011", "Executor MVP форматирует компактный вывод (1 строка)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Строка рекомендации содержит перевод строки"
                    );
                }

                return new SmokeTestResult("DPI2-011", "Executor MVP форматирует компактный вывод (1 строка)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {formatted} | {line}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_AllV2Outputs_StartWithPrefix(CancellationToken ct)
            => RunAsync("DPI2-012", "Префикс [V2] присутствует во всех v2-выводах", () =>
            {
                var executor = new BypassExecutorMvp();

                var tail = "(v2:SilentDrop conf=80; TCP: timeout)";
                if (!executor.TryFormatDiagnosisSuffix(tail, out var formatted))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [V2] присутствует во всех v2-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        "TryFormatDiagnosisSuffix не смог распарсить хвост");
                }

                if (!formatted.Contains(BypassExecutorMvp.V2LogPrefix, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [V2] присутствует во всех v2-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Нет префикса [V2] в форматировании: {formatted}");
                }

                var bypass = "v2:TlsFragment + DropRst (conf=80)";
                if (!executor.TryBuildRecommendationLine("example.com", bypass, out var line))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [V2] присутствует во всех v2-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось построить строку рекомендации");
                }

                if (!line.StartsWith(BypassExecutorMvp.V2LogPrefix, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [V2] присутствует во всех v2-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Строка рекомендации не начинается с [V2]: {line}");
                }

                return new SmokeTestResult("DPI2-012", "Префикс [V2] присутствует во всех v2-выводах", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_ExecutorMvp_DoesNotCallTrafficEngineOrBypassController(CancellationToken ct)
            => RunAsync("DPI2-013", "Executor MVP не выполняет auto-apply (нет вызовов TrafficEngine/BypassController)", () =>
            {
                var forbiddenTypeNames = new[] { "TrafficEngine", "BypassController" };

                if (IlContainsCallsToForbiddenTypes(typeof(BypassExecutorMvp), forbiddenTypeNames))
                {
                    return new SmokeTestResult("DPI2-013", "Executor MVP не выполняет auto-apply (нет вызовов TrafficEngine/BypassController)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "В IL найден вызов к запрещённым типам (TrafficEngine/BypassController). MVP-исполнитель должен только форматировать/логировать.");
                }

                return new SmokeTestResult("DPI2-013", "Executor MVP не выполняет auto-apply (нет вызовов TrafficEngine/BypassController)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: вызовов к TrafficEngine/BypassController не обнаружено");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_ExecutorV2_ManualApply_MapsPlanToBypassOptions(CancellationToken ct)
            => RunAsync("DPI2-019", "Executor v2: ручное применение BypassPlan включает ожидаемые опции", () =>
            {
                // Поднимаем сервис в smoke-режиме (без TrafficEngine), чтобы не требовать админ прав и WinDivert.
                var engine = new TrafficEngine(progress: null);
                var baseProfile = BypassProfile.CreateDefault();
                var tlsService = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false, useTrafficEngine: false, nowProvider: () => DateTime.Now);
                var controller = new BypassController(tlsService, baseProfile);

                var plan = new BypassPlan
                {
                    ForDiagnosis = DiagnosisId.SilentDrop,
                    PlanConfidence = 80,
                    PlannedAtUtc = DateTimeOffset.UtcNow,
                    Reasoning = "smoke",
                    Strategies = new List<BypassStrategy>
                    {
                        new BypassStrategy { Id = StrategyId.TlsFragment, BasePriority = 90, Risk = RiskLevel.Medium },
                        new BypassStrategy { Id = StrategyId.DropRst, BasePriority = 50, Risk = RiskLevel.Medium },
                    }
                };

                controller.ApplyV2PlanAsync(plan, timeout: TimeSpan.FromSeconds(2), cancellationToken: CancellationToken.None)
                    .GetAwaiter().GetResult();

                if (!controller.IsFragmentEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor v2: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyV2PlanAsync будет включён TLS_FRAGMENT");
                }

                if (controller.IsDisorderEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor v2: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что TLS_DISORDER будет выключен (Fragment и Disorder взаимоисключающие)");
                }

                if (!controller.IsDropRstEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor v2: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyV2PlanAsync будет включён DROP_RST");
                }

                return new SmokeTestResult("DPI2-019", "Executor v2: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: опции применены" );
            }, ct);

        public static Task<SmokeTestResult> Dpi2_ExecutorV2_TlsFragment_Params_AffectPresetAndAutoAdjust(CancellationToken ct)
            => RunAsync("DPI2-022", "Executor v2: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", () =>
            {
                // Smoke-режим (без TrafficEngine), чтобы не требовать админ прав и WinDivert.
                var engine = new TrafficEngine(progress: null);
                var baseProfile = BypassProfile.CreateDefault();
                var tlsService = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false, useTrafficEngine: false, nowProvider: () => DateTime.Now);
                var controller = new BypassController(tlsService, baseProfile);

                var plan = new BypassPlan
                {
                    ForDiagnosis = DiagnosisId.SilentDrop,
                    PlanConfidence = 80,
                    PlannedAtUtc = DateTimeOffset.UtcNow,
                    Reasoning = "smoke-params",
                    Strategies = new List<BypassStrategy>
                    {
                        new BypassStrategy
                        {
                            Id = StrategyId.TlsFragment,
                            BasePriority = 90,
                            Risk = RiskLevel.Medium,
                            Parameters = new Dictionary<string, object?>
                            {
                                ["TlsFragmentSizes"] = new[] { 32, 32 },
                                ["AutoAdjustAggressive"] = true
                            }
                        },
                    }
                };

                controller.ApplyV2PlanAsync(plan, timeout: TimeSpan.FromSeconds(2), cancellationToken: CancellationToken.None)
                    .GetAwaiter().GetResult();

                if (!controller.IsFragmentEnabled)
                {
                    return new SmokeTestResult("DPI2-022", "Executor v2: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyV2PlanAsync будет включён TLS_FRAGMENT");
                }

                if (!controller.IsAutoAdjustAggressive)
                {
                    return new SmokeTestResult("DPI2-022", "Executor v2: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что AutoAdjustAggressive=true будет применён из параметров стратегии");
                }

                if (controller.SelectedFragmentPreset == null)
                {
                    return new SmokeTestResult("DPI2-022", "Executor v2: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что SelectedFragmentPreset будет выбран");
                }

                var got = controller.SelectedFragmentPreset.Sizes.ToArray();
                if (got.Length != 2 || got[0] != 32 || got[1] != 32)
                {
                    return new SmokeTestResult("DPI2-022", "Executor v2: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали sizes=[32,32], получили [{string.Join(",", got)}]");
                }

                return new SmokeTestResult("DPI2-022", "Executor v2: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: параметры применены" );
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_PopulatesTlsFragmentParameters(CancellationToken ct)
            => RunAsync("DPI2-023", "StrategySelector v2: TlsFragment содержит параметры (TlsFragmentSizes) в плане", () =>
            {
                var selector = new StandardStrategySelectorV2(feedbackStore: null);

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.SilentDrop,
                    Confidence = 80,
                    ExplanationNotes = new[] { "smoke" },
                    InputSignals = new BlockageSignalsV2
                    {
                        HostKey = "203.0.113.99",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),

                        HasDnsFailure = false,
                        HasFakeIp = false,
                        HasHttpRedirect = false,

                        HasTcpTimeout = true,
                        HasTcpReset = false,
                        RetransmissionRate = 0.25,
                        RstTtlDelta = null,
                        RstLatency = null,

                        HasTlsTimeout = false,
                        HasTlsAuthFailure = false,
                        HasTlsReset = false,

                        SampleSize = 1,
                        IsUnreliable = false
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis, warningLog: null);
                var fragment = plan.Strategies.FirstOrDefault(s => s.Id == StrategyId.TlsFragment);
                if (fragment == null)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector v2: TlsFragment содержит параметры (TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что план будет содержать TlsFragment");
                }

                if (fragment.Parameters == null || fragment.Parameters.Count == 0)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector v2: TlsFragment содержит параметры (TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что у TlsFragment будут параметры");
                }

                if (!fragment.Parameters.TryGetValue("TlsFragmentSizes", out var raw) || raw is not int[] sizes)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector v2: TlsFragment содержит параметры (TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что параметр TlsFragmentSizes будет int[]");
                }

                if (sizes.Length != 1 || sizes[0] != 64)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector v2: TlsFragment содержит параметры (TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали sizes=[64], получили [{string.Join(",", sizes)}]");
                }

                return new SmokeTestResult("DPI2-023", "StrategySelector v2: TlsFragment содержит параметры (TlsFragmentSizes) в плане", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: параметры присутствуют" );
            }, ct);

        public static async Task<SmokeTestResult> Dpi2_ExecutorV2_Cancel_RollbacksToPreviousState(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var engine = new TrafficEngine(progress: null);
                var baseProfile = BypassProfile.CreateDefault();
                var tlsService = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false, useTrafficEngine: false, nowProvider: () => DateTime.Now);
                var controller = new BypassController(tlsService, baseProfile);

                // Исходное состояние: включаем Fake, чтобы проверить откат.
                controller.IsFakeEnabled = true;

                var plan = new BypassPlan
                {
                    ForDiagnosis = DiagnosisId.MultiLayerBlock,
                    PlanConfidence = 90,
                    PlannedAtUtc = DateTimeOffset.UtcNow,
                    Reasoning = "smoke-cancel",
                    Strategies = new List<BypassStrategy>
                    {
                        new BypassStrategy { Id = StrategyId.TlsFragment, BasePriority = 90, Risk = RiskLevel.Medium },
                        new BypassStrategy { Id = StrategyId.DropRst, BasePriority = 50, Risk = RiskLevel.Medium },
                    }
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromMilliseconds(1));

                try
                {
                    await controller.ApplyV2PlanAsync(plan, timeout: TimeSpan.FromSeconds(2), cancellationToken: cts.Token).ConfigureAwait(false);
                    return new SmokeTestResult("DPI2-020", "Executor v2: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали OperationCanceledException, но применение завершилось без отмены");
                }
                catch (OperationCanceledException)
                {
                    // Ожидаемо.
                }

                if (!controller.IsFakeEnabled)
                {
                    return new SmokeTestResult("DPI2-020", "Executor v2: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали откат: Fake должен остаться включенным");
                }

                if (controller.IsFragmentEnabled || controller.IsDropRstEnabled || controller.IsDisorderEnabled)
                {
                    return new SmokeTestResult("DPI2-020", "Executor v2: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали откат: Fragment/DropRst/Disorder не должны остаться включенными после отмены");
                }

                return new SmokeTestResult("DPI2-020", "Executor v2: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: откат выполнен");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("DPI2-020", "Executor v2: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Dpi2_Pipeline_DoesNotAutoApply_BypassControllerOrTlsBypassService(CancellationToken ct)
            => RunAsync("DPI2-021", "Pipeline v2 не выполняет auto-apply (нет вызовов BypassController/TlsBypassService)", () =>
            {
                var forbiddenTypeNames = new[] { "BypassController", "TlsBypassService" };

                if (IlContainsCallsToForbiddenTypes(typeof(LiveTestingPipeline), forbiddenTypeNames))
                {
                    return new SmokeTestResult("DPI2-021", "Pipeline v2 не выполняет auto-apply (нет вызовов BypassController/TlsBypassService)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "В IL найден вызов к запрещённым типам. Pipeline обязан только вычислять/публиковать план, без применения." );
                }

                return new SmokeTestResult("DPI2-021", "Pipeline v2 не выполняет auto-apply (нет вызовов BypassController/TlsBypassService)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: вызовов к BypassController/TlsBypassService не обнаружено");
            }, ct);

        private static HostTested CreateHostTested(IPAddress remoteIp, string? blockageType)
        {
            var host = new HostDiscovered(
                Key: $"{remoteIp}:443:TCP",
                RemoteIp: remoteIp,
                RemotePort: 443,
                Protocol: BypassTransportProtocol.Tcp,
                DiscoveredAt: DateTime.UtcNow)
            {
                Hostname = "example.com",
                SniHostname = "example.com"
            };

            return new HostTested(
                Host: host,
                DnsOk: false,
                TcpOk: false,
                TlsOk: false,
                DnsStatus: BlockageCode.StatusFail,
                Hostname: "example.com",
                SniHostname: "example.com",
                ReverseDnsHostname: null,
                TcpLatencyMs: null,
                BlockageType: blockageType,
                TestedAt: DateTime.UtcNow);
        }

        private static string InvokePrivateBuildBypassStrategyText(BypassPlan plan)
        {
            // Привязываемся к реальному production-формату в LiveTestingPipeline.
            var method = typeof(LiveTestingPipeline).GetMethod(
                "BuildBypassStrategyText",
                BindingFlags.Static | BindingFlags.NonPublic);

            if (method == null)
            {
                return string.Empty;
            }

            return (string?)method.Invoke(null, new object[] { plan }) ?? string.Empty;
        }

        private static bool IlContainsCallsToForbiddenTypes(Type type, IReadOnlyCollection<string> forbiddenTypeNames)
        {
            var module = type.Module;

            var single = new OpCode[0x100];
            var multi = new OpCode[0x100];

            foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                if (field.GetValue(null) is not OpCode op) continue;

                var value = (ushort)op.Value;
                if (value < 0x100)
                {
                    single[value] = op;
                }
                else if ((value & 0xFF00) == 0xFE00)
                {
                    multi[value & 0xFF] = op;
                }
            }

            var methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);

            foreach (var method in methods)
            {
                var body = method.GetMethodBody();
                if (body == null) continue;

                var il = body.GetILAsByteArray();
                if (il == null || il.Length == 0) continue;

                for (var i = 0; i < il.Length;)
                {
                    OpCode op;
                    var code = il[i++];
                    if (code == 0xFE)
                    {
                        var code2 = il[i++];
                        op = multi[code2];
                    }
                    else
                    {
                        op = single[code];
                    }

                    switch (op.OperandType)
                    {
                        case OperandType.InlineMethod:
                        case OperandType.InlineField:
                        case OperandType.InlineType:
                        case OperandType.InlineTok:
                            {
                                var token = BitConverter.ToInt32(il, i);
                                i += 4;

                                MemberInfo? member = null;
                                try { member = module.ResolveMember(token); } catch { }

                                var declaring = member switch
                                {
                                    MethodBase mb => mb.DeclaringType,
                                    FieldInfo fi => fi.DeclaringType,
                                    Type t => t,
                                    _ => null
                                };

                                if (declaring != null && forbiddenTypeNames.Contains(declaring.Name))
                                {
                                    return true;
                                }

                                break;
                            }

                        case OperandType.InlineString:
                        case OperandType.InlineSig:
                        case OperandType.InlineI:
                        case OperandType.InlineBrTarget:
                            i += 4;
                            break;

                        case OperandType.InlineI8:
                        case OperandType.InlineR:
                            i += 8;
                            break;

                        case OperandType.ShortInlineR:
                            i += 4;
                            break;

                        case OperandType.InlineSwitch:
                            {
                                var count = BitConverter.ToInt32(il, i);
                                i += 4 + (count * 4);
                                break;
                            }

                        case OperandType.InlineVar:
                            i += 2;
                            break;

                        case OperandType.ShortInlineBrTarget:
                        case OperandType.ShortInlineI:
                        case OperandType.ShortInlineVar:
                            i += 1;
                            break;

                        case OperandType.InlineNone:
                        default:
                            break;
                    }
                }
            }

            return false;
        }
    }
}
