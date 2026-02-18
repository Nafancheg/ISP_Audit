using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Intelligence.Diagnosis;
using IspAudit.Core.Intelligence.Execution;
using IspAudit.Core.Intelligence.Feedback;
using IspAudit.Core.Intelligence.Signals;
using IspAudit.Core.Intelligence.Strategies;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;
using IspAudit.Utils;
using IspAudit.ViewModels;
using Microsoft.Extensions.DependencyInjection;

using BypassTransportProtocol = IspAudit.Bypass.TransportProtocol;
using IntelBlockageSignals = IspAudit.Core.Intelligence.Contracts.BlockageSignals;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> Dpi2_PolicySetCompiler_DetectsHardConflicts(CancellationToken ct)
            => RunAsync("DPI2-040", "PolicySetCompiler: hard-conflicts детектируются детерминированно", () =>
            {
                // Конфликт: одинаковый приоритет + пересечение match + разные actions.
                var p1 = new FlowPolicy
                {
                    Id = "p1",
                    Priority = 10,
                    Scope = PolicyScope.Local,
                    Match = new MatchCondition
                    {
                        Proto = FlowTransportProtocol.Udp,
                        Port = 443,
                        DstIpSet = ImmutableHashSet.Create("1.1.1.1"),
                        SniPattern = "youtube.com"
                    },
                    Action = PolicyAction.Block
                };

                var p2 = new FlowPolicy
                {
                    Id = "p2",
                    Priority = 10,
                    Scope = PolicyScope.Local,
                    Match = new MatchCondition
                    {
                        Proto = FlowTransportProtocol.Udp,
                        Port = 443,
                        DstIpSet = ImmutableHashSet.Create("1.1.1.1"),
                        SniPattern = "youtube.com"
                    },
                    Action = PolicyAction.Pass
                };

                var conflicts = PolicySetCompiler.DetectHardConflicts(new[] { p1, p2 });
                if (conflicts.Length == 0)
                {
                    return new SmokeTestResult("DPI2-040", "PolicySetCompiler: hard-conflicts детектируются детерминированно", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали hard-conflict (одинаковый приоритет, пересечение match, разные actions), но конфликтов нет");
                }

                try
                {
                    _ = PolicySetCompiler.CompileOrThrow(new[] { p1, p2 });
                    return new SmokeTestResult("DPI2-040", "PolicySetCompiler: hard-conflicts детектируются детерминированно", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали PolicyCompilationException, но компиляция прошла без ошибок");
                }
                catch (PolicyCompilationException ex)
                {
                    if (ex.Conflicts.IsDefaultOrEmpty)
                    {
                        return new SmokeTestResult("DPI2-040", "PolicySetCompiler: hard-conflicts детектируются детерминированно", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PolicyCompilationException получен, но список конфликтов пуст");
                    }
                }

                // Неконфликтный случай: более высокий приоритет снимает неоднозначность.
                var p3 = p2 with { Id = "p3", Priority = 11 };
                _ = PolicySetCompiler.CompileOrThrow(new[] { p1, p3 });

                // Неконфликтный случай: disjoint ip-set.
                var p4 = p2 with
                {
                    Id = "p4",
                    Match = p2.Match with { DstIpSet = ImmutableHashSet.Create("2.2.2.2") },
                    Priority = 10
                };

                _ = PolicySetCompiler.CompileOrThrow(new[] { p1, p4 });

                return new SmokeTestResult("DPI2-040", "PolicySetCompiler: hard-conflicts детектируются детерминированно", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: hard-conflict ловится, а не-амбигуозные кейсы компилируются");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Watchdog_CrashRecovery_AndTimeout_DisablesBypass(CancellationToken ct)
            => RunAsyncAwait("DPI2-027", "Watchdog: crash recovery + timeout => Disable", async innerCt =>
            {
                var prevSessionPath = Environment.GetEnvironmentVariable("ISP_AUDIT_BYPASS_SESSION_PATH");
                var prevTick = Environment.GetEnvironmentVariable("ISP_AUDIT_WATCHDOG_TICK_MS");
                var prevStale = Environment.GetEnvironmentVariable("ISP_AUDIT_WATCHDOG_STALE_MS");

                var tempDir = Path.Combine(Path.GetTempPath(), "isp_audit_smoke", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(tempDir);

                try
                {
                    // 1) Crash recovery: если прошлый shutdown был не clean при активном bypass — при старте должно выполниться Disable.
                    var crashFile = Path.Combine(tempDir, "bypass_session_crash.json");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_BYPASS_SESSION_PATH", crashFile);

                    File.WriteAllText(crashFile,
                        "{\"Version\":1,\"CleanShutdown\":false,\"WasBypassActive\":true,\"UpdatedAtUtc\":\"2025-12-29T00:00:00+00:00\",\"LastReason\":\"smoke_seed\"}");

                    using (var engine = new TrafficEngine(progress: null))
                    {
                        var profile = BypassProfile.CreateDefault();
                        using var provider = BuildIspAuditProvider();
                        var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                        using var manager = managerFactory.GetOrCreate(engine, baseProfile: profile, log: null);
                        await manager.InitializeOnStartupAsync(innerCt).ConfigureAwait(false);
                    }

                    var crashJson = File.ReadAllText(crashFile);
                    using (var doc = JsonDocument.Parse(crashJson))
                    {
                        if (!doc.RootElement.TryGetProperty("WasBypassActive", out var active) || active.GetBoolean() != false)
                        {
                            return new SmokeTestResult("DPI2-027", "Watchdog: crash recovery + timeout => Disable", SmokeOutcome.Fail, TimeSpan.Zero,
                                "Crash recovery: ожидали WasBypassActive=false после InitializeOnStartupAsync");
                        }
                    }

                    // 2) Watchdog timeout: при активном bypass и отсутствии heartbeat/метрик менеджер должен сам выключить bypass.
                    var watchdogFile = Path.Combine(tempDir, "bypass_session_watchdog.json");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_BYPASS_SESSION_PATH", watchdogFile);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_WATCHDOG_TICK_MS", "20");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_WATCHDOG_STALE_MS", "50");

                    using (var engine = new TrafficEngine(progress: null))
                    {
                        var profile = BypassProfile.CreateDefault();

                        // Smoke-safe: не трогаем WinDivert, только логику менеджера.
                        var tls = new TlsBypassService(
                            trafficEngine: engine,
                            baseProfile: profile,
                            log: null,
                            startMetricsTimer: false,
                            useTrafficEngine: false,
                            nowProvider: null);

                        var manager = BypassStateManager.GetOrCreateFromService(tls, profile, log: null);
                        await manager.InitializeOnStartupAsync(innerCt).ConfigureAwait(false);

                        // Включаем любую «реальную» стратегию, чтобы IsAnyEnabled()==true.
                        var options = TlsBypassOptions.CreateDefault(profile) with
                        {
                            DisorderEnabled = true,
                            DropRstEnabled = true
                        };

                        await manager.ApplyTlsOptionsAsync(options, innerCt).ConfigureAwait(false);

                        // Ждём, пока watchdog успеет отработать.
                        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
                        while (DateTime.UtcNow < deadline)
                        {
                            if (!manager.GetOptionsSnapshot().IsAnyEnabled())
                            {
                                break;
                            }

                            await Task.Delay(25, innerCt).ConfigureAwait(false);
                        }

                        if (manager.GetOptionsSnapshot().IsAnyEnabled())
                        {
                            return new SmokeTestResult("DPI2-027", "Watchdog: crash recovery + timeout => Disable", SmokeOutcome.Fail, TimeSpan.Zero,
                                "Watchdog timeout: ожидали авто-Disable при отсутствии heartbeat/метрик");
                        }
                    }

                    return new SmokeTestResult("DPI2-027", "Watchdog: crash recovery + timeout => Disable", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: crash_recovery и watchdog_timeout выключают bypass детерминированно");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_BYPASS_SESSION_PATH", prevSessionPath);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_WATCHDOG_TICK_MS", prevTick);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_WATCHDOG_STALE_MS", prevStale);

                    try { Directory.Delete(tempDir, recursive: true); } catch { }
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_ActivationDetection_Statuses_AreDeterministic(CancellationToken ct)
            => RunAsyncAwait("DPI2-028", "Activation Detection: ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN", async innerCt =>
            {
                var prevEngineGrace = Environment.GetEnvironmentVariable("ISP_AUDIT_ACTIVATION_ENGINE_GRACE_MS");
                var prevWarmup = Environment.GetEnvironmentVariable("ISP_AUDIT_ACTIVATION_WARMUP_MS");
                var prevNoTraffic = Environment.GetEnvironmentVariable("ISP_AUDIT_ACTIVATION_NO_TRAFFIC_MS");
                var prevStale = Environment.GetEnvironmentVariable("ISP_AUDIT_ACTIVATION_STALE_MS");

                try
                {
                    // Для smoke отключаем ENGINE_DEAD по engine.IsRunning, чтобы можно было проверить метрики без WinDivert.
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_ENGINE_GRACE_MS", "999999");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_WARMUP_MS", "0");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_NO_TRAFFIC_MS", "0");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_STALE_MS", "999999");

                    using var engine = new TrafficEngine(progress: null);
                    var profile = BypassProfile.CreateDefault();

                    var tls = new TlsBypassService(
                        trafficEngine: engine,
                        baseProfile: profile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: null);

                    var manager = BypassStateManager.GetOrCreateFromService(tls, profile, log: null);
                    await manager.InitializeOnStartupAsync(innerCt).ConfigureAwait(false);

                    await manager.ApplyTlsOptionsAsync(TlsBypassOptions.CreateDefault(profile) with
                    {
                        DisorderEnabled = true,
                        DropRstEnabled = true
                    }, innerCt).ConfigureAwait(false);

                    // 1) NO_TRAFFIC
                    manager.SetMetricsSnapshotForSmoke(new TlsBypassMetrics
                    {
                        ClientHellosObserved = 0,
                        ClientHellosFragmented = 0,
                        TlsHandled = 0,
                        RstDropped = 0,
                        RstDroppedRelevant = 0,
                        Udp443Dropped = 0
                    });

                    var s1 = manager.GetActivationStatusSnapshot();
                    if (s1.Status != ActivationStatus.NoTraffic)
                    {
                        return new SmokeTestResult("DPI2-028", "Activation Detection: ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали NO_TRAFFIC, получили {s1.Text} ({s1.Details})");
                    }

                    // 2) NOT_ACTIVATED (трафик есть, эффекта нет)
                    manager.SetMetricsSnapshotForSmoke(new TlsBypassMetrics
                    {
                        ClientHellosObserved = 10,
                        ClientHellosFragmented = 0,
                        TlsHandled = 0,
                        RstDropped = 0,
                        RstDroppedRelevant = 0,
                        Udp443Dropped = 0
                    });

                    var s2 = manager.GetActivationStatusSnapshot();
                    if (s2.Status != ActivationStatus.NotActivated)
                    {
                        return new SmokeTestResult("DPI2-028", "Activation Detection: ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали NOT_ACTIVATED, получили {s2.Text} ({s2.Details})");
                    }

                    // 3) ACTIVATED
                    manager.SetMetricsSnapshotForSmoke(new TlsBypassMetrics
                    {
                        ClientHellosObserved = 10,
                        ClientHellosFragmented = 2,
                        TlsHandled = 2,
                        RstDropped = 0,
                        RstDroppedRelevant = 0,
                        Udp443Dropped = 0
                    });

                    var s3 = manager.GetActivationStatusSnapshot();
                    if (s3.Status != ActivationStatus.Activated)
                    {
                        return new SmokeTestResult("DPI2-028", "Activation Detection: ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали ACTIVATED, получили {s3.Text} ({s3.Details})");
                    }

                    // 4) ENGINE_DEAD по stale метрикам
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_STALE_MS", "1");
                    manager.SetMetricsSnapshotForSmoke(new TlsBypassMetrics
                    {
                        ClientHellosObserved = 10,
                        ClientHellosFragmented = 1,
                        TlsHandled = 1,
                        RstDropped = 0,
                        RstDroppedRelevant = 0,
                        Udp443Dropped = 0
                    }, atUtc: DateTime.UtcNow - TimeSpan.FromSeconds(10));

                    var s4 = manager.GetActivationStatusSnapshot();
                    if (s4.Status != ActivationStatus.EngineDead)
                    {
                        return new SmokeTestResult("DPI2-028", "Activation Detection: ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали ENGINE_DEAD, получили {s4.Text} ({s4.Details})");
                    }

                    return new SmokeTestResult("DPI2-028", "Activation Detection: ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: статусы детерминированны");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_ENGINE_GRACE_MS", prevEngineGrace);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_WARMUP_MS", prevWarmup);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_NO_TRAFFIC_MS", prevNoTraffic);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_ACTIVATION_STALE_MS", prevStale);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_OutcomeCheck_Https_TaggedProbe_IsDeterministic_ViaTaggedProbe(CancellationToken ct)
            => RunAsyncAwait("DPI2-029", "Outcome Check (HTTPS): SUCCESS/FAILED/UNKNOWN via tagged probe", async innerCt =>
            {
                var prevDelay = Environment.GetEnvironmentVariable("ISP_AUDIT_OUTCOME_DELAY_MS");
                var prevTimeout = Environment.GetEnvironmentVariable("ISP_AUDIT_OUTCOME_TIMEOUT_MS");

                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_OUTCOME_DELAY_MS", "0");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_OUTCOME_TIMEOUT_MS", "0");

                    using var engine = new TrafficEngine(progress: null);
                    var profile = BypassProfile.CreateDefault();

                    var tls = new TlsBypassService(
                        trafficEngine: engine,
                        baseProfile: profile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: null);

                    var manager = BypassStateManager.GetOrCreateFromService(tls, profile, log: null);
                    await manager.InitializeOnStartupAsync(innerCt).ConfigureAwait(false);

                    // 0) Без цели: outcome остаётся UNKNOWN.
                    manager.SetOutcomeTargetHost(null);
                    await manager.ApplyTlsOptionsAsync(TlsBypassOptions.CreateDefault(profile) with
                    {
                        DisorderEnabled = true,
                        DropRstEnabled = true
                    }, innerCt).ConfigureAwait(false);

                    var o0 = manager.GetOutcomeStatusSnapshot();
                    if (o0.Status != OutcomeStatus.Unknown)
                    {
                        return new SmokeTestResult("DPI2-029", "Outcome Check (HTTPS): SUCCESS/FAILED/UNKNOWN via tagged probe", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали UNKNOWN без цели, получили {o0.Text} ({o0.Details})");
                    }

                    // 1) SUCCESS через детерминированную подмену probe.
                    manager.SetOutcomeProbeForSmoke(async (host, token) =>
                    {
                        await Task.Delay(1, token).ConfigureAwait(false);
                        return new OutcomeStatusSnapshot(OutcomeStatus.Success, "SUCCESS", $"smoke:{host}");
                    });

                    manager.SetOutcomeTargetHost("example.com");
                    await manager.ApplyTlsOptionsAsync(TlsBypassOptions.CreateDefault(profile) with
                    {
                        DisorderEnabled = true,
                        DropRstEnabled = true
                    }, innerCt).ConfigureAwait(false);

                    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);
                    OutcomeStatusSnapshot o1;
                    do
                    {
                        o1 = manager.GetOutcomeStatusSnapshot();
                        if (o1.Status != OutcomeStatus.Unknown) break;
                        await Task.Delay(10, innerCt).ConfigureAwait(false);
                    } while (DateTime.UtcNow < deadline);

                    if (o1.Status != OutcomeStatus.Success)
                    {
                        return new SmokeTestResult("DPI2-029", "Outcome Check (HTTPS): SUCCESS/FAILED/UNKNOWN via tagged probe", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали SUCCESS, получили {o1.Text} ({o1.Details})");
                    }

                    // 2) FAILED через детерминированную подмену probe.
                    manager.SetOutcomeProbeForSmoke(async (host, token) =>
                    {
                        await Task.Delay(1, token).ConfigureAwait(false);
                        return new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"smoke:{host}");
                    });

                    manager.SetOutcomeTargetHost("example.com");
                    await manager.ApplyTlsOptionsAsync(TlsBypassOptions.CreateDefault(profile) with
                    {
                        DisorderEnabled = true,
                        DropRstEnabled = true
                    }, innerCt).ConfigureAwait(false);

                    deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);
                    OutcomeStatusSnapshot o2;
                    do
                    {
                        o2 = manager.GetOutcomeStatusSnapshot();
                        if (o2.Status != OutcomeStatus.Unknown) break;
                        await Task.Delay(10, innerCt).ConfigureAwait(false);
                    } while (DateTime.UtcNow < deadline);

                    if (o2.Status != OutcomeStatus.Failed)
                    {
                        return new SmokeTestResult("DPI2-029", "Outcome Check (HTTPS): SUCCESS/FAILED/UNKNOWN via tagged probe", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали FAILED, получили {o2.Text} ({o2.Details})");
                    }

                    return new SmokeTestResult("DPI2-029", "Outcome Check (HTTPS): SUCCESS/FAILED/UNKNOWN via tagged probe", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: outcome для HTTPS детерминированен и не основан на пассивном анализе");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_OUTCOME_DELAY_MS", prevDelay);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_OUTCOME_TIMEOUT_MS", prevTimeout);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_QuicFallback_DropUdp443_IsSelectiveByObservedIp(CancellationToken ct)
            => RunAsync("DPI2-030", "QUIC fallback (DROP UDP/443): селективен по observed IP цели", () =>
            {
                static uint ToIpv4Int(IPAddress ip)
                {
                    var bytes = ip.GetAddressBytes();
                    if (bytes.Length != 4) throw new ArgumentException("Ожидали IPv4 адрес", nameof(ip));
                    return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                }

                // Важно: тестируем только селективность на уровне BypassFilter,
                // без реального TrafficEngine/сети.
                var profile = new BypassProfile
                {
                    DropUdp443 = true
                };

                var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");

                var targetIp = IPAddress.Parse("203.0.113.10");
                var otherIp = IPAddress.Parse("198.51.100.20");
                var srcIp = IPAddress.Parse("10.0.0.2");

                filter.SetUdp443DropTargetIps(new[] { ToIpv4Int(targetIp) });

                var udpToTarget = BuildIpv4UdpPacket(
                    srcIp,
                    targetIp,
                    srcPort: 50000,
                    dstPort: 443,
                    ttl: 64,
                    ipId: 1,
                    payload: new byte[] { 1, 2, 3 });

                var udpToOther = BuildIpv4UdpPacket(
                    srcIp,
                    otherIp,
                    srcPort: 50001,
                    dstPort: 443,
                    ttl: 64,
                    ipId: 2,
                    payload: new byte[] { 4, 5, 6 });

                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);
                var sender = new DummyPacketSender();

                var allow1 = filter.Process(new InterceptedPacket(udpToTarget, udpToTarget.Length), ctx, sender);
                var allow2 = filter.Process(new InterceptedPacket(udpToOther, udpToOther.Length), ctx, sender);

                if (allow1)
                {
                    return new SmokeTestResult("DPI2-030", "QUIC fallback (DROP UDP/443): селективен по observed IP цели", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали DROP UDP/443 для пакета к target IP, но пакет был пропущен");
                }

                if (!allow2)
                {
                    return new SmokeTestResult("DPI2-030", "QUIC fallback (DROP UDP/443): селективен по observed IP цели", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали PASS UDP/443 для пакета к НЕ-целевому IP, но пакет был дропнут");
                }

                var metrics = filter.GetMetrics();
                if (metrics.Udp443Dropped != 1)
                {
                    return new SmokeTestResult("DPI2-030", "QUIC fallback (DROP UDP/443): селективен по observed IP цели", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Udp443Dropped=1, получили {metrics.Udp443Dropped}");
                }

                return new SmokeTestResult("DPI2-030", "QUIC fallback (DROP UDP/443): селективен по observed IP цели", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: UDP/443 дропается только к target IP");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_PolicyDrivenUdp443_DropUdp443_ViaDecisionGraph(CancellationToken ct)
            => RunAsync("DPI2-041", "Policy-driven UDP/443: DROP UDP/443 через DecisionGraphSnapshot + per-policy метрика", () =>
            {
                static uint ToIpv4Int(IPAddress ip)
                {
                    var bytes = ip.GetAddressBytes();
                    if (bytes.Length != 4) throw new ArgumentException("Ожидали IPv4 адрес", nameof(ip));
                    return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                }

                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_UDP443");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_UDP443", "1");

                    // Тестируем на уровне BypassFilter (без TrafficEngine/сети), но уже через decision graph.
                    var profile = new BypassProfile
                    {
                        DropUdp443 = true
                    };

                    var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");

                    var targetIp = IPAddress.Parse("203.0.113.10");
                    var otherIp = IPAddress.Parse("198.51.100.20");
                    var srcIp = IPAddress.Parse("10.0.0.2");

                    var policyId = "smoke_udp443_drop";
                    var snapshot = IspAudit.Core.Bypass.PolicySetCompiler.CompileOrThrow(new[]
                    {
                        new IspAudit.Core.Models.FlowPolicy
                        {
                            Id = policyId,
                            Priority = 100,
                            Match = new IspAudit.Core.Models.MatchCondition
                            {
                                Proto = IspAudit.Core.Models.FlowTransportProtocol.Udp,
                                Port = 443,
                                DstIpv4Set = new[] { ToIpv4Int(targetIp) }.ToImmutableHashSet()
                            },
                            Action = IspAudit.Core.Models.PolicyAction.DropUdp443,
                            Scope = IspAudit.Core.Models.PolicyScope.Local
                        }
                    });

                    filter.SetDecisionGraphSnapshot(snapshot);

                    var udpToTarget = BuildIpv4UdpPacket(
                        srcIp,
                        targetIp,
                        srcPort: 50000,
                        dstPort: 443,
                        ttl: 64,
                        ipId: 1,
                        payload: new byte[] { 1, 2, 3 });

                    var udpToOther = BuildIpv4UdpPacket(
                        srcIp,
                        otherIp,
                        srcPort: 50001,
                        dstPort: 443,
                        ttl: 64,
                        ipId: 2,
                        payload: new byte[] { 4, 5, 6 });

                    var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);
                    var sender = new DummyPacketSender();

                    var allow1 = filter.Process(new InterceptedPacket(udpToTarget, udpToTarget.Length), ctx, sender);
                    var allow2 = filter.Process(new InterceptedPacket(udpToOther, udpToOther.Length), ctx, sender);

                    if (allow1)
                    {
                        return new SmokeTestResult("DPI2-041", "Policy-driven UDP/443: DROP UDP/443 через DecisionGraphSnapshot + per-policy метрика", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали DROP UDP/443 для пакета к target IP, но пакет был пропущен");
                    }

                    if (!allow2)
                    {
                        return new SmokeTestResult("DPI2-041", "Policy-driven UDP/443: DROP UDP/443 через DecisionGraphSnapshot + per-policy метрика", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали PASS UDP/443 для пакета к НЕ-целевому IP, но пакет был дропнут");
                    }

                    var metrics = filter.GetMetrics();
                    if (metrics.Udp443Dropped != 1)
                    {
                        return new SmokeTestResult("DPI2-041", "Policy-driven UDP/443: DROP UDP/443 через DecisionGraphSnapshot + per-policy метрика", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали Udp443Dropped=1, получили {metrics.Udp443Dropped}");
                    }

                    var perPolicy = filter.GetPolicyAppliedCountsSnapshot();
                    if (!perPolicy.TryGetValue(policyId, out var cnt) || cnt != 1)
                    {
                        var observed = string.Join(", ", perPolicy.Select(kv => kv.Key + "=" + kv.Value));
                        return new SmokeTestResult("DPI2-041", "Policy-driven UDP/443: DROP UDP/443 через DecisionGraphSnapshot + per-policy метрика", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали per-policy счётчик {policyId}=1, получили: {observed}");
                    }

                    return new SmokeTestResult("DPI2-041", "Policy-driven UDP/443: DROP UDP/443 через DecisionGraphSnapshot + per-policy метрика", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: decision graph влияет на runtime, метрика по policy-id инкрементится");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_UDP443", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_PolicyDrivenTtlEndpointBlock_Expires_AndHasHigherPriority(CancellationToken ct)
            => RunAsync("DPI2-042", "TTL endpoint block (policy-driven): истечение TTL + высокий приоритет", () =>
            {
                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TTLBLOCK");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TTLBLOCK", "1");

                    var targetIp = IPAddress.Parse("203.0.113.10");
                    var otherIp = IPAddress.Parse("198.51.100.20");
                    var srcIp = IPAddress.Parse("10.0.0.2");

                    var ttl = TimeSpan.FromMilliseconds(200);
                    var filter = new IspAudit.Core.Traffic.Filters.TemporaryEndpointBlockFilter(
                        name: "smoke_ttl_block",
                        ipv4Targets: new[] { targetIp },
                        ttl: ttl,
                        port: 443,
                        blockTcp: true,
                        blockUdp: true);

                    // Проверяем приоритет относительно BypassFilter (важно для «переподключения»).
                    var bypassFilter = new IspAudit.Core.Traffic.Filters.BypassFilter(new BypassProfile { DropUdp443 = true });
                    if (filter.Priority <= bypassFilter.Priority)
                    {
                        return new SmokeTestResult("DPI2-042", "TTL endpoint block (policy-driven): истечение TTL + высокий приоритет", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали priority TTL-block фильтра > priority BypassFilter, получили {filter.Priority} <= {bypassFilter.Priority}");
                    }

                    var tcpToTarget = BuildIpv4TcpPacket(srcIp, targetIp, srcPort: 50000, dstPort: 443, ttl: 64, ipId: 10, seq: 1000, tcpFlags: 0x18, payload: new byte[] { 1, 2, 3 });
                    var tcpToOther = BuildIpv4TcpPacket(srcIp, otherIp, srcPort: 50001, dstPort: 443, ttl: 64, ipId: 11, seq: 2000, tcpFlags: 0x18, payload: new byte[] { 4, 5, 6 });

                    var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);
                    var sender = new DummyPacketSender();

                    var allowTargetBefore = filter.Process(new InterceptedPacket(tcpToTarget, tcpToTarget.Length), ctx, sender);
                    var allowOtherBefore = filter.Process(new InterceptedPacket(tcpToOther, tcpToOther.Length), ctx, sender);

                    if (allowTargetBefore)
                    {
                        return new SmokeTestResult("DPI2-042", "TTL endpoint block (policy-driven): истечение TTL + высокий приоритет", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали DROP TCP/443 для target IP до истечения TTL, но пакет был пропущен");
                    }

                    if (!allowOtherBefore)
                    {
                        return new SmokeTestResult("DPI2-042", "TTL endpoint block (policy-driven): истечение TTL + высокий приоритет", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали PASS TCP/443 для НЕ-целевого IP до истечения TTL, но пакет был дропнут");
                    }

                    Thread.Sleep(ttl + TimeSpan.FromMilliseconds(80));

                    var allowTargetAfter = filter.Process(new InterceptedPacket(tcpToTarget, tcpToTarget.Length), ctx, sender);
                    if (!allowTargetAfter)
                    {
                        return new SmokeTestResult("DPI2-042", "TTL endpoint block (policy-driven): истечение TTL + высокий приоритет", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали PASS TCP/443 для target IP после истечения TTL, но пакет всё ещё дропается");
                    }

                    return new SmokeTestResult("DPI2-042", "TTL endpoint block (policy-driven): истечение TTL + высокий приоритет", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: TTL-блок работает до истечения TTL и не влияет после");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TTLBLOCK", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_PolicyDrivenTcp80_HttpHostTricks_ViaDecisionGraph(CancellationToken ct)
            => RunAsync("DPI2-043", "TCP/80 HTTP Host tricks: policy-driven через DecisionGraphSnapshot", () =>
            {
                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80", "1");

                    // Важно: в этом smoke намеренно выключаем legacy-флаг профиля,
                    // чтобы проверить, что действие включается именно политикой.
                    var profile = new BypassProfile
                    {
                        DropTcpRst = false,
                        FragmentTlsClientHello = false,
                        TlsStrategy = TlsBypassStrategy.None,
                        TlsFragmentThreshold = 100,
                        HttpHostTricks = false,
                        RedirectRules = Array.Empty<BypassRedirectRule>()
                    };

                    var filter = new IspAudit.Core.Traffic.Filters.BypassFilter(profile, logAction: null, presetName: "smoke");

                    var policyId = "tcp80_http_host_tricks_smoke";
                    var snapshot = IspAudit.Core.Bypass.PolicySetCompiler.CompileOrThrow(new[]
                    {
                        new FlowPolicy
                        {
                            Id = policyId,
                            Priority = 100,
                            Match = new MatchCondition
                            {
                                Proto = FlowTransportProtocol.Tcp,
                                Port = 80
                            },
                            Action = PolicyAction.HttpHostTricks,
                            Scope = PolicyScope.Global
                        }
                    });

                    filter.SetDecisionGraphSnapshot(snapshot);

                    var sender = new CapturePacketSender();
                    var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                    var clientIp = IPAddress.Parse("10.10.0.2");
                    var serverIp = IPAddress.Parse("93.184.216.34");
                    var srcPort = (ushort)50110;
                    var seqBase = 123450u;

                    var http = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: smoke\r\n\r\n";
                    var payload = Encoding.ASCII.GetBytes(http);
                    var pkt = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 80, ttl: 64, ipId: 210, seq: seqBase, tcpFlags: 0x18, payload: payload);

                    var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);
                    if (forwarded)
                    {
                        return new SmokeTestResult("DPI2-043", "TCP/80 HTTP Host tricks: policy-driven через DecisionGraphSnapshot", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали drop оригинального пакета (Process вернёт false)");
                    }

                    if (sender.Sent.Count != 2)
                    {
                        return new SmokeTestResult("DPI2-043", "TCP/80 HTTP Host tricks: policy-driven через DecisionGraphSnapshot", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали 2 отправки (2 сегмента), получили: {sender.Sent.Count}");
                    }

                    var perPolicy = filter.GetPolicyAppliedCountsSnapshot();
                    if (!perPolicy.TryGetValue(policyId, out var cnt) || cnt != 1)
                    {
                        var observed = string.Join(", ", perPolicy.Select(kv => kv.Key + "=" + kv.Value));
                        return new SmokeTestResult("DPI2-043", "TCP/80 HTTP Host tricks: policy-driven через DecisionGraphSnapshot", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали per-policy счётчик {policyId}=1, получили: {observed}");
                    }

                    return new SmokeTestResult("DPI2-043", "TCP/80 HTTP Host tricks: policy-driven через DecisionGraphSnapshot", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: HTTP Host tricks применились через decision graph, метрика по policy-id инкрементнулась");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_PolicyDrivenTcp443_TlsStrategySelection_ViaDecisionGraph(CancellationToken ct)
            => RunAsync("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", () =>
            {
                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", "1");

                    static uint ToIpv4Int(IPAddress ip)
                    {
                        var b = ip.GetAddressBytes();
                        if (b.Length != 4) return 0;
                        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                    }

                    // Legacy стратегия намеренно отличается от policy-выбранных,
                    // чтобы можно было проверить fallback (когда policy не мэтчится).
                    var profile = new BypassProfile
                    {
                        DropTcpRst = false,
                        FragmentTlsClientHello = true,
                        TlsStrategy = TlsBypassStrategy.Fake, // fallback
                        TlsFragmentThreshold = 1,
                        TlsFragmentSizes = new List<int> { 64 },
                        AllowNoSni = true,
                        DropUdp443 = false,
                        HttpHostTricks = false,
                        RedirectRules = Array.Empty<BypassRedirectRule>()
                    };

                    var filter = new IspAudit.Core.Traffic.Filters.BypassFilter(profile, logAction: null, presetName: "smoke");

                    var policyA = "tcp443_tls_strategy_fragment";
                    var policyB = "tcp443_tls_strategy_fake_disorder";

                    var ipA = IPAddress.Parse("203.0.113.10");
                    var ipB = IPAddress.Parse("198.51.100.20");
                    var ipC = IPAddress.Parse("192.0.2.30");
                    var clientIp = IPAddress.Parse("10.10.0.2");

                    var snapshot = IspAudit.Core.Bypass.PolicySetCompiler.CompileOrThrow(new[]
                    {
                        new FlowPolicy
                        {
                            Id = policyA,
                            Priority = 100,
                            Match = new MatchCondition
                            {
                                Proto = FlowTransportProtocol.Tcp,
                                Port = 443,
                                TlsStage = TlsStage.ClientHello,
                                DstIpv4Set = new[] { ToIpv4Int(ipA) }.ToImmutableHashSet()
                            },
                            Action = PolicyAction.TlsBypassStrategy(TlsBypassStrategy.Fragment.ToString()),
                            Scope = PolicyScope.Local
                        },
                        new FlowPolicy
                        {
                            Id = policyB,
                            Priority = 100,
                            Match = new MatchCondition
                            {
                                Proto = FlowTransportProtocol.Tcp,
                                Port = 443,
                                TlsStage = TlsStage.ClientHello,
                                DstIpv4Set = new[] { ToIpv4Int(ipB) }.ToImmutableHashSet()
                            },
                            Action = PolicyAction.TlsBypassStrategy(TlsBypassStrategy.FakeDisorder.ToString()),
                            Scope = PolicyScope.Local
                        }
                    });

                    filter.SetDecisionGraphSnapshot(snapshot);

                    var tlsPayload = new byte[200];
                    tlsPayload[0] = 0x16; // TLS Handshake record
                    tlsPayload[5] = 0x01; // ClientHello

                    var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                    // A) ipA: Fragment => 2 отправки (2 сегмента)
                    {
                        var sender = new CapturePacketSender();
                        var pkt = BuildIpv4TcpPacket(clientIp, ipA, srcPort: 50110, dstPort: 443, ttl: 64, ipId: 210, seq: 123450u, tcpFlags: 0x18, payload: tlsPayload);
                        var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);
                        if (forwarded)
                        {
                            return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                                "ipA: ожидали drop оригинального пакета (Process вернёт false)");
                        }

                        if (sender.Sent.Count != 2)
                        {
                            return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"ipA: ожидали 2 отправки (Fragment), получили: {sender.Sent.Count}");
                        }
                    }

                    // B) ipB: FakeDisorder => 3 отправки (1 fake + 2 сегмента)
                    {
                        var sender = new CapturePacketSender();
                        var pkt = BuildIpv4TcpPacket(clientIp, ipB, srcPort: 50111, dstPort: 443, ttl: 64, ipId: 211, seq: 223450u, tcpFlags: 0x18, payload: tlsPayload);
                        var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);
                        if (forwarded)
                        {
                            return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                                "ipB: ожидали drop оригинального пакета (Process вернёт false)");
                        }

                        if (sender.Sent.Count != 3)
                        {
                            return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"ipB: ожидали 3 отправки (FakeDisorder), получили: {sender.Sent.Count}");
                        }
                    }

                    // C) ipC: нет policy => fallback на профайл (Fake => 1 отправка)
                    {
                        var sender = new CapturePacketSender();
                        var pkt = BuildIpv4TcpPacket(clientIp, ipC, srcPort: 50112, dstPort: 443, ttl: 64, ipId: 212, seq: 323450u, tcpFlags: 0x18, payload: tlsPayload);
                        var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);
                        if (forwarded)
                        {
                            return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                                "ipC: ожидали drop оригинального пакета (Process вернёт false) по legacy Fake");
                        }

                        if (sender.Sent.Count != 1)
                        {
                            return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"ipC: ожидали 1 отправку (legacy Fake), получили: {sender.Sent.Count}");
                        }
                    }

                    var perPolicy = filter.GetPolicyAppliedCountsSnapshot();
                    if (!perPolicy.TryGetValue(policyA, out var cntA) || cntA != 1)
                    {
                        var observed = string.Join(", ", perPolicy.Select(kv => kv.Key + "=" + kv.Value));
                        return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали per-policy счётчик {policyA}=1, получили: {observed}");
                    }

                    if (!perPolicy.TryGetValue(policyB, out var cntB) || cntB != 1)
                    {
                        var observed = string.Join(", ", perPolicy.Select(kv => kv.Key + "=" + kv.Value));
                        return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали per-policy счётчик {policyB}=1, получили: {observed}");
                    }

                    return new SmokeTestResult("DPI2-044", "TCP/443 TLS strategy: policy-driven выбор стратегии (per-endpoint) + fallback", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: per-endpoint TLS стратегии выбираются через decision graph; fallback на legacy работает; per-policy метрики инкрементятся");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_SemanticGroups_Statuses_AreDeterministic(CancellationToken ct)
            => RunAsync("DPI2-045", "Semantic Groups: статусы NO_TRAFFIC/PARTIAL/ENABLED по policy-matched", () =>
            {
                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", "1");

                    static uint ToIpv4Int(IPAddress ip)
                    {
                        var b = ip.GetAddressBytes();
                        if (b.Length != 4) return 0;
                        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                    }

                    var profile = new BypassProfile
                    {
                        DropTcpRst = false,
                        FragmentTlsClientHello = true,
                        TlsStrategy = TlsBypassStrategy.Fake, // fallback не должен влиять на статус группы
                        TlsFragmentThreshold = 1,
                        TlsFragmentSizes = new List<int> { 64 },
                        AllowNoSni = true,
                        DropUdp443 = false,
                        HttpHostTricks = false,
                        RedirectRules = Array.Empty<BypassRedirectRule>()
                    };

                    var filter = new IspAudit.Core.Traffic.Filters.BypassFilter(profile, logAction: null, presetName: "smoke");

                    var ipA = IPAddress.Parse("203.0.113.10");
                    var ipB = IPAddress.Parse("198.51.100.20");
                    var ipC = IPAddress.Parse("192.0.2.30");
                    var clientIp = IPAddress.Parse("10.10.0.2");

                    var pA = new FlowPolicy
                    {
                        Id = "sg_youtube_tcp443_A",
                        Priority = 100,
                        Match = new MatchCondition
                        {
                            Proto = FlowTransportProtocol.Tcp,
                            Port = 443,
                            TlsStage = TlsStage.ClientHello,
                            DstIpv4Set = new[] { ToIpv4Int(ipA) }.ToImmutableHashSet()
                        },
                        Action = PolicyAction.TlsBypassStrategy(TlsBypassStrategy.Fragment.ToString()),
                        Scope = PolicyScope.Local
                    };

                    var pB = new FlowPolicy
                    {
                        Id = "sg_youtube_tcp443_B",
                        Priority = 100,
                        Match = new MatchCondition
                        {
                            Proto = FlowTransportProtocol.Tcp,
                            Port = 443,
                            TlsStage = TlsStage.ClientHello,
                            DstIpv4Set = new[] { ToIpv4Int(ipB) }.ToImmutableHashSet()
                        },
                        Action = PolicyAction.TlsBypassStrategy(TlsBypassStrategy.FakeDisorder.ToString()),
                        Scope = PolicyScope.Local
                    };

                    var pC = new FlowPolicy
                    {
                        Id = "sg_youtube_tcp443_C",
                        Priority = 100,
                        Match = new MatchCondition
                        {
                            Proto = FlowTransportProtocol.Tcp,
                            Port = 443,
                            TlsStage = TlsStage.ClientHello,
                            DstIpv4Set = new[] { ToIpv4Int(ipC) }.ToImmutableHashSet()
                        },
                        Action = PolicyAction.TlsBypassStrategy(TlsBypassStrategy.Fake.ToString()),
                        Scope = PolicyScope.Local
                    };

                    var snapshot = IspAudit.Core.Bypass.PolicySetCompiler.CompileOrThrow(new[] { pA, pB, pC });
                    filter.SetDecisionGraphSnapshot(snapshot);

                    var group = new SemanticGroup
                    {
                        GroupKey = "youtube",
                        DisplayName = "YouTube",
                        DomainPatterns = ImmutableArray.Create("youtube.com", "googlevideo.com", "ytimg.com"),
                        PolicyBundle = snapshot.Policies
                    };

                    // 0) NO_TRAFFIC
                    {
                        var s0 = SemanticGroupEvaluator.EvaluateStatus(group, filter.GetPolicyMatchedCountsSnapshot());
                        if (s0.Status != SemanticGroupStatus.NoTraffic)
                        {
                            return new SmokeTestResult("DPI2-045", "Semantic Groups: статусы NO_TRAFFIC/PARTIAL/ENABLED по policy-matched", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Ожидали NO_TRAFFIC, получили {s0.Text} ({s0.Details})");
                        }
                    }

                    var tlsPayload = new byte[200];
                    tlsPayload[0] = 0x16; // TLS Handshake record
                    tlsPayload[5] = 0x01; // ClientHello

                    var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                    // 1) PARTIAL: был трафик только для A и B
                    {
                        var sender = new CapturePacketSender();
                        var pktA = BuildIpv4TcpPacket(clientIp, ipA, srcPort: 50110, dstPort: 443, ttl: 64, ipId: 210, seq: 123450u, tcpFlags: 0x18, payload: tlsPayload);
                        _ = filter.Process(new InterceptedPacket(pktA, pktA.Length), ctx, sender);

                        var pktB = BuildIpv4TcpPacket(clientIp, ipB, srcPort: 50111, dstPort: 443, ttl: 64, ipId: 211, seq: 223450u, tcpFlags: 0x18, payload: tlsPayload);
                        _ = filter.Process(new InterceptedPacket(pktB, pktB.Length), ctx, sender);

                        var s1 = SemanticGroupEvaluator.EvaluateStatus(group, filter.GetPolicyMatchedCountsSnapshot());
                        if (s1.Status != SemanticGroupStatus.Partial)
                        {
                            return new SmokeTestResult("DPI2-045", "Semantic Groups: статусы NO_TRAFFIC/PARTIAL/ENABLED по policy-matched", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Ожидали PARTIAL после трафика A+B, получили {s1.Text} ({s1.Details})");
                        }
                    }

                    // 2) ENABLED: добавили трафик для C
                    {
                        var sender = new CapturePacketSender();
                        var pktC = BuildIpv4TcpPacket(clientIp, ipC, srcPort: 50112, dstPort: 443, ttl: 64, ipId: 212, seq: 323450u, tcpFlags: 0x18, payload: tlsPayload);
                        _ = filter.Process(new InterceptedPacket(pktC, pktC.Length), ctx, sender);

                        var s2 = SemanticGroupEvaluator.EvaluateStatus(group, filter.GetPolicyMatchedCountsSnapshot());
                        if (s2.Status != SemanticGroupStatus.Enabled)
                        {
                            return new SmokeTestResult("DPI2-045", "Semantic Groups: статусы NO_TRAFFIC/PARTIAL/ENABLED по policy-matched", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Ожидали ENABLED после трафика A+B+C, получили {s2.Text} ({s2.Details})");
                        }
                    }

                    return new SmokeTestResult("DPI2-045", "Semantic Groups: статусы NO_TRAFFIC/PARTIAL/ENABLED по policy-matched", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: статусы группы детерминированны и основаны на policy-matched метриках");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_PolicySnapshotExport_AndActivePolicies_AreValid(CancellationToken ct)
            => RunAsyncAwait("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", async innerCt =>
            {
                static uint ToIpv4Int(IPAddress ip)
                {
                    var bytes = ip.GetAddressBytes();
                    if (bytes.Length != 4) throw new ArgumentException("Ожидали IPv4 адрес", nameof(ip));
                    return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                }

                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_UDP443");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_UDP443", "1");

                    using var engine = new TrafficEngine();
                    var profile = new BypassProfile
                    {
                        DropUdp443 = true,
                        FragmentTlsClientHello = false,
                        DropTcpRst = false
                    };

                    using var service = new TlsBypassService(engine, profile, _ => { }, useTrafficEngine: false, startMetricsTimer: false, nowProvider: () => DateTime.UtcNow);
                    var filter = new IspAudit.Core.Traffic.Filters.BypassFilter(profile, logAction: null, presetName: "smoke");
                    service.SetFilterForSmoke(filter);

                    var targetIp = IPAddress.Parse("203.0.113.10");
                    var otherIp = IPAddress.Parse("198.51.100.20");
                    var srcIp = IPAddress.Parse("10.0.0.2");

                    const string policyId = "smoke_udp443_drop_export";
                    var snapshot = IspAudit.Core.Bypass.PolicySetCompiler.CompileOrThrow(new[]
                    {
                        new FlowPolicy
                        {
                            Id = policyId,
                            Priority = 100,
                            Match = new MatchCondition
                            {
                                Proto = FlowTransportProtocol.Udp,
                                Port = 443,
                                DstIpv4Set = new[] { ToIpv4Int(targetIp) }.ToImmutableHashSet()
                            },
                            Action = PolicyAction.DropUdp443,
                            Scope = PolicyScope.Local
                        }
                    });

                    service.SetDecisionGraphSnapshotForManager(snapshot);

                    // Дадим один пакет, который точно матчится политикой, чтобы появились matched/applied метрики.
                    var udpToTarget = BuildIpv4UdpPacket(
                        srcIp,
                        targetIp,
                        srcPort: 50000,
                        dstPort: 443,
                        ttl: 64,
                        ipId: 1,
                        payload: new byte[] { 1, 2, 3 });

                    var udpToOther = BuildIpv4UdpPacket(
                        srcIp,
                        otherIp,
                        srcPort: 50001,
                        dstPort: 443,
                        ttl: 64,
                        ipId: 2,
                        payload: new byte[] { 4, 5, 6 });

                    var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);
                    var sender = new DummyPacketSender();

                    _ = filter.Process(new InterceptedPacket(udpToTarget, udpToTarget.Length), ctx, sender);
                    _ = filter.Process(new InterceptedPacket(udpToOther, udpToOther.Length), ctx, sender);

                    var tcs = new TaskCompletionSource<TlsBypassMetrics>(TaskCreationOptions.RunContinuationsAsynchronously);
                    void OnMetrics(TlsBypassMetrics m)
                    {
                        if (!tcs.Task.IsCompleted)
                        {
                            tcs.TrySetResult(m);
                        }
                    }

                    service.MetricsUpdated += OnMetrics;
                    await service.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);

                    var completed = await Task.WhenAny(tcs.Task, Task.Delay(500, innerCt)).ConfigureAwait(false);
                    service.MetricsUpdated -= OnMetrics;

                    if (completed != tcs.Task)
                    {
                        throw new InvalidOperationException("Не получили MetricsUpdated после PullMetricsOnceAsyncForSmoke");
                    }

                    var metrics = await tcs.Task.ConfigureAwait(false);

                    if (string.IsNullOrWhiteSpace(metrics.PolicySnapshotJson))
                    {
                        return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PolicySnapshotJson пустой (ожидали JSON со списком политик)");
                    }

                    // 1) JSON парсится и содержит нашу policy-id.
                    using (var doc = JsonDocument.Parse(metrics.PolicySnapshotJson))
                    {
                        var root = doc.RootElement;
                        if (!root.TryGetProperty("Version", out var version) || version.GetString() != "v1")
                        {
                            return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Fail, TimeSpan.Zero,
                                "PolicySnapshotJson: отсутствует Version=v1");
                        }

                        if (!root.TryGetProperty("Policies", out var policies) || policies.ValueKind != JsonValueKind.Array)
                        {
                            return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Fail, TimeSpan.Zero,
                                "PolicySnapshotJson: отсутствует массив Policies");
                        }

                        var found = false;
                        foreach (var row in policies.EnumerateArray())
                        {
                            if (!row.TryGetProperty("Id", out var idProp)) continue;
                            if (!string.Equals(idProp.GetString(), policyId, StringComparison.Ordinal)) continue;
                            found = true;

                            if (!row.TryGetProperty("AppliedCount", out var applied) || applied.GetInt64() <= 0)
                            {
                                return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Fail, TimeSpan.Zero,
                                    "PolicySnapshotJson: AppliedCount для policy-id не увеличился (ожидали >0)");
                            }

                            break;
                        }

                        if (!found)
                        {
                            return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"PolicySnapshotJson: не нашли policy-id={policyId} в Policies");
                        }
                    }

                    // 2) Таблица ActivePolicies присутствует и содержит нашу политику.
                    var table = metrics.ActivePolicies ?? Array.Empty<ActiveFlowPolicyRow>();
                    var rowFound = table.FirstOrDefault(r => string.Equals(r.Id, policyId, StringComparison.Ordinal));
                    if (rowFound == null)
                    {
                        var observed = string.Join(", ", table.Select(r => r.Id));
                        return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"ActivePolicies не содержит policy-id={policyId}. observed=[{observed}]" );
                    }

                    if (rowFound.AppliedCount <= 0)
                    {
                        return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Fail, TimeSpan.Zero,
                            "ActivePolicies: AppliedCount для policy-id не увеличился (ожидали >0)");
                    }

                    return new SmokeTestResult("DPI2-046", "Policy snapshot export: JSON парсится и ActivePolicies отражает policy метрики", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: snapshot экспортируется в JSON, таблица ActivePolicies отражает метрики");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_UDP443", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_PerTargetPolicy_UsesCandidateEndpointsSeed_NoDnsRequired(CancellationToken ct)
            => RunAsyncAwait("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", async innerCt =>
            {
                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", "1");

                    using var engine = new TrafficEngine(progress: null);
                    var profile = BypassProfile.CreateDefault();

                    // Smoke-safe: не трогаем WinDivert/TrafficEngine.StartAsync (требует UAC).
                    var tls = new TlsBypassService(
                        trafficEngine: engine,
                        baseProfile: profile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: null);

                    using var manager = BypassStateManager.GetOrCreateFromService(tls, profile, log: null);

                    const string host = "not-a-real-host.invalid";

                    // 1) Задаём активную цель с per-target TLS стратегией.
                    manager.RememberActiveTargetPolicy(new BypassStateManager.ActiveTargetPolicy
                    {
                        HostKey = host,
                        LastAppliedUtc = DateTime.UtcNow,
                        TlsStrategy = TlsBypassStrategy.Fragment,
                        DropUdp443 = false,
                        AllowNoSni = false,
                        HttpHostTricksEnabled = false
                    });

                    // 2) Подкладываем candidate endpoints (как будто пришли из apply-транзакции/результатов тестов).
                    manager.UpdateActiveTargetCandidateEndpointsBestEffort(host, new[]
                    {
                        "1.2.3.4:443",
                        "5.6.7.8:443"
                    });

                    var active = manager.GetActiveTargetPoliciesSnapshot(host);
                    var activeRow = active.FirstOrDefault(v => string.Equals(v.HostKey, host, StringComparison.OrdinalIgnoreCase));
                    if (activeRow == null || activeRow.CandidateIpEndpoints.Count == 0)
                    {
                        return new SmokeTestResult("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "UpdateActiveTargetCandidateEndpointsBestEffort не сохранил candidate endpoints в ActiveTargetPolicy");
                    }

                    // 3) Apply: должен скомпилировать per-target policy с DstIpv4Set из cache (без DNS).
                    var options = TlsBypassOptions.CreateDefault(profile) with { FragmentEnabled = true };
                    await manager.ApplyTlsOptionsAsync(options, innerCt).ConfigureAwait(false);

                    var observedAfter = manager.GetObservedIpv4TargetsSnapshotForHost(host);
                    if (observedAfter.Length == 0)
                    {
                        return new SmokeTestResult("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "После ApplyTlsOptionsAsync observed IPv4 snapshot пустой (ожидали seed из candidate endpoints)");
                    }

                    var tcs = new TaskCompletionSource<TlsBypassMetrics>(TaskCreationOptions.RunContinuationsAsynchronously);
                    void OnMetrics(TlsBypassMetrics m)
                    {
                        if (!tcs.Task.IsCompleted)
                        {
                            tcs.TrySetResult(m);
                        }
                    }

                    manager.TlsService.MetricsUpdated += OnMetrics;
                    await manager.TlsService.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);
                    var completed = await Task.WhenAny(tcs.Task, Task.Delay(500, innerCt)).ConfigureAwait(false);
                    manager.TlsService.MetricsUpdated -= OnMetrics;

                    if (completed != tcs.Task)
                    {
                        return new SmokeTestResult("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не получили MetricsUpdated после PullMetricsOnceAsyncForSmoke");
                    }

                    var metrics = await tcs.Task.ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(metrics.PolicySnapshotJson))
                    {
                        return new SmokeTestResult("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PolicySnapshotJson пустой (ожидали, что snapshot собран)" );
                    }

                    using var doc = JsonDocument.Parse(metrics.PolicySnapshotJson);
                    var root = doc.RootElement;
                    if (!root.TryGetProperty("Policies", out var policies) || policies.ValueKind != JsonValueKind.Array)
                    {
                        return new SmokeTestResult("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PolicySnapshotJson: отсутствует массив Policies");
                    }

                    var foundPerTarget = false;
                    foreach (var row in policies.EnumerateArray())
                    {
                        if (!row.TryGetProperty("Id", out var idProp)) continue;
                        var id = idProp.GetString() ?? string.Empty;
                        if (!id.StartsWith("tcp443_tls_", StringComparison.Ordinal)) continue;

                        if (!row.TryGetProperty("DstIpv4SetPreview", out var preview) || preview.ValueKind != JsonValueKind.Array)
                        {
                            continue;
                        }

                        var hasA = false;
                        var hasB = false;
                        foreach (var ip in preview.EnumerateArray())
                        {
                            var s = ip.GetString() ?? string.Empty;
                            if (s == "1.2.3.4") hasA = true;
                            if (s == "5.6.7.8") hasB = true;
                        }

                        if (hasA && hasB)
                        {
                            foundPerTarget = true;
                            break;
                        }
                    }

                    if (!foundPerTarget)
                    {
                        return new SmokeTestResult("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не нашли per-target tcp443_tls_* политику с DstIpv4SetPreview=[1.2.3.4, 5.6.7.8]" );
                    }

                    return new SmokeTestResult("DPI2-047", "Per-target policy: DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: per-target DstIpv4Set берётся из candidate endpoints, без DNS" );
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_PerTargetTcp80Policy_UsesCandidateEndpointsSeed_NoDnsRequired(CancellationToken ct)
            => RunAsyncAwait("DPI2-048", "Per-target policy (TCP/80): DstIpv4Set собирается из candidate endpoints (без DNS)", async innerCt =>
            {
                var prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80");
                try
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80", "1");

                    using var engine = new TrafficEngine(progress: null);
                    var profile = BypassProfile.CreateDefault();

                    // Smoke-safe: не трогаем WinDivert/TrafficEngine.StartAsync (требует UAC).
                    var tls = new TlsBypassService(
                        trafficEngine: engine,
                        baseProfile: profile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: null);

                    using var manager = BypassStateManager.GetOrCreateFromService(tls, profile, log: null);

                    const string host = "not-a-real-host.invalid";

                    // 1) Задаём активную цель с per-target TCP/80 HostTricks.
                    manager.RememberActiveTargetPolicy(new BypassStateManager.ActiveTargetPolicy
                    {
                        HostKey = host,
                        LastAppliedUtc = DateTime.UtcNow,
                        TlsStrategy = TlsBypassStrategy.None,
                        DropUdp443 = false,
                        AllowNoSni = false,
                        HttpHostTricksEnabled = true
                    });

                    // 2) Подкладываем candidate endpoints (как будто пришли из apply-транзакции/результатов тестов).
                    manager.UpdateActiveTargetCandidateEndpointsBestEffort(host, new[]
                    {
                        "1.2.3.4:80",
                        "5.6.7.8:80"
                    });

                    // 3) Apply: должен скомпилировать per-target policy с DstIpv4Set из cache (без DNS).
                    var options = TlsBypassOptions.CreateDefault(profile) with { HttpHostTricksEnabled = true };
                    await manager.ApplyTlsOptionsAsync(options, innerCt).ConfigureAwait(false);

                    var observedAfter = manager.GetObservedIpv4TargetsSnapshotForHost(host);
                    if (observedAfter.Length == 0)
                    {
                        return new SmokeTestResult("DPI2-048", "Per-target policy (TCP/80): DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "После ApplyTlsOptionsAsync observed IPv4 snapshot пустой (ожидали seed из candidate endpoints)");
                    }

                    var tcs = new TaskCompletionSource<TlsBypassMetrics>(TaskCreationOptions.RunContinuationsAsynchronously);
                    void OnMetrics(TlsBypassMetrics m)
                    {
                        if (!tcs.Task.IsCompleted)
                        {
                            tcs.TrySetResult(m);
                        }
                    }

                    manager.TlsService.MetricsUpdated += OnMetrics;
                    await manager.TlsService.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);
                    var completed = await Task.WhenAny(tcs.Task, Task.Delay(500, innerCt)).ConfigureAwait(false);
                    manager.TlsService.MetricsUpdated -= OnMetrics;

                    if (completed != tcs.Task)
                    {
                        return new SmokeTestResult("DPI2-048", "Per-target policy (TCP/80): DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не получили MetricsUpdated после PullMetricsOnceAsyncForSmoke");
                    }

                    var metrics = await tcs.Task.ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(metrics.PolicySnapshotJson))
                    {
                        return new SmokeTestResult("DPI2-048", "Per-target policy (TCP/80): DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PolicySnapshotJson пустой (ожидали, что snapshot собран)");
                    }

                    using var doc = JsonDocument.Parse(metrics.PolicySnapshotJson);
                    var root = doc.RootElement;
                    if (!root.TryGetProperty("Policies", out var policies) || policies.ValueKind != JsonValueKind.Array)
                    {
                        return new SmokeTestResult("DPI2-048", "Per-target policy (TCP/80): DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PolicySnapshotJson: отсутствует массив Policies");
                    }

                    var foundPerTarget = false;
                    foreach (var row in policies.EnumerateArray())
                    {
                        if (!row.TryGetProperty("Id", out var idProp)) continue;
                        var id = idProp.GetString() ?? string.Empty;
                        if (!id.StartsWith("tcp80_http_host_tricks_", StringComparison.Ordinal)) continue;

                        if (!row.TryGetProperty("DstIpv4SetPreview", out var preview) || preview.ValueKind != JsonValueKind.Array)
                        {
                            continue;
                        }

                        var hasA = false;
                        var hasB = false;
                        foreach (var ip in preview.EnumerateArray())
                        {
                            var s = ip.GetString() ?? string.Empty;
                            if (s == "1.2.3.4") hasA = true;
                            if (s == "5.6.7.8") hasB = true;
                        }

                        if (hasA && hasB)
                        {
                            foundPerTarget = true;
                            break;
                        }
                    }

                    if (!foundPerTarget)
                    {
                        return new SmokeTestResult("DPI2-048", "Per-target policy (TCP/80): DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не нашли per-target tcp80_http_host_tricks_* политику с DstIpv4SetPreview=[1.2.3.4, 5.6.7.8]");
                    }

                    return new SmokeTestResult("DPI2-048", "Per-target policy (TCP/80): DstIpv4Set собирается из candidate endpoints (без DNS)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: per-target DstIpv4Set (TCP/80) берётся из candidate endpoints, без DNS");
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Guard_BypassStateManager_IsSingleSourceOfTruth(CancellationToken ct)
            => RunAsyncAwait("DPI2-026", "Guard: TrafficEngine/TlsBypassService только через BypassStateManager", async innerCt =>
            {
                // Важно: enforce включается при создании менеджера.
                using var engine = new TrafficEngine(progress: null);
                var profile = BypassProfile.CreateDefault();

                using var provider = BuildIspAuditProvider();
                var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                var manager = managerFactory.GetOrCreate(engine, baseProfile: profile, log: null);

                // 1) В strict-режиме прямой вызов TrafficEngine вне manager-scope должен падать.
                using (BypassStateManagerGuard.EnterStrictModeForSmoke())
                {
                    try
                    {
                        engine.RegisterFilter(new NoOpPacketFilter());
                        return new SmokeTestResult("DPI2-026", "Guard: TrafficEngine/TlsBypassService только через BypassStateManager", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали исключение при прямом вызове TrafficEngine.RegisterFilter вне manager-scope");
                    }
                    catch (InvalidOperationException)
                    {
                        // OK
                    }

                    try
                    {
                        await manager.TlsService.ApplyAsync(TlsBypassOptions.CreateDefault(profile), innerCt).ConfigureAwait(false);
                        return new SmokeTestResult("DPI2-026", "Guard: TrafficEngine/TlsBypassService только через BypassStateManager", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали исключение при прямом вызове TlsBypassService.ApplyAsync вне manager-scope");
                    }
                    catch (InvalidOperationException)
                    {
                        // OK
                    }
                }

                // 2) Через менеджер (manager-scope) — не должно падать.
                await manager.ApplyTlsOptionsAsync(TlsBypassOptions.CreateDefault(profile), innerCt).ConfigureAwait(false);

                return new SmokeTestResult("DPI2-026", "Guard: TrafficEngine/TlsBypassService только через BypassStateManager", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: direct calls blocked, manager calls allowed");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Guard_NoLegacySignalsOrGetSignals_InIntelRuntimePath(CancellationToken ct)
            => RunAsync("DPI2-025", "Guard: в intel runtime-пути нет GetSignals/legacy classifier", () =>
            {
                static string? TryFindRepoRoot(string startDir)
                {
                    try
                    {
                        var dir = new DirectoryInfo(startDir);
                        while (dir != null)
                        {
                            var sln = Path.Combine(dir.FullName, "ISP_Audit.sln");
                            var csproj = Path.Combine(dir.FullName, "ISP_Audit.csproj");
                            if (File.Exists(sln) || File.Exists(csproj))
                            {
                                return dir.FullName;
                            }

                            dir = dir.Parent;
                        }
                    }
                    catch
                    {
                        // ignore
                    }

                    return null;
                }

                var root =
                    TryFindRepoRoot(Environment.CurrentDirectory) ??
                    TryFindRepoRoot(AppContext.BaseDirectory) ??
                    Environment.CurrentDirectory;

                var filesToCheck = new List<string>();

                // Ключевые runtime-файлы, где ранее могли протекать legacy зависимости.
                filesToCheck.Add(Path.Combine(root, "Utils", "LiveTestingPipeline.cs"));
                filesToCheck.Add(Path.Combine(root, "Utils", "AutoHostlistService.cs"));
                filesToCheck.Add(Path.Combine(root, "ViewModels", "DiagnosticOrchestrator.cs"));
                filesToCheck.Add(Path.Combine(root, "ViewModels", "TestResultsManager.cs"));

                // Весь INTEL-слой.
                var intelDir = Path.Combine(root, "Core", "Intelligence");
                if (Directory.Exists(intelDir))
                {
                    filesToCheck.AddRange(Directory.GetFiles(intelDir, "*.cs", SearchOption.AllDirectories));
                }

                filesToCheck = filesToCheck
                    .Where(File.Exists)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (filesToCheck.Count == 0)
                {
                    return new SmokeTestResult("DPI2-025", "Guard: в intel runtime-пути нет GetSignals/legacy classifier", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Не нашли файлы для проверки. root='{root}'");
                }

                var reGetSignalsCall = new Regex(@"\bGetSignals\s*\(", RegexOptions.Compiled);
                var reLegacySignals = new Regex(@"\blegacySignals\s*\.", RegexOptions.Compiled);
                var reNewLegacyClassifier = new Regex(@"\bnew\s+StandardBlockageClassifier\b", RegexOptions.Compiled);
                var reCallLegacyClassifier = new Regex(@"\bStandardBlockageClassifier\s*\.\s*ClassifyBlockage\s*\(", RegexOptions.Compiled);

                var offenders = new List<string>();
                foreach (var file in filesToCheck)
                {
                    ct.ThrowIfCancellationRequested();

                    var text = File.ReadAllText(file);

                    // 1) GetSignals(...) и legacySignals.* запрещены в intel runtime-пути без исключений.
                    // 2) Создание/вызов legacy-классификатора запрещено в runtime-пути (должно быть intel-only).
                    if (reGetSignalsCall.IsMatch(text) || reLegacySignals.IsMatch(text) || reNewLegacyClassifier.IsMatch(text) || reCallLegacyClassifier.IsMatch(text))
                    {
                        var rel = Path.GetRelativePath(root, file);
                        offenders.Add(rel.Replace('\\', '/'));
                        continue;
                    }
                }

                if (offenders.Count > 0)
                {
                    return new SmokeTestResult("DPI2-025", "Guard: в intel runtime-пути нет GetSignals/legacy classifier", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Найдены следы legacy в intel runtime-пути: " + string.Join(", ", offenders));
                }

                return new SmokeTestResult("DPI2-025", "Guard: в intel runtime-пути нет GetSignals/legacy classifier", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: checkedFiles={filesToCheck.Count}, root='{root}'");
            }, ct);

        private sealed class NoOpPacketFilter : IPacketFilter
        {
            public string Name => "NoOp";
            public int Priority => 0;

            public bool Process(InterceptedPacket packet, PacketContext ctx, IPacketSender sender)
            {
                return true;
            }
        }

        public static Task<SmokeTestResult> Dpi2_SignalsAdapter_Observe_AdaptsLegacySignals_ToTtlStore(CancellationToken ct)
            => RunAsync("DPI2-001", "SignalsAdapter пишет inspection сигналы в TTL-store", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapter(store);

                var tested = CreateHostTested(
                    remoteIp: IPAddress.Parse("203.0.113.10"),
                    blockageType: BlockageCode.TcpConnectionReset);

                var inspection = new InspectionSignalsSnapshot(
                    Retransmissions: 0,
                    TotalPackets: 0,
                    HasHttpRedirect: false,
                    RedirectToHost: null,
                    HasHttpsToHttpRedirect: false,
                    RedirectBurstCount: 0,
                    RedirectEtldKnown: false,
                    HasSuspiciousRst: true,
                    SuspiciousRstDetails: "TTL=5 (expected 50-55)",
                    UdpUnansweredHandshakes: 0);
                adapter.Observe(tested, inspection);

                var hostKey = SignalsAdapter.BuildStableHostKey(tested);
                var events = store.ReadWindow(hostKey, DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1), DateTimeOffset.UtcNow + TimeSpan.FromSeconds(1));

                if (!events.Any(e => e.Type == SignalEventType.HostTested))
                {
                    return new SmokeTestResult("DPI2-001", "SignalsAdapter адаптирует legacy сигналы и пишет в TTL-store", SmokeOutcome.Fail, TimeSpan.Zero,
                        "В сторе нет события HostTested после Observe(...)");
                }

                if (!events.Any(e => e.Type == SignalEventType.SuspiciousRstObserved))
                {
                    return new SmokeTestResult("DPI2-001", "SignalsAdapter пишет inspection сигналы в TTL-store", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали событие SuspiciousRstObserved из inspection snapshot, но его нет");
                }

                return new SmokeTestResult("DPI2-001", "SignalsAdapter пишет inspection сигналы в TTL-store", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: events={events.Count}, hostKey={hostKey}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_SignalStore_Ttl_DeletesEventsOlderThan10Minutes(CancellationToken ct)
            => RunAsync("DPI2-002", "TTL событий INTEL: старше 10 минут удаляются при Append", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var hostKey = "203.0.113.20";

                var old = new SignalEvent
                {
                    HostKey = hostKey,
                    Type = SignalEventType.HostTested,
                    ObservedAtUtc = DateTimeOffset.UtcNow - IntelligenceContractDefaults.EventTtl - TimeSpan.FromMinutes(1),
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
                    return new SmokeTestResult("DPI2-002", "TTL событий INTEL: старше 10 минут удаляются при Append", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что старое событие будет удалено, но оно осталось. events={events.Count}");
                }

                if (!events.Any(e => e.Reason == "fresh"))
                {
                    return new SmokeTestResult("DPI2-002", "TTL событий INTEL: старше 10 минут удаляются при Append", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что свежее событие останется, но его нет");
                }

                return new SmokeTestResult("DPI2-002", "TTL событий INTEL: старше 10 минут удаляются при Append", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: старые события удаляются только при Append (без таймеров)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Aggregation_BuildSnapshot_RespectsWindow_30s_60s(CancellationToken ct)
            => RunAsync("DPI2-003", "Агрегация INTEL: BuildSnapshot корректно считает окно 30s/60s", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapter(store);

                var tested = CreateHostTested(remoteIp: IPAddress.Parse("203.0.113.30"), blockageType: BlockageCode.TcpConnectTimeout);
                var hostKey = SignalsAdapter.BuildStableHostKey(tested);

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

                var inspection = new InspectionSignalsSnapshot(
                    Retransmissions: 3,
                    TotalPackets: 10,
                    HasHttpRedirect: false,
                    RedirectToHost: null,
                    HasHttpsToHttpRedirect: false,
                    RedirectBurstCount: 0,
                    RedirectEtldKnown: false,
                    HasSuspiciousRst: false,
                    SuspiciousRstDetails: null,
                    UdpUnansweredHandshakes: 0);
                var snap30 = adapter.BuildSnapshot(tested, inspection, IntelligenceContractDefaults.DefaultAggregationWindow);
                var snap60 = adapter.BuildSnapshot(tested, inspection, IntelligenceContractDefaults.ExtendedAggregationWindow);

                if (snap30.SampleSize < 5 || snap30.SampleSize > 7)
                {
                    return new SmokeTestResult("DPI2-003", "Агрегация INTEL: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали ~5 событий в 30s окне, получили sampleSize={snap30.SampleSize}");
                }

                if (snap60.SampleSize < 10)
                {
                    return new SmokeTestResult("DPI2-003", "Агрегация INTEL: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали >=10 событий в 60s окне, получили sampleSize={snap60.SampleSize}");
                }

                if (!snap30.HasTcpReset)
                {
                    return new SmokeTestResult("DPI2-003", "Агрегация INTEL: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что HasTcpReset будет true из-за события SuspiciousRstObserved в окне");
                }

                return new SmokeTestResult("DPI2-003", "Агрегация INTEL: BuildSnapshot корректно считает окно 30s/60s", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: sampleSize30={snap30.SampleSize}, sampleSize60={snap60.SampleSize}, hostKey={hostKey}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Aggregation_BuildSnapshot_ExtractsRstTtlDelta_AndLatency(CancellationToken ct)
            => RunAsync("DPI2-016", "Агрегация INTEL: BuildSnapshot извлекает RST TTL delta + latency", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapter(store);

                var tested = CreateHostTested(remoteIp: IPAddress.Parse("203.0.113.31"), blockageType: BlockageCode.TcpConnectionReset) with
                {
                    TcpLatencyMs = 120
                };

                var inspection = new InspectionSignalsSnapshot(
                    Retransmissions: 0,
                    TotalPackets: 0,
                    HasHttpRedirect: false,
                    RedirectToHost: null,
                    HasHttpsToHttpRedirect: false,
                    RedirectBurstCount: 0,
                    RedirectEtldKnown: false,
                    HasSuspiciousRst: true,
                    SuspiciousRstDetails: "TTL=64 (обычный=50-55)",
                    UdpUnansweredHandshakes: 0);
                var snap = adapter.BuildSnapshot(tested, inspection, IntelligenceContractDefaults.DefaultAggregationWindow);

                if (!snap.HasTcpReset)
                {
                    return new SmokeTestResult("DPI2-016", "Агрегация INTEL: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали HasTcpReset=true (TCP_CONNECTION_RESET + HasSuspiciousRst)");
                }

                if (snap.RstTtlDelta != 9)
                {
                    return new SmokeTestResult("DPI2-016", "Агрегация INTEL: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали RstTtlDelta=9 (TTL=64 vs 50-55), получили {snap.RstTtlDelta}");
                }

                if (snap.RstLatency is null || Math.Abs(snap.RstLatency.Value.TotalMilliseconds - 120) > 1)
                {
                    return new SmokeTestResult("DPI2-016", "Агрегация INTEL: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали RstLatency≈120ms, получили {snap.RstLatency}");
                }

                return new SmokeTestResult("DPI2-016", "Агрегация INTEL: BuildSnapshot извлекает RST TTL delta + latency", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: rstTtlDelta={snap.RstTtlDelta}, rstLatencyMs={(int)snap.RstLatency.Value.TotalMilliseconds}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_ProducesDiagnosis_WithConfidenceAtLeast50(CancellationToken ct)
            => RunAsync("DPI2-004", "DiagnosisEngine INTEL формирует диагноз с confidence >= 50", () =>
            {
                var engine = new StandardDiagnosisEngine();

                var signals = new IntelBlockageSignals
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
                    return new SmokeTestResult("DPI2-004", "DiagnosisEngine INTEL формирует диагноз с confidence >= 50", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали confidence >= 50, получили {result.Confidence} (diagnosis={result.DiagnosisId})");
                }

                if (result.DiagnosisId != DiagnosisId.SilentDrop)
                {
                    return new SmokeTestResult("DPI2-004", "DiagnosisEngine INTEL формирует диагноз с confidence >= 50", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали DiagnosisId.SilentDrop для timeout+high retx-rate, получили {result.DiagnosisId}");
                }

                return new SmokeTestResult("DPI2-004", "DiagnosisEngine INTEL формирует диагноз с confidence >= 50", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {result.DiagnosisId} ({result.Confidence}%)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_RstTtlDelta_FastClassifiesAsActiveDpiEdge(CancellationToken ct)
            => RunAsync("DPI2-017", "DiagnosisEngine INTEL: RST TTL delta + быстрый reset => ActiveDpiEdge", () =>
            {
                var engine = new StandardDiagnosisEngine();

                var signals = new IntelBlockageSignals
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
                    RstIpIdDelta = null,
                    SuspiciousRstCount = 2,
                    RstLatency = TimeSpan.FromMilliseconds(120),

                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false
                };

                var result = engine.Diagnose(signals);

                if (result.DiagnosisId != DiagnosisId.ActiveDpiEdge)
                {
                    return new SmokeTestResult("DPI2-017", "DiagnosisEngine INTEL: RST TTL delta + быстрый reset => ActiveDpiEdge", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали ActiveDpiEdge, получили {result.DiagnosisId} (conf={result.Confidence})");
                }

                if (result.Confidence < 60)
                {
                    return new SmokeTestResult("DPI2-017", "DiagnosisEngine INTEL: RST TTL delta + быстрый reset => ActiveDpiEdge", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали confidence >= 60, получили {result.Confidence}");
                }

                return new SmokeTestResult("DPI2-017", "DiagnosisEngine INTEL: RST TTL delta + быстрый reset => ActiveDpiEdge", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {result.DiagnosisId} ({result.Confidence}%)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_RstTtlDelta_SlowClassifiesAsStatefulDpi(CancellationToken ct)
            => RunAsync("DPI2-018", "DiagnosisEngine INTEL: RST TTL delta + медленный reset => StatefulDpi", () =>
            {
                var engine = new StandardDiagnosisEngine();

                var signals = new IntelBlockageSignals
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
                    RstIpIdDelta = null,
                    SuspiciousRstCount = 2,
                    RstLatency = TimeSpan.FromMilliseconds(900),

                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false
                };

                var result = engine.Diagnose(signals);

                if (result.DiagnosisId != DiagnosisId.StatefulDpi)
                {
                    return new SmokeTestResult("DPI2-018", "DiagnosisEngine INTEL: RST TTL delta + медленный reset => StatefulDpi", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали StatefulDpi, получили {result.DiagnosisId} (conf={result.Confidence})");
                }

                if (result.Confidence < 60)
                {
                    return new SmokeTestResult("DPI2-018", "DiagnosisEngine INTEL: RST TTL delta + медленный reset => StatefulDpi", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали confidence >= 60, получили {result.Confidence}");
                }

                return new SmokeTestResult("DPI2-018", "DiagnosisEngine INTEL: RST TTL delta + медленный reset => StatefulDpi", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {result.DiagnosisId} ({result.Confidence}%)");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_Aggregation_BuildSnapshot_ExtractsRstIpIdDelta_AndSuspiciousCount(CancellationToken ct)
            => RunAsync("DPI2-031", "Агрегация INTEL: BuildSnapshot извлекает RstIpIdDelta и считает устойчивость suspicious RST", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapter(store);

                var tested = CreateHostTested(remoteIp: IPAddress.Parse("203.0.113.33"), blockageType: BlockageCode.TcpConnectionReset);
                var hostKey = SignalsAdapter.BuildStableHostKey(tested);

                var now = DateTimeOffset.UtcNow;
                store.Append(new SignalEvent
                {
                    HostKey = hostKey,
                    Type = SignalEventType.SuspiciousRstObserved,
                    ObservedAtUtc = now - TimeSpan.FromSeconds(2),
                    Source = "smoke",
                    Value = "IPID=110 (expected 100-120, last 105)",
                    Reason = "rst",
                    Metadata = null
                });
                store.Append(new SignalEvent
                {
                    HostKey = hostKey,
                    Type = SignalEventType.SuspiciousRstObserved,
                    ObservedAtUtc = now - TimeSpan.FromSeconds(1),
                    Source = "smoke",
                    Value = "IPID=110 (expected 100-120, last 105)",
                    Reason = "rst",
                    Metadata = null
                });

                var snap = adapter.BuildSnapshot(tested, InspectionSignalsSnapshot.Empty, IntelligenceContractDefaults.DefaultAggregationWindow);

                if (snap.RstIpIdDelta != 5)
                {
                    return new SmokeTestResult("DPI2-031", "Агрегация INTEL: BuildSnapshot извлекает RstIpIdDelta и считает устойчивость suspicious RST", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали RstIpIdDelta=5 (IPID=110 vs expected 100-120, last 105), получили {snap.RstIpIdDelta}");
                }

                if (snap.SuspiciousRstCount != 2)
                {
                    return new SmokeTestResult("DPI2-031", "Агрегация INTEL: BuildSnapshot извлекает RstIpIdDelta и считает устойчивость suspicious RST", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали SuspiciousRstCount=2, получили {snap.SuspiciousRstCount}");
                }

                return new SmokeTestResult("DPI2-031", "Агрегация INTEL: BuildSnapshot извлекает RstIpIdDelta и считает устойчивость suspicious RST", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: rstIpIdDelta={snap.RstIpIdDelta}, suspiciousRstCount={snap.SuspiciousRstCount}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_SingleRstAnomaly_IsUnknown_NotDpi(CancellationToken ct)
            => RunAsync("DPI2-032", "DiagnosisEngine INTEL: single suspicious RST anomaly => Unknown (без DPI-id)", () =>
            {
                var engine = new StandardDiagnosisEngine();

                var signals = new IntelBlockageSignals
                {
                    HostKey = "203.0.113.44",
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    AggregationWindow = TimeSpan.FromSeconds(30),
                    SampleSize = 1,
                    IsUnreliable = false,

                    HasDnsFailure = false,
                    HasFakeIp = false,
                    HasHttpRedirect = false,

                    HasTcpTimeout = false,
                    HasTcpReset = true,
                    RetransmissionRate = null,

                    RstTtlDelta = 10,
                    RstIpIdDelta = null,
                    SuspiciousRstCount = 1,
                    RstLatency = TimeSpan.FromMilliseconds(120),

                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false
                };

                var result = engine.Diagnose(signals);

                if (result.DiagnosisId != DiagnosisId.Unknown)
                {
                    return new SmokeTestResult("DPI2-032", "DiagnosisEngine INTEL: single suspicious RST anomaly => Unknown (без DPI-id)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Unknown, получили {result.DiagnosisId} (conf={result.Confidence}, rule={result.MatchedRuleName})");
                }

                if (result.Confidence != 55)
                {
                    return new SmokeTestResult("DPI2-032", "DiagnosisEngine INTEL: single suspicious RST anomaly => Unknown (без DPI-id)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали confidence=55 для single-anomaly, получили {result.Confidence} (rule={result.MatchedRuleName})");
                }

                if (!string.Equals(result.MatchedRuleName, "tcp-rst+single-anomaly", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-032", "DiagnosisEngine INTEL: single suspicious RST anomaly => Unknown (без DPI-id)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали rule=tcp-rst+single-anomaly, получили {result.MatchedRuleName}");
                }

                return new SmokeTestResult("DPI2-032", "DiagnosisEngine INTEL: single suspicious RST anomaly => Unknown (без DPI-id)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {result.DiagnosisId} ({result.Confidence}%) rule={result.MatchedRuleName}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_DiagnosisEngine_Explanation_IsFactBased_NoStrategiesMentioned(CancellationToken ct)
            => RunAsync("DPI2-005", "DiagnosisEngine INTEL: пояснение содержит факты, но не упоминает стратегии", () =>
            {
                var engine = new StandardDiagnosisEngine();

                var signals = new IntelBlockageSignals
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

                if (result.DiagnosisId != DiagnosisId.TlsInterference)
                {
                    return new SmokeTestResult("DPI2-005", "DiagnosisEngine INTEL: пояснение содержит факты, но не упоминает стратегии", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали TlsInterference, получили {result.DiagnosisId} (conf={result.Confidence})");
                }

                var text = string.Join(" | ", result.ExplanationNotes);
                var forbidden = new[]
                {
                    "TLS_FRAGMENT", "TLS_DISORDER", "DROP_RST", "DOH",
                    "TlsFragment", "TlsDisorder", "DropRst", "UseDoh",
                    "Fragment", "Disorder", "стратег"
                };

                if (forbidden.Any(f => text.Contains(f, StringComparison.OrdinalIgnoreCase)))
                {
                    return new SmokeTestResult("DPI2-005", "DiagnosisEngine INTEL: пояснение содержит факты, но не упоминает стратегии", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Пояснение содержит упоминание стратегий/обхода: {text}");
                }

                if (!text.Contains("TLS", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("DPI2-005", "DiagnosisEngine INTEL: пояснение содержит факты, но не упоминает стратегии", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что пояснение содержит факт про TLS, получили: {text}");
                }

                return new SmokeTestResult("DPI2-005", "DiagnosisEngine INTEL: пояснение содержит факты, но не упоминает стратегии", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: пояснение фактологическое и без рекомендаций");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_GateMarkers_Gate1_EmittedInProgressLog(CancellationToken ct)
            => RunAsync("DPI2-006", "Gate 1→2: в логе появляется маркер [INTEL][GATE1]", () =>
            {
                var store = new InMemorySignalSequenceStore();
                var adapter = new SignalsAdapter(store);

                var tested = CreateHostTested(remoteIp: IPAddress.Parse("203.0.113.60"), blockageType: BlockageCode.TcpConnectionReset);

                var lines = new List<string>();
                var progress = new ImmediateProgress(lines);

                var inspection = new InspectionSignalsSnapshot(
                    Retransmissions: 2,
                    TotalPackets: 10,
                    HasHttpRedirect: true,
                    RedirectToHost: "example.org",
                    HasHttpsToHttpRedirect: false,
                    RedirectBurstCount: 0,
                    RedirectEtldKnown: false,
                    HasSuspiciousRst: false,
                    SuspiciousRstDetails: null,
                    UdpUnansweredHandshakes: 0);
                adapter.Observe(tested, inspection, progress);

                if (!lines.Any(s => s.Contains("[INTEL][GATE1]", StringComparison.Ordinal)))
                {
                    return new SmokeTestResult("DPI2-006", "Gate 1→2: в логе появляется маркер [INTEL][GATE1]", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не нашли строку [INTEL][GATE1] после Observe(...). Ожидали, что 3 разных типа событий (HostTested + ретранс/редирект) достаточно для Gate 1→2");
                }

                var line = lines.First(s => s.Contains("[INTEL][GATE1]", StringComparison.Ordinal));
                if (!line.Contains("timeline=", StringComparison.Ordinal) || !line.Contains("recentCount=", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-006", "Gate 1→2: в логе появляется маркер [INTEL][GATE1]", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Маркер найден, но формат не совпал ожиданию (timeline/recentCount): {line}");
                }

                return new SmokeTestResult("DPI2-006", "Gate 1→2: в логе появляется маркер [INTEL][GATE1]", SmokeOutcome.Pass, TimeSpan.Zero,
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
            => RunAsync("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", () =>
            {
                var selector = new StandardStrategySelector();
                var executor = new BypassExecutorMvp();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 80,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = new[] { "TLS: timeout" },
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new IntelBlockageSignals
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 3,
                        IsUnreliable = false,

                        // Assist-сигналы для рекомендаций:
                        // - есть UDP/QUIC активность
                        // - SNI отсутствует в большинстве HostTested
                        UdpUnansweredHandshakes = 3,
                        HostTestedCount = 3,
                        HostTestedNoSniCount = 3
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis);
                if (plan.Strategies.Count == 0)
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали непустой план стратегий для ActiveDpiEdge/conf=80");
                }

                var bypassText = InvokePrivateBuildBypassStrategyText(plan);
                if (string.IsNullOrWhiteSpace(bypassText))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось получить текст bypass-стратегий (plan:...)");
                }

                if (!executor.TryBuildRecommendationLine("example.com", bypassText, out var line))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Executor не смог построить строку рекомендации из: {bypassText}");
                }

                if (!line.Contains(BypassExecutorMvp.IntelLogPrefix, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"В строке рекомендации нет префикса {BypassExecutorMvp.IntelLogPrefix}: {line}");
                }

                var hasFragment = line.Contains("TLS_FRAGMENT", StringComparison.Ordinal);
                var hasDisorder = line.Contains("TLS_DISORDER", StringComparison.Ordinal);
                if (!hasFragment && !hasDisorder)
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали одну TLS-стратегию (TLS_FRAGMENT или TLS_DISORDER), но не нашли ни одной: {line}");
                }

                if (hasFragment && hasDisorder)
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что селектор выберет ровно одну TLS-стратегию, но нашли обе: {line}");
                }

                if (!plan.DropUdp443 || !line.Contains("DROP_UDP_443", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали assist DropUdp443 и токен DROP_UDP_443 в строке рекомендации: plan.DropUdp443={plan.DropUdp443}, line={line}");
                }

                if (!plan.AllowNoSni || !line.Contains("ALLOW_NO_SNI", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали assist AllowNoSni и токен ALLOW_NO_SNI в строке рекомендации: plan.AllowNoSni={plan.AllowNoSni}, line={line}");
                }

                return new SmokeTestResult("DPI2-007", "StrategySelector INTEL формирует план и даёт INTEL-рекомендацию", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {line}");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_HighRiskBlocked_WhenConfidenceBelow70(CancellationToken ct)
            => RunAsync("DPI2-008", "High-risk стратегии запрещены при confidence < 70", () =>
            {
                var selector = new StandardStrategySelector();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 60,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new IntelBlockageSignals
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
                var selector = new StandardStrategySelector();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 40,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new IntelBlockageSignals
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

        public static Task<SmokeTestResult> Dpi2_StrategySelector_DnsHijack_RecommendsUseDohOnly(CancellationToken ct)
            => RunAsync("DPI2-034", "DnsHijack → UseDoh (low-risk), без TLS/assist", () =>
            {
                var selector = new StandardStrategySelector();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.DnsHijack,
                    Confidence = 75,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new IntelBlockageSignals
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 2,
                        IsUnreliable = false,

                        // Наличие UDP/443 активности и no-SNI не должно включать assist-флаги без TLS-обхода.
                        UdpUnansweredHandshakes = 10,
                        HostTestedCount = 5,
                        HostTestedNoSniCount = 5
                    },
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };

                var plan = selector.Select(diagnosis);

                if (plan.Strategies.Count != 1 || plan.Strategies[0].Id != StrategyId.UseDoh)
                {
                    return new SmokeTestResult("DPI2-034", "DnsHijack → UseDoh (low-risk), без TLS/assist", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали ровно одну стратегию UseDoh, получили: [{string.Join(", ", plan.Strategies.Select(s => s.Id))}]");
                }

                if (plan.DropUdp443 || plan.AllowNoSni)
                {
                    return new SmokeTestResult("DPI2-034", "DnsHijack → UseDoh (low-risk), без TLS/assist", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Assist-флаги не должны включаться без TLS-обхода: DropUdp443={plan.DropUdp443}, AllowNoSni={plan.AllowNoSni}");
                }

                return new SmokeTestResult("DPI2-034", "DnsHijack → UseDoh (low-risk), без TLS/assist", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: plan=UseDoh only");
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_WarnsAndSkips_UnimplementedStrategies(CancellationToken ct)
            => RunAsync("DPI2-010", "Warning при нереализованных стратегиях (warning + skip)", () =>
            {
                var selector = new StandardStrategySelector();

                var warnings = new List<string>();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 80,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new IntelBlockageSignals
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

        public static Task<SmokeTestResult> Dpi2_StrategySelector_Phase3Strategies_AreImplemented(CancellationToken ct)
            => RunAsync("DPI2-033", "Phase 3: HttpHostTricks/BadChecksum + QUIC→TCP (DropUdp443) реализованы (SSoT, без дублирования)", () =>
            {
                var selector = new StandardStrategySelector();

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 80,
                    MatchedRuleName = "smoke",
                    ExplanationNotes = Array.Empty<string>(),
                    Evidence = new Dictionary<string, string>(),
                    InputSignals = new IntelBlockageSignals
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

                var strategyIds = plan.Strategies.Select(s => s.Id).ToHashSet();

                if (!strategyIds.Contains(StrategyId.HttpHostTricks)
                    || !strategyIds.Contains(StrategyId.BadChecksum))
                {
                    return new SmokeTestResult("DPI2-033", "Phase 3: HttpHostTricks/BadChecksum + QUIC→TCP (DropUdp443) реализованы (SSoT, без дублирования)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали HttpHostTricks/BadChecksum в Strategies, получили: {string.Join(", ", strategyIds)}");
                }

                if (plan.DeferredStrategies.Count != 0)
                {
                    return new SmokeTestResult("DPI2-033", "Phase 3: HttpHostTricks/BadChecksum + QUIC→TCP (DropUdp443) реализованы (SSoT, без дублирования)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали DeferredStrategies=0, получили: {plan.DeferredStrategies.Count}");
                }

                if (!plan.DropUdp443)
                {
                    return new SmokeTestResult("DPI2-033", "Phase 3: HttpHostTricks/BadChecksum + QUIC→TCP (DropUdp443) реализованы (SSoT, без дублирования)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали DropUdp443=true (QUIC→TCP должен быть доступен без дублирования StrategyId.QuicObfuscation)");
                }

                if (string.IsNullOrWhiteSpace(plan.Reasoning))
                {
                    return new SmokeTestResult("DPI2-033", "Phase 3: HttpHostTricks/BadChecksum + QUIC→TCP (DropUdp443) реализованы (SSoT, без дублирования)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Reasoning пустой");
                }

                return new SmokeTestResult("DPI2-033", "Phase 3: HttpHostTricks/BadChecksum + QUIC→TCP (DropUdp443) реализованы (SSoT, без дублирования)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: strategies={plan.Strategies.Count}, dropUdp443={plan.DropUdp443}");
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

                var store = new InMemoryFeedbackStore(options);
                var selector = new StandardStrategySelector(store, options);

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
                    InputSignals = new IntelBlockageSignals
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

                var store = new InMemoryFeedbackStore(options);
                var selector = new StandardStrategySelector(store, options);

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
                    InputSignals = new IntelBlockageSignals
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

                var tail = "(intel:SilentDrop conf=78; TCP: timeout; TCP: retx-rate=0.30)";
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
                var bypass = "plan:TlsFragment + DropRst (conf=78)";
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

        public static Task<SmokeTestResult> Dpi2_AllIntelOutputs_StartWithPrefix(CancellationToken ct)
            => RunAsync("DPI2-012", "Префикс [INTEL] присутствует во всех intel-выводах", () =>
            {
                var executor = new BypassExecutorMvp();

                var tail = "(intel:SilentDrop conf=80; TCP: timeout)";
                if (!executor.TryFormatDiagnosisSuffix(tail, out var formatted))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [INTEL] присутствует во всех intel-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        "TryFormatDiagnosisSuffix не смог распарсить хвост");
                }

                if (!formatted.Contains(BypassExecutorMvp.IntelLogPrefix, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [INTEL] присутствует во всех intel-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Нет префикса [INTEL] в форматировании: {formatted}");
                }

                var bypass = "plan:TlsFragment + DropRst (conf=80)";
                if (!executor.TryBuildRecommendationLine("example.com", bypass, out var line))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [INTEL] присутствует во всех intel-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось построить строку рекомендации");
                }

                if (!line.StartsWith(BypassExecutorMvp.IntelLogPrefix, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-012", "Префикс [INTEL] присутствует во всех intel-выводах", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Строка рекомендации не начинается с [INTEL]: {line}");
                }

                return new SmokeTestResult("DPI2-012", "Префикс [INTEL] присутствует во всех intel-выводах", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
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

        public static Task<SmokeTestResult> Dpi2_ExecutorIntel_ManualApply_MapsPlanToBypassOptions(CancellationToken ct)
            => RunAsync("DPI2-019", "Executor INTEL: ручное применение BypassPlan включает ожидаемые опции", () =>
            {
                // Поднимаем сервис в smoke-режиме (без TrafficEngine), чтобы не требовать админ прав и WinDivert.
                var engine = new TrafficEngine(progress: null);
                var baseProfile = BypassProfile.CreateDefault();
                var tlsService = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false, useTrafficEngine: false, nowProvider: () => DateTime.Now);
                using var provider = BuildIspAuditProvider();
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                var controller = new BypassController(tlsService, baseProfile, autoHostlist);

                var plan = new BypassPlan
                {
                    ForDiagnosis = DiagnosisId.SilentDrop,
                    PlanConfidence = 80,
                    PlannedAtUtc = DateTimeOffset.UtcNow,
                    Reasoning = "smoke",
                    DropUdp443 = true,
                    AllowNoSni = true,
                    Strategies = new List<BypassStrategy>
                    {
                        new BypassStrategy { Id = StrategyId.TlsFragment, BasePriority = 90, Risk = RiskLevel.Medium },
                        new BypassStrategy { Id = StrategyId.DropRst, BasePriority = 50, Risk = RiskLevel.Medium },
                    }
                };

                controller.ApplyIntelPlanAsync(plan, timeout: TimeSpan.FromSeconds(2), cancellationToken: CancellationToken.None)
                    .GetAwaiter().GetResult();

                if (!controller.IsFragmentEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor INTEL: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyIntelPlanAsync будет включён TLS_FRAGMENT");
                }

                if (controller.IsDisorderEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor INTEL: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что TLS_DISORDER будет выключен (Fragment и Disorder взаимоисключающие)");
                }

                if (!controller.IsDropRstEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor INTEL: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyIntelPlanAsync будет включён DROP_RST");
                }

                if (!controller.IsQuicFallbackEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor INTEL: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyIntelPlanAsync будет включён QUIC→TCP (DropUdp443)" );
                }

                if (!controller.IsAllowNoSniEnabled)
                {
                    return new SmokeTestResult("DPI2-019", "Executor INTEL: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyIntelPlanAsync будет включён No SNI (AllowNoSni)" );
                }

                return new SmokeTestResult("DPI2-019", "Executor INTEL: ручное применение BypassPlan включает ожидаемые опции", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: опции применены" );
            }, ct);

        public static Task<SmokeTestResult> Dpi2_ExecutorIntel_TlsFragment_Params_AffectPresetAndAutoAdjust(CancellationToken ct)
            => RunAsync("DPI2-022", "Executor INTEL: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", () =>
            {
                // Smoke-режим (без TrafficEngine), чтобы не требовать админ прав и WinDivert.
                var engine = new TrafficEngine(progress: null);
                var baseProfile = BypassProfile.CreateDefault();
                var tlsService = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false, useTrafficEngine: false, nowProvider: () => DateTime.Now);
                using var provider = BuildIspAuditProvider();
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                var controller = new BypassController(tlsService, baseProfile, autoHostlist);

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

                controller.ApplyIntelPlanAsync(plan, timeout: TimeSpan.FromSeconds(2), cancellationToken: CancellationToken.None)
                    .GetAwaiter().GetResult();

                if (!controller.IsFragmentEnabled)
                {
                    return new SmokeTestResult("DPI2-022", "Executor INTEL: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после ApplyIntelPlanAsync будет включён TLS_FRAGMENT");
                }

                if (!controller.IsAutoAdjustAggressive)
                {
                    return new SmokeTestResult("DPI2-022", "Executor INTEL: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что AutoAdjustAggressive=true будет применён из параметров стратегии");
                }

                if (controller.SelectedFragmentPreset == null)
                {
                    return new SmokeTestResult("DPI2-022", "Executor INTEL: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что SelectedFragmentPreset будет выбран");
                }

                var got = controller.SelectedFragmentPreset.Sizes.ToArray();
                if (got.Length != 2 || got[0] != 32 || got[1] != 32)
                {
                    return new SmokeTestResult("DPI2-022", "Executor INTEL: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали sizes=[32,32], получили [{string.Join(",", got)}]");
                }

                return new SmokeTestResult("DPI2-022", "Executor INTEL: параметры TlsFragment (sizes/autoAdjust) влияют на пресет и опции", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: параметры применены" );
            }, ct);

        public static Task<SmokeTestResult> Dpi2_StrategySelector_PopulatesTlsFragmentParameters(CancellationToken ct)
            => RunAsync("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", () =>
            {
                var selector = new StandardStrategySelector(feedbackStore: null);

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.SilentDrop,
                    Confidence = 80,
                    ExplanationNotes = new[] { "smoke" },
                    InputSignals = new IntelBlockageSignals
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
                    return new SmokeTestResult("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что план будет содержать TlsFragment");
                }

                if (fragment.Parameters == null || fragment.Parameters.Count == 0)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что у TlsFragment будут параметры");
                }

                if (!fragment.Parameters.TryGetValue("PresetName", out var presetRaw) || presetRaw is not string presetName)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что параметр PresetName будет string");
                }

                if (!string.Equals(presetName, "Стандарт", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали PresetName=\"Стандарт\", получили '{presetName}'");
                }

                if (!fragment.Parameters.TryGetValue("TlsFragmentSizes", out var raw) || raw is not int[] sizes)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что параметр TlsFragmentSizes будет int[]");
                }

                if (sizes.Length != 1 || sizes[0] != 64)
                {
                    return new SmokeTestResult("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали sizes=[64], получили [{string.Join(",", sizes)}]");
                }

                return new SmokeTestResult("DPI2-023", "StrategySelector INTEL: TlsFragment содержит параметры (PresetName/TlsFragmentSizes) в плане", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: PresetName и sizes присутствуют" );
            }, ct);

        public static Task<SmokeTestResult> Dpi2_E2E_SelectorPlan_ManualApply_UsesPlanParams(CancellationToken ct)
            => RunAsync("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", () =>
            {
                // 1) Формируем план через селектор (это и есть e2e часть: plan должен включать параметры).
                var selector = new StandardStrategySelector(feedbackStore: null);

                var diagnosis = new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.SilentDrop,
                    Confidence = 80,
                    ExplanationNotes = new[] { "smoke-e2e" },
                    InputSignals = new IntelBlockageSignals
                    {
                        HostKey = "203.0.113.98",
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
                if (plan.Strategies.Count == 0)
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что селектор вернёт непустой план");
                }

                // 2) Применяем план через реальный executor (manual apply) в smoke-режиме (без TrafficEngine/WinDivert).
                var engine = new TrafficEngine(progress: null);
                var baseProfile = BypassProfile.CreateDefault();
                var tlsService = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false, useTrafficEngine: false, nowProvider: () => DateTime.Now);
                using var provider = BuildIspAuditProvider();
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                var controller = new BypassController(tlsService, baseProfile, autoHostlist);

                controller.ApplyIntelPlanAsync(plan, timeout: TimeSpan.FromSeconds(2), cancellationToken: CancellationToken.None)
                    .GetAwaiter().GetResult();

                if (!controller.IsFragmentEnabled)
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после apply будет включён TLS_FRAGMENT");
                }

                if (controller.IsDisorderEnabled)
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что TLS_DISORDER будет выключен (Fragment и Disorder взаимоисключающие)");
                }

                if (!controller.IsDropRstEnabled)
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после apply будет включён DROP_RST (из плана селектора)");
                }

                if (controller.SelectedFragmentPreset == null)
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что SelectedFragmentPreset будет выбран после apply");
                }

                if (!string.Equals(controller.SelectedFragmentPreset.Name, "Стандарт", StringComparison.Ordinal))
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что пресет будет 'Стандарт' (из параметров плана), получили '{controller.SelectedFragmentPreset.Name}'");
                }

                var gotSizes = controller.SelectedFragmentPreset.Sizes.ToArray();
                if (gotSizes.Length != 1 || gotSizes[0] != 64)
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали sizes=[64] (из параметров плана), получили [{string.Join(",", gotSizes)}]");
                }

                if (controller.IsAutoAdjustAggressive)
                {
                    return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали AutoAdjustAggressive=false (из параметров плана)");
                }

                return new SmokeTestResult("DPI2-024", "E2E INTEL: selector → plan → manual apply использует параметры плана", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: параметры плана применены детерминированно" );
            }, ct);

        public static async Task<SmokeTestResult> Dpi2_ExecutorIntel_Cancel_RollbacksToPreviousState(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var engine = new TrafficEngine(progress: null);
                var baseProfile = BypassProfile.CreateDefault();
                using var tlsService = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false, useTrafficEngine: false, nowProvider: () => DateTime.Now);
                using var provider = BuildIspAuditProvider();
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                var controller = new BypassController(tlsService, baseProfile, autoHostlist);

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
                    await controller.ApplyIntelPlanAsync(plan, timeout: TimeSpan.FromSeconds(2), cancellationToken: cts.Token).ConfigureAwait(false);
                    return new SmokeTestResult("DPI2-020", "Executor INTEL: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали OperationCanceledException, но применение завершилось без отмены");
                }
                catch (OperationCanceledException)
                {
                    // Ожидаемо.
                }

                if (!controller.IsFakeEnabled)
                {
                    return new SmokeTestResult("DPI2-020", "Executor INTEL: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали откат: Fake должен остаться включенным");
                }

                if (controller.IsFragmentEnabled || controller.IsDropRstEnabled || controller.IsDisorderEnabled)
                {
                    return new SmokeTestResult("DPI2-020", "Executor INTEL: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали откат: Fragment/DropRst/Disorder не должны остаться включенными после отмены");
                }

                return new SmokeTestResult("DPI2-020", "Executor INTEL: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: откат выполнен");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("DPI2-020", "Executor INTEL: отмена/таймаут приводит к безопасному откату", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Dpi2_Pipeline_DoesNotAutoApply_BypassControllerOrTlsBypassService(CancellationToken ct)
            => RunAsync("DPI2-021", "Pipeline INTEL не выполняет auto-apply (нет вызовов BypassController/TlsBypassService)", () =>
            {
                var forbiddenTypeNames = new[] { "BypassController", "TlsBypassService" };

                if (IlContainsCallsToForbiddenTypes(typeof(LiveTestingPipeline), forbiddenTypeNames))
                {
                    return new SmokeTestResult("DPI2-021", "Pipeline INTEL не выполняет auto-apply (нет вызовов BypassController/TlsBypassService)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "В IL найден вызов к запрещённым типам. Pipeline обязан только вычислять/публиковать план, без применения." );
                }

                return new SmokeTestResult("DPI2-021", "Pipeline INTEL не выполняет auto-apply (нет вызовов BypassController/TlsBypassService)", SmokeOutcome.Pass, TimeSpan.Zero,
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


