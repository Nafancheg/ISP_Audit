using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Intelligence.Diagnosis;
using IspAudit.Core.Intelligence.Strategies;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Traffic;
using IspAudit.Utils;
using IspAudit.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> REG_HardDisable_ClearsActiveTargetUnion_NoEngineStart(CancellationToken ct)
            => RunAsyncAwait("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах", async innerCt =>
            {
                var sw = Stopwatch.StartNew();

                // Логи используем как дополнительный сигнал: при регрессии ожидаем попытку engine_start.
                var logs = new System.Collections.Generic.List<string>();
                void Log(string msg)
                {
                    try
                    {
                        lock (logs)
                        {
                            logs.Add(msg);
                        }
                    }
                    catch
                    {
                        // ignore
                    }
                }

                try
                {
                    var baseProfile = BypassProfile.CreateDefault();
                    using var engine = new TrafficEngine(progress: null);
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile, log: Log);
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(manager, autoHostlist);

                    // Симулируем remembered per-target union (P0.1 Step 1): если DisableAll реализован через Apply,
                    // то даже при выключенных тумблерах effective может «воскреснуть».
                    manager.RememberActiveTargetPolicy(new BypassStateManager.ActiveTargetPolicy
                    {
                        HostKey = "example.com",
                        AllowNoSni = true,
                        // Без DropUdp443/Fragment/Disorder/Fake: избегаем лишних зависимостей (DNS/targets/policy compile).
                        CandidateIpEndpoints = new[] { "1.1.1.1:443" },
                        DropUdp443 = false,
                        HttpHostTricksEnabled = false,
                        TlsStrategy = TlsBypassStrategy.None
                    });

                    // Проверка precondition: active targets действительно есть.
                    var getActive = typeof(BypassStateManager)
                        .GetMethod("GetActiveTargetPoliciesSnapshot", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                    if (getActive == null)
                    {
                        return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                            SmokeOutcome.Fail, sw.Elapsed, "Не нашли GetActiveTargetPoliciesSnapshot через reflection");
                    }

                    var before = getActive.Invoke(manager, new object?[] { null }) as Array;
                    if (before == null || before.Length == 0)
                    {
                        return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                            SmokeOutcome.Fail, sw.Elapsed, "Precondition: active targets пусты (ожидали минимум 1)");
                    }

                    await bypass.DisableAllAsync(innerCt).ConfigureAwait(false);

                    // После hard disable должны быть выключены все опции.
                    var snapAfterDisable = manager.GetOptionsSnapshot();
                    if (snapAfterDisable.IsAnyEnabled())
                    {
                        return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                            SmokeOutcome.Fail, sw.Elapsed, $"После DisableAllAsync bypass всё ещё включён: {snapAfterDisable.ToReadableStrategy()}");
                    }

                    // И cleared per-target union.
                    var after = getActive.Invoke(manager, new object?[] { null }) as Array;
                    if (after != null && after.Length != 0)
                    {
                        return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                            SmokeOutcome.Fail, sw.Elapsed, $"Ожидали очистку active targets, получили count={after.Length}");
                    }

                    // Дополнительный check: «Apply при выключенных тумблерах» после hard disable не должен ре-активировать bypass.
                    await bypass.ApplyBypassOptionsAsync(innerCt).ConfigureAwait(false);
                    var snapAfterApplyOff = manager.GetOptionsSnapshot();
                    if (snapAfterApplyOff.IsAnyEnabled())
                    {
                        return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                            SmokeOutcome.Fail, sw.Elapsed, $"После ApplyBypassOptionsAsync (off) bypass внезапно включён: {snapAfterApplyOff.ToReadableStrategy()}");
                    }

                    string[] lines;
                    lock (logs)
                    {
                        lines = logs.ToArray();
                    }

                    if (lines.Any(l => !string.IsNullOrWhiteSpace(l) && l.Contains("engine_start", StringComparison.OrdinalIgnoreCase)))
                    {
                        return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                            SmokeOutcome.Fail, sw.Elapsed, "Обнаружили engine_start в логах — вероятна регрессия (DisableAll через Apply)");
                    }

                    return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-021", "REG: hard disable очищает per-target union и не запускает engine при выключенных тумблерах",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_QuicInterference_Http3Fail_RecommendsDropUdp443(CancellationToken ct)
            => RunAsync("REG-017", "REG: H3 fail → QuicInterference → assist DropUdp443", () =>
            {
                var engine = new StandardDiagnosisEngine();
                var selector = new StandardStrategySelector();

                var signalsQuicOnly = new BlockageSignals
                {
                    HostKey = "video.googlevideo.com",
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    AggregationWindow = TimeSpan.FromSeconds(30),
                    SampleSize = 10,
                    IsUnreliable = false,

                    // Ключевой сценарий: HTTP/3 пытались, но успехов нет, ошибок/таймаутов есть, платформа H3 поддерживает.
                    Http3AttemptCount = 3,
                    Http3SuccessCount = 0,
                    Http3FailureCount = 2,
                    Http3TimeoutCount = 1,
                    Http3NotSupportedCount = 0,

                    // Чтобы правило «quic only» было применимо, остальные улики должны быть чистыми.
                    HasDnsFailure = false,
                    HasFakeIp = false,
                    HasHttpRedirect = false,
                    HasTcpTimeout = false,
                    HasTcpReset = false,
                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false,
                };

                var dxQuicOnly = engine.Diagnose(signalsQuicOnly);
                if (dxQuicOnly.DiagnosisId != DiagnosisId.QuicInterference)
                {
                    return new SmokeTestResult("REG-017", "REG: H3 fail → QuicInterference → assist DropUdp443", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали DiagnosisId=QuicInterference, получили {dxQuicOnly.DiagnosisId} (rule={dxQuicOnly.MatchedRuleName})");
                }

                var planQuicOnly = selector.Select(dxQuicOnly);
                if (!planQuicOnly.DropUdp443)
                {
                    return new SmokeTestResult("REG-017", "REG: H3 fail → QuicInterference → assist DropUdp443", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали DropUdp443=true по H3-fail уликам (assist-only план допускается)");
                }

                // Регресс-гейт: если уже есть TLS timeout на TCP/443, QUIC→TCP не должно быть приоритетной рекомендацией.
                var signalsTlsTimeout = new BlockageSignals
                {
                    HostKey = signalsQuicOnly.HostKey,
                    CapturedAtUtc = signalsQuicOnly.CapturedAtUtc,
                    AggregationWindow = signalsQuicOnly.AggregationWindow,
                    SampleSize = signalsQuicOnly.SampleSize,
                    IsUnreliable = signalsQuicOnly.IsUnreliable,

                    Http3AttemptCount = signalsQuicOnly.Http3AttemptCount,
                    Http3SuccessCount = signalsQuicOnly.Http3SuccessCount,
                    Http3FailureCount = signalsQuicOnly.Http3FailureCount,
                    Http3TimeoutCount = signalsQuicOnly.Http3TimeoutCount,
                    Http3NotSupportedCount = signalsQuicOnly.Http3NotSupportedCount,

                    HasDnsFailure = signalsQuicOnly.HasDnsFailure,
                    HasFakeIp = signalsQuicOnly.HasFakeIp,
                    HasHttpRedirect = signalsQuicOnly.HasHttpRedirect,
                    HasTcpTimeout = signalsQuicOnly.HasTcpTimeout,
                    HasTcpReset = signalsQuicOnly.HasTcpReset,

                    HasTlsTimeout = true,
                    HasTlsAuthFailure = signalsQuicOnly.HasTlsAuthFailure,
                    HasTlsReset = signalsQuicOnly.HasTlsReset,
                };

                var dxTlsTimeout = engine.Diagnose(signalsTlsTimeout);
                var planTlsTimeout = selector.Select(dxTlsTimeout);

                if (planTlsTimeout.DropUdp443)
                {
                    return new SmokeTestResult("REG-017", "REG: H3 fail → QuicInterference → assist DropUdp443", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Не ожидали DropUdp443=true при HasTlsTimeout=true (dx={dxTlsTimeout.DiagnosisId}, rule={dxTlsTimeout.MatchedRuleName})");
                }

                return new SmokeTestResult("REG-017", "REG: H3 fail → QuicInterference → assist DropUdp443", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
            }, ct);

        public static Task<SmokeTestResult> REG_HttpRedirect_RecommendsHttpHostTricks(CancellationToken ct)
            => RunAsync("REG-018", "REG: HttpRedirect → HttpHostTricks (план не пустой)", () =>
            {
                var engine = new StandardDiagnosisEngine();
                var selector = new StandardStrategySelector();

                var signals = new BlockageSignals
                {
                    HostKey = "example.com",
                    CapturedAtUtc = DateTimeOffset.UtcNow,
                    AggregationWindow = TimeSpan.FromSeconds(30),
                    SampleSize = 5,
                    IsUnreliable = false,

                    HasDnsFailure = false,
                    HasFakeIp = false,
                    HasHttpRedirect = true,
                    RedirectToHost = "warning.rt.ru",

                    HasTcpTimeout = false,
                    HasTcpReset = false,
                    HasTlsTimeout = false,
                    HasTlsAuthFailure = false,
                    HasTlsReset = false,

                    Http3AttemptCount = 0,
                    Http3SuccessCount = 0,
                    Http3FailureCount = 0,
                    Http3TimeoutCount = 0,
                    Http3NotSupportedCount = 0,
                };

                var dx = engine.Diagnose(signals);
                if (dx.DiagnosisId != DiagnosisId.HttpRedirect)
                {
                    return new SmokeTestResult("REG-018", "REG: HttpRedirect → HttpHostTricks (план не пустой)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали DiagnosisId=HttpRedirect, получили {dx.DiagnosisId} (rule={dx.MatchedRuleName})");
                }

                if (!dx.Evidence.TryGetValue("redirectToHost", out var redirectToHost) || !string.Equals(redirectToHost, "warning.rt.ru", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("REG-018", "REG: HttpRedirect → HttpHostTricks (план не пустой)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали evidence redirectToHost=warning.rt.ru, получили '{redirectToHost ?? "<null>"}'");
                }

                if (!dx.Evidence.TryGetValue("redirectKind", out var redirectKind) || !string.Equals(redirectKind, "blockpage", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("REG-018", "REG: HttpRedirect → HttpHostTricks (план не пустой)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали evidence redirectKind=blockpage, получили '{redirectKind ?? "<null>"}'");
                }

                var plan = selector.Select(dx);
                if (!plan.Strategies.Any(s => s.Id == StrategyId.HttpHostTricks))
                {
                    return new SmokeTestResult("REG-018", "REG: HttpRedirect → HttpHostTricks (план не пустой)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали HttpHostTricks в plan.Strategies. Strategies=[{string.Join(",", plan.Strategies.Select(s => s.Id))}] Reason={plan.Reasoning}");
                }

                return new SmokeTestResult("REG-018", "REG: HttpRedirect → HttpHostTricks (план не пустой)", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
            }, ct);

        public static Task<SmokeTestResult> REG_BlockpageHosts_Configurable_JsonOverride(CancellationToken ct)
            => RunAsync("REG-019", "REG: blockpage-hosts JSON влияет на redirectKind", () =>
            {
                const string envVar = "ISP_AUDIT_BLOCKPAGE_HOSTS_PATH";

                var prev = Environment.GetEnvironmentVariable(envVar);
                var tmpDir = Path.Combine(Path.GetTempPath(), "ISP_Audit_smoke");
                Directory.CreateDirectory(tmpDir);
                var tmpPath = Path.Combine(tmpDir, $"blockpage_hosts_{Guid.NewGuid():N}.json");

                try
                {
                    var json = "{\n  \"version\": 1,\n  \"enabled\": true,\n  \"exactHosts\": [\n    \"my.block.test\"\n  ]\n}";
                    File.WriteAllText(tmpPath, json, Encoding.UTF8);

                    Environment.SetEnvironmentVariable(envVar, tmpPath);

                    var engine = new StandardDiagnosisEngine();

                    var signals = new BlockageSignals
                    {
                        HostKey = "example.com",
                        CapturedAtUtc = DateTimeOffset.UtcNow,
                        AggregationWindow = TimeSpan.FromSeconds(30),
                        SampleSize = 5,
                        IsUnreliable = false,

                        HasDnsFailure = false,
                        HasFakeIp = false,
                        HasHttpRedirect = true,
                        RedirectToHost = "my.block.test",

                        HasTcpTimeout = false,
                        HasTcpReset = false,
                        HasTlsTimeout = false,
                        HasTlsAuthFailure = false,
                        HasTlsReset = false,

                        Http3AttemptCount = 0,
                        Http3SuccessCount = 0,
                        Http3FailureCount = 0,
                        Http3TimeoutCount = 0,
                        Http3NotSupportedCount = 0,
                    };

                    var dx = engine.Diagnose(signals);
                    if (dx.DiagnosisId != DiagnosisId.HttpRedirect)
                    {
                        return new SmokeTestResult("REG-019", "REG: blockpage-hosts JSON влияет на redirectKind", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали DiagnosisId=HttpRedirect, получили {dx.DiagnosisId} (rule={dx.MatchedRuleName})");
                    }

                    if (!dx.Evidence.TryGetValue("redirectKind", out var redirectKind) || !string.Equals(redirectKind, "blockpage", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-019", "REG: blockpage-hosts JSON влияет на redirectKind", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали evidence redirectKind=blockpage по кастомному JSON, получили '{redirectKind ?? "<null>"}'");
                    }

                    return new SmokeTestResult("REG-019", "REG: blockpage-hosts JSON влияет на redirectKind", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                finally
                {
                    try { Environment.SetEnvironmentVariable(envVar, prev); } catch { }
                    try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                }
            }, ct);

        public static Task<SmokeTestResult> REG_PostApplyChecks_Persisted_RoundTrip(CancellationToken ct)
            => RunAsync("REG-020", "REG: post-apply-checks persist+reload через PostApplyCheckStore", () =>
            {
                const string envVar = "ISP_AUDIT_POST_APPLY_CHECKS_PATH";

                var prev = Environment.GetEnvironmentVariable(envVar);
                var tmpDir = Path.Combine(Path.GetTempPath(), "ISP_Audit_smoke");
                Directory.CreateDirectory(tmpDir);
                var tmpPath = Path.Combine(tmpDir, $"post_apply_checks_{Guid.NewGuid():N}.json");

                try
                {
                    Environment.SetEnvironmentVariable(envVar, tmpPath);

                    var now = DateTimeOffset.UtcNow;
                    var groupKey = "youtube.com";
                    var entry = new PostApplyCheckStore.PostApplyCheckEntry
                    {
                        GroupKey = groupKey,
                        Verdict = "OK",
                        CheckedAtUtc = now.ToString("u").TrimEnd(),
                        HostKey = "r1---sn.example.googlevideo.com",
                        Mode = "enqueue",
                        Details = "enqueued; ips=3; out=OK"
                    };

                    var dict = new System.Collections.Generic.Dictionary<string, PostApplyCheckStore.PostApplyCheckEntry>(StringComparer.OrdinalIgnoreCase)
                    {
                        [groupKey] = entry
                    };

                    PostApplyCheckStore.PersistByGroupKeyBestEffort(dict, log: null);

                    var loaded = PostApplyCheckStore.LoadByGroupKeyBestEffort(log: null);
                    if (!loaded.TryGetValue(groupKey, out var loadedEntry) || loadedEntry == null)
                    {
                        return new SmokeTestResult("REG-020", "REG: post-apply-checks persist+reload через PostApplyCheckStore", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не нашли сохранённую запись по groupKey");
                    }

                    if (!string.Equals(loadedEntry.Verdict, "OK", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-020", "REG: post-apply-checks persist+reload через PostApplyCheckStore", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали Verdict=OK, получили '{loadedEntry.Verdict}'");
                    }

                    if (string.IsNullOrWhiteSpace(loadedEntry.CheckedAtUtc))
                    {
                        return new SmokeTestResult("REG-020", "REG: post-apply-checks persist+reload через PostApplyCheckStore", SmokeOutcome.Fail, TimeSpan.Zero,
                            "CheckedAtUtc пустой");
                    }

                    return new SmokeTestResult("REG-020", "REG: post-apply-checks persist+reload через PostApplyCheckStore", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                finally
                {
                    try { Environment.SetEnvironmentVariable(envVar, prev); } catch { }
                    try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                }
            }, ct);

        public static Task<SmokeTestResult> REG_UiReasonContract_ReasonCodeReasonText_AreStable(CancellationToken ct)
            => RunAsync("REG-030", "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен", () =>
            {
                try
                {
                    var mapReasonCode = typeof(MainViewModel).GetMethod(
                        "MapReasonCode",
                        BindingFlags.Static | BindingFlags.NonPublic);

                    var mapReasonText = typeof(MainViewModel).GetMethod(
                        "MapReasonText",
                        BindingFlags.Static | BindingFlags.NonPublic);

                    var buildLayerStatusLine = typeof(MainViewModel).GetMethod(
                        "BuildLayerStatusLine",
                        BindingFlags.Static | BindingFlags.NonPublic);

                    if (mapReasonCode == null || mapReasonText == null || buildLayerStatusLine == null)
                    {
                        return new SmokeTestResult(
                            "REG-030",
                            "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            "Не найдены приватные методы контракта (MapReasonCode/MapReasonText/BuildLayerStatusLine)");
                    }

                    string InvokeCode(IspAudit.Models.PostApplyVerdictContract contract, string details)
                        => (string)(mapReasonCode.Invoke(null, new object?[] { contract, details }) ?? string.Empty);

                    string InvokeText(string code)
                        => (string)(mapReasonText.Invoke(null, new object?[] { code }) ?? string.Empty);

                    string InvokeLayer(string rowDetails, string postApplyDetails)
                        => (string)(buildLayerStatusLine.Invoke(null, new object?[] { rowDetails, postApplyDetails }) ?? string.Empty);

                    var okCode = InvokeCode(
                        new IspAudit.Models.PostApplyVerdictContract
                        {
                            Status = IspAudit.Models.VerdictStatus.Ok,
                            UnknownReason = IspAudit.Models.UnknownReason.None,
                            VerdictCode = "OK"
                        },
                        details: string.Empty);

                    if (!string.Equals(okCode, "POST_APPLY_OK", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult(
                            "REG-030",
                            "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"Ожидали POST_APPLY_OK, получили '{okCode}'");
                    }

                    var unknownIpsCode = InvokeCode(
                        new IspAudit.Models.PostApplyVerdictContract
                        {
                            Status = IspAudit.Models.VerdictStatus.Unknown,
                            UnknownReason = IspAudit.Models.UnknownReason.InsufficientIps,
                            VerdictCode = "INSUFFICIENTIPS"
                        },
                        details: "reason=InsufficientIps; no_targets_resolved");

                    if (!string.Equals(unknownIpsCode, "UNKNOWN_INSUFFICIENT_IPS", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult(
                            "REG-030",
                            "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"Ожидали UNKNOWN_INSUFFICIENT_IPS, получили '{unknownIpsCode}'");
                    }

                    var rollbackSkippedCode = InvokeCode(
                        new IspAudit.Models.PostApplyVerdictContract
                        {
                            Status = IspAudit.Models.VerdictStatus.Unknown,
                            UnknownReason = IspAudit.Models.UnknownReason.NoBaselineFresh,
                            VerdictCode = "NOBASELINEFRESH"
                        },
                        details: "guardrailRollback=SKIPPED; guardrailStopReason=NoBaselineFresh");

                    if (!string.Equals(rollbackSkippedCode, "ROLLBACK_SKIPPED_NOBASELINEFRESH", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult(
                            "REG-030",
                            "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"Ожидали ROLLBACK_SKIPPED_NOBASELINEFRESH, получили '{rollbackSkippedCode}'");
                    }

                    var rollbackDoneCode = InvokeCode(
                        new IspAudit.Models.PostApplyVerdictContract
                        {
                            Status = IspAudit.Models.VerdictStatus.Fail,
                            UnknownReason = IspAudit.Models.UnknownReason.None,
                            VerdictCode = "FAIL"
                        },
                        details: "guardrailRollback=DONE; guardrailRegression=1");

                    if (!string.Equals(rollbackDoneCode, "ROLLBACK_DONE", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult(
                            "REG-030",
                            "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"Ожидали ROLLBACK_DONE, получили '{rollbackDoneCode}'");
                    }

                    var rollbackDoneText = InvokeText("ROLLBACK_DONE");
                    if (!string.Equals(rollbackDoneText, "Guardrail обнаружил регрессию и выполнил rollback.", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult(
                            "REG-030",
                            "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"Неожиданный ReasonText для ROLLBACK_DONE: '{rollbackDoneText}'");
                    }

                    var layerLine = InvokeLayer(
                        rowDetails: "DNS:✓ TCP:✗ TLS:✗ HTTP:✗ | TCP_CONNECT_TIMEOUT",
                        postApplyDetails: "redirectClass=suspicious");

                    if (!layerLine.Contains("DNS=✓", StringComparison.Ordinal)
                        || !layerLine.Contains("TCP=✗", StringComparison.Ordinal)
                        || !layerLine.Contains("TLS=✗", StringComparison.Ordinal)
                        || !layerLine.Contains("HTTP=✗", StringComparison.Ordinal)
                        || !layerLine.Contains("RedirectClass=suspicious", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult(
                            "REG-030",
                            "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"Слойный статус сформирован некорректно: '{layerLine}'");
                    }

                    return new SmokeTestResult(
                        "REG-030",
                        "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                        SmokeOutcome.Pass,
                        TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult(
                        "REG-030",
                        "REG: UI reason-контракт (ReasonCode/ReasonText + слойный статус) стабилен",
                        SmokeOutcome.Fail,
                        TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_WinsStore_Persisted_RoundTrip(CancellationToken ct)
            => RunAsync("REG-028", "REG: wins store persist+reload + best-match", () =>
            {
                const string envVar = "ISP_AUDIT_WINS_STORE_PATH";

                var prev = Environment.GetEnvironmentVariable(envVar);
                var tmpDir = Path.Combine(Path.GetTempPath(), "ISP_Audit_smoke");
                Directory.CreateDirectory(tmpDir);
                var tmpPath = Path.Combine(tmpDir, $"wins_store_{Guid.NewGuid():N}.json");

                try
                {
                    Environment.SetEnvironmentVariable(envVar, tmpPath);

                    var now = DateTimeOffset.UtcNow;
                    var baseKey = "example.com";
                    var entry = new IspAudit.Models.WinsEntry
                    {
                        HostKey = baseKey,
                        SniHostname = baseKey,
                        CorrelationId = "tx_smoke_028",
                        AppliedAtUtc = now.AddSeconds(-5).ToString("u").TrimEnd(),
                        VerifiedAtUtc = now.ToString("u").TrimEnd(),
                        VerifiedVerdict = "OK",
                        VerifiedMode = "local",
                        VerifiedDetails = "smoke",
                        SemanticsVersion = 2,
                        AppliedStrategyText = "TLS Fragment",
                        PlanText = "TLS_FRAGMENT",
                        CandidateIpEndpoints = new[] { "1.1.1.1:443" }
                    };

                    var dict = new System.Collections.Generic.Dictionary<string, IspAudit.Models.WinsEntry>(StringComparer.OrdinalIgnoreCase)
                    {
                        [baseKey] = entry
                    };

                    IspAudit.Utils.WinsStore.PersistByHostKeyBestEffort(dict, log: null);

                    var loaded = IspAudit.Utils.WinsStore.LoadByHostKeyBestEffort(log: null);
                    if (!loaded.TryGetValue(baseKey, out var loadedEntry) || loadedEntry == null)
                    {
                        return new SmokeTestResult("REG-028", "REG: wins store persist+reload + best-match", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не нашли сохранённую запись по hostKey");
                    }

                    if (!string.Equals(loadedEntry.VerifiedVerdict, "OK", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-028", "REG: wins store persist+reload + best-match", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали VerifiedVerdict=OK, получили '{loadedEntry.VerifiedVerdict}'");
                    }

                    if (loadedEntry.SemanticsVersion < 2)
                    {
                        return new SmokeTestResult("REG-028", "REG: wins store persist+reload + best-match", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали SemanticsVersion>=2, получили '{loadedEntry.SemanticsVersion}'");
                    }

                    if (!IspAudit.Utils.WinsStore.TryGetBestMatch(loaded, "a.b.example.com", out var best) || best == null)
                    {
                        return new SmokeTestResult("REG-028", "REG: wins store persist+reload + best-match", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали suffix-match a.b.example.com → example.com, но match не найден");
                    }

                    if (!string.Equals(best.HostKey, baseKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-028", "REG: wins store persist+reload + best-match", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали best.HostKey='{baseKey}', получили '{best.HostKey}'");
                    }

                    return new SmokeTestResult("REG-028", "REG: wins store persist+reload + best-match", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                finally
                {
                    try { Environment.SetEnvironmentVariable(envVar, prev); } catch { }
                    try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                }
            }, ct);

        public static Task<SmokeTestResult> REG_WinsStore_LegacyEntries_AreInvalidatedOrMigrated(CancellationToken ct)
            => RunAsync("REG-031", "REG: wins store invalidates legacy local OK and migrates trusted enqueue OK", () =>
            {
                const string envVar = "ISP_AUDIT_WINS_STORE_PATH";

                var prev = Environment.GetEnvironmentVariable(envVar);
                var tmpDir = Path.Combine(Path.GetTempPath(), "ISP_Audit_smoke");
                Directory.CreateDirectory(tmpDir);
                var tmpPath = Path.Combine(tmpDir, $"wins_store_{Guid.NewGuid():N}.json");

                try
                {
                    Environment.SetEnvironmentVariable(envVar, tmpPath);

                    var now = DateTimeOffset.UtcNow;

                    var legacyLocal = new IspAudit.Models.WinsEntry
                    {
                        HostKey = "legacy-local.example.com",
                        SniHostname = "legacy-local.example.com",
                        CorrelationId = "tx_legacy_local",
                        AppliedAtUtc = now.AddSeconds(-20).ToString("u").TrimEnd(),
                        VerifiedAtUtc = now.AddSeconds(-10).ToString("u").TrimEnd(),
                        VerifiedVerdict = "OK",
                        VerifiedMode = "local",
                        VerifiedDetails = "summaryOk=True; summaryFail=False",
                        SemanticsVersion = 0,
                        AppliedStrategyText = "TLS Fragment",
                        PlanText = "TLS_FRAGMENT",
                        CandidateIpEndpoints = new[] { "8.8.8.8:443" }
                    };

                    var legacyEnqueueTrusted = new IspAudit.Models.WinsEntry
                    {
                        HostKey = "legacy-enqueue.example.com",
                        SniHostname = "legacy-enqueue.example.com",
                        CorrelationId = "tx_legacy_enqueue",
                        AppliedAtUtc = now.AddSeconds(-15).ToString("u").TrimEnd(),
                        VerifiedAtUtc = now.ToString("u").TrimEnd(),
                        VerifiedVerdict = "OK",
                        VerifiedMode = "enqueue",
                        VerifiedDetails = "enqueued; ips=1; out=OK; probe=Success:ok",
                        SemanticsVersion = 0,
                        AppliedStrategyText = "TLS Fragment",
                        PlanText = "TLS_FRAGMENT",
                        CandidateIpEndpoints = new[] { "1.1.1.1:443" }
                    };

                    var dict = new System.Collections.Generic.Dictionary<string, IspAudit.Models.WinsEntry>(StringComparer.OrdinalIgnoreCase)
                    {
                        [legacyLocal.HostKey] = legacyLocal,
                        [legacyEnqueueTrusted.HostKey] = legacyEnqueueTrusted
                    };

                    IspAudit.Utils.WinsStore.PersistByHostKeyBestEffort(dict, log: null);

                    var loaded = IspAudit.Utils.WinsStore.LoadByHostKeyBestEffort(log: null);

                    if (loaded.ContainsKey(legacyLocal.HostKey))
                    {
                        return new SmokeTestResult("REG-031", "REG: wins store invalidates legacy local OK and migrates trusted enqueue OK", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Legacy local запись должна быть отброшена, но осталась в store");
                    }

                    if (!loaded.TryGetValue(legacyEnqueueTrusted.HostKey, out var migrated) || migrated == null)
                    {
                        return new SmokeTestResult("REG-031", "REG: wins store invalidates legacy local OK and migrates trusted enqueue OK", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Trusted enqueue legacy запись должна мигрироваться и остаться в store");
                    }

                    if (migrated.SemanticsVersion < 2)
                    {
                        return new SmokeTestResult("REG-031", "REG: wins store invalidates legacy local OK and migrates trusted enqueue OK", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали миграцию до SemanticsVersion>=2, получили '{migrated.SemanticsVersion}'");
                    }

                    var persistedJson = File.ReadAllText(tmpPath);
                    if (persistedJson.Contains("legacy-local.example.com", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-031", "REG: wins store invalidates legacy local OK and migrates trusted enqueue OK", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали auto-clean persisted файла от legacy local записи");
                    }

                    return new SmokeTestResult("REG-031", "REG: wins store invalidates legacy local OK and migrates trusted enqueue OK", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                finally
                {
                    try { Environment.SetEnvironmentVariable(envVar, prev); } catch { }
                    try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                }
            }, ct);

        public static async Task<SmokeTestResult> REG_Tracert_Cp866_NoMojibake(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                var cp866 = Encoding.GetEncoding(866);

                var psi = new ProcessStartInfo
                {
                    FileName = "tracert.exe",
                    Arguments = "-h 1 127.0.0.1",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = cp866,
                    StandardErrorEncoding = cp866
                };

                using var p = Process.Start(psi);
                if (p == null)
                {
                    return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Fail, sw.Elapsed,
                        "Не удалось запустить tracert.exe");
                }

                var outputTask = p.StandardOutput.ReadToEndAsync(ct);
                var errTask = p.StandardError.ReadToEndAsync(ct);

                await Task.WhenAny(Task.WhenAll(outputTask, errTask), Task.Delay(5000, ct)).ConfigureAwait(false);

                try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }

                var output = (await outputTask.ConfigureAwait(false)) + "\n" + (await errTask.ConfigureAwait(false));

                // Простейший критерий: отсутствие replacement char.
                if (output.Contains('�'))
                {
                    return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Fail, sw.Elapsed,
                        "В выводе обнаружен символ замены '�' (возможна проблема с кодировкой)" );
                }

                return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Pass, sw.Elapsed, "OK");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> REG_VpnWarning_WhenVpnDetected(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var prev = NetUtils.LikelyVpnActiveOverrideForSmoke;
                NetUtils.LikelyVpnActiveOverrideForSmoke = () => true;

                try
                {
                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                    var bypass = new BypassController(manager, autoHostlist);

                    await bypass.InitializeOnStartupAsync().ConfigureAwait(false);

                    if (!bypass.IsVpnDetected)
                    {
                        return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Fail, sw.Elapsed,
                            "Ожидали IsVpnDetected=true при принудительном override" );
                    }

                    if (string.IsNullOrWhiteSpace(bypass.VpnWarningText))
                    {
                        return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Fail, sw.Elapsed,
                            "Ожидали непустой VpnWarningText при детекте VPN" );
                    }

                    return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                finally
                {
                    NetUtils.LikelyVpnActiveOverrideForSmoke = prev;
                }
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> REG_ApplyTransactions_Persisted_RoundTrip_NoWpf(CancellationToken ct)
            => RunAsyncAwait("REG-003", "REG: P0.1 apply_transactions persist+reload (без WPF)", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prev = null;
                var tempPath = Path.Combine(Path.GetTempPath(), $"isp_audit_apply_tx_smoke_{Guid.NewGuid():N}.json");

                try
                {
                    prev = Environment.GetEnvironmentVariable("ISP_AUDIT_APPLY_TRANSACTIONS_PATH");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_APPLY_TRANSACTIONS_PATH", tempPath);

                    try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }

                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                    var bypass1 = new BypassController(manager, autoHostlist);

                    bypass1.RecordApplyTransaction(
                        initiatorHostKey: "youtube.com",
                        groupKey: "youtube.com",
                        candidateIpEndpoints: new[] { "1.1.1.1" },
                        appliedStrategyText: "Drop RST",
                        planText: "DROP_RST",
                        reasoning: "smoke");

                    // Persist идет в фоне (best-effort) — ждём появления файла.
                    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(3);
                    while (DateTime.UtcNow < deadline && !File.Exists(tempPath))
                    {
                        await Task.Delay(50, ct).ConfigureAwait(false);
                    }

                    if (!File.Exists(tempPath))
                    {
                        return new SmokeTestResult("REG-003", "REG: P0.1 apply_transactions persist+reload (без WPF)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Файл не появился: {tempPath}");
                    }

                    // Теперь создаём новый контроллер: он должен подхватить сохранённое.
                    var bypass2 = new BypassController(manager, autoHostlist);

                    deadline = DateTime.UtcNow + TimeSpan.FromSeconds(3);
                    while (DateTime.UtcNow < deadline && bypass2.ApplyTransactions.Count == 0)
                    {
                        await Task.Delay(50, ct).ConfigureAwait(false);
                    }

                    if (bypass2.ApplyTransactions.Count == 0)
                    {
                        var json = "";
                        try { json = File.ReadAllText(tempPath); } catch { }
                        return new SmokeTestResult("REG-003", "REG: P0.1 apply_transactions persist+reload (без WPF)", SmokeOutcome.Fail, sw.Elapsed,
                            "После reload ApplyTransactions пуст. persisted json=" + (string.IsNullOrWhiteSpace(json) ? "<empty>" : json.Substring(0, Math.Min(500, json.Length))));
                    }

                    var tx = bypass2.ApplyTransactions.First();
                    if (!string.Equals((tx.GroupKey ?? "").Trim().Trim('.'), "youtube.com", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-003", "REG: P0.1 apply_transactions persist+reload (без WPF)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали GroupKey=youtube.com, получили '{tx.GroupKey}'");
                    }

                    var txJson = bypass2.TryGetLatestApplyTransactionJsonForGroupKey("youtube.com");
                    if (string.IsNullOrWhiteSpace(txJson) || !txJson.Contains("CandidateIpEndpoints", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-003", "REG: P0.1 apply_transactions persist+reload (без WPF)", SmokeOutcome.Fail, sw.Elapsed,
                            "JSON транзакции пуст или не содержит CandidateIpEndpoints");
                    }

                    return new SmokeTestResult("REG-003", "REG: P0.1 apply_transactions persist+reload (без WPF)", SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-003", "REG: P0.1 apply_transactions persist+reload (без WPF)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    try { Environment.SetEnvironmentVariable("ISP_AUDIT_APPLY_TRANSACTIONS_PATH", prev); } catch { }
                    try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                }
            }, ct);

        public static Task<SmokeTestResult> REG_ApplyTransactions_Contract_HasRequestSnapshotResultContributions(CancellationToken ct)
            => RunAsync("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)", () =>
            {
                try
                {
                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                    var bypass = new BypassController(manager, autoHostlist);

                    bypass.RecordApplyTransaction(
                        initiatorHostKey: "youtube.com",
                        groupKey: "youtube.com",
                        candidateIpEndpoints: new[] { "1.1.1.1" },
                        appliedStrategyText: "Drop RST",
                        planText: "DROP_RST",
                        reasoning: "smoke");

                    var json = bypass.TryGetLatestApplyTransactionJsonForGroupKey("youtube.com");
                    if (string.IsNullOrWhiteSpace(json))
                    {
                        return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)",
                            SmokeOutcome.Fail, TimeSpan.Zero, "JSON пуст");
                    }

                    JsonNode? root;
                    try
                    {
                        root = JsonNode.Parse(json);
                    }
                    catch (Exception ex)
                    {
                        return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)",
                            SmokeOutcome.Fail, TimeSpan.Zero, "JSON не парсится: " + ex.Message);
                    }

                    if (root == null)
                    {
                        return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)",
                            SmokeOutcome.Fail, TimeSpan.Zero, "JSON root=null");
                    }

                    // Секции контракта.
                    if (root["request"] == null) return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)", SmokeOutcome.Fail, TimeSpan.Zero, "Нет секции request");
                    if (root["snapshot"] == null) return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)", SmokeOutcome.Fail, TimeSpan.Zero, "Нет секции snapshot");
                    if (root["result"] == null) return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)", SmokeOutcome.Fail, TimeSpan.Zero, "Нет секции result");
                    if (root["contributions"] == null) return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)", SmokeOutcome.Fail, TimeSpan.Zero, "Нет секции contributions");

                    // Обратная совместимость: старые ключи остаются.
                    if (root["candidateIpEndpoints"] == null) return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)", SmokeOutcome.Fail, TimeSpan.Zero, "Нет candidateIpEndpoints (ожидали обратную совместимость)");
                    if (root["activationStatus"] == null) return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)", SmokeOutcome.Fail, TimeSpan.Zero, "Нет activationStatus (ожидали обратную совместимость)");

                    return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)",
                        SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-009", "REG: apply-транзакция содержит контракт (request/snapshot/result/contributions)",
                        SmokeOutcome.Fail, TimeSpan.Zero, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_ApplyTransactions_ResultStatus_Applied_IsPersisted(CancellationToken ct)
            => RunAsync("REG-010", "REG: apply-транзакция сохраняет result.Status=APPLIED", () =>
            {
                try
                {
                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                    var bypass = new BypassController(manager, autoHostlist);

                    bypass.RecordApplyTransaction(
                        initiatorHostKey: "youtube.com",
                        groupKey: "youtube.com",
                        candidateIpEndpoints: new[] { "1.1.1.1" },
                        appliedStrategyText: "Drop RST",
                        planText: "DROP_RST",
                        reasoning: "smoke",
                        resultStatus: "APPLIED");

                    var json = bypass.TryGetLatestApplyTransactionJsonForGroupKey("youtube.com");
                    if (string.IsNullOrWhiteSpace(json))
                    {
                        return new SmokeTestResult("REG-010", "REG: apply-транзакция сохраняет result.Status=APPLIED",
                            SmokeOutcome.Fail, TimeSpan.Zero, "JSON пуст");
                    }

                    JsonNode? root;
                    try
                    {
                        root = JsonNode.Parse(json);
                    }
                    catch (Exception ex)
                    {
                        return new SmokeTestResult("REG-010", "REG: apply-транзакция сохраняет result.Status=APPLIED",
                            SmokeOutcome.Fail, TimeSpan.Zero, "JSON не парсится: " + ex.Message);
                    }

                    var status = root?["result"]?["Status"]?.ToString();
                    if (!string.Equals(status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-010", "REG: apply-транзакция сохраняет result.Status=APPLIED",
                            SmokeOutcome.Fail, TimeSpan.Zero, $"Ожидали result.Status=APPLIED, получили '{status ?? "(null)"}'");
                    }

                    return new SmokeTestResult("REG-010", "REG: apply-транзакция сохраняет result.Status=APPLIED",
                        SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-010", "REG: apply-транзакция сохраняет result.Status=APPLIED",
                        SmokeOutcome.Fail, TimeSpan.Zero, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_ApplyTransactions_ResultStatus_AndRollback_ArePersisted(CancellationToken ct)
            => RunAsync("REG-011", "REG: apply-транзакция сохраняет result.Status + Error + RollbackStatus", () =>
            {
                try
                {
                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                    var bypass = new BypassController(manager, autoHostlist);

                    bypass.RecordApplyTransaction(
                        initiatorHostKey: "failed.test",
                        groupKey: "failed.test",
                        candidateIpEndpoints: new[] { "1.1.1.1" },
                        appliedStrategyText: "Drop RST",
                        planText: "DROP_RST",
                        reasoning: "smoke",
                        resultStatus: "FAILED",
                        error: "boom",
                        rollbackStatus: "DONE");

                    bypass.RecordApplyTransaction(
                        initiatorHostKey: "canceled.test",
                        groupKey: "canceled.test",
                        candidateIpEndpoints: new[] { "1.1.1.1" },
                        appliedStrategyText: "Drop RST",
                        planText: "DROP_RST",
                        reasoning: "smoke",
                        resultStatus: "CANCELED",
                        rollbackStatus: "DONE");

                    static SmokeTestResult Fail(string msg)
                        => new("REG-011", "REG: apply-транзакция сохраняет result.Status + Error + RollbackStatus",
                            SmokeOutcome.Fail, TimeSpan.Zero, msg);

                    static bool TryParse(string json, out JsonNode? root)
                    {
                        try
                        {
                            root = JsonNode.Parse(json);
                            return root != null;
                        }
                        catch
                        {
                            root = null;
                            return false;
                        }
                    }

                    var jsonFailed = bypass.TryGetLatestApplyTransactionJsonForGroupKey("failed.test");
                    if (string.IsNullOrWhiteSpace(jsonFailed))
                    {
                        return Fail("FAILED JSON пуст");
                    }

                    if (!TryParse(jsonFailed, out var rootFailed))
                    {
                        return Fail("FAILED JSON не парсится");
                    }

                    var statusFailed = rootFailed?["result"]?["Status"]?.ToString();
                    var errorFailed = rootFailed?["result"]?["Error"]?.ToString();
                    var rollbackFailed = rootFailed?["result"]?["RollbackStatus"]?.ToString();

                    if (!string.Equals(statusFailed, "FAILED", StringComparison.OrdinalIgnoreCase))
                    {
                        return Fail($"FAILED: ожидали Status=FAILED, получили '{statusFailed ?? "(null)"}'");
                    }

                    if (!string.Equals(errorFailed, "boom", StringComparison.OrdinalIgnoreCase))
                    {
                        return Fail($"FAILED: ожидали Error='boom', получили '{errorFailed ?? "(null)"}'");
                    }

                    if (!string.Equals(rollbackFailed, "DONE", StringComparison.OrdinalIgnoreCase))
                    {
                        return Fail($"FAILED: ожидали RollbackStatus=DONE, получили '{rollbackFailed ?? "(null)"}'");
                    }

                    var jsonCanceled = bypass.TryGetLatestApplyTransactionJsonForGroupKey("canceled.test");
                    if (string.IsNullOrWhiteSpace(jsonCanceled))
                    {
                        return Fail("CANCELED JSON пуст");
                    }

                    if (!TryParse(jsonCanceled, out var rootCanceled))
                    {
                        return Fail("CANCELED JSON не парсится");
                    }

                    var statusCanceled = rootCanceled?["result"]?["Status"]?.ToString();
                    var rollbackCanceled = rootCanceled?["result"]?["RollbackStatus"]?.ToString();

                    if (!string.Equals(statusCanceled, "CANCELED", StringComparison.OrdinalIgnoreCase))
                    {
                        return Fail($"CANCELED: ожидали Status=CANCELED, получили '{statusCanceled ?? "(null)"}'");
                    }

                    if (!string.Equals(rollbackCanceled, "DONE", StringComparison.OrdinalIgnoreCase))
                    {
                        return Fail($"CANCELED: ожидали RollbackStatus=DONE, получили '{rollbackCanceled ?? "(null)"}'");
                    }

                    return new SmokeTestResult("REG-011", "REG: apply-транзакция сохраняет result.Status + Error + RollbackStatus",
                        SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-011", "REG: apply-транзакция сохраняет result.Status + Error + RollbackStatus",
                        SmokeOutcome.Fail, TimeSpan.Zero, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_ApplyIntelPlan_IsSerialized_NoParallelApply(CancellationToken ct)
            => RunAsyncAwait("REG-012", "REG: ApplyIntelPlanAsync сериализован (нет параллельного apply)", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevDelay = null;
                try
                {
                    prevDelay = Environment.GetEnvironmentVariable("ISP_AUDIT_TEST_APPLY_DELAY_MS");

                    const int delayMs = 250;
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_APPLY_DELAY_MS", delayMs.ToString());

                    var baseProfile = BypassProfile.CreateDefault();

                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var tls = new TlsBypassService(
                        engine,
                        baseProfile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: () => DateTime.UtcNow);

                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(tls, baseProfile, autoHostlist);

                    var plan = new IspAudit.Core.Intelligence.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.Intelligence.Contracts.StrategyId.TlsFragment
                            }
                        }
                    };

                    // Запускаем два apply конкурентно. Если gate работает — они должны выполниться строго последовательно.
                    var t1 = bypass.ApplyIntelPlanAsync(plan, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(3), cancellationToken: ct);
                    var t2 = bypass.ApplyIntelPlanAsync(plan, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(3), cancellationToken: ct);
                    await Task.WhenAll(t1, t2).ConfigureAwait(false);

                    var elapsed = sw.Elapsed;
                    var expectedMin = TimeSpan.FromMilliseconds(delayMs * 2 - 50);
                    if (elapsed < expectedMin)
                    {
                        return new SmokeTestResult("REG-012", "REG: ApplyIntelPlanAsync сериализован (нет параллельного apply)", SmokeOutcome.Fail, elapsed,
                            $"Ожидали последовательное выполнение: elapsed={elapsed.TotalMilliseconds:0}ms < {expectedMin.TotalMilliseconds:0}ms (delayMs={delayMs})");
                    }

                    return new SmokeTestResult("REG-012", "REG: ApplyIntelPlanAsync сериализован (нет параллельного apply)", SmokeOutcome.Pass, elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-012", "REG: ApplyIntelPlanAsync сериализован (нет параллельного apply)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_APPLY_DELAY_MS", prevDelay);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_Orchestrator_ApplyDedup_SameDomain_SkipsSecondApply(CancellationToken ct)
            => RunAsyncAwait("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)", async innerCt =>
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    using var engine = new TrafficEngine();
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(manager, autoHostlist);
                    var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                    var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                    var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                    var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                    var orch = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

                    var storePlan = typeof(DiagnosticOrchestrator)
                        .GetMethod("StorePlan", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                    if (storePlan == null)
                    {
                        return new SmokeTestResult("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)",
                            SmokeOutcome.Fail, sw.Elapsed, "Не нашли StorePlan через reflection");
                    }

                    var plan = new BypassPlan
                    {
                        ForDiagnosis = DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new BypassStrategy { Id = StrategyId.TlsFragment }
                        }
                    };

                    storePlan.Invoke(orch, new object?[] { "sub.example.com", plan, bypass });

                    var first = await orch.ApplyRecommendationsForDomainAsync(bypass, "example.com").ConfigureAwait(false);
                    if (first == null)
                    {
                        return new SmokeTestResult("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)",
                            SmokeOutcome.Fail, sw.Elapsed, "Первый Apply вернул null (ожидали outcome)"
                        );
                    }

                    if (!string.Equals(first.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)",
                            SmokeOutcome.Fail, sw.Elapsed, $"Первый Apply: ожидали Status=APPLIED, получили '{first.Status}'");
                    }

                    var second = await orch.ApplyRecommendationsForDomainAsync(bypass, "example.com").ConfigureAwait(false);
                    if (second == null)
                    {
                        return new SmokeTestResult("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)",
                            SmokeOutcome.Fail, sw.Elapsed, "Второй Apply вернул null (ожидали ALREADY_APPLIED)"
                        );
                    }

                    if (!string.Equals(second.Status, "ALREADY_APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)",
                            SmokeOutcome.Fail, sw.Elapsed, $"Второй Apply: ожидали Status=ALREADY_APPLIED, получили '{second.Status}'");
                    }

                    return new SmokeTestResult("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-024", "REG: Orchestrator Apply дедуплицируется для домена (ALREADY_APPLIED)",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_IntelPlan_DominatedPlan_SkipsSecondApply(CancellationToken ct)
            => RunAsyncAwait("REG-029", "REG: Dominated plan (подмножество) не применяется повторно", async innerCt =>
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    using var engine = new TrafficEngine();
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(manager, autoHostlist);
                    var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                    var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                    var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                    var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                    var orch = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

                    var storePlan = typeof(DiagnosticOrchestrator)
                        .GetMethod("StorePlan", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                    if (storePlan == null)
                    {
                        return new SmokeTestResult("REG-029", "REG: Dominated plan (подмножество) не применяется повторно",
                            SmokeOutcome.Fail, sw.Elapsed, "Не нашли StorePlan через reflection");
                    }

                    // Сначала сохраняем и применяем «сильный» план.
                    var strong = new BypassPlan
                    {
                        ForDiagnosis = DiagnosisId.ActiveDpiEdge,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new BypassStrategy { Id = StrategyId.TlsFragment },
                            new BypassStrategy { Id = StrategyId.DropRst },
                        },
                        DropUdp443 = true,
                        AllowNoSni = false,
                        Reasoning = "smoke"
                    };

                    storePlan.Invoke(orch, new object?[] { "sub.example.com", strong, bypass });

                    var first = await orch.ApplyRecommendationsForDomainAsync(bypass, "example.com").ConfigureAwait(false);
                    if (first == null)
                    {
                        return new SmokeTestResult("REG-029", "REG: Dominated plan (подмножество) не применяется повторно",
                            SmokeOutcome.Fail, sw.Elapsed, "Первый Apply вернул null (ожидали outcome)");
                    }

                    if (!string.Equals(first.Status, "APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-029", "REG: Dominated plan (подмножество) не применяется повторно",
                            SmokeOutcome.Fail, sw.Elapsed, $"Первый Apply: ожидали Status=APPLIED, получили '{first.Status}'");
                    }

                    // Затем сохраняем «слабый» план (подмножество strong) и пробуем применить снова.
                    // Ожидаем, что orchestrator распознает доминирование и вернёт ALREADY_APPLIED.
                    var weak = new BypassPlan
                    {
                        ForDiagnosis = DiagnosisId.ActiveDpiEdge,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new BypassStrategy { Id = StrategyId.TlsFragment },
                        },
                        DropUdp443 = false,
                        AllowNoSni = false,
                        Reasoning = "smoke"
                    };

                    storePlan.Invoke(orch, new object?[] { "sub.example.com", weak, bypass });

                    var second = await orch.ApplyRecommendationsForDomainAsync(bypass, "example.com").ConfigureAwait(false);
                    if (second == null)
                    {
                        return new SmokeTestResult("REG-029", "REG: Dominated plan (подмножество) не применяется повторно",
                            SmokeOutcome.Fail, sw.Elapsed, "Второй Apply вернул null (ожидали ALREADY_APPLIED)"
                        );
                    }

                    if (!string.Equals(second.Status, "ALREADY_APPLIED", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-029", "REG: Dominated plan (подмножество) не применяется повторно",
                            SmokeOutcome.Fail, sw.Elapsed, $"Второй Apply: ожидали Status=ALREADY_APPLIED, получили '{second.Status}'");
                    }

                    return new SmokeTestResult("REG-029", "REG: Dominated plan (подмножество) не применяется повторно",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-029", "REG: Dominated plan (подмножество) не применяется повторно",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_ApplyIntelPlan_Timeout_HasPhaseDiagnostics(CancellationToken ct)
            => RunAsyncAwait("REG-016", "REG: ApplyIntelPlanAsync timeout содержит фазовую диагностику (cancelReason/currentPhase/phases)", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevDelay = null;
                try
                {
                    prevDelay = Environment.GetEnvironmentVariable("ISP_AUDIT_TEST_APPLY_DELAY_MS");

                    // Детерминированно создаём таймаут в test_delay фазе.
                    const int delayMs = 500;
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_APPLY_DELAY_MS", delayMs.ToString());

                    var baseProfile = BypassProfile.CreateDefault();

                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var tls = new TlsBypassService(
                        engine,
                        baseProfile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: () => DateTime.UtcNow);

                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(tls, baseProfile, autoHostlist);

                    var plan = new IspAudit.Core.Intelligence.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.Intelligence.Contracts.StrategyId.TlsFragment
                            }
                        }
                    };

                    try
                    {
                        await bypass.ApplyIntelPlanAsync(plan, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromMilliseconds(50), cancellationToken: ct)
                            .ConfigureAwait(false);

                        return new SmokeTestResult("REG-016", "REG: ApplyIntelPlanAsync timeout содержит фазовую диагностику (cancelReason/currentPhase/phases)",
                            SmokeOutcome.Fail, sw.Elapsed, "Ожидали таймаут, но apply завершился без исключения");
                    }
                    catch (IspAudit.Core.Bypass.BypassApplyService.BypassApplyCanceledException ce)
                    {
                        if (!string.Equals(ce.Execution.CancelReason, "timeout", StringComparison.OrdinalIgnoreCase))
                        {
                            return new SmokeTestResult("REG-016", "REG: ApplyIntelPlanAsync timeout содержит фазовую диагностику (cancelReason/currentPhase/phases)",
                                SmokeOutcome.Fail, sw.Elapsed, $"Ожидали CancelReason=timeout, получили '{ce.Execution.CancelReason}'");
                        }

                        if (ce.Execution.Phases == null || ce.Execution.Phases.Count == 0)
                        {
                            return new SmokeTestResult("REG-016", "REG: ApplyIntelPlanAsync timeout содержит фазовую диагностику (cancelReason/currentPhase/phases)",
                                SmokeOutcome.Fail, sw.Elapsed, "Phases пуст (ожидали хотя бы plan_build/test_delay)");
                        }

                        // Должны увидеть test_delay как текущую фазу (мы таймаутим именно там).
                        if (!string.Equals(ce.Execution.CurrentPhase, "test_delay", StringComparison.OrdinalIgnoreCase)
                            && !ce.Execution.Phases.Any(p => string.Equals(p.Name, "test_delay", StringComparison.OrdinalIgnoreCase)))
                        {
                            return new SmokeTestResult("REG-016", "REG: ApplyIntelPlanAsync timeout содержит фазовую диагностику (cancelReason/currentPhase/phases)",
                                SmokeOutcome.Fail, sw.Elapsed, $"Ожидали фазу test_delay (currentPhase или phases), получили currentPhase='{ce.Execution.CurrentPhase}'");
                        }

                        return new SmokeTestResult("REG-016", "REG: ApplyIntelPlanAsync timeout содержит фазовую диагностику (cancelReason/currentPhase/phases)",
                            SmokeOutcome.Pass, sw.Elapsed, "OK");
                    }
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-016", "REG: ApplyIntelPlanAsync timeout содержит фазовую диагностику (cancelReason/currentPhase/phases)",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_APPLY_DELAY_MS", prevDelay);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_IntelPlan_DoH_Skipped_WithoutConsent(CancellationToken ct)
            => RunAsyncAwait("REG-022", "REG: INTEL apply пропускает DoH/DNS без явного согласия (apply_doh_skipped)", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevSkipTls = null;
                string? prevApplyTxPath = null;

                try
                {
                    prevSkipTls = Environment.GetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", "1");

                    prevApplyTxPath = Environment.GetEnvironmentVariable(EnvKeys.ApplyTransactionsPath);
                    var tempApplyTxPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"isp_audit_applytx_{Guid.NewGuid():N}.json");
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, tempApplyTxPath);

                    var phases = new System.Collections.Generic.List<BypassApplyPhaseTiming>();
                    void OnPhase(BypassApplyPhaseTiming e)
                    {
                        try
                        {
                            lock (phases)
                            {
                                phases.Add(e);
                            }
                        }
                        catch
                        {
                            // ignore
                        }
                    }

                    var baseProfile = BypassProfile.CreateDefault();
                    using var engine = new TrafficEngine(progress: null);
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: baseProfile, log: null);

                    var service = new BypassApplyService(manager, log: null);

                    var plan = new BypassPlan
                    {
                        ForDiagnosis = DiagnosisId.DnsHijack,
                        PlanConfidence = 90,
                        PlannedAtUtc = DateTimeOffset.UtcNow,
                        Reasoning = "smoke",
                        Strategies = new System.Collections.Generic.List<BypassStrategy>
                        {
                            new BypassStrategy { Id = StrategyId.UseDoh, BasePriority = 100, Risk = RiskLevel.Medium }
                        }
                    };

                    var result = await service.ApplyIntelPlanWithRollbackAsync(
                        plan,
                        timeout: TimeSpan.FromSeconds(2),
                        currentDoHEnabled: false,
                        selectedDnsPreset: "Cloudflare",
                        allowDnsDohChanges: false,
                        cancellationToken: ct,
                        onPhaseEvent: OnPhase).ConfigureAwait(false);

                    // При отсутствии согласия итоговое состояние DoH не должно поменяться.
                    if (result.PlannedDoHEnabled)
                    {
                        return new SmokeTestResult("REG-022", "REG: INTEL apply пропускает DoH/DNS без явного согласия (apply_doh_skipped)",
                            SmokeOutcome.Fail, sw.Elapsed, "Ожидали PlannedDoHEnabled=false при allowDnsDohChanges=false");
                    }

                    string[] started;
                    lock (phases)
                    {
                        started = phases
                            .Where(p => string.Equals(p.Status, "START", StringComparison.OrdinalIgnoreCase))
                            .Select(p => (p.Name ?? string.Empty).Trim())
                            .Where(p => !string.IsNullOrWhiteSpace(p))
                            .ToArray();
                    }

                    if (!started.Any(p => string.Equals(p, "apply_doh_skipped", StringComparison.OrdinalIgnoreCase)))
                    {
                        var got = string.Join(", ", started);
                        return new SmokeTestResult("REG-022", "REG: INTEL apply пропускает DoH/DNS без явного согласия (apply_doh_skipped)",
                            SmokeOutcome.Fail, sw.Elapsed, $"Не нашли фазу apply_doh_skipped. Got=[{got}]");
                    }

                    if (started.Any(p => string.Equals(p, "apply_doh_enable", StringComparison.OrdinalIgnoreCase))
                        || started.Any(p => string.Equals(p, "apply_doh_disable", StringComparison.OrdinalIgnoreCase)))
                    {
                        var got = string.Join(", ", started);
                        return new SmokeTestResult("REG-022", "REG: INTEL apply пропускает DoH/DNS без явного согласия (apply_doh_skipped)",
                            SmokeOutcome.Fail, sw.Elapsed, $"Не ожидали apply_doh_enable/disable при allowDnsDohChanges=false. Got=[{got}]");
                    }

                    return new SmokeTestResult("REG-022", "REG: INTEL apply пропускает DoH/DNS без явного согласия (apply_doh_skipped)",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-022", "REG: INTEL apply пропускает DoH/DNS без явного согласия (apply_doh_skipped)",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", prevSkipTls);
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, prevApplyTxPath);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_AutoBypass_DoH_Skipped_WithoutConsent(CancellationToken ct)
            => RunAsyncAwait("REG-025", "REG: AutoBypass policy: DoH/DNS не auto-apply без явного согласия", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevSkipTls = null;
                string? prevApplyTxPath = null;

                try
                {
                    prevSkipTls = Environment.GetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", "1");

                    prevApplyTxPath = Environment.GetEnvironmentVariable(EnvKeys.ApplyTransactionsPath);
                    var tempApplyTxPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"isp_audit_applytx_{Guid.NewGuid():N}.json");
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, tempApplyTxPath);

                    var baseProfile = BypassProfile.CreateDefault();
                    using var engine = new TrafficEngine(progress: null);
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: baseProfile, log: null);
                    manager.AllowDnsDohSystemChanges = false;

                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(manager, autoHostlist)
                    {
                        SelectedDnsPreset = "Cloudflare"
                    };

                    var beforeTxCount = bypass.ApplyTransactions.Count;

                    var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                    var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                    var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                    var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                    var orch = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

                    var plan = new BypassPlan
                    {
                        ForDiagnosis = DiagnosisId.DnsHijack,
                        PlanConfidence = 90,
                        PlannedAtUtc = DateTimeOffset.UtcNow,
                        Reasoning = "smoke",
                        Strategies = new List<BypassStrategy>
                        {
                            new BypassStrategy { Id = StrategyId.UseDoh, BasePriority = 100, Risk = RiskLevel.Medium }
                        }
                    };

                    // Путь автопилота — private, поэтому вызываем через reflection.
                    var mi = typeof(DiagnosticOrchestrator).GetMethod(
                        "AutoApplyFromPlanAsync",
                        BindingFlags.Instance | BindingFlags.NonPublic);

                    if (mi == null)
                    {
                        return new SmokeTestResult("REG-025", "REG: AutoBypass не применяет DoH/DNS без явного согласия (apply_doh_skipped)",
                            SmokeOutcome.Fail, sw.Elapsed, "Не нашли private метод DiagnosticOrchestrator.AutoApplyFromPlanAsync (изменился контракт/имя)");
                    }

                    var planSig = "UseDoh|U0|N0";

                    var t = mi.Invoke(orch, new object[] { "example.com", "sub.example.com", plan, planSig, bypass });
                    if (t is not Task task)
                    {
                        return new SmokeTestResult("REG-025", "REG: AutoBypass не применяет DoH/DNS без явного согласия (apply_doh_skipped)",
                            SmokeOutcome.Fail, sw.Elapsed, "AutoApplyFromPlanAsync вернул не Task (неожиданный контракт)");
                    }

                    // Safety-net на случай зависания внутри Apply.
                    var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(4), ct)).ConfigureAwait(false);
                    if (completed != task)
                    {
                        return new SmokeTestResult("REG-025", "REG: AutoBypass не применяет DoH/DNS без явного согласия (apply_doh_skipped)",
                            SmokeOutcome.Fail, sw.Elapsed, "Таймаут ожидания AutoApplyFromPlanAsync (возможное зависание apply)" );
                    }

                    await task.ConfigureAwait(false);

                    // Контракт: без согласия DoH не включается.
                    if (bypass.IsDoHEnabled)
                    {
                        return new SmokeTestResult("REG-025", "REG: AutoBypass policy: DoH/DNS не auto-apply без явного согласия",
                            SmokeOutcome.Fail, sw.Elapsed, "Ожидали IsDoHEnabled=false при AllowDnsDohSystemChanges=false" );
                    }

                    // Контракт: policy запрещает даже попытку apply (без consent), поэтому транзакций быть не должно.
                        if (bypass.ApplyTransactions.Count != beforeTxCount)
                    {
                        return new SmokeTestResult("REG-025", "REG: AutoBypass policy: DoH/DNS не auto-apply без явного согласия",
                            SmokeOutcome.Fail, sw.Elapsed, $"Не ожидали новых apply-транзакций при отсутствии consent. Before={beforeTxCount}, After={bypass.ApplyTransactions.Count}" );
                    }

                    return new SmokeTestResult("REG-025", "REG: AutoBypass policy: DoH/DNS не auto-apply без явного согласия",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-025", "REG: AutoBypass policy: DoH/DNS не auto-apply без явного согласия",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", prevSkipTls);
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, prevApplyTxPath);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_AutoBypass_Policy_Skips_LowConfidence(CancellationToken ct)
            => RunAsyncAwait("REG-026", "REG: AutoBypass policy: confidence < 70 не auto-apply", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevSkipTls = null;
                string? prevApplyTxPath = null;

                try
                {
                    prevSkipTls = Environment.GetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", "1");

                    prevApplyTxPath = Environment.GetEnvironmentVariable(EnvKeys.ApplyTransactionsPath);
                    var tempApplyTxPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"isp_audit_applytx_{Guid.NewGuid():N}.json");
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, tempApplyTxPath);

                    var baseProfile = BypassProfile.CreateDefault();
                    using var engine = new TrafficEngine(progress: null);
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: baseProfile, log: null);
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(manager, autoHostlist);
                    var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                    var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                    var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                    var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                    var orch = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

                    var beforeTxCount = bypass.ApplyTransactions.Count;

                    var plan = new BypassPlan
                    {
                        ForDiagnosis = DiagnosisId.SilentDrop,
                        PlanConfidence = 60,
                        PlannedAtUtc = DateTimeOffset.UtcNow,
                        Reasoning = "smoke",
                        Strategies = new List<BypassStrategy>
                        {
                            new BypassStrategy { Id = StrategyId.TlsFragment, BasePriority = 100, Risk = RiskLevel.Medium }
                        }
                    };

                    var mi = typeof(DiagnosticOrchestrator).GetMethod(
                        "AutoApplyFromPlanAsync",
                        BindingFlags.Instance | BindingFlags.NonPublic);

                    if (mi == null)
                    {
                        return new SmokeTestResult("REG-026", "REG: AutoBypass policy: confidence < 70 не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, "Не нашли private метод DiagnosticOrchestrator.AutoApplyFromPlanAsync (изменился контракт/имя)");
                    }

                    var planSig = "TlsFragment|U0|N0";
                    var t = mi.Invoke(orch, new object[] { "example.com", "sub.example.com", plan, planSig, bypass });
                    if (t is not Task task)
                    {
                        return new SmokeTestResult("REG-026", "REG: AutoBypass policy: confidence < 70 не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, "AutoApplyFromPlanAsync вернул не Task (неожиданный контракт)");
                    }

                    var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(2), ct)).ConfigureAwait(false);
                    if (completed != task)
                    {
                        return new SmokeTestResult("REG-026", "REG: AutoBypass policy: confidence < 70 не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, "Таймаут ожидания AutoApplyFromPlanAsync");
                    }

                    await task.ConfigureAwait(false);

                    if (bypass.ApplyTransactions.Count != beforeTxCount)
                    {
                        return new SmokeTestResult("REG-026", "REG: AutoBypass policy: confidence < 70 не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, $"Не ожидали новых apply-транзакций при confidence < 70. Before={beforeTxCount}, After={bypass.ApplyTransactions.Count}");
                    }

                    return new SmokeTestResult("REG-026", "REG: AutoBypass policy: confidence < 70 не auto-apply",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-026", "REG: AutoBypass policy: confidence < 70 не auto-apply",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", prevSkipTls);
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, prevApplyTxPath);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_AutoBypass_Policy_Skips_HighRiskStrategy(CancellationToken ct)
            => RunAsyncAwait("REG-027", "REG: AutoBypass policy: High-risk стратегия не auto-apply", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevSkipTls = null;
                string? prevApplyTxPath = null;

                try
                {
                    prevSkipTls = Environment.GetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", "1");

                    prevApplyTxPath = Environment.GetEnvironmentVariable(EnvKeys.ApplyTransactionsPath);
                    var tempApplyTxPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"isp_audit_applytx_{Guid.NewGuid():N}.json");
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, tempApplyTxPath);

                    var baseProfile = BypassProfile.CreateDefault();
                    using var engine = new TrafficEngine(progress: null);
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: baseProfile, log: null);
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(manager, autoHostlist);
                    var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                    var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                    var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                    var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                    var orch = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

                    var beforeTxCount = bypass.ApplyTransactions.Count;

                    var plan = new BypassPlan
                    {
                        ForDiagnosis = DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        PlannedAtUtc = DateTimeOffset.UtcNow,
                        Reasoning = "smoke",
                        Strategies = new List<BypassStrategy>
                        {
                            new BypassStrategy { Id = StrategyId.TlsFragment, BasePriority = 100, Risk = RiskLevel.High }
                        }
                    };

                    var mi = typeof(DiagnosticOrchestrator).GetMethod(
                        "AutoApplyFromPlanAsync",
                        BindingFlags.Instance | BindingFlags.NonPublic);

                    if (mi == null)
                    {
                        return new SmokeTestResult("REG-027", "REG: AutoBypass policy: High-risk стратегия не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, "Не нашли private метод DiagnosticOrchestrator.AutoApplyFromPlanAsync (изменился контракт/имя)");
                    }

                    var planSig = "TlsFragment|U0|N0";
                    var t = mi.Invoke(orch, new object[] { "example.com", "sub.example.com", plan, planSig, bypass });
                    if (t is not Task task)
                    {
                        return new SmokeTestResult("REG-027", "REG: AutoBypass policy: High-risk стратегия не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, "AutoApplyFromPlanAsync вернул не Task (неожиданный контракт)");
                    }

                    var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(2), ct)).ConfigureAwait(false);
                    if (completed != task)
                    {
                        return new SmokeTestResult("REG-027", "REG: AutoBypass policy: High-risk стратегия не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, "Таймаут ожидания AutoApplyFromPlanAsync");
                    }

                    await task.ConfigureAwait(false);

                    if (bypass.ApplyTransactions.Count != beforeTxCount)
                    {
                        return new SmokeTestResult("REG-027", "REG: AutoBypass policy: High-risk стратегия не auto-apply",
                            SmokeOutcome.Fail, sw.Elapsed, $"Не ожидали новых apply-транзакций для High-risk стратегии. Before={beforeTxCount}, After={bypass.ApplyTransactions.Count}");
                    }

                    return new SmokeTestResult("REG-027", "REG: AutoBypass policy: High-risk стратегия не auto-apply",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-027", "REG: AutoBypass policy: High-risk стратегия не auto-apply",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_TEST_SKIP_TLS_APPLY", prevSkipTls);
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, prevApplyTxPath);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_EnvVars_AreDocumented_InEnvVarsMd(CancellationToken ct)
            => RunAsync("REG-023", "REG: все ISP_AUDIT_* ENV перечислены в docs/ENV_VARS.md", () =>
            {
                try
                {
                    _ = ct;

                    static string? TryFindRepoRoot()
                    {
                        var markers = new[]
                        {
                            "ISP_Audit.sln",
                            "Directory.Build.props"
                        };

                        var startDirs = new[]
                        {
                            Environment.CurrentDirectory,
                            AppContext.BaseDirectory,
                            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..")),
                            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."))
                        };

                        foreach (var start in startDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            if (string.IsNullOrWhiteSpace(start))
                            {
                                continue;
                            }

                            try
                            {
                                var dir = new DirectoryInfo(start);
                                for (int i = 0; i < 8 && dir != null; i++)
                                {
                                    foreach (var marker in markers)
                                    {
                                        if (File.Exists(Path.Combine(dir.FullName, marker)))
                                        {
                                            return dir.FullName;
                                        }
                                    }

                                    dir = dir.Parent;
                                }
                            }
                            catch
                            {
                                // ignore
                            }
                        }

                        return null;
                    }

                    static bool IsSkippablePath(string fullPath)
                    {
                        var p = fullPath.Replace('/', '\\');
                        return p.Contains("\\\\bin\\\\", StringComparison.OrdinalIgnoreCase)
                            || p.Contains("\\\\obj\\\\", StringComparison.OrdinalIgnoreCase)
                            || p.Contains("\\\\publish\\\\", StringComparison.OrdinalIgnoreCase)
                            || p.Contains("\\\\artifacts\\\\", StringComparison.OrdinalIgnoreCase)
                            || p.Contains("\\\\.git\\\\", StringComparison.OrdinalIgnoreCase);
                    }

                    static HashSet<string> ExtractUsedEnvKeysFromCode(string text)
                    {
                        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                        // 1) Прямые string literal ключи в Get/SetEnvironmentVariable.
                        var rxGet = new Regex(
                            @"Environment\.GetEnvironmentVariable\(\s*""(?<key>ISP_AUDIT_[A-Z0-9_]+)""\s*\)",
                            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        var rxSet = new Regex(
                            @"Environment\.SetEnvironmentVariable\(\s*""(?<key>ISP_AUDIT_[A-Z0-9_]+)""\s*,",
                            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                        foreach (Match m in rxGet.Matches(text))
                        {
                            var v = (m.Groups["key"].Value ?? string.Empty).Trim();
                            if (!string.IsNullOrWhiteSpace(v))
                            {
                                keys.Add(v);
                            }
                        }

                        foreach (Match m in rxSet.Matches(text))
                        {
                            var v = (m.Groups["key"].Value ?? string.Empty).Trim();
                            if (!string.IsNullOrWhiteSpace(v))
                            {
                                keys.Add(v);
                            }
                        }

                        // 2) Ключи, определённые как const string (частый паттерн: EnvVarPathOverride = "ISP_AUDIT_..."),
                        // которые затем передаются в Get/SetEnvironmentVariable.
                        var rxConst = new Regex(
                            @"\bconst\s+string\s+\w+\s*=\s*""(?<key>ISP_AUDIT_[A-Z0-9_]+)""\s*;",
                            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                        foreach (Match m in rxConst.Matches(text))
                        {
                            var v = (m.Groups["key"].Value ?? string.Empty).Trim();
                            if (!string.IsNullOrWhiteSpace(v))
                            {
                                keys.Add(v);
                            }
                        }

                        return keys;
                    }

                    static HashSet<string> ExtractDocumentedEnvKeysFromDoc(string text)
                    {
                        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                        // В доке достаточно вытащить любые токены ISP_AUDIT_* (они обычно в backticks).
                        var rx = new Regex(@"\bISP_AUDIT_[A-Z0-9_]+\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                        foreach (Match m in rx.Matches(text))
                        {
                            if (!m.Success)
                            {
                                continue;
                            }

                            var v = (m.Value ?? string.Empty).Trim();
                            if (!string.IsNullOrWhiteSpace(v))
                            {
                                keys.Add(v);
                            }
                        }

                        return keys;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
                    {
                        return new SmokeTestResult("REG-023", "REG: все ISP_AUDIT_* ENV перечислены в docs/ENV_VARS.md",
                            SmokeOutcome.Fail, TimeSpan.Zero, "Не удалось найти корень репозитория (ожидали ISP_Audit.sln/Directory.Build.props)" );
                    }

                    var docPath = Path.Combine(root, "docs", "ENV_VARS.md");
                    if (!File.Exists(docPath))
                    {
                        return new SmokeTestResult("REG-023", "REG: все ISP_AUDIT_* ENV перечислены в docs/ENV_VARS.md",
                            SmokeOutcome.Fail, TimeSpan.Zero, $"Не найден файл реестра: {docPath}" );
                    }

                    var docText = File.ReadAllText(docPath);
                    var docKeys = ExtractDocumentedEnvKeysFromDoc(docText);
                    if (docKeys.Count == 0)
                    {
                        return new SmokeTestResult("REG-023", "REG: все ISP_AUDIT_* ENV перечислены в docs/ENV_VARS.md",
                            SmokeOutcome.Fail, TimeSpan.Zero, "В docs/ENV_VARS.md не нашли ни одной ISP_AUDIT_* переменной" );
                    }

                    var codeKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
                    {
                        if (IsSkippablePath(file))
                        {
                            continue;
                        }

                        string text;
                        try
                        {
                            text = File.ReadAllText(file);
                        }
                        catch
                        {
                            continue;
                        }

                        foreach (var k in ExtractUsedEnvKeysFromCode(text))
                        {
                            codeKeys.Add(k);
                        }
                    }

                    var missing = codeKeys
                        .Where(k => !docKeys.Contains(k))
                        .OrderBy(k => k, StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    if (missing.Length > 0)
                    {
                        var preview = string.Join(", ", missing.Take(12));
                        var tail = missing.Length > 12 ? $" (+{missing.Length - 12} ещё)" : string.Empty;
                        return new SmokeTestResult("REG-023", "REG: все ISP_AUDIT_* ENV перечислены в docs/ENV_VARS.md",
                            SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Не задокументированы в docs/ENV_VARS.md: {preview}{tail}" );
                    }

                    return new SmokeTestResult("REG-023", "REG: все ISP_AUDIT_* ENV перечислены в docs/ENV_VARS.md",
                        SmokeOutcome.Pass, TimeSpan.Zero, $"OK (codeKeys={codeKeys.Count}, docKeys={docKeys.Count})" );
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-023", "REG: все ISP_AUDIT_* ENV перечислены в docs/ENV_VARS.md",
                        SmokeOutcome.Fail, TimeSpan.Zero, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_GroupBypassAttachmentStore_DeterministicMerge_AndExcludedSticky(CancellationToken ct)
            => RunAsync("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается", () =>
            {
                try
                {
                    _ = ct;

                    var store = new GroupBypassAttachmentStore();
                    const string groupKey = "example.com";

                    store.PinHostKeyToGroupKey("a.example.com", groupKey);
                    var excludedNow = store.ToggleExcluded(groupKey, "a.example.com");
                    if (!excludedNow)
                    {
                        return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                            SmokeOutcome.Fail, TimeSpan.Zero, "Ожидали excludedNow=true после ToggleExcluded");
                    }

                    // Apply-обновление не должно снимать ручное исключение.
                    store.UpdateAttachmentFromApply(groupKey, "a.example.com", new[] { "1.1.1.1:443" }, planText: "DROP_UDP_443");
                    if (!store.IsExcluded(groupKey, "a.example.com"))
                    {
                        return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                            SmokeOutcome.Fail, TimeSpan.Zero, "excluded сброшен после UpdateAttachmentFromApply (ожидали sticky excluded)");
                    }

                    store.PinHostKeyToGroupKey("b.example.com", groupKey);
                    store.UpdateAttachmentFromApply(groupKey, "b.example.com", new[] { "2.2.2.2:443", "1.1.1.1:443" }, planText: "ALLOW_NO_SNI, DROP_UDP_443");

                    var cfg = store.GetEffectiveGroupConfig(groupKey);
                    if (cfg.AttachmentCount != 2)
                    {
                        return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                            SmokeOutcome.Fail, TimeSpan.Zero, $"Ожидали AttachmentCount=2, получили {cfg.AttachmentCount}");
                    }

                    if (cfg.IncludedCount != 1 || cfg.ExcludedCount != 1)
                    {
                        return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                            SmokeOutcome.Fail, TimeSpan.Zero, $"Ожидали IncludedCount=1 и ExcludedCount=1, получили Included={cfg.IncludedCount}, Excluded={cfg.ExcludedCount}");
                    }

                    if (!cfg.DropUdp443 || !cfg.AllowNoSni)
                    {
                        return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                            SmokeOutcome.Fail, TimeSpan.Zero, $"Ожидали DropUdp443=true и AllowNoSni=true, получили DropUdp443={cfg.DropUdp443}, AllowNoSni={cfg.AllowNoSni}");
                    }

                    var union = cfg.CandidateIpEndpointsUnion ?? Array.Empty<string>();
                    if (union.Count != 2
                        || !union.Contains("1.1.1.1:443", StringComparer.OrdinalIgnoreCase)
                        || !union.Contains("2.2.2.2:443", StringComparer.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                            SmokeOutcome.Fail, TimeSpan.Zero, "Ожидали union endpoints из 2 элементов (1.1.1.1:443 и 2.2.2.2:443)");
                    }

                    // Детерминированность: union должен быть отсортирован.
                    var sorted = union.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToArray();
                    if (!union.SequenceEqual(sorted, StringComparer.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                            SmokeOutcome.Fail, TimeSpan.Zero, "Ожидали отсортированный CandidateIpEndpointsUnion");
                    }

                    return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                        SmokeOutcome.Pass, TimeSpan.Zero, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-013", "REG: GroupBypassAttachmentStore merge (union/OR) и excluded не сбрасывается",
                        SmokeOutcome.Fail, TimeSpan.Zero, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_GroupParticipation_Persisted_RoundTrip_ThroughStore(CancellationToken ct)
            => RunAsyncAwait("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore", async _ =>
            {
                var sw = Stopwatch.StartNew();
                var tempPath = Path.Combine(Path.GetTempPath(), $"isp_audit_group_participation_{Guid.NewGuid():N}.json");

                try
                {
                    _ = ct;

                    var store1 = new GroupBypassAttachmentStore();
                    const string groupKey = "example.com";

                    store1.PinHostKeyToGroupKey("a.example.com", groupKey);
                    store1.PinHostKeyToGroupKey("b.example.com", groupKey);
                    store1.ToggleExcluded(groupKey, "a.example.com");

                    // Добавим apply-обновление, чтобы гарантировать, что наличие attachments не ломает persist.
                    store1.UpdateAttachmentFromApply(groupKey, "b.example.com", new[] { "1.1.1.1:443" }, planText: "ALLOW_NO_SNI");

                    store1.PersistToDiskBestEffort(tempPath);

                    // Дадим файловой системе момент на flush в CI/медленных дисках.
                    for (var i = 0; i < 20 && !File.Exists(tempPath); i++)
                    {
                        await Task.Delay(25, CancellationToken.None).ConfigureAwait(false);
                    }

                    if (!File.Exists(tempPath))
                    {
                        return new SmokeTestResult("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore",
                            SmokeOutcome.Fail, sw.Elapsed, $"Файл не создан: {tempPath}");
                    }

                    var store2 = new GroupBypassAttachmentStore();
                    store2.LoadFromDiskBestEffort(tempPath);

                    if (!store2.TryGetPinnedGroupKey("a.example.com", out var pinnedA) || !string.Equals(pinnedA, groupKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore",
                            SmokeOutcome.Fail, sw.Elapsed, $"Ожидали pinned groupKey='{groupKey}' для a.example.com, получили '{pinnedA}'");
                    }

                    if (!store2.TryGetPinnedGroupKey("b.example.com", out var pinnedB) || !string.Equals(pinnedB, groupKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore",
                            SmokeOutcome.Fail, sw.Elapsed, $"Ожидали pinned groupKey='{groupKey}' для b.example.com, получили '{pinnedB}'");
                    }

                    if (!store2.IsExcluded(groupKey, "a.example.com"))
                    {
                        return new SmokeTestResult("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore",
                            SmokeOutcome.Fail, sw.Elapsed, "Ожидали, что a.example.com останется excluded после reload");
                    }

                    if (store2.IsExcluded(groupKey, "b.example.com"))
                    {
                        return new SmokeTestResult("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore",
                            SmokeOutcome.Fail, sw.Elapsed, "Не ожидали excluded для b.example.com после reload");
                    }

                    return new SmokeTestResult("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-014", "REG: group_participation persist+reload через GroupBypassAttachmentStore",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { /* best-effort */ }
                }
            }, ct);

        public static Task<SmokeTestResult> REG_ObservedIps_Seeded_FromCandidateEndpoints(CancellationToken ct)
            => RunAsync("REG-015", "REG: observed IPv4 цели засеваются из candidate endpoints (P0.2 Stage 5.4)", () =>
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    _ = ct;

                    using var engine = new TrafficEngine(progress: null);
                    using var provider = BuildIspAuditProvider();
                    var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                    using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);

                    const string host = "example.com";

                    manager.SeedObservedIpv4TargetsFromCandidateEndpointsBestEffort(host, new[]
                    {
                        "1.2.3.4:443",
                        "5.6.7.8:80",
                        "bad",
                        "[::1]:443" // IPv6 игнорируем
                    });

                    var snap = manager.GetObservedIpv4TargetsSnapshotForHost(host);
                    if (snap.Length < 2)
                    {
                        return new SmokeTestResult("REG-015", "REG: observed IPv4 цели засеваются из candidate endpoints (P0.2 Stage 5.4)",
                            SmokeOutcome.Fail, sw.Elapsed, $"Ожидали минимум 2 IPv4 адреса, получили {snap.Length}");
                    }

                    static uint ToIpv4Int(string ip)
                    {
                        var bytes = IPAddress.Parse(ip).GetAddressBytes();
                        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
                    }

                    var expectedA = ToIpv4Int("1.2.3.4");
                    var expectedB = ToIpv4Int("5.6.7.8");

                    if (!snap.Contains(expectedA) || !snap.Contains(expectedB))
                    {
                        var observed = string.Join(", ", snap.Select(v => v.ToString()));
                        return new SmokeTestResult("REG-015", "REG: observed IPv4 цели засеваются из candidate endpoints (P0.2 Stage 5.4)",
                            SmokeOutcome.Fail, sw.Elapsed, $"IPv4 адреса не найдены в snapshot. observed=[{observed}]");
                    }

                    return new SmokeTestResult("REG-015", "REG: observed IPv4 цели засеваются из candidate endpoints (P0.2 Stage 5.4)",
                        SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-015", "REG: observed IPv4 цели засеваются из candidate endpoints (P0.2 Stage 5.4)",
                        SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_PerCardRetest_Queued_DuringRun_ThenFlushed(CancellationToken ct)
            => RunAsync("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", () =>
            {
                using var provider = BuildIspAuditProvider();
                var vm = provider.GetRequiredService<MainViewModel>();

                var test = new IspAudit.Models.TestResult
                {
                    Target = new IspAudit.Models.Target
                    {
                        Host = "127.0.0.1",
                        Name = "loopback",
                        Service = "443",
                        Critical = false
                    }
                };

                vm.Results.TestResults.Add(test);

                // Эмулируем состояние "идёт диагностика" без реального запуска pipeline.
                SetPrivateField(vm.Orchestrator, "_isDiagnosticRunning", true);

                vm.RetestFromResultCommand.Execute(test);

                var queuedStageStatusText = (test.ActionStatusText ?? string.Empty).Trim();
                var queuedStageLooksQueued = queuedStageStatusText.Contains("заплан", StringComparison.OrdinalIgnoreCase);
                var queuedStageLooksFinalized = queuedStageStatusText.Contains("ReasonCode:", StringComparison.OrdinalIgnoreCase)
                    || queuedStageStatusText.Contains("LastAction:", StringComparison.OrdinalIgnoreCase);
                if (string.IsNullOrWhiteSpace(queuedStageStatusText) || (!queuedStageLooksQueued && !queuedStageLooksFinalized))
                {
                    return new SmokeTestResult("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали статус 'запланирован' или финальный post-apply статус, получили '{test.ActionStatusText}'");
                }

                var pending = GetPrivateField<System.Collections.Generic.HashSet<string>>(vm, "_pendingManualRetestHostKeys");
                if (!pending.Contains("127.0.0.1"))
                {
                    return new SmokeTestResult("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что hostKey окажется в очереди _pendingManualRetestHostKeys");
                }

                // Завершение диагностики: очередь должна быть сброшена и ретест должен быть запущен асинхронно.
                SetPrivateField(vm.Orchestrator, "_isDiagnosticRunning", false);

                var task = (Task)InvokePrivateMethod(vm, "RunPendingManualRetestsAfterRunAsync")!;
                task.GetAwaiter().GetResult();

                pending = GetPrivateField<System.Collections.Generic.HashSet<string>>(vm, "_pendingManualRetestHostKeys");
                if (pending.Count != 0)
                {
                    return new SmokeTestResult("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", SmokeOutcome.Fail, TimeSpan.Zero,
                        "После flush ожидали, что очередь будет пустой");
                }

                var statusText = (test.ActionStatusText ?? string.Empty).Trim();
                var looksQueued = statusText.Contains("очеред", StringComparison.OrdinalIgnoreCase);
                var looksFinalized = statusText.Contains("ReasonCode:", StringComparison.OrdinalIgnoreCase)
                    || statusText.Contains("LastAction:", StringComparison.OrdinalIgnoreCase);
                if (string.IsNullOrWhiteSpace(statusText) || (!looksQueued && !looksFinalized))
                {
                    return new SmokeTestResult("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали статус с 'очередь' или финальный post-apply статус, получили '{test.ActionStatusText}'");
                }

                return new SmokeTestResult("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
            }, ct);

        public static Task<SmokeTestResult> REG_QuicFallback_Selective_MultiTarget_DoesNotForgetPrevious(CancellationToken ct)
            => RunAsyncAwait("REG-005", "REG: QUIC fallback (селективно) поддерживает несколько активных целей", async _ =>
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    var baseProfile = BypassProfile.CreateDefault();

                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var tls = new TlsBypassService(
                        engine,
                        baseProfile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: () => DateTime.UtcNow);

                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(tls, baseProfile, autoHostlist);

                    // Включаем QUIC→TCP (DROP UDP/443) в селективном режиме.
                    bypass.IsQuicFallbackEnabled = true;
                    bypass.IsQuicFallbackGlobal = false;

                    // Используем IPv4-строки как "host": Dns.GetHostAddressesAsync на них возвращает тот же IP.
                    bypass.SetOutcomeTargetHost("1.1.1.1");
                    await bypass.ApplyBypassOptionsAsync(ct).ConfigureAwait(false);

                    var manager = GetPrivateField<IspAudit.Bypass.BypassStateManager>(bypass, "_stateManager");
                    var count1 = manager.GetUdp443DropTargetIpCountSnapshot();
                    if (count1 < 1)
                    {
                        return new SmokeTestResult("REG-005", "REG: QUIC fallback (селективно) поддерживает несколько активных целей", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали targets>=1 после первой цели, получили {count1}");
                    }

                    bypass.SetOutcomeTargetHost("2.2.2.2");
                    await bypass.ApplyBypassOptionsAsync(ct).ConfigureAwait(false);

                    var count2 = manager.GetUdp443DropTargetIpCountSnapshot();
                    if (count2 < 2)
                    {
                        return new SmokeTestResult("REG-005", "REG: QUIC fallback (селективно) поддерживает несколько активных целей", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали union targets>=2 после второй цели (мульти-цель), получили {count2}");
                    }

                    return new SmokeTestResult("REG-005", "REG: QUIC fallback (селективно) поддерживает несколько активных целей", SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-005", "REG: QUIC fallback (селективно) поддерживает несколько активных целей", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_Tcp443TlsStrategy_PerTarget_MultiGroup(CancellationToken ct)
            => RunAsyncAwait("REG-006", "REG: TCP/443 TLS стратегия выбирается per-target (multi-group)", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevGate = null;
                try
                {
                    prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", "1");

                    var baseProfile = BypassProfile.CreateDefault();

                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var tls = new TlsBypassService(
                        engine,
                        baseProfile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: () => DateTime.UtcNow);

                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(tls, baseProfile, autoHostlist);

                    // 1) Цель A: Fragment
                    var planA = new IspAudit.Core.Intelligence.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.Intelligence.Contracts.StrategyId.TlsFragment
                            }
                        }
                    };

                    // 2) Цель B: Disorder
                    var planB = new IspAudit.Core.Intelligence.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.Intelligence.Contracts.StrategyId.TlsDisorder
                            }
                        }
                    };

                    await bypass.ApplyIntelPlanAsync(planA, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);
                    await bypass.ApplyIntelPlanAsync(planB, outcomeTargetHost: "2.2.2.2", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);

                    var manager = GetPrivateField<IspAudit.Bypass.BypassStateManager>(bypass, "_stateManager");
                    var tlsService = GetPrivateField<IspAudit.Bypass.TlsBypassService>(manager, "_tlsService");
                    var snapshot = GetPrivateField<IspAudit.Core.Models.DecisionGraphSnapshot?>(tlsService, "_decisionGraphSnapshot");

                    if (snapshot == null)
                    {
                        return new SmokeTestResult("REG-006", "REG: TCP/443 TLS стратегия выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            "Ожидали DecisionGraphSnapshot != null (gate TCP443=1), получили null");
                    }

                    static uint ToIpv4Int(string ipText)
                    {
                        var ip = IPAddress.Parse(ipText);
                        var bytes = ip.GetAddressBytes();
                        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
                    }

                    var ipA = ToIpv4Int("1.1.1.1");
                    var ipB = ToIpv4Int("2.2.2.2");

                    var selA = snapshot.EvaluateTcp443TlsClientHello(ipA, isIpv4: true, isIpv6: false, tlsStage: IspAudit.Core.Models.TlsStage.ClientHello);
                    var selB = snapshot.EvaluateTcp443TlsClientHello(ipB, isIpv4: true, isIpv6: false, tlsStage: IspAudit.Core.Models.TlsStage.ClientHello);

                    if (selA == null || selB == null)
                    {
                        return new SmokeTestResult("REG-006", "REG: TCP/443 TLS стратегия выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали, что обе цели смэтчатся (selA={(selA == null ? "null" : selA.Id)}; selB={(selB == null ? "null" : selB.Id)})");
                    }

                    string? rawA = null;
                    selA.Action.Parameters.TryGetValue(IspAudit.Core.Models.PolicyAction.ParameterKeyTlsStrategy, out rawA);
                    string? rawB = null;
                    selB.Action.Parameters.TryGetValue(IspAudit.Core.Models.PolicyAction.ParameterKeyTlsStrategy, out rawB);

                    if (!string.Equals(rawA, nameof(TlsBypassStrategy.Fragment), StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-006", "REG: TCP/443 TLS стратегия выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали strategy=Fragment для 1.1.1.1, получили '{rawA ?? "(null)"}' (policy={selA.Id})");
                    }

                    if (!string.Equals(rawB, nameof(TlsBypassStrategy.Disorder), StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-006", "REG: TCP/443 TLS стратегия выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали strategy=Disorder для 2.2.2.2, получили '{rawB ?? "(null)"}' (policy={selB.Id})");
                    }

                    return new SmokeTestResult("REG-006", "REG: TCP/443 TLS стратегия выбирается per-target (multi-group)", SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-006", "REG: TCP/443 TLS стратегия выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_Tcp80HttpHostTricks_PerTarget_MultiGroup(CancellationToken ct)
            => RunAsyncAwait("REG-007", "REG: TCP/80 HTTP Host tricks выбирается per-target (multi-group)", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevGate = null;
                try
                {
                    prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80", "1");

                    var baseProfile = BypassProfile.CreateDefault();

                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var tls = new TlsBypassService(
                        engine,
                        baseProfile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: () => DateTime.UtcNow);

                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(tls, baseProfile, autoHostlist);

                    static IspAudit.Core.Intelligence.Contracts.BypassPlan CreateHostTricksPlan()
                        => new()
                        {
                            ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.SilentDrop,
                            PlanConfidence = 100,
                            Strategies =
                            {
                                new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                                {
                                    Id = IspAudit.Core.Intelligence.Contracts.StrategyId.HttpHostTricks
                                }
                            }
                        };

                    // Важно: используем IPv4-строки как "host": Dns.GetHostAddressesAsync на них возвращает тот же IP.
                    await bypass.ApplyIntelPlanAsync(CreateHostTricksPlan(), outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);
                    await bypass.ApplyIntelPlanAsync(CreateHostTricksPlan(), outcomeTargetHost: "2.2.2.2", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);

                    var manager = GetPrivateField<IspAudit.Bypass.BypassStateManager>(bypass, "_stateManager");
                    var tlsService = GetPrivateField<IspAudit.Bypass.TlsBypassService>(manager, "_tlsService");
                    var snapshot = GetPrivateField<IspAudit.Core.Models.DecisionGraphSnapshot?>(tlsService, "_decisionGraphSnapshot");

                    if (snapshot == null)
                    {
                        return new SmokeTestResult("REG-007", "REG: TCP/80 HTTP Host tricks выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            "Ожидали DecisionGraphSnapshot != null (gate TCP80=1), получили null");
                    }

                    static uint ToIpv4Int(string ipText)
                    {
                        var ip = IPAddress.Parse(ipText);
                        var bytes = ip.GetAddressBytes();
                        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
                    }

                    static IspAudit.Core.Models.FlowPolicy? EvaluateTcp80HostTricks(IspAudit.Core.Models.DecisionGraphSnapshot snapshot, uint dstIpv4Int)
                    {
                        foreach (var policy in snapshot.GetCandidates(IspAudit.Core.Models.FlowTransportProtocol.Tcp, 80, tlsStage: null))
                        {
                            if (policy.Action.Kind != IspAudit.Core.Models.PolicyActionKind.Strategy) continue;
                            if (!string.Equals(policy.Action.StrategyId, IspAudit.Core.Models.PolicyAction.StrategyIdHttpHostTricks, StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            if (!policy.Match.MatchesTcpPacket(dstIpv4Int, isIpv4: true, isIpv6: false))
                            {
                                continue;
                            }

                            return policy;
                        }

                        return null;
                    }

                    var ipA = ToIpv4Int("1.1.1.1");
                    var ipB = ToIpv4Int("2.2.2.2");

                    var selA = EvaluateTcp80HostTricks(snapshot, ipA);
                    var selB = EvaluateTcp80HostTricks(snapshot, ipB);

                    if (selA == null || selB == null)
                    {
                        return new SmokeTestResult("REG-007", "REG: TCP/80 HTTP Host tricks выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали, что обе цели смэтчатся (selA={(selA == null ? "null" : selA.Id)}; selB={(selB == null ? "null" : selB.Id)})");
                    }

                    if (!selA.Id.Contains("1_1_1_1", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-007", "REG: TCP/80 HTTP Host tricks выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали per-target policy для 1.1.1.1, получили policy={selA.Id}");
                    }

                    if (!selB.Id.Contains("2_2_2_2", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("REG-007", "REG: TCP/80 HTTP Host tricks выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали per-target policy для 2.2.2.2, получили policy={selB.Id}");
                    }

                    return new SmokeTestResult("REG-007", "REG: TCP/80 HTTP Host tricks выбирается per-target (multi-group)", SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-007", "REG: TCP/80 HTTP Host tricks выбирается per-target (multi-group)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP80", prevGate);
                }
            }, ct);

        public static Task<SmokeTestResult> REG_CapabilitiesUnion_TlsFragmentAndDisorder_StayEnabled(CancellationToken ct)
            => RunAsyncAwait("REG-008", "REG: capabilities union (TLS): Fragment+Disorder не выключаются при multi-target apply", async _ =>
            {
                var sw = Stopwatch.StartNew();
                string? prevGate = null;
                try
                {
                    // Не обязательно для union, но включаем policy-driven TCP/443, чтобы сценарий соответствовал Step 1.
                    prevGate = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443");
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", "1");

                    var baseProfile = BypassProfile.CreateDefault();

                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    using var tls = new TlsBypassService(
                        engine,
                        baseProfile,
                        log: null,
                        startMetricsTimer: false,
                        useTrafficEngine: false,
                        nowProvider: () => DateTime.UtcNow);

                    using var provider = BuildIspAuditProvider();
                    var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                    var bypass = new BypassController(tls, baseProfile, autoHostlist);

                    var planFragment = new IspAudit.Core.Intelligence.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.Intelligence.Contracts.StrategyId.TlsFragment
                            }
                        }
                    };

                    var planDisorder = new IspAudit.Core.Intelligence.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.Intelligence.Contracts.StrategyId.TlsDisorder
                            }
                        }
                    };

                    // 1) Применяем Fragment к цели A
                    await bypass.ApplyIntelPlanAsync(planFragment, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);

                    // 2) Применяем Disorder к цели B — важно, чтобы Fragment не «выключился» в effective options
                    await bypass.ApplyIntelPlanAsync(planDisorder, outcomeTargetHost: "2.2.2.2", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);

                    var manager = GetPrivateField<IspAudit.Bypass.BypassStateManager>(bypass, "_stateManager");
                    var options = manager.GetOptionsSnapshot();

                    if (!options.FragmentEnabled || !options.DisorderEnabled)
                    {
                        return new SmokeTestResult("REG-008", "REG: capabilities union (TLS): Fragment+Disorder не выключаются при multi-target apply", SmokeOutcome.Fail, sw.Elapsed,
                            $"Ожидали FragmentEnabled=true и DisorderEnabled=true после двух apply; получили FragmentEnabled={options.FragmentEnabled}, DisorderEnabled={options.DisorderEnabled}");
                    }

                    return new SmokeTestResult("REG-008", "REG: capabilities union (TLS): Fragment+Disorder не выключаются при multi-target apply", SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("REG-008", "REG: capabilities union (TLS): Fragment+Disorder не выключаются при multi-target apply", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_TCP443", prevGate);
                }
            }, ct);
    }
}
