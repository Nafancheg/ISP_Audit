using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Utils;
using IspAudit.ViewModels;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
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

                var outputTask = p.StandardOutput.ReadToEndAsync();
                var errTask = p.StandardError.ReadToEndAsync();

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
                    var bypass = new BypassController(engine);

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
                    var bypass1 = new BypassController(engine);

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
                    var bypass2 = new BypassController(engine);

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
                    var bypass = new BypassController(engine);

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
                    var bypass = new BypassController(engine);

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
                    var bypass = new BypassController(engine);

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

                    var bypass = new BypassController(tls, baseProfile);

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

                    var bypass = new BypassController(tls, baseProfile);

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
                        await Task.Delay(25).ConfigureAwait(false);
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
                    using var manager = BypassStateManager.GetOrCreate(engine, baseProfile: null, log: null);

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
                var vm = new MainViewModel();

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

                if (string.IsNullOrWhiteSpace(test.ActionStatusText) || !test.ActionStatusText.Contains("заплан", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали статус 'запланирован', получили '{test.ActionStatusText}'");
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

                if (string.IsNullOrWhiteSpace(test.ActionStatusText) || !test.ActionStatusText.Contains("очеред", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("REG-004", "REG: per-card ретест ставится в очередь во время диагностики", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали статус с 'очередь', получили '{test.ActionStatusText}'");
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

                    var bypass = new BypassController(tls, baseProfile);

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

                    var bypass = new BypassController(tls, baseProfile);

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

                    var bypass = new BypassController(tls, baseProfile);

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

                    var bypass = new BypassController(tls, baseProfile);

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
