using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
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
                    var planA = new IspAudit.Core.IntelligenceV2.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.IntelligenceV2.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.IntelligenceV2.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.IntelligenceV2.Contracts.StrategyId.TlsFragment
                            }
                        }
                    };

                    // 2) Цель B: Disorder
                    var planB = new IspAudit.Core.IntelligenceV2.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.IntelligenceV2.Contracts.DiagnosisId.SilentDrop,
                        PlanConfidence = 100,
                        Strategies =
                        {
                            new IspAudit.Core.IntelligenceV2.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.IntelligenceV2.Contracts.StrategyId.TlsDisorder
                            }
                        }
                    };

                    await bypass.ApplyV2PlanAsync(planA, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);
                    await bypass.ApplyV2PlanAsync(planB, outcomeTargetHost: "2.2.2.2", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);

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

                    static IspAudit.Core.IntelligenceV2.Contracts.BypassPlan CreateHostTricksPlan()
                        => new()
                        {
                            ForDiagnosis = IspAudit.Core.IntelligenceV2.Contracts.DiagnosisId.SilentDrop,
                            PlanConfidence = 100,
                            Strategies =
                            {
                                new IspAudit.Core.IntelligenceV2.Contracts.BypassStrategy
                                {
                                    Id = IspAudit.Core.IntelligenceV2.Contracts.StrategyId.HttpHostTricks
                                }
                            }
                        };

                    // Важно: используем IPv4-строки как "host": Dns.GetHostAddressesAsync на них возвращает тот же IP.
                    await bypass.ApplyV2PlanAsync(CreateHostTricksPlan(), outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);
                    await bypass.ApplyV2PlanAsync(CreateHostTricksPlan(), outcomeTargetHost: "2.2.2.2", timeout: TimeSpan.FromSeconds(2), cancellationToken: ct).ConfigureAwait(false);

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
    }
}
