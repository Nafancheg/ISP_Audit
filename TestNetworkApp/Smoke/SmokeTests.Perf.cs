using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.ViewModels;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;
using IspAudit.Utils;
using System.Collections.Immutable;
using Microsoft.Extensions.DependencyInjection;

using TransportProtocol = IspAudit.Bypass.TransportProtocol;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        private sealed class FastSyntheticHostTester : IHostTester
        {
            private readonly Func<HostDiscovered, HostTested> _factory;

            public FastSyntheticHostTester(Func<HostDiscovered, HostTested> factory)
            {
                _factory = factory;
            }

            public Task<HostTested> TestHostAsync(HostDiscovered host, CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                return Task.FromResult(_factory(host));
            }
        }

        public static async Task<SmokeTestResult> PERF_Load_500Hosts_HealthLogAndNoBacklog(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var lines = new ConcurrentQueue<string>();
                var progress = new Progress<string>(msg =>
                {
                    if (!string.IsNullOrWhiteSpace(msg))
                    {
                        lines.Enqueue(msg);
                    }
                });

                var tester = new FastSyntheticHostTester(host => new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: false,
                    TlsOk: false,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: host.Hostname,
                    SniHostname: host.SniHostname,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: null,
                    BlockageType: BlockageCode.TcpConnectTimeout,
                    TestedAt: DateTime.UtcNow));

                var config = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false,
                    MaxConcurrentTests = 10,
                    TestTimeout = TimeSpan.FromSeconds(1)
                };

                using var provider = BuildIspAuditProvider();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                using var pipeline = pipelineFactory.Create(
                    config,
                    filter: trafficFilter,
                    progress: progress,
                    trafficEngine: null,
                    dnsParser: null,
                    stateStore: null,
                    autoHostlist: null,
                    testerOverride: tester);

                var enqueueSw = Stopwatch.StartNew();
                var maxPending = 0;

                // Симулируем 500 "соединений" быстро.
                for (var i = 0; i < 500; i++)
                {
                    ct.ThrowIfCancellationRequested();

                    var ip = IPAddress.Parse($"10.0.0.{(i % 250) + 1}");
                    var host = new HostDiscovered(
                        Key: $"{ip}:443:TCP:{i}",
                        RemoteIp: ip,
                        RemotePort: 443,
                        Protocol: TransportProtocol.Tcp,
                        DiscoveredAt: DateTime.UtcNow)
                    {
                        Hostname = $"load-{i}.example"
                    };

                    await pipeline.EnqueueHostAsync(host).ConfigureAwait(false);

                    var pending = pipeline.PendingCount;
                    if (pending > maxPending) maxPending = pending;
                }

                enqueueSw.Stop();

                // Ждём завершения обработки.
                var completed = await pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
                if (!completed)
                {
                    return new SmokeTestResult("PERF-001", "PERF: обработка множества соединений (>100/сек)", SmokeOutcome.Fail, sw.Elapsed,
                        $"Таймаут DrainAndCompleteAsync, pending={pipeline.PendingCount}, maxPending={maxPending}");
                }

                // Даём health-loop шанс написать хотя бы один лог.
                await Task.Delay(TimeSpan.FromSeconds(11), ct).ConfigureAwait(false);

                var health = lines.Any(x => x.Contains("[PipelineHealth]", StringComparison.Ordinal));
                if (!health)
                {
                    return new SmokeTestResult("PERF-001", "PERF: обработка множества соединений (>100/сек)", SmokeOutcome.Fail, sw.Elapsed,
                        "Не найден [PipelineHealth] лог (ожидали хотя бы один тик health-loop)");
                }

                return new SmokeTestResult("PERF-001", "PERF: обработка множества соединений (>100/сек)", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: enqueue={enqueueSw.ElapsedMilliseconds}ms, maxPending={maxPending}");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PERF-001", "PERF: обработка множества соединений (>100/сек)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> PERF_Memory_NoLinearGrowth_ShortRun(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var progress = new Progress<string>(_ => { });

                var tester = new FastSyntheticHostTester(host => new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: true,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: host.Hostname,
                    SniHostname: host.SniHostname,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 1,
                    BlockageType: null,
                    TestedAt: DateTime.UtcNow));

                var config = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false,
                    MaxConcurrentTests = 10,
                    TestTimeout = TimeSpan.FromSeconds(1)
                };

                using var provider = BuildIspAuditProvider();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();

                // Прогрев
                using (var warm = pipelineFactory.Create(
                    config,
                    filter: trafficFilter,
                    progress: progress,
                    trafficEngine: null,
                    dnsParser: null,
                    stateStore: null,
                    autoHostlist: null,
                    testerOverride: tester))
                {
                    for (var i = 0; i < 50; i++)
                    {
                        var ip = IPAddress.Parse($"10.10.0.{(i % 250) + 1}");
                        await warm.EnqueueHostAsync(new HostDiscovered($"{ip}:443:TCP:warm:{i}", ip, 443, TransportProtocol.Tcp, DateTime.UtcNow)).ConfigureAwait(false);
                    }

                    await warm.DrainAndCompleteAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                }

                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                var baseline = GC.GetTotalMemory(forceFullCollection: true);

                using (var pipeline = pipelineFactory.Create(
                    config,
                    filter: trafficFilter,
                    progress: progress,
                    trafficEngine: null,
                    dnsParser: null,
                    stateStore: null,
                    autoHostlist: null,
                    testerOverride: tester))
                {
                    var endAt = DateTime.UtcNow + TimeSpan.FromSeconds(20);
                    var i = 0;
                    while (DateTime.UtcNow < endAt)
                    {
                        ct.ThrowIfCancellationRequested();

                        var ip = IPAddress.Parse($"10.20.0.{(i % 250) + 1}");
                        var host = new HostDiscovered($"{ip}:443:TCP:mem:{i}", ip, 443, TransportProtocol.Tcp, DateTime.UtcNow)
                        {
                            Hostname = $"mem-{i}.example"
                        };

                        await pipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                        i++;

                        await Task.Delay(20, ct).ConfigureAwait(false);
                    }

                    await pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                }

                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                var after = GC.GetTotalMemory(forceFullCollection: true);
                var deltaMb = (after - baseline) / (1024.0 * 1024.0);

                // Это укороченный surrogate для PERF-002 (1+ час). Ставим мягкий порог.
                if (deltaMb > 80)
                {
                    return new SmokeTestResult("PERF-002", "PERF: отсутствие линейного роста памяти (surrogate)", SmokeOutcome.Fail, sw.Elapsed,
                        $"Подозрение на рост памяти: +{deltaMb:F1} MB (baseline={baseline}, after={after})");
                }

                return new SmokeTestResult("PERF-002", "PERF: отсутствие линейного роста памяти (surrogate)", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: +{deltaMb:F1} MB");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PERF-002", "PERF: отсутствие линейного роста памяти (surrogate)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> PERF_Store_ThreadSafety_InMemoryBlockageStateStore(CancellationToken ct)
            => RunAsync("PERF-003", "PERF: thread-safety InMemoryBlockageStateStore", () =>
            {
                var store = new InMemoryBlockageStateStore();
                var errors = new ConcurrentQueue<Exception>();

                var tasks = Enumerable.Range(0, 20).Select(worker => Task.Run(() =>
                {
                    try
                    {
                        for (var i = 0; i < 200; i++)
                        {
                            var ip = IPAddress.Parse($"192.0.2.{(i % 250) + 1}");
                            var host = new HostDiscovered($"{ip}:443:TCP:{worker}:{i}", ip, 443, TransportProtocol.Tcp, DateTime.UtcNow)
                            {
                                Hostname = $"ts-{worker}-{i}.example"
                            };

                            store.TryBeginHostTest(host, host.Hostname);

                            var tested = new HostTested(
                                Host: host,
                                DnsOk: true,
                                TcpOk: false,
                                TlsOk: false,
                                DnsStatus: BlockageCode.StatusOk,
                                Hostname: host.Hostname,
                                SniHostname: null,
                                ReverseDnsHostname: null,
                                TcpLatencyMs: null,
                                BlockageType: BlockageCode.TcpConnectTimeout,
                                TestedAt: DateTime.UtcNow);

                            store.RegisterResult(tested);
                            _ = store.GetSignals(tested, TimeSpan.FromSeconds(60));
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Enqueue(ex);
                    }
                }, ct)).ToArray();

                Task.WaitAll(tasks);

                if (!errors.IsEmpty)
                {
                    var first = errors.TryDequeue(out var ex) ? ex : null;
                    return new SmokeTestResult("PERF-003", "PERF: thread-safety InMemoryBlockageStateStore", SmokeOutcome.Fail, TimeSpan.Zero,
                        first?.Message ?? "Исключение в параллельном доступе");
                }

                return new SmokeTestResult("PERF-003", "PERF: thread-safety InMemoryBlockageStateStore", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
            }, ct);

        public static Task<SmokeTestResult> PERF_DecisionGraph_Evaluate_100_500_1000(CancellationToken ct)
            => RunAsync("PERF-004", "PERF: DecisionGraphSnapshot.Evaluate() при 100/500/1000 политиках", () =>
            {
                try
                {
                    static long Measure(int policyCount, int iterations)
                    {
                        // Худший кейс: каждая Evaluate должна пройти почти весь список кандидатов.
                        // Для этого создаём N-1 политик с DstIpv4Set=empty (никогда не мэтчатся)
                        // и одну (последнюю) с DstIpv4Set=null (мэтчится всегда).
                        var policies = new List<FlowPolicy>(policyCount);

                        for (var i = 0; i < policyCount; i++)
                        {
                            var neverMatches = i < policyCount - 1;
                            policies.Add(new FlowPolicy
                            {
                                Id = $"perf_tcp443_{policyCount}_{i}",
                                Priority = policyCount - i,
                                Scope = PolicyScope.Global,
                                Match = new MatchCondition
                                {
                                    Proto = FlowTransportProtocol.Tcp,
                                    Port = 443,
                                    TlsStage = TlsStage.ClientHello,
                                    DstIpv4Set = neverMatches ? ImmutableHashSet<uint>.Empty : null
                                },
                                Action = PolicyAction.Pass
                            });
                        }

                        var snapshot = PolicySetCompiler.CompileOrThrow(policies);

                        var sw = Stopwatch.StartNew();
                        FlowPolicy? last = null;
                        for (var i = 0; i < iterations; i++)
                        {
                            last = snapshot.EvaluateTcp443TlsClientHello(dstIpv4Int: 0x01020304, isIpv4: true, isIpv6: false, tlsStage: TlsStage.ClientHello);
                        }

                        sw.Stop();
                        if (last == null)
                        {
                            throw new InvalidOperationException("Evaluate вернул null (ожидали хотя бы одну совпадающую политику)");
                        }

                        return sw.ElapsedMilliseconds;
                    }

                    ct.ThrowIfCancellationRequested();

                    // Нормируем количество проверок: iterations * policyCount ~= 2_000_000.
                    var ms100 = Measure(100, iterations: 20_000);
                    ct.ThrowIfCancellationRequested();
                    var ms500 = Measure(500, iterations: 4_000);
                    ct.ThrowIfCancellationRequested();
                    var ms1000 = Measure(1000, iterations: 2_000);

                    // Мягкий порог: чтобы ловить регрессии, но не флапать на медленных машинах.
                    // Ожидаемо это должно укладываться в < 4-5с суммарно на dev-ноутбуке.
                    var total = ms100 + ms500 + ms1000;
                    if (total > 5500)
                    {
                        return new SmokeTestResult("PERF-004", "PERF: DecisionGraphSnapshot.Evaluate() при 100/500/1000 политиках", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Слишком медленно: 100={ms100}ms; 500={ms500}ms; 1000={ms1000}ms; total={total}ms");
                    }

                    return new SmokeTestResult("PERF-004", "PERF: DecisionGraphSnapshot.Evaluate() при 100/500/1000 политиках", SmokeOutcome.Pass, TimeSpan.Zero,
                        $"OK: 100={ms100}ms; 500={ms500}ms; 1000={ms1000}ms; total={total}ms");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("PERF-004", "PERF: DecisionGraphSnapshot.Evaluate() при 100/500/1000 политиках", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> PERF_ProcessPacketForSmoke_10k_LatencyStats(CancellationToken ct)
            => RunAsync("PERF-006", "PERF: ProcessPacketForSmoke 10K packets (p50/p95/p99)", () =>
            {
                // Важно: тест не зависит от WinDivert (не стартуем драйвер). Это чистый hot-path smoke.
                using var engine = new TrafficEngine(progress: null);

                var packetBytes = BuildIpv4TcpPacket(
                    srcIp: IPAddress.Parse("192.0.2.10"),
                    dstIp: IPAddress.Parse("93.184.216.34"),
                    srcPort: 12345,
                    dstPort: 443,
                    ttl: 64,
                    ipId: 1,
                    seq: 1,
                    tcpFlags: 0x02);

                var packet = new InterceptedPacket(packetBytes, packetBytes.Length);
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                // Прогрев JIT/кэшей.
                for (var i = 0; i < 2000; i++)
                {
                    _ = engine.ProcessPacketForSmoke(packet, ctx);
                }

                const int n = 10_000;
                var ticks = new long[n];
                var freq = (double)Stopwatch.Frequency;

                for (var i = 0; i < n; i++)
                {
                    ct.ThrowIfCancellationRequested();

                    var start = Stopwatch.GetTimestamp();
                    _ = engine.ProcessPacketForSmoke(packet, ctx);
                    var end = Stopwatch.GetTimestamp();
                    ticks[i] = end - start;
                }

                Array.Sort(ticks);

                static long Percentile(long[] sorted, double p)
                {
                    if (sorted.Length == 0) return 0;
                    var idx = (int)Math.Round((sorted.Length - 1) * p, MidpointRounding.AwayFromZero);
                    idx = Math.Clamp(idx, 0, sorted.Length - 1);
                    return sorted[idx];
                }

                var p50 = Percentile(ticks, 0.50);
                var p95 = Percentile(ticks, 0.95);
                var p99 = Percentile(ticks, 0.99);
                var max = ticks[^1];

                var p50Us = p50 * 1_000_000.0 / freq;
                var p95Us = p95 * 1_000_000.0 / freq;
                var p99Us = p99 * 1_000_000.0 / freq;
                var maxUs = max * 1_000_000.0 / freq;

                // Мягкий порог на явную деградацию (не должен флапать на разных машинах).
                if (p99Us > 10_000)
                {
                    return new SmokeTestResult("PERF-006", "PERF: ProcessPacketForSmoke 10K packets (p50/p95/p99)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Слишком медленно: p99={p99Us:F1}us (ожидали <= 10000us). p50={p50Us:F1}us, p95={p95Us:F1}us, max={maxUs:F1}us");
                }

                return new SmokeTestResult("PERF-006", "PERF: ProcessPacketForSmoke 10K packets (p50/p95/p99)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: n={n}; p50={p50Us:F1}us; p95={p95Us:F1}us; p99={p99Us:F1}us; max={maxUs:F1}us");
            }, ct);

        public static Task<SmokeTestResult> PERF_ApplyDisable_10x_P95_Under3s(CancellationToken ct)
            => RunAsyncAwait("PERF-005", "PERF: 10 Apply/Disable, p95 < 3s", async innerCt =>
            {
                var sw = Stopwatch.StartNew();

                // Снимаем/восстанавливаем env, чтобы тест был изолированным и детерминированным.
                var prevDelay = Environment.GetEnvironmentVariable(EnvKeys.TestApplyDelayMs);
                var prevSkipTls = Environment.GetEnvironmentVariable(EnvKeys.TestSkipTlsApply);
                var prevApplyTxPath = Environment.GetEnvironmentVariable(EnvKeys.ApplyTransactionsPath);
                var prevSessionPath = Environment.GetEnvironmentVariable(EnvKeys.BypassSessionPath);

                var tempApplyTxPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"isp_audit_perf_applytx_{Guid.NewGuid():N}.json");
                var tempSessionPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"isp_audit_perf_session_{Guid.NewGuid():N}.json");

                try
                {
                    // В PERF не должно быть искусственных задержек/скипов.
                    Environment.SetEnvironmentVariable(EnvKeys.TestApplyDelayMs, null);
                    Environment.SetEnvironmentVariable(EnvKeys.TestSkipTlsApply, null);

                    // Не трогаем реальный state пользователя.
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, tempApplyTxPath);
                    Environment.SetEnvironmentVariable(EnvKeys.BypassSessionPath, tempSessionPath);

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

                    // Прогрев (JIT + файловые пути). В замеры не включаем.
                    await bypass.ApplyIntelPlanAsync(plan, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(3), cancellationToken: innerCt)
                        .ConfigureAwait(false);
                    await bypass.DisableAllAsync(innerCt).ConfigureAwait(false);

                    var samplesMs = new List<long>(capacity: 10);

                    for (var i = 0; i < 10; i++)
                    {
                        innerCt.ThrowIfCancellationRequested();

                        var iterSw = Stopwatch.StartNew();
                        await bypass.ApplyIntelPlanAsync(plan, outcomeTargetHost: "1.1.1.1", timeout: TimeSpan.FromSeconds(3), cancellationToken: innerCt)
                            .ConfigureAwait(false);
                        await bypass.DisableAllAsync(innerCt).ConfigureAwait(false);
                        iterSw.Stop();

                        samplesMs.Add(iterSw.ElapsedMilliseconds);
                    }

                    // Постусловие: всё выключено.
                    var after = tls.GetOptionsSnapshot();
                    if (after.IsAnyEnabled())
                    {
                        return new SmokeTestResult("PERF-005", "PERF: 10 Apply/Disable, p95 < 3s", SmokeOutcome.Fail, sw.Elapsed,
                            $"После DisableAllAsync bypass всё ещё включён: {after.ToReadableStrategy()}");
                    }

                    samplesMs.Sort();
                    var p95Index = (int)Math.Ceiling(samplesMs.Count * 0.95) - 1;
                    if (p95Index < 0) p95Index = 0;
                    if (p95Index >= samplesMs.Count) p95Index = samplesMs.Count - 1;
                    var p95 = samplesMs[p95Index];
                    var p50 = samplesMs[samplesMs.Count / 2];
                    var max = samplesMs[^1];

                    if (p95 >= 3000)
                    {
                        return new SmokeTestResult("PERF-005", "PERF: 10 Apply/Disable, p95 < 3s", SmokeOutcome.Fail, sw.Elapsed,
                            $"Порог нарушен: p50={p50}ms, p95={p95}ms, max={max}ms; samples=[{string.Join(",", samplesMs)}]");
                    }

                    return new SmokeTestResult("PERF-005", "PERF: 10 Apply/Disable, p95 < 3s", SmokeOutcome.Pass, sw.Elapsed,
                        $"OK: p50={p50}ms, p95={p95}ms, max={max}ms; samples=[{string.Join(",", samplesMs)}]");
                }
                finally
                {
                    Environment.SetEnvironmentVariable(EnvKeys.TestApplyDelayMs, prevDelay);
                    Environment.SetEnvironmentVariable(EnvKeys.TestSkipTlsApply, prevSkipTls);
                    Environment.SetEnvironmentVariable(EnvKeys.ApplyTransactionsPath, prevApplyTxPath);
                    Environment.SetEnvironmentVariable(EnvKeys.BypassSessionPath, prevSessionPath);

                    try { if (System.IO.File.Exists(tempApplyTxPath)) System.IO.File.Delete(tempApplyTxPath); } catch { /* best-effort */ }
                    try { if (System.IO.File.Exists(tempSessionPath)) System.IO.File.Delete(tempSessionPath); } catch { /* best-effort */ }
                }
            }, ct);
    }
}
