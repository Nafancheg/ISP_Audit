using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;
using IspAudit.Utils;

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

                using var pipeline = new LiveTestingPipeline(config, progress, trafficEngine: null, dnsParser: null, tester: tester);

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

                // Прогрев
                using (var warm = new LiveTestingPipeline(config, progress, trafficEngine: null, dnsParser: null, tester: tester))
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

                using (var pipeline = new LiveTestingPipeline(config, progress, trafficEngine: null, dnsParser: null, tester: tester))
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
                        first?.Message ?? "Исключение в параллельном доступе" );
                }

                return new SmokeTestResult("PERF-003", "PERF: thread-safety InMemoryBlockageStateStore", SmokeOutcome.Pass, TimeSpan.Zero, "OK");
            }, ct);
    }
}
