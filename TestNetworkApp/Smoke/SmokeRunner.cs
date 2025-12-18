using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Utils;

using BypassTransportProtocol = IspAudit.Bypass.TransportProtocol;

namespace TestNetworkApp.Smoke
{
    internal enum SmokeOutcome
    {
        Pass,
        Fail,
        Skip
    }

    internal sealed record SmokeTestResult(
        string Id,
        string Name,
        SmokeOutcome Outcome,
        TimeSpan Duration,
        string? Details = null);

    internal sealed class SmokeRunner
    {
        private readonly List<Func<CancellationToken, Task<SmokeTestResult>>> _tests = new();

        public SmokeRunner Add(Func<CancellationToken, Task<SmokeTestResult>> test)
        {
            _tests.Add(test);
            return this;
        }

        public async Task<int> RunAsync(CancellationToken ct)
        {
            var results = new List<SmokeTestResult>();

            Console.WriteLine("=== ISP_Audit Smoke Runner ===");
            Console.WriteLine($"Время: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"PID: {Environment.ProcessId}");
            Console.WriteLine($"Admin: {(TrafficEngine.HasAdministratorRights ? "да" : "нет")}");
            Console.WriteLine();

            foreach (var test in _tests)
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                SmokeTestResult r;
                try
                {
                    r = await test(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    r = new SmokeTestResult("SMOKE-CANCEL", "Отмена", SmokeOutcome.Skip, TimeSpan.Zero, "Отменено токеном");
                }
                catch (Exception ex)
                {
                    r = new SmokeTestResult("SMOKE-EX", "Непойманное исключение", SmokeOutcome.Fail, TimeSpan.Zero, ex.ToString());
                }

                results.Add(r);

                var status = r.Outcome switch
                {
                    SmokeOutcome.Pass => "PASS",
                    SmokeOutcome.Fail => "FAIL",
                    SmokeOutcome.Skip => "SKIP",
                    _ => r.Outcome.ToString().ToUpperInvariant()
                };

                Console.WriteLine($"[{status}] {r.Id} {r.Name} ({r.Duration.TotalMilliseconds:F0}ms)");
                if (!string.IsNullOrWhiteSpace(r.Details))
                {
                    Console.WriteLine($"  {r.Details}");
                }
            }

            var pass = results.Count(x => x.Outcome == SmokeOutcome.Pass);
            var fail = results.Count(x => x.Outcome == SmokeOutcome.Fail);
            var skip = results.Count(x => x.Outcome == SmokeOutcome.Skip);

            Console.WriteLine();
            Console.WriteLine("--- Итоги ---");
            Console.WriteLine($"PASS: {pass}");
            Console.WriteLine($"FAIL: {fail}");
            Console.WriteLine($"SKIP: {skip}");

            return fail == 0 ? 0 : 1;
        }

        public static SmokeRunner Build(string category)
        {
            var runner = new SmokeRunner();

            var cat = (category ?? "all").Trim().ToLowerInvariant();
            bool all = cat == "all";

            if (all || cat == "infra")
            {
                runner
                    .Add(SmokeTests.Infra_EncodingCp866)
                    .Add(SmokeTests.Infra_FilterOrder)
                    .Add(SmokeTests.Infra_WinDivertSocketLayerReady);
            }

            if (all || cat == "pipe")
            {
                runner
                    .Add(SmokeTests.Pipe_UiReducerSmoke)
                    .Add(SmokeTests.Pipe_UnifiedFilter_LoopbackDropped)
                    .Add(SmokeTests.Pipe_UnifiedFilter_OkSuppressed)
                    .Add(SmokeTests.Pipe_Collector_DedupByRemoteIpPortProto_Polling);
            }

            if (all || cat == "bypass")
            {
                runner
                    .Add(SmokeTests.Bypass_BypassFilter_MetricsDefault)
                    .Add(SmokeTests.Bypass_TlsBypassService_PresetsBuilt);
            }

            return runner;
        }
    }

    internal static class SmokeTests
    {
        public static Task<SmokeTestResult> Infra_EncodingCp866(CancellationToken ct)
            => RunAsync("INFRA-004", "CP866 доступен (CodePagesEncodingProvider)", () =>
            {
                // На .NET нужно зарегистрировать провайдер, иначе Encoding.GetEncoding(866) может бросить.
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

                var enc = Encoding.GetEncoding(866);
                if (enc.CodePage != 866)
                {
                    return new SmokeTestResult("INFRA-004", "CP866 доступен (CodePagesEncodingProvider)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 866, получили {enc.CodePage}");
                }

                return new SmokeTestResult("INFRA-004", "CP866 доступен (CodePagesEncodingProvider)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "Encoding.GetEncoding(866) работает");
            }, ct);

        public static Task<SmokeTestResult> Infra_FilterOrder(CancellationToken ct)
            => RunAsync("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", () =>
            {
                using var engine = new TrafficEngine();
                var monitor = new TrafficMonitorFilter();
                var bypass = new BypassFilter(BypassProfile.CreateDefault());

                engine.RegisterFilter(bypass);
                engine.RegisterFilter(monitor);

                var filters = GetEngineFiltersSnapshot(engine);
                var order = string.Join(" > ", filters.Select(f => $"{f.Name}({f.Priority})"));

                var idxMonitor = filters.FindIndex(f => f.Name == monitor.Name);
                var idxBypass = filters.FindIndex(f => f.Name == bypass.Name);

                if (idxMonitor < 0 || idxBypass < 0)
                {
                    return new SmokeTestResult("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Не нашли ожидаемые фильтры. Порядок: {order}");
                }

                if (idxMonitor > idxBypass)
                {
                    return new SmokeTestResult("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали TrafficMonitor раньше Bypass. Порядок: {order}");
                }

                return new SmokeTestResult("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {order}");
            }, ct);

        public static async Task<SmokeTestResult> Infra_WinDivertSocketLayerReady(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            if (!TrafficEngine.HasAdministratorRights)
            {
                return new SmokeTestResult("INFRA-002", "WinDivert Socket Layer доступен", SmokeOutcome.Skip, sw.Elapsed,
                    "Пропуск: нет прав администратора (для WinDivert требуется Elevated)");
            }

            try
            {
                var progress = new Progress<string>(s => Console.WriteLine(s));
                using var monitor = new ConnectionMonitorService(progress)
                {
                    UsePollingMode = false
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(2));

                await monitor.StartAsync(cts.Token).ConfigureAwait(false);
                await monitor.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("INFRA-002", "WinDivert Socket Layer доступен", SmokeOutcome.Pass, sw.Elapsed,
                    "WinDivert Open/RecvOnly стартует и останавливается");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("INFRA-002", "WinDivert Socket Layer доступен", SmokeOutcome.Fail, sw.Elapsed,
                    ex.Message);
            }
        }

        public static Task<SmokeTestResult> Pipe_UiReducerSmoke(CancellationToken ct)
            => RunAsync("PIPE-001", "UI reducer smoke (--ui-reducer-smoke)", () =>
            {
                Program.RunUiReducerSmoke_ForSmokeRunner();
                return new SmokeTestResult("PIPE-001", "UI reducer smoke (--ui-reducer-smoke)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "Выполнено без исключений");
            }, ct);

        public static Task<SmokeTestResult> Pipe_UnifiedFilter_LoopbackDropped(CancellationToken ct)
            => RunAsync("PIPE-004", "UnifiedTrafficFilter: loopback дропается", () =>
            {
                var filter = new UnifiedTrafficFilter();
                var host = new HostDiscovered(
                    Key: "127.0.0.1:443:TCP",
                    RemoteIp: IPAddress.Loopback,
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var decision = filter.ShouldTest(host);
                if (decision.Action != FilterAction.Drop)
                {
                    return new SmokeTestResult("PIPE-004", "UnifiedTrafficFilter: loopback дропается", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Drop, получили {decision.Action} ({decision.Reason})");
                }

                return new SmokeTestResult("PIPE-004", "UnifiedTrafficFilter: loopback дропается", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {decision.Reason}");
            }, ct);

        public static Task<SmokeTestResult> Pipe_UnifiedFilter_OkSuppressed(CancellationToken ct)
            => RunAsync("PIPE-005", "UnifiedTrafficFilter: OK не засоряет UI (LogOnly/Drop для noise)", () =>
            {
                // В GUI этот фильтр инициализируется в DiagnosticOrchestrator.
                // Для smoke-теста делаем то же, иначе singleton NoiseHostFilter работает только на fallback-паттернах.
                var noisePath = Path.Combine(Directory.GetCurrentDirectory(), "noise_hosts.json");
                NoiseHostFilter.Initialize(noisePath);

                var filter = new UnifiedTrafficFilter();

                var host = new HostDiscovered(
                    Key: "203.0.113.10:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.10"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: true,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: "example.com",
                    SniHostname: null,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 10,
                    BlockageType: null,
                    TestedAt: DateTime.UtcNow);

                var ok = new HostBlocked(
                    TestResult: tested,
                    BypassStrategy: PipelineContract.BypassNone,
                    RecommendedAction: BlockageCode.StatusOk);

                var decision = filter.ShouldDisplay(ok);
                if (decision.Action != FilterAction.LogOnly)
                {
                    return new SmokeTestResult("PIPE-005", "UnifiedTrafficFilter: OK не засоряет UI (LogOnly/Drop для noise)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали LogOnly для OK, получили {decision.Action} ({decision.Reason})");
                }

                // noise host: должен быть Drop, если OK и bypass none
                var testedNoise = tested with { Hostname = "dns.google" };
                var okNoise = ok with { TestResult = testedNoise };
                var decisionNoise = filter.ShouldDisplay(okNoise);

                if (decisionNoise.Action != FilterAction.Drop)
                {
                    return new SmokeTestResult("PIPE-005", "UnifiedTrafficFilter: OK не засоряет UI (LogOnly/Drop для noise)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Drop для noise OK, получили {decisionNoise.Action} ({decisionNoise.Reason})");
                }

                return new SmokeTestResult("PIPE-005", "UnifiedTrafficFilter: OK не засоряет UI (LogOnly/Drop для noise)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: обычный OK=LogOnly, noise OK=Drop");
            }, ct);

        public static async Task<SmokeTestResult> Pipe_Collector_DedupByRemoteIpPortProto_Polling(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            try
            {
                var progress = new Progress<string>(_ => { /* без лишнего шума */ });

                using var connectionMonitor = new ConnectionMonitorService(progress)
                {
                    UsePollingMode = true
                };

                var pidTracker = new PidTrackerService(Environment.ProcessId, progress);
                await pidTracker.StartAsync(ct).ConfigureAwait(false);

                var trafficMonitor = new TrafficMonitorFilter();
                using var dnsParser = new DnsParserService(trafficMonitor, progress);

                using var collector = new TrafficCollector(connectionMonitor, pidTracker, dnsParser, progress, new UnifiedTrafficFilter());

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                await connectionMonitor.StartAsync(cts.Token).ConfigureAwait(false);

                int yielded = 0;

                var collectTask = Task.Run(async () =>
                {
                    await foreach (var _ in collector.CollectAsync(TimeSpan.FromSeconds(5), cts.Token).ConfigureAwait(false))
                    {
                        Interlocked.Increment(ref yielded);
                    }
                }, cts.Token);

                // Делаем две попытки TCP соединения к одному и тому же remote endpoint.
                // Polling даст два события (разные localPort), но TrafficCollector обязан дедупить по RemoteIp:RemotePort:Protocol.
                await Task.Delay(300, cts.Token).ConfigureAwait(false);
                await MakeTcpAttemptAsync(IPAddress.Parse("1.1.1.1"), 443, TimeSpan.FromMilliseconds(800), cts.Token).ConfigureAwait(false);
                await Task.Delay(300, cts.Token).ConfigureAwait(false);
                await MakeTcpAttemptAsync(IPAddress.Parse("1.1.1.1"), 443, TimeSpan.FromMilliseconds(800), cts.Token).ConfigureAwait(false);

                await Task.WhenAny(collectTask, Task.Delay(4500, cts.Token)).ConfigureAwait(false);

                await connectionMonitor.StopAsync().ConfigureAwait(false);
                await pidTracker.StopAsync().ConfigureAwait(false);

                // Ожидаем 1 yielded (дедуп). Если 0 — значит не увидели соединение (возможна среда/политики).
                // Это не должно падать «жёстко»: помечаем как SKIP, чтобы не ломать CI без сети.
                if (yielded == 0)
                {
                    return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Skip, sw.Elapsed,
                        "Не удалось увидеть соединение в snapshot (возможен no-network/политики). Повторите с админом/живой сетью.");
                }

                if (yielded > 1)
                {
                    return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Fail, sw.Elapsed,
                        $"Ожидали 1 уникальную цель, получили {yielded}");
                }

                return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: повторные попытки соединения не порождают новую цель");
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Skip, sw.Elapsed,
                    "Отменено/таймаут"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Fail, sw.Elapsed,
                    ex.Message);
            }
        }

        public static Task<SmokeTestResult> Bypass_BypassFilter_MetricsDefault(CancellationToken ct)
            => RunAsync("BYPASS-001", "BypassFilter: метрики по умолчанию = 0", () =>
            {
                var filter = new BypassFilter(BypassProfile.CreateDefault());
                var m = filter.GetMetrics();

                if (m.PacketsProcessed != 0 || m.RstDropped != 0 || m.ClientHellosFragmented != 0)
                {
                    return new SmokeTestResult("BYPASS-001", "BypassFilter: метрики по умолчанию = 0", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали нули, получили Packets={m.PacketsProcessed}, RstDropped={m.RstDropped}, Fragmented={m.ClientHellosFragmented}");
                }

                return new SmokeTestResult("BYPASS-001", "BypassFilter: метрики по умолчанию = 0", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: базовые счётчики нулевые");
            }, ct);

        public static Task<SmokeTestResult> Bypass_TlsBypassService_PresetsBuilt(CancellationToken ct)
            => RunAsync("BYPASS-004", "TlsBypassService: пресеты фрагментации доступны", () =>
            {
                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var names = svc.FragmentPresets.Select(p => p.Name).ToList();

                if (names.Count == 0)
                {
                    return new SmokeTestResult("BYPASS-004", "TlsBypassService: пресеты фрагментации доступны", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Список пресетов пуст");
                }

                if (!names.Contains("Профиль"))
                {
                    return new SmokeTestResult("BYPASS-004", "TlsBypassService: пресеты фрагментации доступны", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Нет пресета 'Профиль' (размеры из bypass_profile.json)");
                }

                return new SmokeTestResult("BYPASS-004", "TlsBypassService: пресеты фрагментации доступны", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {string.Join(", ", names)}");
            }, ct);

        private static async Task MakeTcpAttemptAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
        {
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            try
            {
                await tcp.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            }
            catch
            {
                // Нам не важен успех рукопожатия, важен факт попытки соединения в TCP таблице.
            }
        }

        private static List<IPacketFilter> GetEngineFiltersSnapshot(TrafficEngine engine)
        {
            // Smoke-тест: используем reflection, чтобы проверить реальный порядок после сортировки.
            var fields = typeof(TrafficEngine)
                .GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);

            var listField = fields.FirstOrDefault(f => typeof(List<IPacketFilter>).IsAssignableFrom(f.FieldType));
            if (listField == null)
            {
                return new List<IPacketFilter>();
            }

            var value = listField.GetValue(engine) as List<IPacketFilter>;
            if (value == null)
            {
                return new List<IPacketFilter>();
            }

            lock (value)
            {
                return value.ToList();
            }
        }

        private static async Task<SmokeTestResult> RunAsync(string id, string name, Func<SmokeTestResult> body, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                ct.ThrowIfCancellationRequested();
                var result = body();
                sw.Stop();
                return result with { Duration = sw.Elapsed };
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                return new SmokeTestResult(id, name, SmokeOutcome.Skip, sw.Elapsed, "Отменено");
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new SmokeTestResult(id, name, SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }
    }
}
