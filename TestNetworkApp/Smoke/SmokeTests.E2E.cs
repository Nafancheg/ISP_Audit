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
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Utils;
using IspAudit.ViewModels;
using Microsoft.Extensions.DependencyInjection;

using TransportProtocol = IspAudit.Bypass.TransportProtocol;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static async Task<SmokeTestResult> E2E_FullPipeline_EnqueueToUiCard(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var uiLines = new ConcurrentQueue<string>();
                // В smoke-тестах важно, чтобы Report был синхронным.
                // System.Progress может постить в SynchronizationContext, который не «пампится» в консольном раннере,
                // из-за чего UI-строки иногда не попадают в очередь (флапающий тест).
                IProgress<string> progress = new InlineProgress(msg =>
                {
                    if (!string.IsNullOrWhiteSpace(msg)) uiLines.Enqueue(msg);
                });

                var config = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false,
                    MaxConcurrentTests = 2,
                    TestTimeout = TimeSpan.FromSeconds(2)
                };

                var tester = new FastSyntheticHostTester(host => new IspAudit.Core.Models.HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: false,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: host.Hostname,
                    SniHostname: host.SniHostname,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 5,
                    BlockageType: BlockageCode.TlsHandshakeTimeout,
                    TestedAt: DateTime.UtcNow));

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

                var ip = IPAddress.Parse("203.0.113.1");
                var host = new IspAudit.Core.Models.HostDiscovered(
                    Key: $"{ip}:443:TCP",
                    RemoteIp: ip,
                    RemotePort: 443,
                    Protocol: TransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = "test-net"
                };

                await pipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                await pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(6)).ConfigureAwait(false);

                // Важно: DrainAndCompleteAsync не ждёт UiWorker (UI очередь не входит в PendingCount).
                // Дождёмся хотя бы одной UI-строки (❌/✓) коротким поллингом.
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
                while (DateTime.UtcNow < deadline)
                {
                    if (uiLines.Any(l => l.StartsWith("❌", StringComparison.Ordinal) || l.StartsWith("✓", StringComparison.Ordinal)))
                    {
                        break;
                    }

                    await Task.Delay(50, ct).ConfigureAwait(false);
                }

                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var mgr = new TestResultsManager(noiseHostFilter);
                mgr.Initialize();

                foreach (var line in uiLines)
                {
                    mgr.ParsePipelineMessage(line);
                }

                if (mgr.TestResults.Count == 0)
                {
                    return new SmokeTestResult("E2E-001", "E2E: Enqueue→Test→Classify→UI", SmokeOutcome.Fail, sw.Elapsed,
                        "Не получили ни одной карточки из pipeline UI-логов");
                }

                var hasDiagnosis = mgr.TestResults.Any(x =>
                    !string.IsNullOrWhiteSpace(x.Details)
                    || !string.IsNullOrWhiteSpace(x.Error)
                    || !string.IsNullOrWhiteSpace(x.BypassStrategy));
                if (!hasDiagnosis)
                {
                    return new SmokeTestResult("E2E-001", "E2E: Enqueue→Test→Classify→UI", SmokeOutcome.Fail, sw.Elapsed,
                        "Карточка появилась, но отсутствует рекомендация/диагноз (Recommendation пуст)" );
                }

                return new SmokeTestResult("E2E-001", "E2E: Enqueue→Test→Classify→UI", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: карточек={mgr.TestResults.Count}");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("E2E-001", "E2E: Enqueue→Test→Classify→UI", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        private sealed class InlineProgress(Action<string> onReport) : IProgress<string>
        {
            public void Report(string value) => onReport(value);
        }

        public static async Task<SmokeTestResult> E2E_BypassEnabled_ProducesFragmentationMetrics(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var engine = new TrafficEngine();
                var profile = new BypassProfile
                {
                    DropTcpRst = true,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.Fragment,
                    TlsFragmentThreshold = 1,
                    TlsFragmentSizes = new List<int> { 8, 8, 8 },
                    FragmentPresetName = "Smoke",
                    AutoAdjustAggressive = false
                };

                using var service = new TlsBypassService(engine, profile, _ => { }, useTrafficEngine: false, startMetricsTimer: false, nowProvider: () => DateTime.UtcNow);

                var filter = new BypassFilter(profile);
                var sender = new CapturePacketSender();
                service.SetFilterForSmoke(filter);

                // Метрики получаем так же, как в BYPASS-003: через событие MetricsUpdated.
                var tcs = new TaskCompletionSource<TlsBypassMetrics>(TaskCreationOptions.RunContinuationsAsynchronously);
                void OnMetrics(TlsBypassMetrics m)
                {
                    // Берём первый апдейт после ручного PullMetricsOnceAsyncForSmoke.
                    if (!tcs.Task.IsCompleted)
                    {
                        tcs.TrySetResult(m);
                    }
                }

                service.MetricsUpdated += OnMetrics;

                // Даем входящий ClientHello@443 с SNI.
                var src = IPAddress.Parse("10.0.0.2");
                var dst = IPAddress.Parse("93.184.216.34");
                var hello = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 600);
                var pkt = BuildIpv4TcpPacket(src, dst, 50000, 443, ttl: 64, ipId: 10, seq: 1000, tcpFlags: 0x18, payload: hello);

                var intercepted = new InterceptedPacket(pkt, pkt.Length);
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                filter.Process(intercepted, ctx, sender);

                await service.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);

                // Ждём коротко, чтобы успело прийти событие.
                var completed = await Task.WhenAny(tcs.Task, Task.Delay(500, ct)).ConfigureAwait(false);
                service.MetricsUpdated -= OnMetrics;

                if (completed != tcs.Task)
                {
                    return new SmokeTestResult("E2E-002", "E2E: bypass включается и работает (метрики)", SmokeOutcome.Fail, sw.Elapsed,
                        "Не получили MetricsUpdated после PullMetricsOnceAsyncForSmoke");
                }

                var metrics = await tcs.Task.ConfigureAwait(false);

                if (metrics.ClientHellosObserved <= 0)
                {
                    return new SmokeTestResult("E2E-002", "E2E: bypass включается и работает (метрики)", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали ClientHellosObserved>0");
                }

                // С фрагментацией должно быть >=1 фрагментированного.
                if (metrics.ClientHellosFragmented <= 0)
                {
                    return new SmokeTestResult("E2E-002", "E2E: bypass включается и работает (метрики)", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали ClientHellosFragmented>0");
                }

                return new SmokeTestResult("E2E-002", "E2E: bypass включается и работает (метрики)", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: observed={metrics.ClientHellosObserved}, fragmented={metrics.ClientHellosFragmented}");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("E2E-002", "E2E: bypass включается и работает (метрики)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> E2E_AutoBypass_PreemptivePreset_AppliesExpectedOptions(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("E2E-003", "E2E: auto-bypass вызывает ApplyPreemptiveAsync", SmokeOutcome.Skip, sw.Elapsed,
                        "Нет прав администратора (preemptive bypass включается только в Elevated)" );
                }

                using var engine = new TrafficEngine();
                using var provider = BuildIspAuditProvider();
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                var bypass = new BypassController(manager, autoHostlist);

                await bypass.EnablePreemptiveBypassAsync().ConfigureAwait(false);

                // ApplyPreemptiveAsync выставляет Disorder=true и DropRst=true.
                var snapshot = bypass.TlsService.GetOptionsSnapshot();
                if (!snapshot.DisorderEnabled || !snapshot.DropRstEnabled)
                {
                    return new SmokeTestResult("E2E-003", "E2E: auto-bypass вызывает ApplyPreemptiveAsync", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали DisorderEnabled=true и DropRstEnabled=true после EnablePreemptiveBypassAsync");
                }

                return new SmokeTestResult("E2E-003", "E2E: auto-bypass вызывает ApplyPreemptiveAsync", SmokeOutcome.Pass, sw.Elapsed,
                    "OK");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("E2E-003", "E2E: auto-bypass вызывает ApplyPreemptiveAsync", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> E2E_AttachProcess_AddPid_AllowsTraffic(CancellationToken ct)
            => RunAsync("E2E-004", "E2E: attach к процессу (AddPid) пропускает события", () =>
            {
                // Пид-трекер: стартовый PID любой, затем "attach" через TryAddPid.
                var tracker = new PidTrackerService(1000);
                var attachedPid = 2000;
                tracker.TryAddPid(attachedPid);

                var monitor = new ConnectionMonitorService();
                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();

                var monitorFilter = new TrafficMonitorFilter();
                var dns = new DnsParserService(monitorFilter, noiseHostFilter, progress: null);

                var collector = new TrafficCollector(monitor, tracker, dns, trafficFilter, progress: null);

                var ok = collector.TryBuildHostFromConnectionEventForSmoke(
                    pid: attachedPid,
                    protocol: 6,
                    remoteIp: IPAddress.Parse("93.184.216.34"),
                    remotePort: 443,
                    out var discovered);

                if (!ok)
                {
                    return new SmokeTestResult("E2E-004", "E2E: attach к процессу (AddPid) пропускает события", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что событие будет принято после TryAddPid" );
                }

                if (discovered.RemotePort != 443)
                {
                    return new SmokeTestResult("E2E-004", "E2E: attach к процессу (AddPid) пропускает события", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Неверный RemotePort в HostDiscovered" );
                }

                return new SmokeTestResult("E2E-004", "E2E: attach к процессу (AddPid) пропускает события", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);

        public static async Task<SmokeTestResult> E2E_ProcessExit_StopsMonitoring(CancellationToken ct)
        {
            // Повторяем ключевую часть ORCH-005, но с другим Test ID.
            var sw = Stopwatch.StartNew();

            using var engine = new TrafficEngine();
            using var provider = BuildIspAuditProvider();
            var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
            var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
            var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
            var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
            var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
            using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
            var orchestrator = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c exit 0",
                CreateNoWindow = true,
                UseShellExecute = false
            });

            if (proc == null)
            {
                return new SmokeTestResult("E2E-005", "E2E: завершение процесса останавливает мониторинг", SmokeOutcome.Fail, sw.Elapsed,
                    "Не удалось запустить cmd.exe для теста");
            }

            proc.WaitForExit(2000);

            var pidTracker = new PidTrackerService(proc.Id);
            SetPrivateField(orchestrator, "_pidTracker", pidTracker);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            SetPrivateField(orchestrator, "_cts", cts);

            try
            {
                var monitorTask = (Task)InvokePrivateMethod(orchestrator, "RunProcessMonitorAsync")!;
                var done = await Task.WhenAny(monitorTask, Task.Delay(3500, ct)).ConfigureAwait(false);
                if (done != monitorTask)
                {
                    return new SmokeTestResult("E2E-005", "E2E: завершение процесса останавливает мониторинг", SmokeOutcome.Fail, sw.Elapsed,
                        "Таймаут ожидания реакции на завершение процесса");
                }

                var stopReason = GetPrivateField<string?>(orchestrator, "_stopReason");
                if (!string.Equals(stopReason, "ProcessExited", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("E2E-005", "E2E: завершение процесса останавливает мониторинг", SmokeOutcome.Fail, sw.Elapsed,
                        $"Ожидали stopReason='ProcessExited', получили '{stopReason ?? "<null>"}'");
                }

                return new SmokeTestResult("E2E-005", "E2E: завершение процесса останавливает мониторинг", SmokeOutcome.Pass, sw.Elapsed,
                    "OK");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("E2E-005", "E2E: завершение процесса останавливает мониторинг", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
            finally
            {
                try { cts.Cancel(); cts.Dispose(); } catch { }
            }
        }
    }
}
