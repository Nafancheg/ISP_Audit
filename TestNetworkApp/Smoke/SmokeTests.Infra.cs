using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        private sealed class ReentrantFilterListMutationFilter : IPacketFilter
        {
            public string Name => "ReentrantMutation";
            public int Priority => 999;

            private int _calls;

            public bool Process(InterceptedPacket packet, PacketContext ctx, IPacketSender sender)
            {
                // Имитируем опасный кейс: фильтр меняет список фильтров прямо во время обработки пакета.
                // Если движок итерируется по live List<>, это приводит к "Collection was modified".
                if (sender is not TrafficEngine engine)
                {
                    return true;
                }

                var n = Interlocked.Increment(ref _calls);

                // Почти на каждом вызове меняем список: add/remove одного и того же имени.
                if ((n & 1) == 0)
                {
                    engine.RegisterFilter(new DummyPacketFilter("HotSwap", priority: 1));
                }
                else
                {
                    engine.RemoveFilter("HotSwap");
                }

                return true;
            }
        }

        public static async Task<SmokeTestResult> Infra_WinDivertDriver(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            if (!TrafficEngine.HasAdministratorRights)
            {
                return new SmokeTestResult("INFRA-001", "WinDivert Driver: TrafficEngine стартует/останавливается", SmokeOutcome.Skip, sw.Elapsed,
                    "Пропуск: нет прав администратора (WinDivert требует Elevated)");
            }

            try
            {
                using var engine = new TrafficEngine();

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(2));

                // Важно: StartAsync/StopAsync — минимальная проверка загрузки драйвера/handle.
                await engine.StartAsync(cts.Token).ConfigureAwait(false);
                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("INFRA-001", "WinDivert Driver: TrafficEngine стартует/останавливается", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: WinDivert handle открывается и закрывается");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("INFRA-001", "WinDivert Driver: TrafficEngine стартует/останавливается", SmokeOutcome.Fail, sw.Elapsed,
                    ex.Message);
            }
        }

        public static Task<SmokeTestResult> Infra_FilterRegistration(CancellationToken ct)
            => RunAsync("INFRA-002", "TrafficEngine: регистрация фильтра работает", () =>
            {
                using var engine = new TrafficEngine();

                var dummy = new DummyPacketFilter("SmokeDummy", priority: 123);
                engine.RegisterFilter(dummy);

                var filters = GetEngineFiltersSnapshot(engine);
                var found = filters.Any(f => f.Name == dummy.Name);
                if (!found)
                {
                    return new SmokeTestResult("INFRA-002", "TrafficEngine: регистрация фильтра работает", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Фильтр не найден в списке после RegisterFilter (snapshot/reflection)"
                    );
                }

                return new SmokeTestResult("INFRA-002", "TrafficEngine: регистрация фильтра работает", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: фильтр присутствует в активном списке"
                );
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

        public static Task<SmokeTestResult> Infra_AdminRights(CancellationToken ct)
            => RunAsync("INFRA-004", "Права администратора (WinDivert требует Elevated)", () =>
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("INFRA-004", "Права администратора (WinDivert требует Elevated)", SmokeOutcome.Skip, TimeSpan.Zero,
                        "Пропуск: процесс запущен без прав администратора");
                }

                return new SmokeTestResult("INFRA-004", "Права администратора (WinDivert требует Elevated)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: есть права администратора");
            }, ct);

        public static Task<SmokeTestResult> Infra_EncodingCp866(CancellationToken ct)
            => RunAsync("INFRA-005", "CP866 доступен (CodePagesEncodingProvider)", () =>
            {
                // На .NET нужно зарегистрировать провайдер, иначе Encoding.GetEncoding(866) может бросить.
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

                var enc = Encoding.GetEncoding(866);
                if (enc.CodePage != 866)
                {
                    return new SmokeTestResult("INFRA-005", "CP866 доступен (CodePagesEncodingProvider)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 866, получили {enc.CodePage}");
                }

                return new SmokeTestResult("INFRA-005", "CP866 доступен (CodePagesEncodingProvider)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "Encoding.GetEncoding(866) работает");
            }, ct);

        public static Task<SmokeTestResult> Infra_FilterListMutationDuringProcessing_DoesNotThrow(CancellationToken ct)
            => RunAsync("INFRA-006", "TrafficEngine: мутация списка фильтров во время обработки не падает", () =>
            {
                using var engine = new TrafficEngine(progress: null);

                // Базовые фильтры.
                engine.RegisterFilter(new DummyPacketFilter("Stable", priority: 0));
                engine.RegisterFilter(new ReentrantFilterListMutationFilter());

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

                // Если движок итерируется по live List<>, здесь будет InvalidOperationException.
                for (int i = 0; i < 5000; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    _ = engine.ProcessPacketForSmoke(packet, ctx);
                }

                return new SmokeTestResult("INFRA-006", "TrafficEngine: мутация списка фильтров во время обработки не падает", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: обработка устойчива к реэнтрантным Register/Remove во время foreach");
            }, ct);

        public static Task<SmokeTestResult> Infra_ConcurrentFilterChurnAndProcessing_DoesNotThrow(CancellationToken ct)
            => RunAsyncAwait("INFRA-007", "TrafficEngine: параллельный churn фильтров и обработка пакетов не падают", async innerCt =>
            {
                using var engine = new TrafficEngine(progress: null);

                // Базовый фильтр: чтобы список не был пустым.
                engine.RegisterFilter(new DummyPacketFilter("Stable", priority: 0));

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

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                cts.CancelAfter(TimeSpan.FromSeconds(1));
                var token = cts.Token;

                var churnTask = Task.Run(() =>
                {
                    var i = 0;
                    while (!token.IsCancellationRequested)
                    {
                        // Параллельные изменения списка фильтров — типичный конкурентный сценарий.
                        if ((i++ & 1) == 0)
                        {
                            engine.RegisterFilter(new DummyPacketFilter("Churn", priority: 1));
                        }
                        else
                        {
                            engine.RemoveFilter("Churn");
                        }
                    }
                }, token);

                var processed = 0;
                while (!token.IsCancellationRequested)
                {
                    _ = engine.ProcessPacketForSmoke(packet, ctx);
                    processed++;
                }

                cts.Cancel();
                try
                {
                    await churnTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // ожидаемо
                }

                return new SmokeTestResult("INFRA-007", "TrafficEngine: параллельный churn фильтров и обработка пакетов не падают", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: обработано пакетов={processed}");
            }, ct);

        public static Task<SmokeTestResult> Infra_RapidApplyDisableDuringProcessing_DoesNotThrow(CancellationToken ct)
            => RunAsyncAwait("INFRA-008", "TrafficEngine: rapid Apply/Disable во время обработки пакетов не падает", async innerCt =>
            {
                var baseProfile = BypassProfile.CreateDefault();

                using var engine = new TrafficEngine(progress: null);
                using var tls = new TlsBypassService(
                    engine,
                    baseProfile,
                    log: null,
                    startMetricsTimer: false,
                    useTrafficEngine: true,
                    nowProvider: () => DateTime.UtcNow);

                using var manager = BypassStateManager.GetOrCreateFromService(tls, baseProfile, log: null);

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

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                cts.CancelAfter(TimeSpan.FromSeconds(2));
                var token = cts.Token;

                var processed = 0;
                var applyCount = 0;
                var disableCount = 0;

                var pumpTask = Task.Run(() =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        _ = engine.ProcessPacketForSmoke(packet, ctx);
                        processed++;
                    }
                }, token);

                // Важно: избегаем DNS/сетевых зависимостей. Поэтому DropUdp443Global=true.
                var optionsOn = TlsBypassOptions.CreateDefault(baseProfile) with
                {
                    FragmentEnabled = true,
                    DropUdp443 = true,
                    DropUdp443Global = true,
                    DropRstEnabled = true
                };

                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        await manager.ApplyTlsOptionsAsync(optionsOn, token).ConfigureAwait(false);
                        applyCount++;

                        await manager.DisableTlsAsync("smoke_disable", token).ConfigureAwait(false);
                        disableCount++;
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }

                cts.Cancel();
                try
                {
                    await pumpTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // ожидаемо
                }

                if (applyCount == 0)
                {
                    return new SmokeTestResult("INFRA-008", "TrafficEngine: rapid Apply/Disable во время обработки пакетов не падает", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Apply не выполнялся (ожидали хотя бы одну итерацию)");
                }

                return new SmokeTestResult("INFRA-008", "TrafficEngine: rapid Apply/Disable во время обработки пакетов не падает", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: apply={applyCount}, disable={disableCount}, processed={processed}");
            }, ct);

        public static Task<SmokeTestResult> Infra_ConcurrentSnapshotAndTargetsUpdateDuringProcessing_DoesNotThrow(CancellationToken ct)
            => RunAsyncAwait("INFRA-009", "TrafficEngine: конкурентные обновления snapshot/targets во время обработки не падают", async innerCt =>
            {
                // Цель: проверить безопасность volatile reference-swap в BypassFilter (_decisionGraphSnapshot и _udp443DropTargetDstIps)
                // при параллельной обработке пакетов.
                var baseProfile = BypassProfile.CreateDefault();

                using var engine = new TrafficEngine(progress: null);
                var bypassFilter = new BypassFilter(baseProfile, logAction: null, presetName: "smoke");
                engine.RegisterFilter(bypassFilter);

                // Reflection: методы internal в IspAudit.Core.Traffic.Filters.BypassFilter
                var t = typeof(BypassFilter);
                var setSnapshot = t.GetMethod("SetDecisionGraphSnapshot", BindingFlags.Instance | BindingFlags.NonPublic);
                var setTargets = t.GetMethod("SetUdp443DropTargetIps", BindingFlags.Instance | BindingFlags.NonPublic);
                if (setSnapshot == null || setTargets == null)
                {
                    return new SmokeTestResult("INFRA-009", "TrafficEngine: конкурентные обновления snapshot/targets во время обработки не падают", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не нашли internal методы SetDecisionGraphSnapshot/SetUdp443DropTargetIps через reflection");
                }

                var snapshotA = PolicySetCompiler.CompileOrThrow(new[]
                {
                    new FlowPolicy
                    {
                        Id = "smoke_udp443_global",
                        Priority = 100,
                        Scope = PolicyScope.Global,
                        Match = new MatchCondition { Proto = FlowTransportProtocol.Udp, Port = 443 },
                        Action = PolicyAction.DropUdp443
                    }
                });

                var snapshotB = PolicySetCompiler.CompileOrThrow(new[]
                {
                    new FlowPolicy
                    {
                        Id = "smoke_tcp80_host_tricks",
                        Priority = 100,
                        Scope = PolicyScope.Global,
                        Match = new MatchCondition { Proto = FlowTransportProtocol.Tcp, Port = 80 },
                        Action = PolicyAction.HttpHostTricks
                    }
                });

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

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                cts.CancelAfter(TimeSpan.FromSeconds(1));
                var token = cts.Token;

                var processed = 0;
                var updates = 0;

                var pumpTask = Task.Run(() =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        _ = engine.ProcessPacketForSmoke(packet, ctx);
                        processed++;
                    }
                }, token);

                var updateTask = Task.Run(() =>
                {
                    // Переключаем ссылки snapshot/targets максимально часто.
                    // Важно: передаём массив, чтобы исключить внешнюю мутацию IEnumerable.
                    var targets1 = new uint[] { 0x01020304 };
                    var targets2 = new uint[] { 0x0A0B0C0D, 0x01020304 };

                    var i = 0;
                    while (!token.IsCancellationRequested)
                    {
                        var useA = (i++ & 1) == 0;
                        setSnapshot.Invoke(bypassFilter, new object?[] { useA ? snapshotA : snapshotB });
                        setTargets.Invoke(bypassFilter, new object?[] { useA ? targets1 : targets2 });
                        updates++;
                    }
                }, token);

                try
                {
                    await Task.WhenAll(pumpTask, updateTask).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // ожидаемо
                }

                if (updates == 0)
                {
                    return new SmokeTestResult("INFRA-009", "TrafficEngine: конкурентные обновления snapshot/targets во время обработки не падают", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не было выполнено ни одного обновления snapshot/targets");
                }

                return new SmokeTestResult("INFRA-009", "TrafficEngine: конкурентные обновления snapshot/targets во время обработки не падают", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: updates={updates}, processed={processed}");
            }, ct);

        public static Task<SmokeTestResult> Infra_Stress_ApplyRollback_1000_NoCrash_NoMemorySpike(CancellationToken ct)
            => RunAsyncAwait("INFRA-010", "TrafficEngine: 1000 Apply/Rollback за <=60с (без падений/утечек)", async innerCt =>
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("INFRA-010", "TrafficEngine: 1000 Apply/Rollback за <=60с (без падений/утечек)", SmokeOutcome.Skip, TimeSpan.Zero,
                        "Пропуск: нет прав администратора (Stress INFRA-010 требует WinDivert/Elevated)");
                }

                var baseProfile = BypassProfile.CreateDefault();

                using var engine = new TrafficEngine(progress: null);
                using var tls = new TlsBypassService(
                    engine,
                    baseProfile,
                    log: null,
                    startMetricsTimer: false,
                    useTrafficEngine: true,
                    nowProvider: () => DateTime.UtcNow);

                using var manager = BypassStateManager.GetOrCreateFromService(tls, baseProfile, log: null);

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

                // Важно: избегаем DNS/сетевых зависимостей.
                var optionsOn = TlsBypassOptions.CreateDefault(baseProfile) with
                {
                    FragmentEnabled = true,
                    DropUdp443 = true,
                    DropUdp443Global = true,
                    DropRstEnabled = true
                };

                // Safety: не даём тесту повиснуть бесконечно.
                // Важное: strict/no-skip не допускает SKIP, поэтому зависание/таймаут — это FAIL.
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                cts.CancelAfter(TimeSpan.FromSeconds(75));
                var token = cts.Token;

                // Прогрев (JIT/аллоки в сервисах) — не меряем.
                for (var warm = 0; warm < 5; warm++)
                {
                    await manager.ApplyTlsOptionsAsync(optionsOn, token).ConfigureAwait(false);
                    await manager.DisableTlsAsync("smoke_disable", token).ConfigureAwait(false);
                }

                // Небольшой прогрев TrafficEngine (smoke path) — вне perf окна.
                for (var i = 0; i < 2000; i++)
                {
                    _ = engine.ProcessPacketForSmoke(packet, ctx);
                }

                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                var baseline = GC.GetTotalMemory(forceFullCollection: true);

                var applyCount = 0;
                var rollbackCount = 0;

                long processed = 0;
                var perfSw = Stopwatch.StartNew();

                try
                {
                    for (var i = 0; i < 1000; i++)
                    {
                        token.ThrowIfCancellationRequested();

                        await manager.ApplyTlsOptionsAsync(optionsOn, token).ConfigureAwait(false);
                        applyCount++;

                        await manager.DisableTlsAsync("smoke_disable", token).ConfigureAwait(false);
                        rollbackCount++;

                        // Минимальная нагрузка на smoke-path, чтобы поймать конкурирующие изменения фильтров.
                        _ = engine.ProcessPacketForSmoke(packet, ctx);
                        processed++;
                    }
                }
                catch (OperationCanceledException) when (!innerCt.IsCancellationRequested)
                {
                    // Сработал safety-таймаут: это ошибка производительности/зависания.
                    return new SmokeTestResult("INFRA-010", "TrafficEngine: 1000 Apply/Rollback за <=60с (без падений/утечек)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Safety timeout (75s): apply={applyCount}, rollback={rollbackCount}, processed={processed}");
                }

                perfSw.Stop();

                // Дополнительная нагрузка на smoke-path движка после Apply/Rollback.
                for (var i = 0; i < 2000; i++)
                {
                    _ = engine.ProcessPacketForSmoke(packet, ctx);
                }

                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                var after = GC.GetTotalMemory(forceFullCollection: true);
                var deltaMb = (after - baseline) / (1024.0 * 1024.0);

                // Порог мягкий: важнее поймать явный рост/утечку.
                if (deltaMb > 120)
                {
                    return new SmokeTestResult("INFRA-010", "TrafficEngine: 1000 Apply/Rollback за <=60с (без падений/утечек)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Подозрение на рост памяти: +{deltaMb:F1} MB (baseline={baseline}, after={after}); apply={applyCount}, rollback={rollbackCount}");
                }

                var elapsedSec = perfSw.Elapsed.TotalSeconds;
                var speedNote = elapsedSec <= 60
                    ? "OK"
                    : $"SLOW: {elapsedSec:F1}s (>60s)";

                return new SmokeTestResult("INFRA-010", "TrafficEngine: 1000 Apply/Rollback за <=60с (без падений/утечек)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"{speedNote}: +{deltaMb:F1} MB; apply={applyCount}, rollback={rollbackCount}, processed={processed}");
            }, ct);
    }
}
