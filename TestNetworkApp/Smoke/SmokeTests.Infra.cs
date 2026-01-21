using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using IspAudit.Bypass;
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
    }
}
