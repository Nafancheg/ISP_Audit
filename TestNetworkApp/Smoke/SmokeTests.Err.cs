using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Utils;
using Microsoft.Extensions.DependencyInjection;

using TransportProtocol = IspAudit.Bypass.TransportProtocol;
using IspAudit.ViewModels;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static async Task<SmokeTestResult> Err_DnsFailure_DoesNotCrash(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var provider = BuildIspAuditProvider();
                var testerFactory = provider.GetRequiredService<IHostTesterFactory>();
                var tester = testerFactory.CreateStandard(progress: null, dnsCache: null, testTimeout: TimeSpan.FromSeconds(3));
                var host = new IspAudit.Core.Models.HostDiscovered(
                    Key: "1.2.3.4:443:TCP",
                    RemoteIp: IPAddress.Parse("1.2.3.4"),
                    RemotePort: 443,
                    Protocol: TransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = "nonexistent.invalid"
                };

                var tested = await tester.TestHostAsync(host, ct).ConfigureAwait(false);

                // DNS должен упасть (скорее всего), но самое главное — не исключение.
                if (tested.DnsOk)
                {
                    return new SmokeTestResult("ERR-001", "DNS сбой не крашит pipeline", SmokeOutcome.Pass, sw.Elapsed,
                        "DNS внезапно успешен (возможен кеш), но тест прошёл: исключений нет");
                }

                return new SmokeTestResult("ERR-001", "DNS сбой не крашит pipeline", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: DnsOk=false и нет исключений");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ERR-001", "DNS сбой не крашит pipeline", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Err_VpnDetected_WarningIsConsistent(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var expected = NetUtils.LikelyVpnActive();

                using var engine = new TrafficEngine();
                using var provider = BuildIspAuditProvider();
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                var bypass = new BypassController(engine, autoHostlist);
                await bypass.InitializeOnStartupAsync().ConfigureAwait(false);

                if (bypass.IsVpnDetected != expected)
                {
                    return new SmokeTestResult("ERR-002", "VPN-конфликт: предупреждение формируется", SmokeOutcome.Fail, sw.Elapsed,
                        $"Ожидали IsVpnDetected={expected}, получили {bypass.IsVpnDetected}");
                }

                return new SmokeTestResult("ERR-002", "VPN-конфликт: предупреждение формируется", SmokeOutcome.Pass, sw.Elapsed,
                    expected ? "OK: VPN детектится и предупреждение доступно" : "OK: VPN не детектится");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ERR-002", "VPN-конфликт: предупреждение формируется", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Err_WinDivertMissing_FallbackPollingStarts(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var monitor = new ConnectionMonitorService();
                monitor.UsePollingMode = true;

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(2));

                await monitor.StartAsync(cts.Token).ConfigureAwait(false);
                await monitor.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("ERR-003", "Fallback: ConnectionMonitor polling не крашит приложение", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: polling-режим запускается/останавливается без WinDivert");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ERR-003", "Fallback: ConnectionMonitor polling не крашит приложение", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Err_TrafficEngine_HandleCleanup_AdminGated(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            if (!TrafficEngine.HasAdministratorRights)
            {
                return new SmokeTestResult("ERR-004", "TrafficEngine: handle cleanup", SmokeOutcome.Skip, sw.Elapsed,
                    "Пропуск: нет прав администратора (WinDivert требует Elevated)");
            }

            try
            {
                using var engine = new TrafficEngine();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(3));

                await engine.StartAsync(cts.Token).ConfigureAwait(false);
                await engine.StopAsync().ConfigureAwait(false);

                var handle = GetPrivateField<object?>(engine, "_handle");
                if (handle != null)
                {
                    return new SmokeTestResult("ERR-004", "TrafficEngine: handle cleanup", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали _handle=null после StopAsync");
                }

                return new SmokeTestResult("ERR-004", "TrafficEngine: handle cleanup", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: handle очищается");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ERR-004", "TrafficEngine: handle cleanup", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        private sealed class ThrowingFilter : IPacketFilter
        {
            public string Name => "SmokeThrowing";
            public int Priority => 999;
            public bool Process(InterceptedPacket packet, PacketContext ctx, IPacketSender sender) => throw new Exception("smoke filter boom");
        }

        private sealed class ProbeFilter : IPacketFilter
        {
            private readonly TaskCompletionSource<bool> _tcs;
            public ProbeFilter(TaskCompletionSource<bool> tcs) => _tcs = tcs;
            public string Name => "SmokeProbe";
            public int Priority => 1;
            public bool Process(InterceptedPacket packet, PacketContext ctx, IPacketSender sender)
            {
                _tcs.TrySetResult(true);
                return true;
            }
        }

        public static async Task<SmokeTestResult> Err_FilterException_DoesNotCrashEngine_AdminGated(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            if (!TrafficEngine.HasAdministratorRights)
            {
                return new SmokeTestResult("ERR-005", "TrafficEngine: исключение фильтра не валит loop", SmokeOutcome.Skip, sw.Elapsed,
                    "Пропуск: нет прав администратора (WinDivert требует Elevated)");
            }

            using var engine = new TrafficEngine();
            var probeTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            try
            {
                engine.RegisterFilter(new ThrowingFilter());
                engine.RegisterFilter(new ProbeFilter(probeTcs));

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                await engine.StartAsync(cts.Token).ConfigureAwait(false);

                // Генерируем трафик (попытка TCP соединения). Даже если неуспешно — пакеты должны пройти через WinDivert.
                _ = MakeTcpAttemptAsync(IPAddress.Parse("1.1.1.1"), 80, TimeSpan.FromSeconds(2), ct);

                var completed = await Task.WhenAny(probeTcs.Task, Task.Delay(2500, ct)).ConfigureAwait(false);
                if (completed != probeTcs.Task)
                {
                    return new SmokeTestResult("ERR-005", "TrafficEngine: исключение фильтра не валит loop", SmokeOutcome.Fail, sw.Elapsed,
                        "Не дождались прохождения пакета до probe-фильтра (возможно нет трафика/WinDivert)");
                }

                return new SmokeTestResult("ERR-005", "TrafficEngine: исключение фильтра не валит loop", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: после исключения в фильтре loop продолжает работу");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ERR-005", "TrafficEngine: исключение фильтра не валит loop", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
            finally
            {
                try { await engine.StopAsync().ConfigureAwait(false); } catch { }
            }
        }

        public static async Task<SmokeTestResult> Err_DoHOnly_NoHostname_DoesNotCrash(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var provider = BuildIspAuditProvider();
                var testerFactory = provider.GetRequiredService<IHostTesterFactory>();
                var tester = testerFactory.CreateStandard(progress: null, dnsCache: null, testTimeout: TimeSpan.FromSeconds(3));
                var host = new IspAudit.Core.Models.HostDiscovered(
                    Key: "8.8.8.8:443:TCP",
                    RemoteIp: IPAddress.Parse("8.8.8.8"),
                    RemotePort: 443,
                    Protocol: TransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = await tester.TestHostAsync(host, ct).ConfigureAwait(false);

                // Важно: отсутствие hostname не должно падать; tlsOk не должен быть true, если tcpOk false.
                if (tested.TlsOk && !tested.TcpOk)
                {
                    return new SmokeTestResult("ERR-006", "DoH-only: без hostname пайплайн не падает", SmokeOutcome.Fail, sw.Elapsed,
                        "TlsOk=true при TcpOk=false (неожиданно)" );
                }

                return new SmokeTestResult("ERR-006", "DoH-only: без hostname пайплайн не падает", SmokeOutcome.Pass, sw.Elapsed,
                    "OK");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ERR-006", "DoH-only: без hostname пайплайн не падает", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Err_Ipv6Host_ParsesAndTests(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var provider = BuildIspAuditProvider();
                var testerFactory = provider.GetRequiredService<IHostTesterFactory>();
                var tester = testerFactory.CreateStandard(progress: null, dnsCache: null, testTimeout: TimeSpan.FromSeconds(3));
                var ip6 = IPAddress.Parse("2606:4700:4700::1111"); // Cloudflare
                var host = new IspAudit.Core.Models.HostDiscovered(
                    Key: $"{ip6}:443:TCP",
                    RemoteIp: ip6,
                    RemotePort: 443,
                    Protocol: TransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = await tester.TestHostAsync(host, ct).ConfigureAwait(false);

                if (!tested.Host.RemoteIp.Equals(ip6))
                {
                    return new SmokeTestResult("ERR-007", "IPv6: адреса парсятся и тестируются", SmokeOutcome.Fail, sw.Elapsed,
                        "RemoteIp изменился/не совпадает" );
                }

                return new SmokeTestResult("ERR-007", "IPv6: адреса парсятся и тестируются", SmokeOutcome.Pass, sw.Elapsed,
                    "OK (успех/провал сети не критичен — важна стабильность)");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ERR-007", "IPv6: адреса парсятся и тестируются", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Err_LongClientHello_Fragmentation_NoOverflow(CancellationToken ct)
            => RunAsync("ERR-008", "Длинный ClientHello (>1500) фрагментируется без переполнения", () =>
            {
                var profile = new BypassProfile
                {
                    DropTcpRst = true,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.Fragment,
                    TlsFragmentThreshold = 1,
                    TlsFragmentSizes = new List<int> { 600, 600, 600 },
                    FragmentPresetName = "Smoke",
                    AutoAdjustAggressive = false
                };

                var filter = new BypassFilter(profile);
                var sender = new CapturePacketSender();

                var src = IPAddress.Parse("10.0.0.2");
                var dst = IPAddress.Parse("93.184.216.34");

                var hello = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 2000);
                var pkt = BuildIpv4TcpPacket(src, dst, 50000, 443, ttl: 64, ipId: 10, seq: 1000, tcpFlags: 0x18, payload: hello);

                var intercepted = new InterceptedPacket(pkt, pkt.Length);
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                var ok = filter.Process(intercepted, ctx, sender);

                // Фильтр должен отправить несколько сегментов через sender.
                if (sender.Sent.Count < 2)
                {
                    return new SmokeTestResult("ERR-008", "Длинный ClientHello (>1500) фрагментируется без переполнения", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали >=2 фрагмента, получили {sender.Sent.Count}");
                }

                // И исходный пакет обычно не должен уходить дальше.
                if (ok)
                {
                    return new SmokeTestResult("ERR-008", "Длинный ClientHello (>1500) фрагментируется без переполнения", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что исходный пакет будет подавлен (return false)" );
                }

                return new SmokeTestResult("ERR-008", "Длинный ClientHello (>1500) фрагментируется без переполнения", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: отправлено фрагментов: {sender.Sent.Count}");
            }, ct);
    }
}
