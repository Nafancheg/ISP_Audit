using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        private static BypassProfile CreateBypassProfileForSmoke(TlsBypassOptions options, BypassProfile baseProfile)
        {
            var tlsStrategy = TlsBypassStrategy.None;

            if (options.DisorderEnabled && options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.FakeDisorder;
            else if (options.FragmentEnabled && options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.FakeFragment;
            else if (options.DisorderEnabled)
                tlsStrategy = TlsBypassStrategy.Disorder;
            else if (options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.Fake;
            else if (options.FragmentEnabled)
                tlsStrategy = TlsBypassStrategy.Fragment;

            return new BypassProfile
            {
                DropTcpRst = options.DropRstEnabled,
                FragmentTlsClientHello = options.FragmentEnabled || options.DisorderEnabled || options.FakeEnabled,
                TlsStrategy = tlsStrategy,
                TlsFirstFragmentSize = baseProfile.TlsFirstFragmentSize,
                TlsFragmentThreshold = baseProfile.TlsFragmentThreshold,
                TlsFragmentSizes = options.FragmentSizes,
                TtlTrick = options.TtlTrickEnabled,
                TtlTrickValue = options.TtlTrickValue,
                AutoTtl = options.AutoTtlEnabled,
                RedirectRules = baseProfile.RedirectRules,
                FragmentPresetName = options.PresetName,
                AutoAdjustAggressive = options.AutoAdjustAggressive
            };
        }

        private static void FeedBypassFilter(BypassFilter filter, byte[] packetBytes)
        {
            var intercepted = new InterceptedPacket(packetBytes, packetBytes.Length);
            var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);
            var sender = new DummyPacketSender();
            filter.Process(intercepted, ctx, sender);
        }

        private static byte[] BuildTlsClientHelloPayload(int length)
        {
            if (length < 7) length = 7;
            var payload = new byte[length];
            payload[0] = 0x16; // TLS Handshake
            payload[5] = 0x01; // ClientHello
            return payload;
        }

        public static async Task<SmokeTestResult> Bypass_TlsBypassService_RegistersFilter(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Skip, sw.Elapsed,
                        "Пропуск: нет прав администратора (WinDivert требует Elevated)"
                    );
                }

                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var options = svc.GetOptionsSnapshot() with
                {
                    FragmentEnabled = true,
                    DisorderEnabled = false,
                    FakeEnabled = false,
                    DropRstEnabled = false
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(3));

                await svc.ApplyAsync(options, cts.Token).ConfigureAwait(false);

                var filters = GetEngineFiltersSnapshot(engine);
                if (!filters.Any(f => f.Name == "BypassFilter"))
                {
                    return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Fail, sw.Elapsed,
                        "BypassFilter не найден в списке фильтров TrafficEngine после ApplyAsync"
                    );
                }

                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: BypassFilter зарегистрирован"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Bypass_TlsBypassService_RemovesFilter(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Skip, sw.Elapsed,
                        "Пропуск: нет прав администратора (WinDivert требует Elevated)"
                    );
                }

                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var enable = svc.GetOptionsSnapshot() with
                {
                    FragmentEnabled = true,
                    DisorderEnabled = false,
                    FakeEnabled = false,
                    DropRstEnabled = false
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(4));

                await svc.ApplyAsync(enable, cts.Token).ConfigureAwait(false);
                await svc.DisableAsync(cts.Token).ConfigureAwait(false);

                var filters = GetEngineFiltersSnapshot(engine);
                if (filters.Any(f => f.Name == "BypassFilter"))
                {
                    return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Fail, sw.Elapsed,
                        "BypassFilter всё ещё присутствует после DisableAsync"
                    );
                }

                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: BypassFilter удалён"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Bypass_TlsBypassService_ProfilePresetPresent(CancellationToken ct)
            => RunAsync("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", () =>
            {
                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var names = svc.FragmentPresets.Select(p => p.Name).ToList();

                if (names.Count == 0)
                {
                    return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Список пресетов пуст");
                }

                if (!names.Contains("Профиль"))
                {
                    return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Нет пресета 'Профиль' (размеры из bypass_profile.json)");
                }

                return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {string.Join(", ", names)}");
            }, ct);

        public static async Task<SmokeTestResult> Bypass_TlsBypassService_MetricsUpdated_Periodic(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                ct.ThrowIfCancellationRequested();

                var baseProfile = new BypassProfile
                {
                    DropTcpRst = true,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.Fragment,
                    TlsFirstFragmentSize = 32,
                    TlsFragmentThreshold = 64,
                    TlsFragmentSizes = new[] { 32, 32 },
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false);

                var options = svc.GetOptionsSnapshot() with
                {
                    FragmentEnabled = true,
                    DisorderEnabled = false,
                    FakeEnabled = false,
                    DropRstEnabled = true,
                    PresetName = "Стандарт",
                    AutoAdjustAggressive = false,
                    TtlTrickEnabled = false,
                    AutoTtlEnabled = false
                };

                var filterProfile = CreateBypassProfileForSmoke(options, baseProfile);
                var filter = new BypassFilter(filterProfile, logAction: null, presetName: options.PresetName);
                svc.SetFilterForSmoke(filter, metricsSince: DateTime.Now, options: options);

                var updates = 0;
                TlsBypassMetrics? last = null;
                svc.MetricsUpdated += m =>
                {
                    updates++;
                    last = m;
                };

                var clientIp = IPAddress.Parse("10.10.0.2");
                var serverIp = IPAddress.Parse("93.184.216.34");
                var srcPort = (ushort)50000;
                var tlsPayload = BuildTlsClientHelloPayload(length: 200);

                for (var i = 0; i < 3; i++)
                {
                    var pkt = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: (ushort)(100 + i), seq: (uint)(1000 + i), tcpFlags: 0x18, payload: tlsPayload);
                    FeedBypassFilter(filter, pkt);
                }

                for (var i = 0; i < 2; i++)
                {
                    var rst = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: (ushort)(200 + i), seq: (uint)(2000 + i), tcpFlags: 0x04, payload: default);
                    FeedBypassFilter(filter, rst);
                }

                await svc.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);

                for (var i = 0; i < 2; i++)
                {
                    var pkt = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: (ushort)(300 + i), seq: (uint)(3000 + i), tcpFlags: 0x18, payload: tlsPayload);
                    FeedBypassFilter(filter, pkt);
                }

                for (var i = 0; i < 2; i++)
                {
                    var rst = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: (ushort)(400 + i), seq: (uint)(4000 + i), tcpFlags: 0x04, payload: default);
                    FeedBypassFilter(filter, rst);
                }

                await svc.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);

                if (updates < 2)
                {
                    return new SmokeTestResult("BYPASS-003", "TlsBypassService: MetricsUpdated публикуется периодически", SmokeOutcome.Fail, sw.Elapsed,
                        $"Ожидали минимум 2 публикации MetricsUpdated, получили: {updates}");
                }

                if (last == null)
                {
                    return new SmokeTestResult("BYPASS-003", "TlsBypassService: MetricsUpdated публикуется периодически", SmokeOutcome.Fail, sw.Elapsed,
                        "MetricsUpdated не вернул метрики");
                }

                if (last.ClientHellosObserved <= 0 || last.ClientHellosFragmented <= 0 || last.RstDropped <= 0)
                {
                    return new SmokeTestResult("BYPASS-003", "TlsBypassService: MetricsUpdated публикуется периодически", SmokeOutcome.Fail, sw.Elapsed,
                        $"Метрики не содержат ожидаемых полей: observed={last.ClientHellosObserved}, fragmented={last.ClientHellosFragmented}, rst={last.RstDropped}");
                }

                return new SmokeTestResult("BYPASS-003", "TlsBypassService: MetricsUpdated публикуется периодически", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: observed={last.ClientHellosObserved}, fragmented={last.ClientHellosFragmented}, rst={last.RstDropped}");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-003", "TlsBypassService: MetricsUpdated публикуется периодически", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Bypass_TlsBypassService_VerdictChanged_RatioThresholds(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                static async Task<(bool ok, string details)> RunCaseAsync(VerdictColor expected, int rstRelevant)
                {
                    var baseProfile = new BypassProfile
                    {
                        DropTcpRst = true,
                        FragmentTlsClientHello = true,
                        TlsStrategy = TlsBypassStrategy.Fragment,
                        TlsFirstFragmentSize = 32,
                        TlsFragmentThreshold = 64,
                        TlsFragmentSizes = new[] { 32, 32 },
                        RedirectRules = Array.Empty<BypassRedirectRule>()
                    };

                    using var engine = new TrafficEngine();
                    using var svc = new TlsBypassService(engine, baseProfile, log: null, startMetricsTimer: false);

                    var options = svc.GetOptionsSnapshot() with
                    {
                        FragmentEnabled = true,
                        DisorderEnabled = false,
                        FakeEnabled = false,
                        DropRstEnabled = true,
                        PresetName = "Стандарт",
                        AutoAdjustAggressive = false,
                        TtlTrickEnabled = false,
                        AutoTtlEnabled = false
                    };

                    var filterProfile = CreateBypassProfileForSmoke(options, baseProfile);
                    var filter = new BypassFilter(filterProfile, logAction: null, presetName: options.PresetName);
                    svc.SetFilterForSmoke(filter, metricsSince: DateTime.Now, options: options);

                    VerdictColor? got = null;
                    svc.VerdictChanged += v => got = v.Color;

                    var clientIp = IPAddress.Parse("10.10.0.2");
                    var serverIp = IPAddress.Parse("93.184.216.34");
                    var srcPort = (ushort)50000;
                    var tlsPayload = BuildTlsClientHelloPayload(length: 200);

                    // fragmentsRaw = 10 (иначе будет Gray: "Мало данных")
                    for (var i = 0; i < 10; i++)
                    {
                        var pkt = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: (ushort)(100 + i), seq: (uint)(1000 + i), tcpFlags: 0x18, payload: tlsPayload);
                        FeedBypassFilter(filter, pkt);
                    }

                    // RstDroppedRelevant = rstRelevant
                    for (var i = 0; i < rstRelevant; i++)
                    {
                        var rst = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: (ushort)(500 + i), seq: (uint)(5000 + i), tcpFlags: 0x04, payload: default);
                        FeedBypassFilter(filter, rst);
                    }

                    await svc.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);

                    if (got == null)
                    {
                        return (false, "VerdictChanged не был вызван");
                    }

                    if (got.Value != expected)
                    {
                        return (false, $"Ожидали {expected}, получили {got.Value}");
                    }

                    return (true, $"OK: {expected}");
                }

                ct.ThrowIfCancellationRequested();

                // ratio = (RstDroppedRelevant - 5) / fragments
                // fragments = 10
                // Red: ratio > 4 => rstRelevant = 5 + 50 = 55
                // Yellow: 1.5 < ratio <= 4 => rstRelevant = 5 + 20 = 25
                // Green: ratio <= 1.5 => rstRelevant = 5 + 10 = 15
                var red = await RunCaseAsync(VerdictColor.Red, rstRelevant: 55).ConfigureAwait(false);
                if (!red.ok)
                {
                    return new SmokeTestResult("BYPASS-004", "TlsBypassService: VerdictChanged корректен по ratio RST/фрагментации", SmokeOutcome.Fail, sw.Elapsed,
                        $"Красный кейс: {red.details}");
                }

                var yellow = await RunCaseAsync(VerdictColor.Yellow, rstRelevant: 25).ConfigureAwait(false);
                if (!yellow.ok)
                {
                    return new SmokeTestResult("BYPASS-004", "TlsBypassService: VerdictChanged корректен по ratio RST/фрагментации", SmokeOutcome.Fail, sw.Elapsed,
                        $"Жёлтый кейс: {yellow.details}");
                }

                var green = await RunCaseAsync(VerdictColor.Green, rstRelevant: 15).ConfigureAwait(false);
                if (!green.ok)
                {
                    return new SmokeTestResult("BYPASS-004", "TlsBypassService: VerdictChanged корректен по ratio RST/фрагментации", SmokeOutcome.Fail, sw.Elapsed,
                        $"Зелёный кейс: {green.details}");
                }

                return new SmokeTestResult("BYPASS-004", "TlsBypassService: VerdictChanged корректен по ratio RST/фрагментации", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: красный/жёлтый/зелёный пороги пройдены");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-004", "TlsBypassService: VerdictChanged корректен по ratio RST/фрагментации", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }
    }
}
