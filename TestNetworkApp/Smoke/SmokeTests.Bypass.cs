using System;
using System.Collections.Generic;
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
                var tlsPayload = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 200);

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
                    var tlsPayload = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 200);

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

        public static Task<SmokeTestResult> Bypass_BypassFilter_Fragments_ClientHello_SeqAndLen(CancellationToken ct)
            => RunAsync("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", () =>
            {
                var profile = new BypassProfile
                {
                    DropTcpRst = false,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.Fragment,
                    TlsFragmentThreshold = 100,
                    TlsFragmentSizes = new[] { 80, 220 },
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");
                var sender = new CapturePacketSender();
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                var clientIp = IPAddress.Parse("10.10.0.2");
                var serverIp = IPAddress.Parse("93.184.216.34");
                var srcPort = (ushort)50010;
                var seqBase = 1000u;
                var payload = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 300);

                if (payload.Length != 300)
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали ClientHello длиной 300 байт, получили: {payload.Length}");
                }

                var pkt = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: 123, seq: seqBase, tcpFlags: 0x18, payload: payload);
                var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);

                if (forwarded)
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что пакет будет обработан (drop оригинала) и вернётся false");
                }

                if (sender.Sent.Count < 2)
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 2+ отправленных сегмента, получили: {sender.Sent.Count}");
                }

                // Для пресета [80,220] ожидаем ровно 2 сегмента.
                if (sender.Sent.Count != 2)
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 2 сегмента для пресета [80,220], получили: {sender.Sent.Count}");
                }

                var s0 = sender.Sent[0].Bytes;
                var s1 = sender.Sent[1].Bytes;

                var len0 = ReadTcpPayloadLength(s0);
                var len1 = ReadTcpPayloadLength(s1);
                var seq0 = ReadTcpSequence(s0);
                var seq1 = ReadTcpSequence(s1);

                if (len0 != 80 || len1 != 220)
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали длины payload [80,220], получили: [{len0},{len1}]");
                }

                if (seq0 != seqBase || seq1 != seqBase + 80)
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали seq [{seqBase},{seqBase + 80}], получили: [{seq0},{seq1}]");
                }

                var reassembled = sender.Sent
                    .Select(p => new { Seq = ReadTcpSequence(p.Bytes), Payload = SliceTcpPayload(p.Bytes).ToArray() })
                    .OrderBy(x => x.Seq)
                    .SelectMany(x => x.Payload)
                    .ToArray();

                if (!reassembled.SequenceEqual(payload))
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Реассемблинг по SEQ не совпал с исходным ClientHello");
                }

                var m = filter.GetMetrics();
                if (m.ClientHellosFragmented < 1)
                {
                    return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Метрика Fragmented++ не увеличилась");
                }

                return new SmokeTestResult("BYPASS-006", "BypassFilter: фрагментация TLS ClientHello даёт 2+ сегмента и корректные seq/len", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: segs=2, seq=[{seq0},{seq1}], len=[{len0},{len1}]");
            }, ct);

        public static Task<SmokeTestResult> Bypass_BypassFilter_Disorder_ReversesSegments(CancellationToken ct)
            => RunAsync("BYPASS-007", "BypassFilter: disorder отправляет сегменты в обратном порядке", () =>
            {
                var profile = new BypassProfile
                {
                    DropTcpRst = false,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.Disorder,
                    TlsFragmentThreshold = 100,
                    TlsFragmentSizes = new[] { 80, 220 },
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");
                var sender = new CapturePacketSender();
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                var clientIp = IPAddress.Parse("10.10.0.2");
                var serverIp = IPAddress.Parse("93.184.216.34");
                var srcPort = (ushort)50011;
                var seqBase = 2000u;
                var payload = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 300);

                var pkt = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: 124, seq: seqBase, tcpFlags: 0x18, payload: payload);
                var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);
                if (forwarded)
                {
                    return new SmokeTestResult("BYPASS-007", "BypassFilter: disorder отправляет сегменты в обратном порядке", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что пакет будет обработан (drop оригинала) и вернётся false");
                }

                if (sender.Sent.Count != 2)
                {
                    return new SmokeTestResult("BYPASS-007", "BypassFilter: disorder отправляет сегменты в обратном порядке", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 2 сегмента для пресета [80,220], получили: {sender.Sent.Count}");
                }

                var firstSeq = ReadTcpSequence(sender.Sent[0].Bytes);
                if (firstSeq == seqBase)
                {
                    return new SmokeTestResult("BYPASS-007", "BypassFilter: disorder отправляет сегменты в обратном порядке", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Первый отправленный сегмент имеет базовый SEQ — не похоже на reverse order");
                }

                var reassembled = sender.Sent
                    .Select(p => new { Seq = ReadTcpSequence(p.Bytes), Payload = SliceTcpPayload(p.Bytes).ToArray() })
                    .OrderBy(x => x.Seq)
                    .SelectMany(x => x.Payload)
                    .ToArray();

                if (!reassembled.SequenceEqual(payload))
                {
                    return new SmokeTestResult("BYPASS-007", "BypassFilter: disorder отправляет сегменты в обратном порядке", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Реассемблинг по SEQ не совпал с исходным ClientHello");
                }

                return new SmokeTestResult("BYPASS-007", "BypassFilter: disorder отправляет сегменты в обратном порядке", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: order reversed (firstSeq={firstSeq}, base={seqBase})");
            }, ct);

        public static Task<SmokeTestResult> Bypass_BypassFilter_TtlTrick_SendsFakeLowTtl(CancellationToken ct)
            => RunAsync("BYPASS-008", "BypassFilter: Fake TTL (TTL Trick) отправляет фейковый пакет с коротким TTL", () =>
            {
                var profile = new BypassProfile
                {
                    DropTcpRst = false,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.None,
                    TlsFragmentThreshold = 100,
                    TlsFirstFragmentSize = 0,
                    TlsFragmentSizes = Array.Empty<int>(),
                    TtlTrick = true,
                    TtlTrickValue = 5,
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");
                var sender = new CapturePacketSender();
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                var clientIp = IPAddress.Parse("10.10.0.2");
                var serverIp = IPAddress.Parse("93.184.216.34");
                var srcPort = (ushort)50012;
                var payload = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 200);

                var pkt = BuildIpv4TcpPacket(clientIp, serverIp, srcPort, 443, ttl: 64, ipId: 125, seq: 3000, tcpFlags: 0x18, payload: payload);
                var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);

                if (!forwarded)
                {
                    return new SmokeTestResult("BYPASS-008", "BypassFilter: Fake TTL (TTL Trick) отправляет фейковый пакет с коротким TTL", SmokeOutcome.Fail, TimeSpan.Zero,
                        "При TlsStrategy=None ожидаем, что оригинальный пакет будет пропущен (Process вернёт true)" );
                }

                if (sender.Sent.Count != 1)
                {
                    return new SmokeTestResult("BYPASS-008", "BypassFilter: Fake TTL (TTL Trick) отправляет фейковый пакет с коротким TTL", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 1 отправку (fake), получили: {sender.Sent.Count}. Примечание: real пакет проходит по цепочке без sender.Send" );
                }

                var fakeTtl = ReadIpv4Ttl(sender.Sent[0].Bytes);
                if (fakeTtl != 5)
                {
                    return new SmokeTestResult("BYPASS-008", "BypassFilter: Fake TTL (TTL Trick) отправляет фейковый пакет с коротким TTL", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали fake TTL=5, получили: {fakeTtl}");
                }

                return new SmokeTestResult("BYPASS-008", "BypassFilter: Fake TTL (TTL Trick) отправляет фейковый пакет с коротким TTL", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: fake packet sent with TTL=5 (original TTL=64 проходит дальше как есть)");
            }, ct);

        public static Task<SmokeTestResult> Bypass_BypassFilter_DropRst_DropsInboundRst(CancellationToken ct)
            => RunAsync("BYPASS-009", "BypassFilter: Drop RST отбрасывает входящий RST и увеличивает RstDropped", () =>
            {
                var profile = new BypassProfile
                {
                    DropTcpRst = true,
                    FragmentTlsClientHello = false,
                    TlsStrategy = TlsBypassStrategy.None,
                    TlsFragmentThreshold = 100,
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");
                var sender = new CapturePacketSender();
                var ctx = CreatePacketContext(isOutbound: false, isLoopback: false);

                var serverIp = IPAddress.Parse("93.184.216.34");
                var clientIp = IPAddress.Parse("10.10.0.2");
                var clientPort = (ushort)50013;

                // Входящий RST: srcPort=443 (сервер), dstPort=ephemeral (клиент)
                var rst = BuildIpv4TcpPacket(serverIp, clientIp, 443, clientPort, ttl: 64, ipId: 126, seq: 4000, tcpFlags: 0x04);
                var forwarded = filter.Process(new InterceptedPacket(rst, rst.Length), ctx, sender);

                if (forwarded)
                {
                    return new SmokeTestResult("BYPASS-009", "BypassFilter: Drop RST отбрасывает входящий RST и увеличивает RstDropped", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что входящий RST будет отброшен (Process вернёт false)");
                }

                var m = filter.GetMetrics();
                if (m.RstDropped < 1)
                {
                    return new SmokeTestResult("BYPASS-009", "BypassFilter: Drop RST отбрасывает входящий RST и увеличивает RstDropped", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Метрика RstDropped++ не увеличилась");
                }

                return new SmokeTestResult("BYPASS-009", "BypassFilter: Drop RST отбрасывает входящий RST и увеличивает RstDropped", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: dropped={m.RstDropped}");
            }, ct);

        public static Task<SmokeTestResult> Bypass_BypassFilter_Gating_443AndSni(CancellationToken ct)
            => RunAsync("BYPASS-010", "BypassFilter: гейт по 443 и наличию SNI (Non443++/NoSni++, без фрагментации)", () =>
            {
                var profile = new BypassProfile
                {
                    DropTcpRst = false,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.Fragment,
                    TlsFragmentThreshold = 100,
                    TlsFragmentSizes = new[] { 80, 220 },
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");
                var sender = new CapturePacketSender();
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                var clientIp = IPAddress.Parse("10.10.0.2");
                var serverIp = IPAddress.Parse("93.184.216.34");

                // 1) ClientHello на не-443
                var withSni = BuildTlsClientHelloPayloadWithSni("example.com", desiredTotalLength: 200);
                var non443 = BuildIpv4TcpPacket(clientIp, serverIp, 50014, 80, ttl: 64, ipId: 127, seq: 5000, tcpFlags: 0x18, payload: withSni);
                var f1 = filter.Process(new InterceptedPacket(non443, non443.Length), ctx, sender);
                if (!f1)
                {
                    return new SmokeTestResult("BYPASS-010", "BypassFilter: гейт по 443 и наличию SNI (Non443++/NoSni++, без фрагментации)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "ClientHello на не-443 не должен модифицироваться (Process должен вернуть true)");
                }

                // 2) ClientHello:443 без SNI (валидная структура, но без server_name extension)
                var noSniPayload = BuildTlsClientHelloPayloadWithoutSni(desiredTotalLength: 200);
                var noSni = BuildIpv4TcpPacket(clientIp, serverIp, 50015, 443, ttl: 64, ipId: 128, seq: 6000, tcpFlags: 0x18, payload: noSniPayload);
                var f2 = filter.Process(new InterceptedPacket(noSni, noSni.Length), ctx, sender);
                if (!f2)
                {
                    return new SmokeTestResult("BYPASS-010", "BypassFilter: гейт по 443 и наличию SNI (Non443++/NoSni++, без фрагментации)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "ClientHello:443 без SNI не должен модифицироваться (Process должен вернуть true)");
                }

                if (sender.Sent.Count != 0)
                {
                    return new SmokeTestResult("BYPASS-010", "BypassFilter: гейт по 443 и наличию SNI (Non443++/NoSni++, без фрагментации)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Не ожидали sender.Send на Non443/NoSni сценариях, но отправок: {sender.Sent.Count}");
                }

                var m = filter.GetMetrics();
                if (m.ClientHellosNon443 < 1)
                {
                    return new SmokeTestResult("BYPASS-010", "BypassFilter: гейт по 443 и наличию SNI (Non443++/NoSni++, без фрагментации)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Метрика Non443++ не увеличилась");
                }

                if (m.ClientHellosNoSni < 1)
                {
                    return new SmokeTestResult("BYPASS-010", "BypassFilter: гейт по 443 и наличию SNI (Non443++/NoSni++, без фрагментации)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Метрика NoSni++ не увеличилась");
                }

                return new SmokeTestResult("BYPASS-010", "BypassFilter: гейт по 443 и наличию SNI (Non443++/NoSni++, без фрагментации)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: non443={m.ClientHellosNon443}, noSni={m.ClientHellosNoSni}");
            }, ct);

        public static Task<SmokeTestResult> Bypass_BypassFilter_Threshold_ShortClientHelloNotFragmented(CancellationToken ct)
            => RunAsync("BYPASS-011", "BypassFilter: порог threshold не фрагментирует короткий ClientHello (ShortClientHello++)", () =>
            {
                var profile = new BypassProfile
                {
                    DropTcpRst = false,
                    FragmentTlsClientHello = true,
                    TlsStrategy = TlsBypassStrategy.Fragment,
                    TlsFragmentThreshold = 100,
                    TlsFragmentSizes = new[] { 80, 220 },
                    RedirectRules = Array.Empty<BypassRedirectRule>()
                };

                var filter = new BypassFilter(profile, logAction: null, presetName: "smoke");
                var sender = new CapturePacketSender();
                var ctx = CreatePacketContext(isOutbound: true, isLoopback: false);

                var clientIp = IPAddress.Parse("10.10.0.2");
                var serverIp = IPAddress.Parse("93.184.216.34");
                var shortPayload = BuildTlsClientHelloPayload(length: 50); // достаточно для IsClientHello, но < threshold

                var pkt = BuildIpv4TcpPacket(clientIp, serverIp, 50016, 443, ttl: 64, ipId: 129, seq: 7000, tcpFlags: 0x18, payload: shortPayload);
                var forwarded = filter.Process(new InterceptedPacket(pkt, pkt.Length), ctx, sender);

                if (!forwarded)
                {
                    return new SmokeTestResult("BYPASS-011", "BypassFilter: порог threshold не фрагментирует короткий ClientHello (ShortClientHello++)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Короткий ClientHello (<threshold) не должен модифицироваться (Process должен вернуть true)");
                }

                if (sender.Sent.Count != 0)
                {
                    return new SmokeTestResult("BYPASS-011", "BypassFilter: порог threshold не фрагментирует короткий ClientHello (ShortClientHello++)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Короткий ClientHello не должен приводить к sender.Send, но отправок: {sender.Sent.Count}");
                }

                var m = filter.GetMetrics();
                if (m.ClientHellosShort < 1)
                {
                    return new SmokeTestResult("BYPASS-011", "BypassFilter: порог threshold не фрагментирует короткий ClientHello (ShortClientHello++)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Метрика ShortClientHello++ не увеличилась");
                }

                return new SmokeTestResult("BYPASS-011", "BypassFilter: порог threshold не фрагментирует короткий ClientHello (ShortClientHello++)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: short={m.ClientHellosShort}");
            }, ct);
    }
}
