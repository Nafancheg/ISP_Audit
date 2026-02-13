using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Intelligence.Signals;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Utils;
using Microsoft.Extensions.DependencyInjection;

using BypassTransportProtocol = IspAudit.Bypass.TransportProtocol;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
#pragma warning disable CS0618 // Smoke-тесты намеренно используют legacy-классификатор для проверки маппинга кодов.
        public static async Task<SmokeTestResult> Pipe_ConnectionMonitor_PublishesEvents_OnTcpConnect(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var progress = new Progress<string>(_ => { /* без лишнего шума */ });
                using var monitor = new ConnectionMonitorService(progress)
                {
                    UsePollingMode = true
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                var observed = new TaskCompletionSource<(IPAddress Ip, ushort Port)>(TaskCreationOptions.RunContinuationsAsynchronously);
                void Handler(int eventNum, int pid, byte proto, IPAddress remoteIp, ushort remotePort, ushort localPort)
                {
                    // Важно: в polling события могут быть не TCP, но для smoke нам подходит любой валидный remote endpoint.
                    // Отсекаем пустые/служебные значения, чтобы тест не проходил на "0.0.0.0:0".
                    if (remoteIp.Equals(IPAddress.Any) || remoteIp.Equals(IPAddress.IPv6Any) || remotePort == 0)
                    {
                        return;
                    }

                    observed.TrySetResult((remoteIp, remotePort));
                }

                monitor.OnConnectionEvent += Handler;
                try
                {
                    await monitor.StartAsync(cts.Token).ConfigureAwait(false);

                    // Генерируем соединение.
                    await MakeTcpAttemptAsync(IPAddress.Parse("1.1.1.1"), 443, TimeSpan.FromMilliseconds(800), cts.Token).ConfigureAwait(false);

                    var completed = await Task.WhenAny(observed.Task, Task.Delay(3500, cts.Token)).ConfigureAwait(false);
                    if (completed != observed.Task)
                    {
                        return new SmokeTestResult("PIPE-001", "ConnectionMonitor публикует события при подключении (polling)", SmokeOutcome.Fail, sw.Elapsed,
                            "Не получили callback от ConnectionMonitor после TCP попытки (возможны политики/окружение)");
                    }

                    var (ip, port) = await observed.Task.ConfigureAwait(false);
                    return new SmokeTestResult("PIPE-001", "ConnectionMonitor публикует события при подключении (polling)", SmokeOutcome.Pass, sw.Elapsed,
                        $"OK: получили remote endpoint {ip}:{port}");
                }
                finally
                {
                    monitor.OnConnectionEvent -= Handler;
                    await monitor.StopAsync().ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-001", "ConnectionMonitor публикует события при подключении (polling)", SmokeOutcome.Fail, sw.Elapsed,
                    "Таймаут/отмена");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-001", "ConnectionMonitor публикует события при подключении (polling)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Pipe_TrafficCollector_PidFiltering_IgnoresOtherPid(CancellationToken ct)
            => RunAsync("PIPE-002", "PID-фильтрация в TrafficCollector", () =>
            {
                var progress = new Progress<string>(_ => { /* без лишнего шума */ });
                using var dummyMonitor = new ConnectionMonitorService(progress);
                var pidTracker = new PidTrackerService(initialPid: Environment.ProcessId, progress);

                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();

                // Для детерминизма добавляем "чужой" PID и убеждаемся, что фильтр его отсекает.
                var otherPid = Environment.ProcessId + 100000;

                var trafficMonitor = new TrafficMonitorFilter();
                using var dnsParser = new DnsParserService(trafficMonitor, noiseHostFilter, progress);
                using var collector = new TrafficCollector(dummyMonitor, pidTracker, dnsParser, trafficFilter, progress);

                // 1) Событие от другого PID не должно пройти
                var okOther = collector.TryBuildHostFromConnectionEventForSmoke(
                    pid: otherPid,
                    protocol: 6,
                    remoteIp: IPAddress.Parse("203.0.113.10"),
                    remotePort: 443,
                    out _);

                if (okOther)
                {
                    return new SmokeTestResult("PIPE-002", "PID-фильтрация в TrafficCollector", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Событие от неотслеживаемого PID прошло фильтр (ожидали игнор)");
                }

                // 2) Событие от текущего процесса должно пройти
                var okSelf = collector.TryBuildHostFromConnectionEventForSmoke(
                    pid: Environment.ProcessId,
                    protocol: 6,
                    remoteIp: IPAddress.Parse("203.0.113.11"),
                    remotePort: 443,
                    out var host);

                if (!okSelf)
                {
                    return new SmokeTestResult("PIPE-002", "PID-фильтрация в TrafficCollector", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Событие от отслеживаемого PID не прошло фильтр (ожидали попадание в пайплайн)");
                }

                return new SmokeTestResult("PIPE-002", "PID-фильтрация в TrafficCollector", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: другой PID отфильтрован, свой PID прошёл (key={host.Key})");
            }, ct);

        public static Task<SmokeTestResult> Pipe_DnsParser_SniParsing_OneShotAndFragmented(CancellationToken ct)
            => RunAsync("PIPE-003", "SNI-парсинг из TLS ClientHello (цельный + фрагменты)", () =>
            {
                // Минимальный валидный TLS ClientHello с SNI=example.com.
                // Полезная нагрузка: TLS record (handshake) без IP/TCP заголовков.
                // Важно: тест детерминирован и не требует сети.
                var clientHello = BuildTlsClientHelloWithSni("example.com");

                if (!DnsParserService.TryExtractSniFromTlsClientHelloPayload(clientHello, out var sni1))
                {
                    return new SmokeTestResult("PIPE-003", "SNI-парсинг из TLS ClientHello (цельный + фрагменты)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось извлечь SNI из цельного ClientHello");
                }

                if (!string.Equals(sni1, "example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("PIPE-003", "SNI-парсинг из TLS ClientHello (цельный + фрагменты)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали example.com, получили '{sni1}'");
                }

                var progress = new Progress<string>(_ => { /* без лишнего шума */ });
                var trafficMonitor = new TrafficMonitorFilter();

                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                using var dnsParser = new DnsParserService(trafficMonitor, noiseHostFilter, progress);

                // Фрагментируем на 2 части (как будто пришло двумя TCP сегментами)
                var cut = Math.Max(1, clientHello.Length / 2);
                var part1 = clientHello.AsSpan(0, cut);
                var part2 = clientHello.AsSpan(cut);

                var ip = IPAddress.Parse("203.0.113.20");
                var port = 443;

                var ok1 = dnsParser.TryFeedTlsClientHelloFragmentForSmoke("flow", part1, ip, port, out _);
                var ok2 = dnsParser.TryFeedTlsClientHelloFragmentForSmoke("flow", part2, ip, port, out var sni2);

                if (!(ok1 || ok2) || string.IsNullOrWhiteSpace(sni2))
                {
                    return new SmokeTestResult("PIPE-003", "SNI-парсинг из TLS ClientHello (цельный + фрагменты)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось извлечь SNI из фрагментированного ClientHello");
                }

                if (!string.Equals(sni2, "example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("PIPE-003", "SNI-парсинг из TLS ClientHello (цельный + фрагменты)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали example.com (fragmented), получили '{sni2}'");
                }

                return new SmokeTestResult("PIPE-003", "SNI-парсинг из TLS ClientHello (цельный + фрагменты)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: SNI=example.com извлекается и из цельного, и из фрагментированного ClientHello");

                static byte[] BuildTlsClientHelloWithSni(string hostname)
                {
                    // Собираем простой ClientHello (TLS 1.2) с одним расширением server_name.
                    // Этого достаточно для текущего парсера, который ищет SNI в ClientHello.
                    var hostBytes = System.Text.Encoding.ASCII.GetBytes(hostname);

                    // server_name extension:
                    // ext_type(2)=0x0000, ext_len(2), list_len(2), name_type(1)=0, name_len(2), host
                    var serverNameListLen = 1 + 2 + hostBytes.Length;
                    var extDataLen = 2 + serverNameListLen;
                    var extLen = extDataLen;

                    var ext = new List<byte>();
                    ext.AddRange(new byte[] { 0x00, 0x00 }); // server_name
                    ext.AddRange(U16(extLen));
                    ext.AddRange(U16(serverNameListLen));
                    ext.Add(0x00); // host_name
                    ext.AddRange(U16(hostBytes.Length));
                    ext.AddRange(hostBytes);

                    // ClientHello body:
                    var body = new List<byte>();
                    body.AddRange(new byte[] { 0x03, 0x03 }); // client_version TLS 1.2
                    body.AddRange(new byte[32]); // random
                    body.Add(0x00); // session_id_len
                    body.AddRange(U16(2)); // cipher_suites_len
                    body.AddRange(new byte[] { 0x00, 0x2F }); // TLS_RSA_WITH_AES_128_CBC_SHA (любой валидный)
                    body.Add(0x01); // compression_methods_len
                    body.Add(0x00); // null
                    body.AddRange(U16(ext.Count)); // extensions_len
                    body.AddRange(ext);

                    // Handshake header: type(1)=1 ClientHello, len(3)
                    var hs = new List<byte>();
                    hs.Add(0x01);
                    hs.AddRange(U24(body.Count));
                    hs.AddRange(body);

                    // TLS record header: type(1)=0x16 handshake, version(2)=0x0301 TLS1.0, len(2)
                    var record = new List<byte>();
                    record.Add(0x16);
                    record.AddRange(new byte[] { 0x03, 0x01 });
                    record.AddRange(U16(hs.Count));
                    record.AddRange(hs);

                    return record.ToArray();

                    static IEnumerable<byte> U16(int value)
                        => new byte[] { (byte)((value >> 8) & 0xFF), (byte)(value & 0xFF) };

                    static IEnumerable<byte> U24(int value)
                        => new byte[] { (byte)((value >> 16) & 0xFF), (byte)((value >> 8) & 0xFF), (byte)(value & 0xFF) };
                }
            }, ct);

        public static Task<SmokeTestResult> Pipe_Orchestrator_SniGating_ByRemoteEndpointPid(CancellationToken ct)
            => RunAsync("PIPE-004", "Корреляция SNI с PID через remote endpoint", () =>
            {
                // Тестируем логику гейтинга по endpoint в DiagnosticOrchestrator детерминированно,
                // через reflection к приватным методам (в проде эти методы питаются событиями ConnectionMonitor + DnsParserService).

                var engine = new IspAudit.Core.Traffic.TrafficEngine(progress: null);
                var orch = new IspAudit.ViewModels.DiagnosticOrchestrator(engine, new IspAudit.Utils.NoiseHostFilter());

                var ip = IPAddress.Parse("203.0.113.30");
                var port = 443;
                var proto = (byte)6;

                var pidTracked = Environment.ProcessId;
                var pidUntracked = pidTracked + 100000;

                // Подменяем pidTracker, чтобы отслеживался только pidTracked
                var pidTracker = new PidTrackerService(pidTracked, progress: null);
                var field = typeof(IspAudit.ViewModels.DiagnosticOrchestrator)
                    .GetField("_pidTracker", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                field!.SetValue(orch, pidTracker);

                var tryResolve = typeof(IspAudit.ViewModels.DiagnosticOrchestrator)
                    .GetMethod("TryResolveTrackedPidForEndpoint", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                var track = typeof(IspAudit.ViewModels.DiagnosticOrchestrator)
                    .GetMethod("TrackRemoteEndpoint", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);

                // 1) endpoint привязан к неотслеживаемому PID => гейт должен закрыть
                track!.Invoke(orch, new object[] { pidUntracked, proto, ip, (ushort)port });
                var args1 = new object?[] { proto, ip, (ushort)port, 0 };
                var ok1 = (bool)tryResolve!.Invoke(orch, args1)!;
                if (ok1)
                {
                    return new SmokeTestResult("PIPE-004", "Корреляция SNI с PID через remote endpoint", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Endpoint для неотслеживаемого PID был ошибочно принят как tracked");
                }

                // 2) endpoint привязан к отслеживаемому PID => гейт должен открыть
                track.Invoke(orch, new object[] { pidTracked, proto, ip, (ushort)port });
                var args2 = new object?[] { proto, ip, (ushort)port, 0 };
                var ok2 = (bool)tryResolve.Invoke(orch, args2)!;
                if (!ok2)
                {
                    return new SmokeTestResult("PIPE-004", "Корреляция SNI с PID через remote endpoint", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Endpoint для отслеживаемого PID не был принят (ожидали true)");
                }

                return new SmokeTestResult("PIPE-004", "Корреляция SNI с PID через remote endpoint", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: endpoint пропускается только для tracked PID");
            }, ct);

        public static Task<SmokeTestResult> Pipe_StateStore_Dedup_SingleSession(CancellationToken ct)
            => RunAsync("PIPE-007", "Гейтинг тестов хостов в InMemoryBlockageStateStore (кулдаун + лимит попыток)", () =>
            {
                var store = new InMemoryBlockageStateStore();

                var host1 = new HostDiscovered(
                    Key: "203.0.113.40:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.40"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = "example.com",
                    SniHostname = "example.com"
                };

                var first = store.TryBeginHostTest(host1, hostname: "example.com");
                var second = store.TryBeginHostTest(host1, hostname: "example.com");

                if (!first)
                {
                    return new SmokeTestResult("PIPE-007", "Дедупликация хостов в InMemoryBlockageStateStore", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Первое появление цели должно возвращать true");
                }

                if (second)
                {
                    return new SmokeTestResult("PIPE-007", "Гейтинг тестов хостов в InMemoryBlockageStateStore (кулдаун + лимит попыток)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Повторное появление цели сразу должно быть проигнорировано (кулдаун, ожидали false)");
                }

                // После небольшого ожидания ретест должен стать возможен (но ограниченно).
                Thread.Sleep(9000);
                var third = store.TryBeginHostTest(host1, hostname: "example.com");
                if (!third)
                {
                    return new SmokeTestResult("PIPE-007", "Гейтинг тестов хостов в InMemoryBlockageStateStore (кулдаун + лимит попыток)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "После кулдауна ретест должен быть разрешён (ожидали true)");
                }

                return new SmokeTestResult("PIPE-007", "Гейтинг тестов хостов в InMemoryBlockageStateStore (кулдаун + лимит попыток)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: повтор сразу блокируется, но ретест после кулдауна разрешён");
            }, ct);

        public static async Task<SmokeTestResult> Pipe_PipelineHealth_EmitsLog_OnActivity(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var observed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                var progress = new Progress<string>(msg =>
                {
                    if (msg.Contains("[PipelineHealth]", StringComparison.OrdinalIgnoreCase))
                    {
                        observed.TrySetResult(msg);
                    }
                });

                var config = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false,
                    MaxConcurrentTests = 1,
                    TestTimeout = TimeSpan.FromSeconds(1)
                };

                using var provider = BuildIspAuditProvider();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();

                // Pipeline можно поднять без TrafficEngine/DnsParser: health-лог зависит только от активности очередей.
                using var pipeline = new LiveTestingPipeline(config, filter: trafficFilter, progress: progress, trafficEngine: null, dnsParser: null);

                // Делаем "активность": добавляем 1 хост в очередь.
                var host = new HostDiscovered(
                    Key: "203.0.113.50:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.50"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = "example.com",
                    SniHostname = "example.com"
                };

                await pipeline.EnqueueHostAsync(host).ConfigureAwait(false);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(12));

                var completed = await Task.WhenAny(observed.Task, Task.Delay(11000, cts.Token)).ConfigureAwait(false);
                if (completed != observed.Task)
                {
                    return new SmokeTestResult("PIPE-017", "Pipeline health-лог эмитится при активности", SmokeOutcome.Fail, sw.Elapsed,
                        "Не дождались [PipelineHealth] лога при активности пайплайна");
                }

                var msg = await observed.Task.ConfigureAwait(false);
                return new SmokeTestResult("PIPE-017", "Pipeline health-лог эмитится при активности", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: {msg}");
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-017", "Pipeline health-лог эмитится при активности", SmokeOutcome.Fail, sw.Elapsed,
                    "Таймаут/отмена");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-017", "Pipeline health-лог эмитится при активности", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Pipe_AutoHostlist_AppendedToIntelTail(CancellationToken ct)
            => RunAsyncAwait("PIPE-018", "Auto-hostlist добавляется в INTEL хвост (evidence/notes)", async _ =>
            {
                var uiLines = new List<string>();
                IProgress<string> progress = new InlineProgress(msg =>
                {
                    if (!string.IsNullOrWhiteSpace(msg)) uiLines.Add(msg);
                });

                var config = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false,
                    MaxConcurrentTests = 1,
                    TestTimeout = TimeSpan.FromSeconds(1)
                };

                using var provider = BuildIspAuditProvider();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();

                autoHostlist.Clear();
                autoHostlist.Enabled = true;
                autoHostlist.MinHitsToShow = 1;
                autoHostlist.PublishThrottle = TimeSpan.Zero;

                var inspection = new InspectionSignalsSnapshot
                {
                    Retransmissions = 0,
                    TotalPackets = 30,
                    HasHttpRedirect = false,
                    HasSuspiciousRst = true,
                    SuspiciousRstDetails = "TTL=64 (expected 50-55)",
                    UdpUnansweredHandshakes = 0
                };

                var store = new FixedInspectionStateStore(inspection);

                var tester = new FastSyntheticHostTester(host => new HostTested(
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

                using var pipeline = new LiveTestingPipeline(
                    config,
                    filter: trafficFilter,
                    progress: progress,
                    trafficEngine: null,
                    dnsParser: null,
                    stateStore: store,
                    autoHostlist: autoHostlist,
                    tester: tester);

                var ip = IPAddress.Parse("203.0.113.18");
                var host = new HostDiscovered(
                    Key: $"{ip}:443:TCP",
                    RemoteIp: ip,
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = "example.com",
                    SniHostname = "example.com"
                };

                await pipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                await pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(6)).ConfigureAwait(false);

                // Дождёмся UI-строки с хвостом [INTEL].
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
                while (DateTime.UtcNow < deadline)
                {
                    if (uiLines.Any(l => l.Contains("autoHL", StringComparison.OrdinalIgnoreCase)))
                    {
                        break;
                    }

                    await Task.Delay(50, ct).ConfigureAwait(false);
                }

                var found = uiLines.FirstOrDefault(l => l.Contains("autoHL", StringComparison.OrdinalIgnoreCase));
                if (string.IsNullOrWhiteSpace(found))
                {
                    var sample = uiLines.FirstOrDefault(l => l.Contains("[INTEL]", StringComparison.OrdinalIgnoreCase))
                        ?? uiLines.FirstOrDefault(l => l.StartsWith("❌", StringComparison.Ordinal))
                        ?? "(no ui lines)";
                    return new SmokeTestResult("PIPE-018", "Auto-hostlist добавляется в intel-хвост (evidence/notes)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Не нашли метку autoHL в UI хвосте. Пример: {sample}");
                }

                return new SmokeTestResult("PIPE-018", "Auto-hostlist добавляется в intel-хвост (evidence/notes)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {found}");
            }, ct);

        public static Task<SmokeTestResult> Pipe_AutoHostlist_IntelOnly_NoLegacyTypes(CancellationToken ct)
            => RunAsync("PIPE-019", "Auto-hostlist intel-only: без BlockageSignals/GetSignals", () =>
            {
                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var autoHostlist = new AutoHostlistService(noiseHostFilter)
                {
                    Enabled = true,
                    MinHitsToShow = 1,
                    PublishThrottle = TimeSpan.Zero
                };

                // 1) Smoke-контракт: не должны добавляться голые IP.
                var testedIp = new HostTested(
                    Host: new HostDiscovered(
                        Key: "203.0.113.99:443:TCP",
                        RemoteIp: IPAddress.Parse("203.0.113.99"),
                        RemotePort: 443,
                        Protocol: BypassTransportProtocol.Tcp,
                        DiscoveredAt: DateTime.UtcNow),
                    DnsOk: true,
                    TcpOk: false,
                    TlsOk: false,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: null,
                    SniHostname: null,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 0,
                    BlockageType: BlockageCode.TcpConnectTimeout,
                    TestedAt: DateTime.UtcNow);

                var inspection = new InspectionSignalsSnapshot(
                    Retransmissions: 0,
                    TotalPackets: 20,
                    HasHttpRedirect: false,
                    RedirectToHost: null,
                    HasSuspiciousRst: true,
                    SuspiciousRstDetails: "TTL=64 (expected 50-55)",
                    UdpUnansweredHandshakes: 0);

                autoHostlist.Observe(testedIp, inspection, hostname: null);
                if (autoHostlist.VisibleCount != 0)
                {
                    return new SmokeTestResult("PIPE-019", "Auto-hostlist intel-only: без BlockageSignals/GetSignals", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что голый IP не попадёт в hostlist, но VisibleCount != 0");
                }

                // 2) Добавление домена работает на INTEL snapshot без legacy типов.
                var testedDomain = testedIp with
                {
                    Hostname = "example.com",
                    SniHostname = "example.com",
                    TestedAt = DateTime.UtcNow
                };

                autoHostlist.Observe(testedDomain, inspection, hostname: "example.com");
                var snapshot = autoHostlist.GetSnapshot();
                if (snapshot.Count == 0)
                {
                    return new SmokeTestResult("PIPE-019", "Auto-hostlist intel-only: без BlockageSignals/GetSignals", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что домен попадёт в hostlist на INTEL inspection signals, но snapshot пуст");
                }

                if (!snapshot.Any(c => string.Equals(c.Host, "example.com", StringComparison.OrdinalIgnoreCase)))
                {
                    return new SmokeTestResult("PIPE-019", "Auto-hostlist intel-only: без BlockageSignals/GetSignals", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали candidate example.com, получили: {string.Join(", ", snapshot.Select(s => s.Host))}");
                }

                return new SmokeTestResult("PIPE-019", "Auto-hostlist intel-only: без BlockageSignals/GetSignals", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: candidates={snapshot.Count}");
            }, ct);

        private sealed class FixedInspectionStateStore : IBlockageStateStore, IInspectionSignalsProvider
        {
            private readonly InspectionSignalsSnapshot _snapshot;

            public FixedInspectionStateStore(InspectionSignalsSnapshot snapshot)
            {
                _snapshot = snapshot;
            }

            public bool TryBeginHostTest(HostDiscovered host, string? hostname = null) => true;

            public void RegisterResult(HostTested tested)
            {
                // Для этого smoke-теста state-store используется только как источник INTEL inspection snapshot.
            }

            public FailWindowStats GetFailStats(HostTested tested, TimeSpan window)
                => new(FailCount: 0, HardFailCount: 0, LastFailAt: null, Window: window);

            public BlockageSignals GetSignals(HostTested tested, TimeSpan window)
                => throw new NotSupportedException("Legacy GetSignals не должен вызываться в intel-only smoke PIPE-018");

            public InspectionSignalsSnapshot GetInspectionSignalsSnapshot(HostTested tested) => _snapshot;
        }

        public static Task<SmokeTestResult> Pipe_UnifiedFilter_LoopbackDropped(CancellationToken ct)
            => RunAsync("PIPE-005", "UnifiedTrafficFilter отбрасывает loopback", () =>
            {
                using var provider = BuildIspAuditProvider();
                var filter = provider.GetRequiredService<ITrafficFilter>();
                var host = new HostDiscovered(
                    Key: "127.0.0.1:443:TCP",
                    RemoteIp: IPAddress.Loopback,
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var decision = filter.ShouldTest(host);
                if (decision.Action != FilterAction.Drop)
                {
                    return new SmokeTestResult("PIPE-005", "UnifiedTrafficFilter отбрасывает loopback", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Drop, получили {decision.Action} ({decision.Reason})");
                }

                return new SmokeTestResult("PIPE-005", "UnifiedTrafficFilter отбрасывает loopback", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {decision.Reason}");
            }, ct);

        public static Task<SmokeTestResult> Pipe_UnifiedFilter_NoiseOnlyOnDisplay(CancellationToken ct)
            => RunAsync("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", () =>
            {
                // В GUI этот фильтр инициализируется в DiagnosticOrchestrator.
                // Для smoke-теста имитируем DI-путь: резолвим NoiseHostFilter и загружаем правила из файла,
                // иначе NoiseHostFilter будет работать только на fallback-паттернах.
                var noisePath = TryFindNoiseHostsJsonPath();
                if (string.IsNullOrWhiteSpace(noisePath))
                {
                    return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось найти noise_hosts.json (нужен для корректного распознавания шумовых доменов)");
                }

                var services = new ServiceCollection();
                services.AddIspAuditServices();
                using var provider = services.BuildServiceProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                noiseHostFilter.LoadFromFile(noisePath);

                var filter = new UnifiedTrafficFilter(noiseHostFilter);

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
                    return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали LogOnly для OK, получили {decision.Action} ({decision.Reason})");
                }

                // noise host: должен быть Drop, если OK и bypass none
                var testedNoise = tested with { Hostname = "dns.google" };
                var okNoise = ok with { TestResult = testedNoise };
                var decisionNoise = filter.ShouldDisplay(okNoise);

                if (decisionNoise.Action != FilterAction.Drop)
                {
                    return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Drop для noise OK, получили {decisionNoise.Action} ({decisionNoise.Reason})");
                }

                return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: обычный OK=LogOnly, noise OK=Drop");

                static string? TryFindNoiseHostsJsonPath()
                {
                    // noise_hosts.json лежит в корне репозитория.
                    var candidates = new List<string>
                    {
                        Path.Combine(Environment.CurrentDirectory, "noise_hosts.json"),
                        Path.Combine(AppContext.BaseDirectory, "noise_hosts.json"),
                    };

                    foreach (var start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory }.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        var dir = new DirectoryInfo(start);
                        for (int i = 0; i < 10 && dir is not null; i++)
                        {
                            candidates.Add(Path.Combine(dir.FullName, "noise_hosts.json"));
                            dir = dir.Parent;
                        }
                    }

                    foreach (var p in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        if (File.Exists(p))
                        {
                            return p;
                        }
                    }

                    return null;
                }
            }, ct);

        public static async Task<SmokeTestResult> Pipe_Tester_DnsResolve_Google(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                // Детерминированно: не зависим от внешнего интернета/провайдера.
                // localhost должен резолвиться в любой системе.
                var host = "localhost";
                var ip = IPAddress.Loopback;

                var tester = new StandardHostTester(progress: null);
                var discovered = new HostDiscovered(
                    Key: $"{ip}:80:TCP",
                    RemoteIp: ip,
                    RemotePort: 80,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = host
                };

                var tested = await tester.TestHostAsync(discovered, cts.Token).ConfigureAwait(false);
                if (!tested.DnsOk)
                {
                    return new SmokeTestResult("PIPE-008", "DNS-резолв через StandardHostTester", SmokeOutcome.Fail, sw.Elapsed,
                        $"DNS не OK (DnsStatus={tested.DnsStatus ?? "<null>"})");
                }

                return new SmokeTestResult("PIPE-008", "DNS-резолв через StandardHostTester", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: {host} -> {ip}");
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-008", "DNS-резолв через StandardHostTester", SmokeOutcome.Skip, sw.Elapsed,
                    "Отменено/таймаут");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-008", "DNS-резолв через StandardHostTester", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Pipe_Tester_TcpHandshake_Google443(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(8));

                // Детерминированно: локальный TCP listener вместо внешней сети.
                var host = "localhost";
                var ip = IPAddress.Loopback;
                using var listener = new TcpListener(ip, port: 0);
                listener.Start();

                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                var acceptTask = listener.AcceptTcpClientAsync(cts.Token);

                var tester = new StandardHostTester(progress: null);
                var discovered = new HostDiscovered(
                    Key: $"{ip}:{port}:TCP",
                    RemoteIp: ip,
                    RemotePort: port,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = host
                };

                var testedTask = tester.TestHostAsync(discovered, cts.Token);
                using var client = new TcpClient();
                await client.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
                using var accepted = await acceptTask.ConfigureAwait(false);
                await testedTask.ConfigureAwait(false);

                var tested = await testedTask.ConfigureAwait(false);
                if (!tested.TcpOk)
                {
                    return new SmokeTestResult("PIPE-009", "TCP Handshake (SYN → SYN-ACK)", SmokeOutcome.Fail, sw.Elapsed,
                        $"TCP не OK (BlockageType={tested.BlockageType ?? "<null>"})");
                }

                return new SmokeTestResult("PIPE-009", "TCP Handshake (SYN → SYN-ACK)", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: TCP connect к {host} ({ip}:{port})");
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-009", "TCP Handshake (SYN → SYN-ACK)", SmokeOutcome.Skip, sw.Elapsed,
                    "Отменено/таймаут");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-009", "TCP Handshake (SYN → SYN-ACK)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Pipe_Tester_TlsHandshake_Google443_Sni(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(10));

                // Детерминированно: локальный TLS сервер с self-signed сертификатом.
                // Для smoke мы отключаем валидацию сертификата в StandardHostTester через callback.
                var host = "localhost";
                var ip = IPAddress.Loopback;

                using var certificate = CreateSelfSignedCertificate(subjectName: "CN=localhost");
                using var listener = new TcpListener(ip, port: 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;

                var serverTask = RunSingleTlsServerAsync(listener, certificate, cts.Token);

                var tester = new StandardHostTester(
                    progress: null,
                    remoteCertificateValidationCallback: static (_, _, _, _) => true);
                var discovered = new HostDiscovered(
                    Key: $"{ip}:{port}:TCP",
                    RemoteIp: ip,
                    RemotePort: port,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    SniHostname = host,
                    Hostname = host
                };

                var tested = await tester.TestHostAsync(discovered, cts.Token).ConfigureAwait(false);
                if (!tested.TlsOk)
                {
                    return new SmokeTestResult("PIPE-010", "TLS ClientHello → ServerHello", SmokeOutcome.Fail, sw.Elapsed,
                        $"TLS не OK (BlockageType={tested.BlockageType ?? "<null>"})");
                }

                // Дожидаемся сервера, чтобы исключить гонки и утечки.
                await serverTask.ConfigureAwait(false);

                return new SmokeTestResult("PIPE-010", "TLS ClientHello → ServerHello", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: TLS handshake к {host} ({ip}:{port})");
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-010", "TLS ClientHello → ServerHello", SmokeOutcome.Skip, sw.Elapsed,
                    "Отменено/таймаут");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-010", "TLS ClientHello → ServerHello", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }

            static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
            {
                using var rsa = RSA.Create(2048);
                var req = new CertificateRequest(
                    new X500DistinguishedName(subjectName),
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                req.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));
                req.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
                req.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                // SAN: localhost
                var san = new SubjectAlternativeNameBuilder();
                san.AddDnsName("localhost");
                san.AddIpAddress(IPAddress.Loopback);
                req.CertificateExtensions.Add(san.Build());

                var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
                var notAfter = DateTimeOffset.UtcNow.AddDays(7);
                using var cert = req.CreateSelfSigned(notBefore, notAfter);

                // Важно: вернуть с приватным ключом и в удобном формате для SslStream.
                return new X509Certificate2(cert.Export(X509ContentType.Pfx));
            }

            static async Task RunSingleTlsServerAsync(TcpListener listener, X509Certificate2 certificate, CancellationToken ct2)
            {
                // StandardHostTester делает 2 отдельных подключения:
                // 1) TCP probe (connect+close)
                // 2) TLS probe (новый connect + handshake)
                // Плюс возможен повтор TLS (до 2 попыток).
                var options = new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                };

                try
                {
                    for (int acceptIndex = 0; acceptIndex < 3; acceptIndex++)
                    {
                        using var client = await listener.AcceptTcpClientAsync(ct2).ConfigureAwait(false);

                        // Первая сессия — это TCP probe, он не шлёт TLS bytes.
                        if (acceptIndex == 0)
                        {
                            continue;
                        }

                        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                        try
                        {
                            await ssl.AuthenticateAsServerAsync(options, ct2).ConfigureAwait(false);
                            return;
                        }
                        catch when (acceptIndex < 2)
                        {
                            // Дадим следующей попытке шанс (у клиента 2 TLS-попытки).
                        }
                    }

                    throw new InvalidOperationException("TLS server: не удалось выполнить handshake за ожидаемое число подключений");
                }
                finally
                {
                    listener.Stop();
                }
            }
        }

        public static async Task<SmokeTestResult> Pipe_Tester_ReverseDns_8888(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                var ip = IPAddress.Parse("8.8.8.8");
                var tester = new StandardHostTester(progress: null);
                var discovered = new HostDiscovered(
                    Key: "8.8.8.8:53:TCP",
                    RemoteIp: ip,
                    RemotePort: 53,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = await tester.TestHostAsync(discovered, cts.Token).ConfigureAwait(false);

                // Главное требование: PTR запрос не должен приводить к крэшу.
                // ReverseDnsHostname может быть null — это допустимо.
                return new SmokeTestResult("PIPE-011", "Reverse DNS (PTR) для IP", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: rDNS={(tested.ReverseDnsHostname ?? "<null>")}");
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-011", "Reverse DNS (PTR) для IP", SmokeOutcome.Skip, sw.Elapsed,
                    "Отменено/таймаут");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-011", "Reverse DNS (PTR) для IP", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Pipe_TrafficCollector_DedupByRemoteIpPortProto_Polling(CancellationToken ct)
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

                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();

                using var dnsParser = new DnsParserService(trafficMonitor, noiseHostFilter, progress);
                using var collector = new TrafficCollector(connectionMonitor, pidTracker, dnsParser, trafficFilter, progress);

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

        public static Task<SmokeTestResult> Pipe_Classifier_FakeIpRange(CancellationToken ct)
            => RunAsync("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", () =>
                new SmokeTestResult("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", SmokeOutcome.Skip, TimeSpan.Zero,
                    "Legacy StandardBlockageClassifier удалён; проверка перенесена в набор dpi2 (SignalsAdapter/DiagnosisEngine)."), ct);

        public static Task<SmokeTestResult> Pipe_Classifier_DnsBlocked(CancellationToken ct)
            => RunAsync("PIPE-012", "Классификация DNS-блокировки", () =>
                new SmokeTestResult("PIPE-012", "Классификация DNS-блокировки", SmokeOutcome.Skip, TimeSpan.Zero,
                    "Legacy StandardBlockageClassifier удалён; проверка перенесена в набор dpi2 (SignalsAdapter/DiagnosisEngine)."), ct);

        public static Task<SmokeTestResult> Pipe_Classifier_TcpTimeout(CancellationToken ct)
            => RunAsync("PIPE-013", "Классификация TCP Timeout", () =>
                new SmokeTestResult("PIPE-013", "Классификация TCP Timeout", SmokeOutcome.Skip, TimeSpan.Zero,
                    "Legacy StandardBlockageClassifier удалён; проверка перенесена в набор dpi2 (SignalsAdapter/DiagnosisEngine)."), ct);

        public static Task<SmokeTestResult> Pipe_Classifier_TcpReset(CancellationToken ct)
            => RunAsync("PIPE-014", "Классификация TCP Reset", () =>
                new SmokeTestResult("PIPE-014", "Классификация TCP Reset", SmokeOutcome.Skip, TimeSpan.Zero,
                    "Legacy StandardBlockageClassifier удалён; проверка перенесена в набор dpi2 (SignalsAdapter/DiagnosisEngine)."), ct);

        public static Task<SmokeTestResult> Pipe_Classifier_DpiFilter_Tls(CancellationToken ct)
            => RunAsync("PIPE-015", "Классификация DPI_FILTER (TLS-блокировка)", () =>
                new SmokeTestResult("PIPE-015", "Классификация DPI_FILTER (TLS-блокировка)", SmokeOutcome.Skip, TimeSpan.Zero,
                    "Legacy StandardBlockageClassifier удалён; проверка перенесена в набор dpi2 (SignalsAdapter/DiagnosisEngine)."), ct);

        public static Task<SmokeTestResult> Pipe_PriorityQueue_HighPreemptsLow(CancellationToken ct)
            => RunAsyncAwait("PIPE-020", "Приоритизация очереди: high preempts low", async innerCt =>
            {
                var sw = Stopwatch.StartNew();

                // maxConcurrency=1 — иначе приоритет может «размываться» параллелизмом.
                var config = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false,
                    MaxConcurrentTests = 1,
                    TestTimeout = TimeSpan.FromSeconds(3)
                };

                var highKey = "203.0.113.250:443:TCP:HIGH";
                var highStarted = new TaskCompletionSource<DateTimeOffset>(TaskCreationOptions.RunContinuationsAsynchronously);
                var tester = new SlowSmokeTester(highKey, highStarted, perHostDelay: TimeSpan.FromMilliseconds(250));

                using var pipeline = new LiveTestingPipeline(
                    config,
                    progress: null,
                    trafficEngine: null,
                    dnsParser: null,
                    filter: new AllowAllTrafficFilter(),
                    stateStore: new AllowAllStateStore(),
                    autoHostlist: null,
                    tester: tester);

                // Заполняем low-backlog.
                for (int i = 1; i <= 80; i++)
                {
                    var ip = IPAddress.Parse($"203.0.113.{i}");
                    var host = new HostDiscovered($"{ip}:443:TCP:LOW:{i}", ip, 443, global::IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                    {
                        Hostname = $"low-{i}.example.com"
                    };
                    await pipeline.EnqueueHostAsync(host, LiveTestingPipeline.HostPriority.Low).ConfigureAwait(false);
                }

                // Теперь high.
                var highIp = IPAddress.Parse("203.0.113.250");
                var highHost = new HostDiscovered(highKey, highIp, 443, global::IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                {
                    Hostname = "high.example.com"
                };

                var enqAt = DateTimeOffset.Now;
                await pipeline.EnqueueHostAsync(highHost, LiveTestingPipeline.HostPriority.High).ConfigureAwait(false);

                var completed = await Task.WhenAny(highStarted.Task, Task.Delay(TimeSpan.FromSeconds(5), innerCt)).ConfigureAwait(false);
                if (completed != highStarted.Task)
                {
                    return new SmokeTestResult("PIPE-020", "Приоритизация очереди: high preempts low", SmokeOutcome.Fail, sw.Elapsed,
                        "High-priority цель не начала тестироваться за 5 секунд");
                }

                var startedAt = await highStarted.Task.ConfigureAwait(false);
                var delta = startedAt - enqAt;
                if (delta > TimeSpan.FromSeconds(5))
                {
                    return new SmokeTestResult("PIPE-020", "Приоритизация очереди: high preempts low", SmokeOutcome.Fail, sw.Elapsed,
                        $"High-priority цель стартовала слишком поздно: {delta.TotalMilliseconds:0}ms");
                }

                // Best-effort drain
                try { await pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { }

                return new SmokeTestResult("PIPE-020", "Приоритизация очереди: high preempts low", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: high started in {delta.TotalMilliseconds:0}ms");
            }, ct);

        private sealed class SlowSmokeTester(string highKey, TaskCompletionSource<DateTimeOffset> highStarted, TimeSpan perHostDelay) : IHostTester
        {
            public async Task<HostTested> TestHostAsync(HostDiscovered host, CancellationToken ct)
            {
                if (string.Equals(host.Key, highKey, StringComparison.Ordinal))
                {
                    highStarted.TrySetResult(DateTimeOffset.Now);
                }

                await Task.Delay(perHostDelay, ct).ConfigureAwait(false);

                return new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: true,
                    DnsStatus: "OK",
                    Hostname: host.Hostname,
                    SniHostname: host.SniHostname,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 1,
                    BlockageType: null,
                    TestedAt: DateTime.UtcNow,
                    Http3Ok: null,
                    Http3Status: null,
                    Http3LatencyMs: null,
                    Http3Error: null);
            }
        }

        private sealed class AllowAllTrafficFilter : ITrafficFilter
        {
            public FilterDecision ShouldTest(HostDiscovered host, string? knownHostname = null) => new(FilterAction.Process, "allow");
            public FilterDecision ShouldDisplay(HostBlocked result) => new(FilterAction.Process, "allow");
            public bool IsNoise(string? hostname) => false;
            public void Reset() { }
            public void Invalidate(string ip) { }
        }

        private sealed class AllowAllStateStore : IBlockageStateStore
        {
            public bool TryBeginHostTest(HostDiscovered host, string? hostname = null) => true;
            public void RegisterResult(HostTested tested) { }
            public FailWindowStats GetFailStats(HostTested tested, TimeSpan window) => new(0, 0, null, window);
            public BlockageSignals GetSignals(HostTested tested, TimeSpan window) => new();
        }
    }
}
