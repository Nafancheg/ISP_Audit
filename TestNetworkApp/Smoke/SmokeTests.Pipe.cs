using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Utils;

using BypassTransportProtocol = IspAudit.Bypass.TransportProtocol;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> Pipe_UnifiedFilter_LoopbackDropped(CancellationToken ct)
            => RunAsync("PIPE-005", "UnifiedTrafficFilter отбрасывает loopback", () =>
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
                // Для smoke-теста делаем то же, иначе singleton NoiseHostFilter работает только на fallback-паттернах.
                var noisePath = TryFindNoiseHostsJsonPath();
                if (string.IsNullOrWhiteSpace(noisePath))
                {
                    return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось найти noise_hosts.json (нужен для корректного распознавания шумовых доменов)");
                }

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

                var host = "google.com";
                var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(cts.Token).ConfigureAwait(false);
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();

                if (ip == null)
                {
                    return new SmokeTestResult("PIPE-008", "DNS-резолв через StandardHostTester", SmokeOutcome.Fail, sw.Elapsed,
                        "DNS.GetHostAddressesAsync вернул пустой список");
                }

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

                var host = "google.com";
                var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(cts.Token).ConfigureAwait(false);
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();

                if (ip == null)
                {
                    return new SmokeTestResult("PIPE-009", "TCP Handshake (SYN → SYN-ACK)", SmokeOutcome.Fail, sw.Elapsed,
                        "DNS.GetHostAddressesAsync вернул пустой список");
                }

                var tester = new StandardHostTester(progress: null);
                var discovered = new HostDiscovered(
                    Key: $"{ip}:443:TCP",
                    RemoteIp: ip,
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = host
                };

                var tested = await tester.TestHostAsync(discovered, cts.Token).ConfigureAwait(false);
                if (!tested.TcpOk)
                {
                    return new SmokeTestResult("PIPE-009", "TCP Handshake (SYN → SYN-ACK)", SmokeOutcome.Fail, sw.Elapsed,
                        $"TCP не OK (BlockageType={tested.BlockageType ?? "<null>"})");
                }

                return new SmokeTestResult("PIPE-009", "TCP Handshake (SYN → SYN-ACK)", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: TCP connect к {host} ({ip}:443)");
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

                var host = "google.com";
                var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(cts.Token).ConfigureAwait(false);
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();

                if (ip == null)
                {
                    return new SmokeTestResult("PIPE-010", "TLS ClientHello → ServerHello", SmokeOutcome.Fail, sw.Elapsed,
                        "DNS.GetHostAddressesAsync вернул пустой список");
                }

                var tester = new StandardHostTester(progress: null);
                var discovered = new HostDiscovered(
                    Key: $"{ip}:443:TCP",
                    RemoteIp: ip,
                    RemotePort: 443,
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

                return new SmokeTestResult("PIPE-010", "TLS ClientHello → ServerHello", SmokeOutcome.Pass, sw.Elapsed,
                    $"OK: TLS handshake к {host} ({ip}:443)");
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

        public static Task<SmokeTestResult> Pipe_Classifier_FakeIpRange(CancellationToken ct)
            => RunAsync("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", () =>
            {
                var classifier = new StandardBlockageClassifier();
                var host = new HostDiscovered(
                    Key: "198.18.0.1:443:TCP",
                    RemoteIp: IPAddress.Parse("198.18.0.1"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: true,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: null,
                    SniHostname: null,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 10,
                    BlockageType: null,
                    TestedAt: DateTime.UtcNow);

                var blocked = classifier.ClassifyBlockage(tested);
                if (BlockageCode.Normalize(blocked.TestResult.BlockageType) != BlockageCode.FakeIp)
                {
                    return new SmokeTestResult("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали {BlockageCode.FakeIp}, получили '{blocked.TestResult.BlockageType ?? "<null>"}'");
                }

                return new SmokeTestResult("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: адрес из 198.18/15 помечается как FakeIp");
            }, ct);

        public static Task<SmokeTestResult> Pipe_Classifier_DnsBlocked(CancellationToken ct)
            => RunAsync("PIPE-012", "Классификация DNS-блокировки", () =>
            {
                var classifier = new StandardBlockageClassifier();
                var host = new HostDiscovered(
                    Key: "203.0.113.10:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.10"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = "blocked.example"
                };

                // В реальном StandardHostTester DNS проблема идёт через DnsStatus,
                // а BlockageType может быть пустым. Smoke-тест фиксирует ожидаемую классификацию.
                var tested = new HostTested(
                    Host: host,
                    DnsOk: false,
                    TcpOk: false,
                    TlsOk: false,
                    DnsStatus: BlockageCode.DnsError,
                    Hostname: host.Hostname,
                    SniHostname: null,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 0,
                    BlockageType: null,
                    TestedAt: DateTime.UtcNow);

                var blocked = classifier.ClassifyBlockage(tested);
                var normalized = BlockageCode.Normalize(blocked.TestResult.BlockageType);

                if (!string.Equals(normalized, BlockageCode.DnsError, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("PIPE-012", "Классификация DNS-блокировки", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали {BlockageCode.DnsError}, получили '{blocked.TestResult.BlockageType ?? "<null>"}'");
                }

                return new SmokeTestResult("PIPE-012", "Классификация DNS-блокировки", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: DnsOk=false приводит к DNS_ERROR");
            }, ct);

        public static Task<SmokeTestResult> Pipe_Classifier_TcpTimeout(CancellationToken ct)
            => RunAsync("PIPE-013", "Классификация TCP Timeout", () =>
            {
                var classifier = new StandardBlockageClassifier();
                var host = new HostDiscovered(
                    Key: "203.0.113.10:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.10"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = new HostTested(
                    Host: host,
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

                var blocked = classifier.ClassifyBlockage(tested);
                if (BlockageCode.Normalize(blocked.TestResult.BlockageType) != BlockageCode.TcpConnectTimeout)
                {
                    return new SmokeTestResult("PIPE-013", "Классификация TCP Timeout", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали {BlockageCode.TcpConnectTimeout}, получили '{blocked.TestResult.BlockageType ?? "<null>"}'");
                }

                return new SmokeTestResult("PIPE-013", "Классификация TCP Timeout", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: TCP_CONNECT_TIMEOUT классифицируется корректно");
            }, ct);

        public static Task<SmokeTestResult> Pipe_Classifier_TcpReset(CancellationToken ct)
            => RunAsync("PIPE-014", "Классификация TCP Reset", () =>
            {
                var classifier = new StandardBlockageClassifier();
                var host = new HostDiscovered(
                    Key: "203.0.113.10:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.10"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: false,
                    TlsOk: false,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: null,
                    SniHostname: null,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 0,
                    BlockageType: BlockageCode.TcpConnectionReset,
                    TestedAt: DateTime.UtcNow);

                var blocked = classifier.ClassifyBlockage(tested);
                if (BlockageCode.Normalize(blocked.TestResult.BlockageType) != BlockageCode.TcpConnectionReset)
                {
                    return new SmokeTestResult("PIPE-014", "Классификация TCP Reset", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали {BlockageCode.TcpConnectionReset}, получили '{blocked.TestResult.BlockageType ?? "<null>"}'");
                }

                return new SmokeTestResult("PIPE-014", "Классификация TCP Reset", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: TCP_CONNECTION_RESET классифицируется корректно");
            }, ct);

        public static Task<SmokeTestResult> Pipe_Classifier_DpiFilter_Tls(CancellationToken ct)
            => RunAsync("PIPE-015", "Классификация DPI_FILTER (TLS-блокировка)", () =>
            {
                var classifier = new StandardBlockageClassifier();
                var host = new HostDiscovered(
                    Key: "203.0.113.10:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.10"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow)
                {
                    Hostname = "example.com",
                    SniHostname = "example.com",
                };

                var tested = new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: false,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: host.Hostname,
                    SniHostname: host.SniHostname,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 10,
                    BlockageType: BlockageCode.TlsHandshakeTimeout,
                    TestedAt: DateTime.UtcNow);

                var blocked = classifier.ClassifyBlockage(tested);
                if (BlockageCode.Normalize(blocked.TestResult.BlockageType) != BlockageCode.TlsHandshakeTimeout)
                {
                    return new SmokeTestResult("PIPE-015", "Классификация DPI_FILTER (TLS-блокировка)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали {BlockageCode.TlsHandshakeTimeout}, получили '{blocked.TestResult.BlockageType ?? "<null>"}'");
                }

                return new SmokeTestResult("PIPE-015", "Классификация DPI_FILTER (TLS-блокировка)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: TLS_HANDSHAKE_TIMEOUT классифицируется корректно");
            }, ct);
    }
}
