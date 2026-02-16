using System;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;

namespace IspAudit.Core.Modules
{
    public class StandardHostTester : IHostTester
    {
        private readonly IStandardHostTesterProbeService _probes;
        private readonly IProgress<string>? _progress;
        private readonly System.Collections.Generic.IReadOnlyDictionary<string, string>? _dnsCache;
        private readonly TimeSpan _testTimeout;
        private readonly RemoteCertificateValidationCallback? _remoteCertificateValidationCallback;

        private const int TcpMaxAttempts = 2;
        private const int TlsMaxAttempts = 2;

        public StandardHostTester(
            IStandardHostTesterProbeService probes,
            IProgress<string>? progress,
            System.Collections.Generic.IReadOnlyDictionary<string, string>? dnsCache = null,
            TimeSpan? testTimeout = null,
            RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null)
        {
            _probes = probes ?? throw new ArgumentNullException(nameof(probes));
            _progress = progress;
            _dnsCache = dnsCache;
            _testTimeout = testTimeout.HasValue && testTimeout.Value > TimeSpan.Zero
                ? testTimeout.Value
                : TimeSpan.FromSeconds(3);
            _remoteCertificateValidationCallback = remoteCertificateValidationCallback;
        }

        public async Task<HostTested> TestHostAsync(HostDiscovered host, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            bool dnsOk = true;
            bool tcpOk = false;
            bool tlsOk = false;
            bool? http3Ok = null;
            string dnsStatus = BlockageCode.StatusOk;
            string? hostname = null;
            string? sniHostname = null;
            string? reverseDnsHostname = null;
            string? blockageType = null;
            int tcpLatencyMs = 0;
            string? http3Status = null;
            int? http3LatencyMs = null;
            string? http3Error = null;

            try
            {
                var hostnameFromCacheOrInput = false;

                var ipString = host.RemoteIp.ToString();

                // 0. Проверка переданного hostname или DNS кеша
                if (!string.IsNullOrEmpty(host.SniHostname))
                {
                    sniHostname = host.SniHostname;
                    hostname = host.SniHostname;
                    hostnameFromCacheOrInput = true;
                }
                else if (!string.IsNullOrEmpty(host.Hostname))
                {
                    hostname = host.Hostname;
                    hostnameFromCacheOrInput = true;
                }
                else if (_dnsCache != null && _dnsCache.TryGetValue(host.RemoteIp.ToString(), out var cachedName))
                {
                    hostname = cachedName;
                    hostnameFromCacheOrInput = true;
                }

                // 1. Reverse DNS (PTR) — сохраняем отдельно, даже если hostname уже есть.
                // ВАЖНО: reverse DNS не используем как "достоверное" имя для TLS/SNI.
                try
                {
                    var rdnsTimeout = TimeSpan.FromMilliseconds(1500);
                    reverseDnsHostname = await _probes.TryReverseDnsAsync(ipString, rdnsTimeout, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // Таймаут reverse DNS — это нормально.
                }
                catch
                {
                    System.Diagnostics.Debug.WriteLine($"[HostTester] Reverse DNS error for {ipString}");
                }

                // Если совсем нет hostname (SNI/DNS), можем использовать reverse DNS только как fallback для UI
                if (string.IsNullOrEmpty(hostname) && !string.IsNullOrWhiteSpace(reverseDnsHostname))
                {
                    hostname = reverseDnsHostname;
                }

                // 1.1 Проверка Forward DNS (если есть hostname) - реальная проверка на DNS блокировку
                if (!string.IsNullOrEmpty(hostname) && hostnameFromCacheOrInput)
                {
                    try
                    {
                        var dnsTimeoutMs = (int)Math.Clamp(_testTimeout.TotalMilliseconds, 2000, 4000);
                        var dnsTimeout = TimeSpan.FromMilliseconds(dnsTimeoutMs);

                        var dnsCompleted = await _probes.CheckForwardDnsAsync(hostname, dnsTimeout, ct).ConfigureAwait(false);
                        if (!dnsCompleted)
                        {
                            dnsOk = false;
                            dnsStatus = BlockageCode.DnsTimeout;
                        }
                        // Если успешно разрезолвилось - DNS работает
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        dnsOk = false;
                        dnsStatus = BlockageCode.DnsTimeout;
                    }
                    catch
                    {
                        dnsOk = false;
                        dnsStatus = BlockageCode.DnsError;
                    }
                }

                // 2. TCP connect (ретраи в рамках общего таймаута)
                {
                    var tcp = await _probes.ProbeTcpAsync(host.RemoteIp, host.RemotePort, _testTimeout, TcpMaxAttempts, ct).ConfigureAwait(false);
                    tcpOk = tcp.Ok;
                    if (tcpOk)
                    {
                        tcpLatencyMs = (int)sw.ElapsedMilliseconds;
                    }
                    blockageType = tcp.BlockageType;
                }

                // 3. TLS handshake (обычно только для 443). Для тестов/нестандартных портов допускаем TLS probe,
                // если задано SNI (это явный сигнал, что соединение TLS).
                var shouldProbeTls = host.RemotePort == 443 || !string.IsNullOrEmpty(host.SniHostname);
                if (tcpOk && shouldProbeTls && !string.IsNullOrEmpty(hostname) && hostnameFromCacheOrInput)
                {
                    var tls = await _probes.ProbeTlsAsync(
                        host.RemoteIp,
                        host.RemotePort,
                        hostname,
                        _testTimeout,
                        TlsMaxAttempts,
                        _remoteCertificateValidationCallback,
                        ct).ConfigureAwait(false);

                    tlsOk = tls.Ok;
                    blockageType ??= tls.BlockageType;
                }
                else if (host.RemotePort == 443)
                {
                    // Не можем проверить TLS без hostname.
                    // Фикс недетерминированности делаем не через «псевдо-ошибку», а через стабилизацию SNI-кеша и таймаутов.
                    tlsOk = tcpOk;
                }
                else
                {
                    // Не HTTPS - считаем OK если TCP прошел
                    tlsOk = tcpOk;
                }

                // 4. HTTP/3 (QUIC) probe — отдельный тест от TCP/TLS.
                // Важно: QUIC использует TLS 1.3 внутри QUIC поверх UDP/443, но это не тот же самый канал, что TCP/TLS.
                // Поэтому фиксируем это отдельными полями и НЕ смешиваем с tlsOk.
                if (host.RemotePort == 443 && !string.IsNullOrEmpty(hostname) && hostnameFromCacheOrInput)
                {
                    var h3TimeoutMs = (int)Math.Clamp(_testTimeout.TotalMilliseconds, 700, 2000);
                    var h3Timeout = TimeSpan.FromMilliseconds(h3TimeoutMs);

                    var h3 = await _probes.ProbeHttp3Async(hostname, h3Timeout, ct).ConfigureAwait(false);
                    http3Ok = h3.Ok;
                    http3Status = h3.Status;
                    http3LatencyMs = h3.LatencyMs;
                    http3Error = h3.Error;
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[TESTER] Ошибка {host.RemoteIp}:{host.RemotePort}: {ex.Message}");
            }

            return new HostTested(
                host,
                dnsOk,
                tcpOk,
                tlsOk,
                dnsStatus,
                hostname,
                sniHostname,
                reverseDnsHostname,
                tcpLatencyMs,
                blockageType,
                DateTime.UtcNow,
                http3Ok,
                http3Status,
                http3LatencyMs,
                http3Error
            );
        }
    }
}
