using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
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
        private readonly IProgress<string>? _progress;
        private readonly System.Collections.Generic.IReadOnlyDictionary<string, string>? _dnsCache;
        private readonly TimeSpan _testTimeout;
        private readonly RemoteCertificateValidationCallback? _remoteCertificateValidationCallback;

        private const int TcpMaxAttempts = 2;
        private const int TlsMaxAttempts = 2;

        public StandardHostTester(
            IProgress<string>? progress,
            System.Collections.Generic.IReadOnlyDictionary<string, string>? dnsCache = null,
            TimeSpan? testTimeout = null,
            RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null)
        {
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
                    // Важно: Dns.GetHostEntryAsync иногда игнорирует CancellationToken (зависит от ОС/резолвера).
                    // Поэтому делаем жёсткий таймаут через WhenAny и не блокируем тест.
                    var rdnsTimeout = TimeSpan.FromMilliseconds(1500);
                    var rdnsTask = System.Net.Dns.GetHostEntryAsync(ipString, CancellationToken.None);
                    var (rdnsCompleted, rdnsEntry) = await WithTimeoutAsync(rdnsTask, rdnsTimeout, ct).ConfigureAwait(false);
                    if (rdnsCompleted && rdnsEntry != null && !string.IsNullOrWhiteSpace(rdnsEntry.HostName))
                    {
                        reverseDnsHostname = rdnsEntry.HostName;
                    }
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

                        var dnsTask = System.Net.Dns.GetHostEntryAsync(hostname, CancellationToken.None);
                        var (dnsCompleted, _) = await WithTimeoutAsync(dnsTask, dnsTimeout, ct).ConfigureAwait(false);
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
                    var tcpDeadline = DateTime.UtcNow + _testTimeout;
                    for (int attempt = 1; attempt <= TcpMaxAttempts; attempt++)
                    {
                        var remaining = tcpDeadline - DateTime.UtcNow;
                        if (remaining <= TimeSpan.FromMilliseconds(200))
                        {
                            break;
                        }

                        try
                        {
                            using var tcpClient = new System.Net.Sockets.TcpClient();
                            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            linkedCts.CancelAfter(remaining);

                            await tcpClient.ConnectAsync(host.RemoteIp, host.RemotePort, linkedCts.Token).ConfigureAwait(false);
                            tcpOk = true;
                            tcpLatencyMs = (int)sw.ElapsedMilliseconds;
                            break;
                        }
                        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                        {
                            // Таймаут попытки. Дадим ещё один шанс в рамках общего тайм-бюджета.
                        }
                        catch (System.Net.Sockets.SocketException ex)
                        {
                            tcpOk = false;
                            if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionRefused)
                            {
                                // Порт закрыт, но хост доступен
                                blockageType = BlockageCode.PortClosed;
                            }
                            else if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
                            {
                                // Нейтральная фактура: соединение сброшено (ConnectionReset).
                                blockageType = BlockageCode.TcpConnectionReset;
                            }
                            else
                            {
                                blockageType = BlockageCode.TcpError;
                            }
                            break;
                        }
                    }

                    if (!tcpOk && blockageType == null)
                    {
                        blockageType = BlockageCode.TcpConnectTimeout;
                    }
                }

                // 3. TLS handshake (обычно только для 443). Для тестов/нестандартных портов допускаем TLS probe,
                // если задано SNI (это явный сигнал, что соединение TLS).
                var shouldProbeTls = host.RemotePort == 443 || !string.IsNullOrEmpty(host.SniHostname);
                if (tcpOk && shouldProbeTls && !string.IsNullOrEmpty(hostname) && hostnameFromCacheOrInput)
                {
                    var tlsDeadline = DateTime.UtcNow + _testTimeout;
                    for (int attempt = 1; attempt <= TlsMaxAttempts; attempt++)
                    {
                        var remaining = tlsDeadline - DateTime.UtcNow;
                        if (remaining <= TimeSpan.FromMilliseconds(300))
                        {
                            break;
                        }

                        try
                        {
                            using var tcpClient = new System.Net.Sockets.TcpClient();
                            using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            attemptCts.CancelAfter(remaining);

                            await tcpClient.ConnectAsync(host.RemoteIp, host.RemotePort, attemptCts.Token).ConfigureAwait(false);
                            using var sslStream = new System.Net.Security.SslStream(
                                tcpClient.GetStream(),
                                leaveInnerStreamOpen: false,
                                userCertificateValidationCallback: _remoteCertificateValidationCallback);

                            var sslOptions = new System.Net.Security.SslClientAuthenticationOptions
                            {
                                TargetHost = hostname,
                                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
                            };

                            await sslStream.AuthenticateAsClientAsync(sslOptions, attemptCts.Token).ConfigureAwait(false);
                            tlsOk = true;
                            break;
                        }
                        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                        {
                            // Таймаут попытки. Дадим ещё один шанс в рамках общего тайм-бюджета.
                            blockageType = BlockageCode.TlsHandshakeTimeout;
                        }
                        catch (System.Security.Authentication.AuthenticationException)
                        {
                            tlsOk = false;
                            // Нейтральная фактура: TLS рукопожатие завершилось AuthenticationException.
                            // Это НЕ доказательство DPI; причины могут быть разными (MITM/прокси/фильтрация/несовпадение параметров).
                            blockageType = BlockageCode.TlsAuthFailure;
                            break;
                        }
                        catch
                        {
                            tlsOk = false;
                            blockageType = blockageType ?? BlockageCode.TlsError;
                        }
                    }
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
                    await ProbeHttp3Async(hostname, h3Timeout, ct).ConfigureAwait(false);
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

            static async Task<(bool Completed, T? Result)> WithTimeoutAsync<T>(Task<T> task, TimeSpan timeout, CancellationToken ct)
            {
                // ct: уважать внешнюю отмену (например пользователь нажал Stop)
                if (ct.IsCancellationRequested)
                {
                    throw new OperationCanceledException(ct);
                }

                var delayTask = Task.Delay(timeout, ct);
                var completed = await Task.WhenAny(task, delayTask).ConfigureAwait(false);
                if (completed == task)
                {
                    return (true, await task.ConfigureAwait(false));
                }

                // Таймаут: не ждём дальше, но обязательно «наблюдаем» возможные исключения,
                // чтобы не получить UnobservedTaskException, когда DNS завершится позже.
                _ = task.ContinueWith(
                    t =>
                    {
                        _ = t.Exception;
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted,
                    TaskScheduler.Default);

                return (false, default);
            }

            async Task ProbeHttp3Async(string targetHost, TimeSpan timeout, CancellationToken outerCt)
            {
                // Фиксируем факт попытки даже если она упадёт.
                http3Ok = null;
                http3Status = "H3_NOT_ATTEMPTED";
                http3LatencyMs = null;
                http3Error = null;

                try
                {
                    using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(outerCt);
                    attemptCts.CancelAfter(timeout);

                    var h3Sw = Stopwatch.StartNew();

                    // SocketsHttpHandler использует MsQuic на Windows для HTTP/3.
                    using var handler = new SocketsHttpHandler
                    {
                        AllowAutoRedirect = false,
                        AutomaticDecompression = DecompressionMethods.None,
                        UseCookies = false,
                        ConnectTimeout = timeout
                    };

                    handler.SslOptions = new System.Net.Security.SslClientAuthenticationOptions
                    {
                        TargetHost = targetHost,
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                        CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
                    };

                    using var http = new HttpClient(handler, disposeHandler: false)
                    {
                        // Управляем таймаутом через CancellationToken, чтобы отличать отмену от общего ct.
                        Timeout = Timeout.InfiniteTimeSpan
                    };

                    var uri = new Uri($"https://{targetHost}/");
                    using var req = new HttpRequestMessage(HttpMethod.Head, uri)
                    {
                        Version = HttpVersion.Version30,
                        VersionPolicy = HttpVersionPolicy.RequestVersionExact
                    };

                    using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, attemptCts.Token).ConfigureAwait(false);

                    h3Sw.Stop();
                    http3LatencyMs = (int)Math.Max(0, Math.Round(h3Sw.Elapsed.TotalMilliseconds, MidpointRounding.AwayFromZero));

                    if (resp.Version.Major == 3)
                    {
                        http3Ok = true;
                        http3Status = "H3_OK";
                    }
                    else
                    {
                        // При RequestVersionExact сюда почти не должны попадать, но оставляем как защиту.
                        http3Ok = false;
                        http3Status = $"H3_DOWNGRADED_{resp.Version}";
                    }
                }
                catch (PlatformNotSupportedException ex)
                {
                    // MsQuic/HTTP3 недоступен на системе — это НЕ диагноз блокировки провайдера.
                    http3Ok = null;
                    http3Status = "H3_NOT_SUPPORTED";
                    http3Error = ex.GetType().Name;
                }
                catch (NotSupportedException ex)
                {
                    http3Ok = null;
                    http3Status = "H3_NOT_SUPPORTED";
                    http3Error = ex.GetType().Name;
                }
                catch (OperationCanceledException) when (!outerCt.IsCancellationRequested)
                {
                    http3Ok = false;
                    http3Status = "H3_TIMEOUT";
                }
                catch (HttpRequestException ex)
                {
                    http3Ok = false;
                    http3Status = "H3_FAILED";
                    http3Error = ex.GetType().Name;
                }
                catch (Exception ex)
                {
                    http3Ok = false;
                    http3Status = "H3_FAILED";
                    http3Error = ex.GetType().Name;
                }
            }
        }
    }
}
