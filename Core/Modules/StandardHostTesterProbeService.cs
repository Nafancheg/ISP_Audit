using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;

namespace IspAudit.Core.Modules
{
    public sealed class StandardHostTesterProbeService : IStandardHostTesterProbeService
    {
        public async Task<string?> TryReverseDnsAsync(string ipString, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                // Важно: Dns.GetHostEntryAsync иногда игнорирует CancellationToken (зависит от ОС/резолвера).
                // Поэтому делаем жёсткий таймаут через WhenAny и не блокируем тест.
                var rdnsTask = Dns.GetHostEntryAsync(ipString, CancellationToken.None);
                var (completed, entry) = await WithTimeoutAsync(rdnsTask, timeout, ct).ConfigureAwait(false);
                if (completed && entry != null && !string.IsNullOrWhiteSpace(entry.HostName))
                {
                    return entry.HostName;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Таймаут reverse DNS — это нормально.
            }
            catch
            {
                Debug.WriteLine($"[HostTester] Reverse DNS error for {ipString}");
            }

            return null;
        }

        public async Task<bool> CheckForwardDnsAsync(string hostname, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                var dnsTask = Dns.GetHostEntryAsync(hostname, CancellationToken.None);
                var (completed, _) = await WithTimeoutAsync(dnsTask, timeout, ct).ConfigureAwait(false);
                return completed;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }

        public async Task<TcpProbeResult> ProbeTcpAsync(IPAddress ip, int port, TimeSpan totalTimeout, int maxAttempts, CancellationToken ct)
        {
            string? blockageType = null;

            var deadline = DateTime.UtcNow + totalTimeout;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.FromMilliseconds(200))
                {
                    break;
                }

                try
                {
                    using var tcpClient = new System.Net.Sockets.TcpClient();
                    using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    linkedCts.CancelAfter(remaining);

                    await tcpClient.ConnectAsync(ip, port, linkedCts.Token).ConfigureAwait(false);
                    return new TcpProbeResult(true, null);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // Таймаут попытки. Дадим ещё один шанс в рамках общего тайм-бюджета.
                }
                catch (System.Net.Sockets.SocketException ex)
                {
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

                    return new TcpProbeResult(false, blockageType);
                }
            }

            blockageType ??= BlockageCode.TcpConnectTimeout;
            return new TcpProbeResult(false, blockageType);
        }

        public async Task<TlsProbeResult> ProbeTlsAsync(
            IPAddress ip,
            int port,
            string hostname,
            TimeSpan totalTimeout,
            int maxAttempts,
            RemoteCertificateValidationCallback? remoteCertificateValidationCallback,
            CancellationToken ct)
        {
            string? blockageType = null;

            var deadline = DateTime.UtcNow + totalTimeout;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.FromMilliseconds(300))
                {
                    break;
                }

                try
                {
                    using var tcpClient = new System.Net.Sockets.TcpClient();
                    using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    attemptCts.CancelAfter(remaining);

                    await tcpClient.ConnectAsync(ip, port, attemptCts.Token).ConfigureAwait(false);
                    using var sslStream = new SslStream(
                        tcpClient.GetStream(),
                        leaveInnerStreamOpen: false,
                        userCertificateValidationCallback: remoteCertificateValidationCallback);

                    var sslOptions = new SslClientAuthenticationOptions
                    {
                        TargetHost = hostname,
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                        CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
                    };

                    await sslStream.AuthenticateAsClientAsync(sslOptions, attemptCts.Token).ConfigureAwait(false);
                    return new TlsProbeResult(true, blockageType);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // Таймаут попытки. Дадим ещё один шанс в рамках общего тайм-бюджета.
                    blockageType = BlockageCode.TlsHandshakeTimeout;
                }
                catch (System.Security.Authentication.AuthenticationException)
                {
                    // Нейтральная фактура: TLS рукопожатие завершилось AuthenticationException.
                    // Это НЕ доказательство DPI; причины могут быть разными (MITM/прокси/фильтрация/несовпадение параметров).
                    blockageType = BlockageCode.TlsAuthFailure;
                    return new TlsProbeResult(false, blockageType);
                }
                catch
                {
                    blockageType ??= BlockageCode.TlsError;
                }
            }

            blockageType ??= BlockageCode.TlsHandshakeTimeout;
            return new TlsProbeResult(false, blockageType);
        }

        public async Task<HttpProbeResult> ProbeHttpAsync(string targetHost, TimeSpan timeout, CancellationToken ct)
        {
            static bool IsHttpSuccessStatusCode(HttpStatusCode code)
            {
                var value = (int)code;
                return value is >= 200 and <= 399;
            }

            static bool ShouldFallbackToGet(HttpStatusCode code)
            {
                // Для web-like допускаем fallback, если HEAD не поддержан/запрещён/не дал успех.
                return code == HttpStatusCode.MethodNotAllowed
                       || code == HttpStatusCode.NotImplemented
                       || code == HttpStatusCode.Forbidden
                       || code == HttpStatusCode.NotFound
                       || (int)code >= 400;
            }

            static bool IsHttpsToHttpRedirect(HttpResponseMessage response)
            {
                var location = response.Headers.Location;
                if (location == null)
                {
                    return false;
                }

                if (!location.IsAbsoluteUri)
                {
                    return false;
                }

                return string.Equals(location.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
            }

            try
            {
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linkedCts.CancelAfter(timeout);

                using var handler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    AutomaticDecompression = DecompressionMethods.None,
                    UseCookies = false,
                    ConnectTimeout = timeout
                };

                handler.SslOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = targetHost,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                    CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
                };

                using var http = new HttpClient(handler, disposeHandler: false)
                {
                    Timeout = Timeout.InfiniteTimeSpan
                };

                var uri = new Uri($"https://{targetHost}/");

                using (var headReq = new HttpRequestMessage(HttpMethod.Head, uri))
                using (var headResp = await http.SendAsync(headReq, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token).ConfigureAwait(false))
                {
                    var isHeadDowngrade = IsHttpsToHttpRedirect(headResp);

                    if (IsHttpSuccessStatusCode(headResp.StatusCode))
                    {
                        return new HttpProbeResult(true, "HTTP_OK_HEAD", (int)headResp.StatusCode, "HEAD", null, isHeadDowngrade);
                    }

                    if (!ShouldFallbackToGet(headResp.StatusCode))
                    {
                        return new HttpProbeResult(false, "HTTP_FAILED_HEAD", (int)headResp.StatusCode, "HEAD", null, isHeadDowngrade);
                    }
                }

                using var getReq = new HttpRequestMessage(HttpMethod.Get, uri);
                using var getResp = await http.SendAsync(getReq, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token).ConfigureAwait(false);
                var isGetDowngrade = IsHttpsToHttpRedirect(getResp);

                if (IsHttpSuccessStatusCode(getResp.StatusCode))
                {
                    return new HttpProbeResult(true, "HTTP_OK_GET", (int)getResp.StatusCode, "GET", null, isGetDowngrade);
                }

                return new HttpProbeResult(false, "HTTP_FAILED_GET", (int)getResp.StatusCode, "GET", null, isGetDowngrade);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new HttpProbeResult(false, "HTTP_TIMEOUT", null, "HEAD/GET", null, false);
            }
            catch (HttpRequestException ex)
            {
                return new HttpProbeResult(false, "HTTP_FAILED", null, "HEAD/GET", ex.GetType().Name, false);
            }
            catch (Exception ex)
            {
                return new HttpProbeResult(false, "HTTP_FAILED", null, "HEAD/GET", ex.GetType().Name, false);
            }
        }

        public async Task<Http3ProbeResult> ProbeHttp3Async(string targetHost, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
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

                handler.SslOptions = new SslClientAuthenticationOptions
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
                var latencyMs = (int)Math.Max(0, Math.Round(h3Sw.Elapsed.TotalMilliseconds, MidpointRounding.AwayFromZero));

                if (resp.Version.Major == 3)
                {
                    return new Http3ProbeResult(true, "H3_OK", latencyMs, null);
                }

                // При RequestVersionExact сюда почти не должны попадать, но оставляем как защиту.
                return new Http3ProbeResult(false, $"H3_DOWNGRADED_{resp.Version}", latencyMs, null);
            }
            catch (PlatformNotSupportedException ex)
            {
                // MsQuic/HTTP3 недоступен на системе — это НЕ диагноз блокировки провайдера.
                return new Http3ProbeResult(null, "H3_NOT_SUPPORTED", null, ex.GetType().Name);
            }
            catch (NotSupportedException ex)
            {
                return new Http3ProbeResult(null, "H3_NOT_SUPPORTED", null, ex.GetType().Name);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new Http3ProbeResult(false, "H3_TIMEOUT", null, null);
            }
            catch (HttpRequestException ex)
            {
                return new Http3ProbeResult(false, "H3_FAILED", null, ex.GetType().Name);
            }
            catch (Exception ex)
            {
                return new Http3ProbeResult(false, "H3_FAILED", null, ex.GetType().Name);
            }
        }

        private static async Task<(bool Completed, T? Result)> WithTimeoutAsync<T>(Task<T> task, TimeSpan timeout, CancellationToken ct)
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
    }
}
