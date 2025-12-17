using System;
using System.Net;
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

        public StandardHostTester(IProgress<string>? progress, System.Collections.Generic.IReadOnlyDictionary<string, string>? dnsCache = null)
        {
            _progress = progress;
            _dnsCache = dnsCache;
        }

        public async Task<HostTested> TestHostAsync(HostDiscovered host, CancellationToken ct)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            bool dnsOk = true;
            bool tcpOk = false;
            bool tlsOk = false;
            string dnsStatus = BlockageCode.StatusOk;
            string? hostname = null;
            string? sniHostname = null;
            string? reverseDnsHostname = null;
            string? blockageType = null;
            int tcpLatencyMs = 0;

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
                    var rdnsTask = System.Net.Dns.GetHostEntryAsync(ipString);
                    var timeoutTask = Task.Delay(1500, ct);
                    var completedTask = await Task.WhenAny(rdnsTask, timeoutTask).ConfigureAwait(false);
                    if (completedTask == rdnsTask)
                    {
                        var hostEntry = await rdnsTask.ConfigureAwait(false);
                        if (!string.IsNullOrWhiteSpace(hostEntry.HostName))
                        {
                            reverseDnsHostname = hostEntry.HostName;
                        }
                    }
                }
                catch
                {
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
                        var dnsCheckTask = System.Net.Dns.GetHostEntryAsync(hostname);
                        var timeoutTask = Task.Delay(2000, ct);
                        
                        var completedTask = await Task.WhenAny(dnsCheckTask, timeoutTask).ConfigureAwait(false);
                        if (completedTask != dnsCheckTask)
                        {
                            dnsOk = false;
                            dnsStatus = BlockageCode.DnsTimeout;
                        }
                        else
                        {
                            await dnsCheckTask.ConfigureAwait(false);
                            // Если успешно разрезолвилось - DNS работает
                        }
                    }
                    catch
                    {
                        dnsOk = false;
                        dnsStatus = BlockageCode.DnsError;
                    }
                }

                // 2. TCP connect (таймаут 3с)
                try
                {
                    using var tcpClient = new System.Net.Sockets.TcpClient();
                    // Используем CancellationToken для корректной отмены
                    using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    linkedCts.CancelAfter(3000);

                    try 
                    {
                        await tcpClient.ConnectAsync(host.RemoteIp, host.RemotePort, linkedCts.Token).ConfigureAwait(false);
                        tcpOk = true;
                        tcpLatencyMs = (int)sw.ElapsedMilliseconds;
                    }
                    catch (OperationCanceledException)
                    {
                        // Нейтральная фактура: TCP connect не завершился за таймаут.
                        blockageType = BlockageCode.TcpConnectTimeout;
                    }
                }
                catch (System.Net.Sockets.SocketException ex)
                {
                    if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionRefused)
                    {
                        // Порт закрыт, но хост доступен
                        tcpOk = false;
                        blockageType = BlockageCode.PortClosed;
                    }
                    else if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
                    {
                        tcpOk = false;
                        // Нейтральная фактура: соединение сброшено (ConnectionReset).
                        blockageType = BlockageCode.TcpConnectionReset;
                    }
                    else
                    {
                        tcpOk = false;
                        blockageType = BlockageCode.TcpError;
                    }
                }

                // 3. TLS handshake (только для порта 443 и если TCP прошел)
                if (tcpOk && host.RemotePort == 443 && !string.IsNullOrEmpty(hostname) && hostnameFromCacheOrInput)
                {
                    try
                    {
                        using var tcpClient = new System.Net.Sockets.TcpClient();
                        // Используем CancellationToken
                        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        connectCts.CancelAfter(3000);
                        await tcpClient.ConnectAsync(host.RemoteIp, 443, connectCts.Token).ConfigureAwait(false);
                        
                        using var sslStream = new System.Net.Security.SslStream(tcpClient.GetStream(), false);
                        
                        // Используем опции для поддержки CancellationToken
                        var sslOptions = new System.Net.Security.SslClientAuthenticationOptions
                        {
                            TargetHost = hostname,
                            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                            CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
                        };

                        using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        tlsCts.CancelAfter(3000);
                        
                        await sslStream.AuthenticateAsClientAsync(sslOptions, tlsCts.Token).ConfigureAwait(false);
                        tlsOk = true;
                    }
                    catch (OperationCanceledException)
                    {
                        // Нейтральная фактура: TLS рукопожатие не завершилось за таймаут.
                        blockageType = BlockageCode.TlsHandshakeTimeout;
                    }
                    catch (System.Security.Authentication.AuthenticationException)
                    {
                        tlsOk = false;
                        // Нейтральная фактура: TLS рукопожатие завершилось AuthenticationException.
                        // Это НЕ доказательство DPI; причины могут быть разными (MITM/прокси/фильтрация/несовпадение параметров).
                        blockageType = BlockageCode.TlsAuthFailure;
                    }
                    catch
                    {
                        tlsOk = false;
                        blockageType = blockageType ?? BlockageCode.TlsError;
                    }
                }
                else if (host.RemotePort == 443)
                {
                    // Не можем проверить TLS без hostname
                    tlsOk = tcpOk;
                }
                else
                {
                    // Не HTTPS - считаем OK если TCP прошел
                    tlsOk = tcpOk;
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
                DateTime.UtcNow
            );
        }
    }
}