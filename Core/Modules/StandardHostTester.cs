using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
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
            string dnsStatus = "OK";
            string? hostname = null;
            string? blockageType = null;
            int tcpLatencyMs = 0;

            try
            {
                // 0. Проверка переданного hostname или DNS кеша
                if (!string.IsNullOrEmpty(host.Hostname))
                {
                    hostname = host.Hostname;
                }
                else if (_dnsCache != null && _dnsCache.TryGetValue(host.RemoteIp.ToString(), out var cachedName))
                {
                    hostname = cachedName;
                }

                // 1. Reverse DNS (если нет в кеше)
                if (string.IsNullOrEmpty(hostname))
                {
                    try
                    {
                        // Используем таймаут 2с для DNS, чтобы не зависать
                        var dnsTask = System.Net.Dns.GetHostEntryAsync(host.RemoteIp.ToString());
                        var timeoutTask = Task.Delay(2000, ct);
                        
                        var completedTask = await Task.WhenAny(dnsTask, timeoutTask).ConfigureAwait(false);
                        if (completedTask == dnsTask)
                        {
                            var hostEntry = await dnsTask.ConfigureAwait(false);
                            hostname = hostEntry.HostName;
                        }
                    }
                    catch
                    {
                        // Не критично, продолжаем - отсутствие PTR записи не означает блокировку
                    }
                }

                // 1.1 Проверка Forward DNS (если есть hostname) - реальная проверка на DNS блокировку
                if (!string.IsNullOrEmpty(hostname))
                {
                    try
                    {
                        var dnsCheckTask = System.Net.Dns.GetHostEntryAsync(hostname);
                        var timeoutTask = Task.Delay(2000, ct);
                        
                        var completedTask = await Task.WhenAny(dnsCheckTask, timeoutTask).ConfigureAwait(false);
                        if (completedTask != dnsCheckTask)
                        {
                            dnsOk = false;
                            dnsStatus = "DNS_TIMEOUT";
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
                        dnsStatus = "DNS_ERROR";
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
                        blockageType = "TCP_TIMEOUT";
                    }
                }
                catch (System.Net.Sockets.SocketException ex)
                {
                    if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionRefused)
                    {
                        // Порт закрыт, но хост доступен
                        tcpOk = false;
                        blockageType = "PORT_CLOSED";
                    }
                    else if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
                    {
                        tcpOk = false;
                        blockageType = "TCP_RST";
                    }
                    else
                    {
                        tcpOk = false;
                        blockageType = "TCP_ERROR";
                    }
                }

                // 3. TLS handshake (только для порта 443 и если TCP прошел)
                if (tcpOk && host.RemotePort == 443 && !string.IsNullOrEmpty(hostname))
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
                        blockageType = "TLS_TIMEOUT";
                    }
                    catch (System.Security.Authentication.AuthenticationException)
                    {
                        tlsOk = false;
                        blockageType = "TLS_DPI";
                    }
                    catch
                    {
                        tlsOk = false;
                        blockageType = blockageType ?? "TLS_ERROR";
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
                tcpLatencyMs,
                blockageType,
                DateTime.UtcNow
            );
        }
    }
}