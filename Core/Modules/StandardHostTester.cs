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

        public StandardHostTester(IProgress<string>? progress)
        {
            _progress = progress;
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
                // 1. Reverse DNS (быстро)
                try
                {
                    var hostEntry = await System.Net.Dns.GetHostEntryAsync(host.RemoteIp.ToString()).ConfigureAwait(false);
                    hostname = hostEntry.HostName;
                }
                catch
                {
                    // Не критично, продолжаем
                }

                // 2. TCP connect (таймаут 3с)
                try
                {
                    using var tcpClient = new System.Net.Sockets.TcpClient();
                    var connectTask = tcpClient.ConnectAsync(host.RemoteIp, host.RemotePort);
                    
                    var timeoutTask = Task.Delay(3000, ct);
                    var completedTask = await Task.WhenAny(connectTask, timeoutTask).ConfigureAwait(false);
                    
                    if (completedTask == connectTask)
                    {
                        await connectTask.ConfigureAwait(false); // Проверяем исключения
                        tcpOk = true;
                        tcpLatencyMs = (int)sw.ElapsedMilliseconds;
                    }
                    else
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
                        await tcpClient.ConnectAsync(host.RemoteIp, 443, ct).ConfigureAwait(false);
                        
                        using var sslStream = new System.Net.Security.SslStream(tcpClient.GetStream(), false);
                        var tlsTask = sslStream.AuthenticateAsClientAsync(hostname, null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
                        
                        var timeoutTask = Task.Delay(3000, ct);
                        var completedTask = await Task.WhenAny(tlsTask, timeoutTask).ConfigureAwait(false);
                        
                        if (completedTask == tlsTask)
                        {
                            await tlsTask.ConfigureAwait(false);
                            tlsOk = true;
                        }
                        else
                        {
                            blockageType = "TLS_TIMEOUT";
                        }
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