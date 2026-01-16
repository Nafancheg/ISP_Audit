using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Активная outcome-проверка для HTTPS: пытаемся установить TCP+TLS соединение и получить любой HTTP ответ.
    /// Это НЕ пассивный анализ (и не MITM), поэтому вывод «SUCCESS/FAILED» не основан на перехвате HTTPS контента.
    /// </summary>
    internal static class HttpsOutcomeProbe
    {
        internal static async Task<OutcomeStatusSnapshot> RunAsync(
            string host,
            Action<IPEndPoint, IPEndPoint>? onConnected,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "не задан host для outcome-probe");
            }

            using var timeoutCts = timeout > TimeSpan.Zero
                ? new CancellationTokenSource(timeout)
                : null;

            using var linked = timeoutCts != null
                ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            var ct = linked.Token;

            try
            {
                ct.ThrowIfCancellationRequested();

                // Предпочитаем IPv4, чтобы корректно работать в текущем WinDivert/фильтре.
                var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (ip == null)
                {
                    return new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "у цели нет IPv4 адреса (IPv6-only)");
                }

                using var client = new TcpClient(AddressFamily.InterNetwork);
                await client.ConnectAsync(ip, 443, ct).ConfigureAwait(false);

                if (client.Client.LocalEndPoint is IPEndPoint local && client.Client.RemoteEndPoint is IPEndPoint remote)
                {
                    onConnected?.Invoke(local, remote);
                }

                await using var network = client.GetStream();

                using var ssl = new SslStream(network, leaveInnerStreamOpen: true);

                var sslOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };

                await ssl.AuthenticateAsClientAsync(sslOptions, ct).ConfigureAwait(false);

                // Любой корректный HTTP-ответ считаем успехом (код неважен: 200/301/403/404 и т.д.).
                // Если DPI/блокировка ломает TLS/соединение, мы получим исключение или таймаут.
                var request =
                    $"GET / HTTP/1.1\r\n" +
                    $"Host: {host}\r\n" +
                    "User-Agent: ISP_Audit-outcome-probe\r\n" +
                    "Connection: close\r\n\r\n";

                var bytes = Encoding.ASCII.GetBytes(request);
                await ssl.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
                await ssl.FlushAsync(ct).ConfigureAwait(false);

                using var reader = new StreamReader(ssl, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
                var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);

                if (string.IsNullOrWhiteSpace(line))
                {
                    return new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", "TLS OK, но HTTP ответ пустой");
                }

                var text = line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) ? line.Trim() : "HTTP (unknown)";
                return new OutcomeStatusSnapshot(OutcomeStatus.Success, "SUCCESS", $"{text}");
            }
            catch (OperationCanceledException)
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "outcome-probe отменён/таймаут");
            }
            catch (SocketException ex)
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"socket: {ex.SocketErrorCode}");
            }
            catch (AuthenticationException ex)
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"tls: {ex.Message}");
            }
            catch (IOException ex)
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"io: {ex.Message}");
            }
            catch (Exception ex)
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"error: {ex.Message}");
            }
        }

        internal static uint ToIpv4UInt32NetworkOrder(IPAddress address)
        {
            var bytes = address.GetAddressBytes();
            if (bytes.Length != 4) throw new ArgumentException("Только IPv4", nameof(address));
            return BinaryPrimitives.ReadUInt32BigEndian(bytes);
        }
    }
}
