using System;
using System.Net;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Core.Interfaces
{
    public interface IStandardHostTesterProbeService
    {
        Task<string?> TryReverseDnsAsync(string ipString, TimeSpan timeout, CancellationToken ct);

        Task<bool> CheckForwardDnsAsync(string hostname, TimeSpan timeout, CancellationToken ct);

        Task<TcpProbeResult> ProbeTcpAsync(IPAddress ip, int port, TimeSpan totalTimeout, int maxAttempts, CancellationToken ct);

        Task<TlsProbeResult> ProbeTlsAsync(
            IPAddress ip,
            int port,
            string hostname,
            TimeSpan totalTimeout,
            int maxAttempts,
            RemoteCertificateValidationCallback? remoteCertificateValidationCallback,
            CancellationToken ct);

        Task<HttpProbeResult> ProbeHttpAsync(string targetHost, TimeSpan timeout, CancellationToken ct);

        Task<Http3ProbeResult> ProbeHttp3Async(string targetHost, TimeSpan timeout, CancellationToken ct);
    }

    public readonly record struct TcpProbeResult(bool Ok, string? BlockageType);

    public readonly record struct TlsProbeResult(bool Ok, string? BlockageType);

    public readonly record struct HttpProbeResult(bool Ok, string Status, int? StatusCode, string MethodUsed, string? Error);

    public readonly record struct Http3ProbeResult(bool? Ok, string Status, int? LatencyMs, string? Error);
}
