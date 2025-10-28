using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace IspAudit.Tests
{
    public record HttpResult(string url, bool success, int? status, string? serverHeader, string? error, string? cert_cn);

    public class HttpTest
    {
        private readonly Config _cfg;
        public HttpTest(Config cfg) { _cfg = cfg; }

        public async Task<List<HttpResult>> CheckAsync(string host)
        {
            var results = new List<HttpResult>();
            var urls = new List<string>();
            urls.Add($"https://{host}");
            if (!host.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) urls.Add($"https://www.{host}");
            urls.Add($"https://{host}/generate_204");

            foreach (var url in urls)
            {
                HttpResult r;
                try
                {
                    X509Certificate2? cert = null;
                    var h = new HttpClientHandler
                    {
                        AutomaticDecompression = DecompressionMethods.All,
                        ServerCertificateCustomValidationCallback = (req, certificate, chain, errors) =>
                        {
                            try { cert = new X509Certificate2(certificate!); } catch { }
                            return true; // proceed; we only observe
                        }
                    };
                    using var client = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(_cfg.HttpTimeoutSeconds) };
                    using var resp = await client.GetAsync(url).ConfigureAwait(false);
                    string? serverHeader = resp.Headers.Server != null ? string.Join(" ", resp.Headers.Server) : null;
                    string? cn = cert?.GetNameInfo(X509NameType.SimpleName, false);
                    r = new HttpResult(url, true, (int)resp.StatusCode, serverHeader, null, cn);
                }
                catch (TaskCanceledException)
                {
                    r = new HttpResult(url, false, null, null, "timeout", null);
                }
                catch (Exception ex)
                {
                    r = new HttpResult(url, false, null, null, ex.Message, null);
                }
                results.Add(r);
            }

            return results;
        }
    }
}

