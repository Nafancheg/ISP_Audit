using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace IspAudit.Tests
{
    public record HttpResult(string url, bool success, int? status, string? serverHeader, string? error, string? cert_cn, bool? cert_cn_matches);

    public class HttpTest
    {
        private readonly Config _cfg;
        public HttpTest(Config cfg) { _cfg = cfg; }

        /// <summary>
        /// Validates if certificate CN matches the expected host.
        /// Supports wildcard certificates (*.example.com).
        /// </summary>
        private static bool ValidateCertificateCN(string certCN, string expectedHost)
        {
            if (string.IsNullOrWhiteSpace(certCN) || string.IsNullOrWhiteSpace(expectedHost))
                return false;

            // Exact match
            if (certCN.Equals(expectedHost, StringComparison.OrdinalIgnoreCase))
                return true;

            // Wildcard match (*.example.com matches www.example.com but not example.com)
            if (certCN.StartsWith("*.", StringComparison.OrdinalIgnoreCase))
            {
                var domain = certCN.Substring(2); // Remove "*."
                // Check if expectedHost ends with the domain and has a subdomain
                if (expectedHost.EndsWith(domain, StringComparison.OrdinalIgnoreCase))
                {
                    // Ensure there's a subdomain (e.g., www.example.com, not just example.com)
                    var prefix = expectedHost.Substring(0, expectedHost.Length - domain.Length);
                    if (prefix.Length > 0 && prefix.EndsWith("."))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

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

                    // Validate CN matches the host
                    bool? cnMatches = null;
                    if (cn != null)
                    {
                        cnMatches = ValidateCertificateCN(cn, host);
                    }

                    r = new HttpResult(url, true, (int)resp.StatusCode, serverHeader, null, cn, cnMatches);
                }
                catch (TaskCanceledException ex)
                {
                    r = new HttpResult(url, false, null, null, "timeout", null, null);
                }
                catch (Exception ex)
                {
                    r = new HttpResult(url, false, null, null, ex.Message, null, null);
                }
                results.Add(r);
            }

            return results;
        }
    }
}

