using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using IspAudit.Tests;

namespace IspAudit.Output
{
    public class RunReport
    {
        public DateTime run_at { get; set; }
        public string cli { get; set; } = string.Empty;
        public string ext_ip { get; set; } = string.Empty;
        public Summary summary { get; set; } = new Summary();
        public Dictionary<string, TargetReport> targets { get; set; } = new();
        public UdpDnsResult? udp_test { get; set; }
        public RstHeuristicResult? rst_heuristic { get; set; }
    }

    public class Summary
    {
        public string dns { get; set; } = "UNKNOWN";
        public string tcp { get; set; } = "UNKNOWN";
        public string udp { get; set; } = "UNKNOWN";
        public string tls { get; set; } = "UNKNOWN";
        public string rst_inject { get; set; } = "UNKNOWN";
    }

    public class TargetReport
    {
        public string host { get; set; } = string.Empty;
        public List<string> system_dns { get; set; } = new();
        public List<string> doh { get; set; } = new();
        public string dns_status { get; set; } = "UNKNOWN";
        public List<TcpResult> tcp { get; set; } = new();
        public List<HttpResult> http { get; set; } = new();
        public TraceResult? traceroute { get; set; }
    }

    public static class ReportWriter
    {
        private static readonly JsonSerializerOptions JsonOpts = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public static Summary BuildSummary(RunReport run)
        {
            var summary = new Summary();

            // DNS: worst status across targets
            string DnsRank(string s) => s switch
            {
                nameof(DnsStatus.DNS_BOGUS) => "DNS_BOGUS",
                nameof(DnsStatus.DNS_FILTERED) => "DNS_FILTERED",
                nameof(DnsStatus.WARN) => "WARN",
                nameof(DnsStatus.OK) => "OK",
                _ => "UNKNOWN"
            };
            var dnsStatuses = run.targets.Values.Select(t => DnsRank(t.dns_status)).ToList();
            summary.dns = dnsStatuses.Contains("DNS_BOGUS") ? "DNS_BOGUS" :
                          dnsStatuses.Contains("DNS_FILTERED") ? "DNS_FILTERED" :
                          dnsStatuses.Contains("WARN") ? "WARN" :
                          dnsStatuses.Count > 0 ? "OK" : "UNKNOWN";

            // TCP: OK if any open across all targets, else FAIL if any present, else UNKNOWN
            var tcpAll = run.targets.Values.SelectMany(t => t.tcp).ToList();
            if (tcpAll.Count == 0) summary.tcp = "UNKNOWN";
            else summary.tcp = tcpAll.Any(r => r.open) ? "OK" : "FAIL";

            // UDP: from udp_test
            summary.udp = run.udp_test == null ? "UNKNOWN" : (run.udp_test.reply ? "OK" : "FAIL");

            // TLS: SUSPECT if any target has failures while TCP 443 open; else OK if any 2xx/3xx
            bool anyTlsOk = false;
            bool suspect = false;
            foreach (var t in run.targets.Values)
            {
                bool tcp443Open = t.tcp.Any(r => r.port == 443 && r.open);
                bool httpOk = t.http.Any(h => h.success && h.status is >= 200 and < 400);
                if (httpOk) anyTlsOk = true;
                if (tcp443Open && !httpOk) suspect = true;
            }
            summary.tls = suspect ? "SUSPECT" : (anyTlsOk ? "OK" : (run.targets.Count == 0 ? "UNKNOWN" : "FAIL"));

            // RST heuristic: UNKNOWN if connect succeeded (ambiguous), else OK/UNKNOWN by elapsed
            if (run.rst_heuristic == null) summary.rst_inject = "UNKNOWN";
            else summary.rst_inject = "UNKNOWN"; // cannot be definitive without pcap

            return summary;
        }

        public static string BuildAdviceText(RunReport run)
        {
            var lines = new List<string>();

            // DNS advice
            var dnsBadTargets = run.targets.Where(kv => kv.Value.dns_status == nameof(DnsStatus.DNS_BOGUS) || kv.Value.dns_status == nameof(DnsStatus.DNS_FILTERED))
                                           .Select(kv => kv.Key).ToList();
            if (dnsBadTargets.Count > 0)
            {
                lines.Add($"DNS: обнаружены проблемы у: {string.Join(", ", dnsBadTargets)}.");
                lines.Add("— Системный DNS пуст или возвращает приватные/некорректные адреса. Возможна фильтрация провайдером.");
                lines.Add("— Сравните с DoH (Cloudflare). Рекомендуется сменить резолвер или включить DoH/DoT в ОС/браузере (Chrome/Firefox/Windows 11).");
                lines.Add("— Обход: DoH/DoT, DNSCrypt, VPN, или локальный резолвер (unbound) с TLS.");
            }
            else if (run.summary.dns == "WARN")
            {
                lines.Add("DNS: предупреждение — системный и DoH ответы не пересекаются. Это может быть геолокация/CDN, но проверьте, нет ли невалидных IP.");
            }

            // TCP advice
            if (run.summary.tcp == "FAIL")
            {
                lines.Add("TCP: все проверенные порты закрыты. Возможна блокировка на уровне сети/фаервола/провайдера.");
                lines.Add("— Проверьте локальный фаервол/VPN, анти-вирус, ограничения роутера.");
                lines.Add("— Обход: VPN/прокси, смена сети/роутера, проверка MTU.");
            }

            // UDP advice
            if (run.summary.udp == "FAIL")
            {
                lines.Add("UDP: нет ответа от 1.1.1.1:53 — возможна блокировка UDP/QUIC или проблемы DNS/периметра.");
                lines.Add("— Обход: переключиться на DoH/DoT (HTTPS/TLS), либо использовать VPN.");
            }

            // TLS advice
            if (run.summary.tls == "SUSPECT")
            {
                lines.Add("TLS: подозрение на блокировку TLS/SNI — TCP:443 открыт, но HTTPS-запросы не проходят.");
                lines.Add("— Обход: ESNI/ECH (если доступно), прокси по HTTPS/HTTP2, VPN, зеркала по HTTP/80 (временно).");
            }

            if (lines.Count == 0)
                lines.Add("Явных проблем не выявлено. Все основные проверки пройдены.");

            return string.Join(Environment.NewLine, lines);
        }

        public static async Task SaveJsonAsync(RunReport run, string path)
        {
            var json = JsonSerializer.Serialize(run, JsonOpts);
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            await File.WriteAllTextAsync(path, json);
        }

        public static string BuildShortSummaryJson(RunReport run)
        {
            var obj = new
            {
                run_at = run.run_at.ToString("o"),
                ext_ip = run.ext_ip,
                summary = run.summary,
            };
            return JsonSerializer.Serialize(obj, JsonOpts);
        }

        public static void PrintHuman(RunReport run, Config cfg)
        {
            Console.Write(BuildHumanText(run, cfg));
        }
        public static string BuildHumanText(RunReport run, Config cfg)
        {
            var sb = new System.Text.StringBuilder();
            void W(string s="") { sb.AppendLine(s); }

            W("Summary:");
            W($"  DNS: {run.summary.dns}");
            W($"  TCP: {run.summary.tcp}");
            W($"  UDP: {run.summary.udp}");
            W($"  TLS: {run.summary.tls}");
            W($"  RST: {run.summary.rst_inject}");
            W();

            foreach (var kv in run.targets)
            {
                var t = kv.Value;
                W($"Target: {kv.Key}");
                W($"  system_dns: [{string.Join(", ", t.system_dns)}]");
                W($"  doh:        [{string.Join(", ", t.doh)}]");
                W($"  dns_status: {t.dns_status}");

                W("  tcp:");
                foreach (var r in t.tcp)
                    W($"    {r.ip}:{r.port} -> {(r.open ? "open" : "closed")} ({r.elapsed_ms} ms)");

                W("  http:");
                foreach (var h in t.http)
                {
                    string status = h.success ? (h.status?.ToString() ?? "-") : (h.error ?? "error");
                    W($"    {h.url} => {status}{(string.IsNullOrEmpty(h.cert_cn) ? "" : $", cert={h.cert_cn}")}");
                }

                if (t.traceroute != null && t.traceroute.hops.Count > 0)
                {
                    W("  traceroute:");
                    foreach (var hop in t.traceroute.hops)
                        W($"    {hop.hop}\t{hop.ip}\t{hop.status}");
                }

                W();
            }

            if (run.udp_test != null)
            {
                var u = run.udp_test;
                W($"UDP DNS to {u.target}: reply={(u.reply ? "yes" : "no")} rtt={u.rtt_ms?.ToString() ?? "-"}ms bytes={u.replyBytes}");
                if (!string.IsNullOrEmpty(u.note)) W("  note: " + u.note);
                W();
            }

            return sb.ToString();
        }
    }
}
