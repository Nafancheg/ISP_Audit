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
        public List<UdpProbeResult> udp_tests { get; set; } = new();
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
        public string display_name { get; set; } = string.Empty;
        public string service { get; set; } = string.Empty;
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

            // UDP: анализируем ожидаемые ответы
            if (run.udp_tests == null || run.udp_tests.Count == 0)
            {
                summary.udp = "UNKNOWN";
            }
            else if (run.udp_tests.Any(r => r.expect_reply))
            {
                bool fail = run.udp_tests.Any(r => r.expect_reply && !r.success);
                bool ok = run.udp_tests.Any(r => r.expect_reply && r.success);
                summary.udp = fail ? "FAIL" : (ok ? "OK" : "UNKNOWN");
            }
            else
            {
                summary.udp = "INFO";
            }

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
            string FormatTarget(KeyValuePair<string, TargetReport> kv)
                => string.IsNullOrWhiteSpace(kv.Value.service) ? kv.Key : $"{kv.Key} ({kv.Value.service})";
            var udpTests = run.udp_tests ?? new List<UdpProbeResult>();

            // DNS advice
            var dnsBadTargets = run.targets
                .Where(kv => kv.Value.dns_status == nameof(DnsStatus.DNS_BOGUS) || kv.Value.dns_status == nameof(DnsStatus.DNS_FILTERED))
                .Select(FormatTarget)
                .ToList();
            if (dnsBadTargets.Count > 0)
            {
                lines.Add($"DNS: обнаружены проблемы у сервисов: {string.Join(", ", dnsBadTargets)}.");
                lines.Add("— Системный DNS пуст или возвращает приватные/некорректные адреса. Возможна фильтрация провайдером или некорректный локальный DNS.");
                lines.Add("— Сравните результаты с DoH (Cloudflare) и при необходимости переключите лаунчер/игру на DoH/DoT или альтернативный резолвер.");
                lines.Add("— Обход: DoH/DoT, DNSCrypt, VPN, либо локальный резолвер (unbound) с TLS.");
            }
            else if (run.summary.dns == nameof(DnsStatus.WARN))
            {
                var warnTargets = run.targets
                    .Where(kv => kv.Value.dns_status == nameof(DnsStatus.WARN))
                    .Select(FormatTarget)
                    .ToList();
                var suffix = warnTargets.Count > 0 ? $" ({string.Join(", ", warnTargets)})" : string.Empty;
                lines.Add($"DNS: предупреждение{suffix} — системный и DoH ответы не совпадают. Это может быть CDN, но проверьте гео/валидность IP.");
            }

            // TCP advice (лаунчер/CDN/игровые сервера)
            var tcpFailures = run.targets
                .Where(kv => kv.Value.tcp.Count > 0 && !kv.Value.tcp.Any(r => r.open))
                .Select(FormatTarget)
                .ToList();
            if (tcpFailures.Count > 0)
            {
                lines.Add($"TCP: порты закрыты для: {string.Join(", ", tcpFailures)}.");
                lines.Add("— Проверьте, что порты 80/443 и диапазон 8000–8020 для лаунчера/патчера Star Citizen не блокируются файрволом или провайдером.");
                lines.Add("— Обход: открыть порты на роутере, временно отключить фильтрацию, протестировать через VPN/другую сеть.");
            }

            // UDP advice (DNS + игровые шлюзы)
            var udpExpectedFails = udpTests
                .Where(u => u.expect_reply && !u.success)
                .ToList();
            if (udpExpectedFails.Count > 0)
            {
                lines.Add($"UDP: нет ответа от {string.Join(", ", udpExpectedFails.Select(u => $"{u.name} ({u.service})"))}.");
                lines.Add("— Возможна блокировка UDP/QUIC на порту 53 или ограничение провайдера. Проверьте настройки роутера и брандмауэра.");
            }

            var udpRawErrors = udpTests
                .Where(u => !u.expect_reply && !u.success)
                .ToList();
            if (udpRawErrors.Count > 0)
            {
                lines.Add($"UDP: не удалось отправить пакеты к шлюзам Star Citizen: {string.Join(", ", udpRawErrors.Select(u => $"{u.name} ({u.host}:{u.port})"))}.");
                lines.Add("— Убедитесь, что провайдер не блокирует исходящие UDP 64090+ и что NAT/UPnP открывает сессии для игры.");
            }

            // TLS advice
            if (run.summary.tls == "SUSPECT")
            {
                var tlsSuspects = run.targets
                    .Where(kv => kv.Value.tcp.Any(r => r.port == 443 && r.open) && !kv.Value.http.Any(h => h.success && h.status is >= 200 and < 400))
                    .Select(FormatTarget)
                    .ToList();
                var suffix = tlsSuspects.Count > 0 ? $": {string.Join(", ", tlsSuspects)}" : string.Empty;
                lines.Add($"TLS: подозрение на блокировку TLS/SNI{suffix} — TCP:443 открыт, но HTTPS не отвечает.");
                lines.Add("— Попробуйте VPN, прокси по HTTPS/HTTP2, либо дождитесь разблокировки. Для лаунчера можно временно переключиться на альтернативную сеть.");
            }

            if (lines.Count == 0)
            {
                lines.Add("Явных проблем не выявлено. Все основные сервисы Star Citizen отвечают корректно.");
            }

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
                var serviceLabel = string.IsNullOrWhiteSpace(t.service) ? string.Empty : $" [{t.service}]";
                W($"Target: {kv.Key}{serviceLabel}");
                W($"  host: {t.host}");
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

            if (run.udp_tests != null && run.udp_tests.Count > 0)
            {
                W("UDP проверки:");
                foreach (var u in run.udp_tests)
                {
                    var status = u.success ? (u.reply ? "ответ получен" : "пакет отправлен") : (u.note ?? "ошибка");
                    var rttText = u.rtt_ms.HasValue ? $"{u.rtt_ms} мс" : "—";
                    var expect = u.expect_reply ? "да" : "нет";
                    W($"  {u.name} [{u.service}] {u.host}:{u.port} -> {status} (ожидался ответ: {expect}, RTT={rttText}, bytes={u.reply_bytes})");
                    if (!string.IsNullOrWhiteSpace(u.description))
                        W($"    описание: {u.description}");
                }
                W();
            }

            return sb.ToString();
        }
    }
}
