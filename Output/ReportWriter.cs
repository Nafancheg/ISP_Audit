using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
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
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public static string GetReadableStatus(string status)
        {
            return status switch
            {
                "OK" => "норма",
                "WARN" => "есть предупреждения",
                "FAIL" => "не пройдено",
                "SUSPECT" => "подозрение на блокировку",
                "DNS_BOGUS" => "ошибочные ответы",
                "DNS_FILTERED" => "возможна фильтрация",
                "INFO" => "информативно",
                "UNKNOWN" => "нет данных",
                _ => status
            };
        }

        public static string FormatPortList(IEnumerable<int> ports) => PortsToRangeText(ports);

        public static Summary BuildSummary(RunReport run)
        {
            var summary = new Summary();

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

            var tcpAll = run.targets.Values.SelectMany(t => t.tcp).ToList();
            if (tcpAll.Count == 0) summary.tcp = "UNKNOWN";
            else summary.tcp = tcpAll.Any(r => r.open) ? "OK" : "FAIL";

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

            if (run.rst_heuristic == null) summary.rst_inject = "UNKNOWN";
            else summary.rst_inject = "UNKNOWN";

            return summary;
        }

        public static string BuildAdviceText(RunReport run)
        {
            var lines = new List<string>();
            string FormatTarget(KeyValuePair<string, TargetReport> kv)
                => string.IsNullOrWhiteSpace(kv.Value.service) ? kv.Key : $"{kv.Key} ({kv.Value.service})";
            var udpTests = run.udp_tests ?? new List<UdpProbeResult>();

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
            var sb = new StringBuilder();
            void W(string s = "") { sb.AppendLine(s); }

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

        public static string BuildCompactSummaryText(RunReport run, string advice)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Итог проверки ISP Audit:");
            sb.AppendLine($"DNS — {GetReadableStatus(run.summary.dns)}");
            sb.AppendLine($"TCP — {GetReadableStatus(run.summary.tcp)}");
            sb.AppendLine($"UDP — {GetReadableStatus(run.summary.udp)}");
            sb.AppendLine($"TLS — {GetReadableStatus(run.summary.tls)}");
            if (!string.IsNullOrWhiteSpace(run.summary.rst_inject) && !string.Equals(run.summary.rst_inject, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"RST — {GetReadableStatus(run.summary.rst_inject)}");
            }

            var targets = BuildTargetSummaries(run);
            if (targets.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Цели:");
                foreach (var line in targets)
                {
                    sb.AppendLine("• " + line);
                }
            }

            var udp = BuildUdpSummaries(run);
            if (udp.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("UDP:");
                foreach (var line in udp)
                {
                    sb.AppendLine("• " + line);
                }
            }

            if (!string.IsNullOrWhiteSpace(advice))
            {
                sb.AppendLine();
                sb.AppendLine("Рекомендации:");
                sb.AppendLine(advice.Trim());
            }

            return sb.ToString().TrimEnd();
        }

        public static string BuildHtmlReport(RunReport run, Config cfg)
        {
            var advice = BuildAdviceText(run);
            var targetSummaries = BuildTargetSummaries(run);
            var udpSummaries = BuildUdpSummaries(run);

            static string ParagraphsToHtml(IEnumerable<string> paragraphs)
            {
                var sb = new StringBuilder();
                foreach (var paragraph in paragraphs)
                {
                    if (string.IsNullOrWhiteSpace(paragraph)) continue;
                    sb.Append("<p>");
                    sb.Append(paragraph);
                    sb.AppendLine("</p>");
                }
                return sb.ToString();
            }

            string adviceHtml = ParagraphsToHtml(advice.Split(Environment.NewLine).Select(line => HtmlEncode(line.Trim())));
            var sbHtml = new StringBuilder();
            sbHtml.AppendLine("<!DOCTYPE html>");
            sbHtml.AppendLine("<html lang=\"ru\">");
            sbHtml.AppendLine("<head>");
            sbHtml.AppendLine("  <meta charset=\"utf-8\">");
            sbHtml.AppendLine("  <title>ISP Audit — отчёт</title>");
            sbHtml.AppendLine("  <style>");
            sbHtml.AppendLine("    body { font-family: 'Segoe UI', 'DejaVu Sans', sans-serif; margin: 32px; color: #0f172a; background: #f8fafc; }");
            sbHtml.AppendLine("    h1 { font-size: 28px; margin-bottom: 4px; }");
            sbHtml.AppendLine("    h2 { margin-top: 32px; font-size: 22px; border-bottom: 2px solid #e2e8f0; padding-bottom: 4px; }");
            sbHtml.AppendLine("    h3 { margin-bottom: 4px; }");
            sbHtml.AppendLine("    .meta { color: #475569; margin: 0 0 16px 0; }");
            sbHtml.AppendLine("    .summary-grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); margin: 24px 0; }");
            sbHtml.AppendLine("    .summary-card { background: white; border-radius: 12px; padding: 16px; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.15); }");
            sbHtml.AppendLine("    .summary-card span { display: block; margin-top: 4px; font-weight: 600; }");
            sbHtml.AppendLine("    .status { font-weight: 600; }");
            sbHtml.AppendLine("    .status-ok { color: #16a34a; }");
            sbHtml.AppendLine("    .status-warn { color: #f59e0b; }");
            sbHtml.AppendLine("    .status-fail { color: #dc2626; }");
            sbHtml.AppendLine("    .status-unknown { color: #334155; }");
            sbHtml.AppendLine("    .targets { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }");
            sbHtml.AppendLine("    .target { background: white; border-radius: 12px; padding: 16px; box-shadow: 0 1px 2px rgba(148, 163, 184, 0.3); }");
            sbHtml.AppendLine("    .target ul { padding-left: 18px; margin: 8px 0 0 0; }");
            sbHtml.AppendLine("    .target li { margin: 6px 0; }");
            sbHtml.AppendLine("    .udp-list, .recommendations { background: white; border-radius: 12px; padding: 16px; box-shadow: 0 1px 2px rgba(148, 163, 184, 0.3); }");
            sbHtml.AppendLine("    footer { margin-top: 32px; font-size: 12px; color: #64748b; }");
            sbHtml.AppendLine("  </style>");
            sbHtml.AppendLine("</head>");
            sbHtml.AppendLine("<body>");
            sbHtml.AppendLine("  <header>");
            sbHtml.AppendLine("    <h1>ISP Audit — отчёт</h1>");
            sbHtml.AppendLine($"    <p class=\"meta\">Дата: {HtmlEncode(run.run_at.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss"))} · Внешний IP: {HtmlEncode(run.ext_ip ?? "—")} · TCP-порты: {HtmlEncode(PortsToRangeText(cfg.Ports))}</p>");
            sbHtml.AppendLine("  </header>");
            sbHtml.AppendLine("  <section>");
            sbHtml.AppendLine("    <div class=\"summary-grid\">");
            sbHtml.AppendLine($"      <div class=\"summary-card\"><strong>DNS</strong><span class=\"status {GetStatusCssClass(run.summary.dns)}\">{HtmlEncode(GetReadableStatus(run.summary.dns))}</span></div>");
            sbHtml.AppendLine($"      <div class=\"summary-card\"><strong>TCP</strong><span class=\"status {GetStatusCssClass(run.summary.tcp)}\">{HtmlEncode(GetReadableStatus(run.summary.tcp))}</span></div>");
            sbHtml.AppendLine($"      <div class=\"summary-card\"><strong>UDP</strong><span class=\"status {GetStatusCssClass(run.summary.udp)}\">{HtmlEncode(GetReadableStatus(run.summary.udp))}</span></div>");
            sbHtml.AppendLine($"      <div class=\"summary-card\"><strong>TLS</strong><span class=\"status {GetStatusCssClass(run.summary.tls)}\">{HtmlEncode(GetReadableStatus(run.summary.tls))}</span></div>");
            sbHtml.AppendLine("    </div>");
            sbHtml.AppendLine("  </section>");

            if (targetSummaries.Count > 0)
            {
                sbHtml.AppendLine("  <section>");
                sbHtml.AppendLine("    <h2>Цели</h2>");
                sbHtml.AppendLine("    <div class=\"targets\">");
                foreach (var kv in run.targets.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                {
                    var t = kv.Value;
                    string displayName = string.IsNullOrWhiteSpace(t.display_name) ? kv.Key : t.display_name;
                    string service = string.IsNullOrWhiteSpace(t.service) ? "—" : t.service;
                    bool anyOpen = t.tcp.Any(r => r.open);
                    bool httpOk = t.http.Any(h => h.success && h.status is >= 200 and < 400);
                    string tcpPorts = t.tcp.Count == 0 ? "—" : string.Join(", ", t.tcp.Select(r => $"{r.port}:{(r.open ? "открыт" : "закрыт")}"));
                    string httpSummary = t.http.Count == 0
                        ? "HTTP-запросы не выполнялись"
                        : string.Join(", ", t.http.Select(h => h.success ? (h.status?.ToString() ?? "успех") : (h.error ?? "ошибка")));

                    sbHtml.AppendLine("      <article class=\"target\">");
                    sbHtml.AppendLine($"        <h3>{HtmlEncode(displayName)}</h3>");
                    sbHtml.AppendLine($"        <p class=\"meta\">{HtmlEncode(service)} · {HtmlEncode(t.host)}</p>");
                    sbHtml.AppendLine("        <ul>");
                    sbHtml.AppendLine($"          <li><strong>DNS:</strong> <span class=\"status {GetStatusCssClass(t.dns_status)}\">{HtmlEncode(GetReadableStatus(t.dns_status))}</span></li>");
                    sbHtml.AppendLine($"          <li><strong>TCP:</strong> {HtmlEncode(anyOpen ? "порты доступны" : "порты закрыты")}</li>");
                    sbHtml.AppendLine($"          <li><strong>TCP-порты проверены:</strong> {HtmlEncode(tcpPorts)}</li>");
                    sbHtml.AppendLine($"          <li><strong>HTTPS:</strong> {HtmlEncode(httpOk ? "ответ есть" : "ответов нет")}</li>");
                    sbHtml.AppendLine($"          <li><strong>HTTP детали:</strong> {HtmlEncode(httpSummary)}</li>");
                    if (t.traceroute != null && t.traceroute.hops.Count > 0)
                    {
                        sbHtml.AppendLine($"          <li><strong>Traceroute:</strong> {t.traceroute.hops.Count} хоп(ов)</li>");
                    }
                    sbHtml.AppendLine("        </ul>");
                    if (t.system_dns.Count > 0 || t.doh.Count > 0)
                    {
                        sbHtml.AppendLine("        <div class=\"meta\"><strong>DNS ответы:</strong> системный — " + HtmlEncode(string.Join(", ", t.system_dns)) + "; DoH — " + HtmlEncode(string.Join(", ", t.doh)) + "</div>");
                    }
                    sbHtml.AppendLine("      </article>");
                }
                sbHtml.AppendLine("    </div>");
                sbHtml.AppendLine("  </section>");
            }

            if (udpSummaries.Count > 0)
            {
                sbHtml.AppendLine("  <section>");
                sbHtml.AppendLine("    <h2>UDP тесты</h2>");
                sbHtml.AppendLine("    <div class=\"udp-list\">");
                sbHtml.AppendLine("      <ul>");
                foreach (var line in udpSummaries)
                {
                    sbHtml.AppendLine($"        <li>{HtmlEncode(line)}</li>");
                }
                sbHtml.AppendLine("      </ul>");
                sbHtml.AppendLine("    </div>");
                sbHtml.AppendLine("  </section>");
            }

            sbHtml.AppendLine("  <section>");
            sbHtml.AppendLine("    <h2>Рекомендации</h2>");
            sbHtml.AppendLine("    <div class=\"recommendations\">");
            if (!string.IsNullOrWhiteSpace(adviceHtml))
            {
                sbHtml.Append(adviceHtml);
            }
            else
            {
                sbHtml.AppendLine("<p>Проблем не обнаружено. Рекомендации отсутствуют.</p>");
            }
            sbHtml.AppendLine("    </div>");
            sbHtml.AppendLine("  </section>");

            sbHtml.AppendLine("  <footer>");
            sbHtml.AppendLine("    Отчёт сгенерирован инструментом ISP Audit. Храните файл локально или прикрепите к обращению в поддержку.");
            sbHtml.AppendLine("  </footer>");
            sbHtml.AppendLine("</body>");
            sbHtml.AppendLine("</html>");

            return sbHtml.ToString();
        }

        public static async Task SaveHtmlReportAsync(RunReport run, Config cfg, string path)
        {
            var html = BuildHtmlReport(run, cfg);
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            await File.WriteAllTextAsync(path, html, Encoding.UTF8);
        }

        public static async Task SavePdfReportAsync(RunReport run, Config cfg, string path)
        {
            var advice = BuildAdviceText(run);
            var image = RenderReportToImage(run, cfg, advice);
            var pdf = BuildPdfFromImage(image.Data, image.Width, image.Height);
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            await File.WriteAllBytesAsync(path, pdf);
        }

        private static (byte[] Data, int Width, int Height) RenderReportToImage(RunReport run, Config cfg, string advice)
        {
            int width = 1654;
            int height = 2480;
            var targetSummaries = BuildTargetSummaries(run);
            var udpSummaries = BuildUdpSummaries(run);

            using var bmp = new Bitmap(width, height);
            using var g = Graphics.FromImage(bmp);
            g.Clear(Color.White);
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

            int margin = 120;
            int contentWidth = width - margin * 2;
            int x = margin;
            float y = margin;

            using var titleFont = CreateFont("Segoe UI", 38, FontStyle.Bold);
            using var subtitleFont = CreateFont("Segoe UI", 20, FontStyle.Regular);
            using var sectionFont = CreateFont("Segoe UI", 26, FontStyle.Bold);
            using var bodyFont = CreateFont("Segoe UI", 20, FontStyle.Regular);
            using var bulletFont = CreateFont("Segoe UI", 20, FontStyle.Regular);

            y = DrawParagraph(g, "ISP Audit — отчёт", titleFont, x, y, contentWidth, Color.Black, 28);
            string meta = $"Дата: {run.run_at.ToLocalTime():dd.MM.yyyy HH:mm:ss} · Внешний IP: {run.ext_ip ?? "—"} · TCP-порты: {PortsToRangeText(cfg.Ports)}";
            y = DrawParagraph(g, meta, subtitleFont, x, y, contentWidth, Color.FromArgb(71, 85, 105), 20);

            y += 12;
            y = DrawParagraph(g, "Статусы", sectionFont, x, y, contentWidth, Color.Black, 24);
            y = DrawParagraph(g, $"DNS — {GetReadableStatus(run.summary.dns)}", bodyFont, x, y, contentWidth, Color.Black, 16);
            y = DrawParagraph(g, $"TCP — {GetReadableStatus(run.summary.tcp)}", bodyFont, x, y, contentWidth, Color.Black, 16);
            y = DrawParagraph(g, $"UDP — {GetReadableStatus(run.summary.udp)}", bodyFont, x, y, contentWidth, Color.Black, 16);
            y = DrawParagraph(g, $"TLS — {GetReadableStatus(run.summary.tls)}", bodyFont, x, y, contentWidth, Color.Black, 16);

            if (targetSummaries.Count > 0)
            {
                y += 12;
                y = DrawParagraph(g, "Цели", sectionFont, x, y, contentWidth, Color.Black, 24);
                foreach (var line in targetSummaries)
                {
                    y = DrawParagraph(g, "• " + line, bulletFont, x + 20, y, contentWidth - 20, Color.Black, 12);
                }
            }

            if (udpSummaries.Count > 0)
            {
                y += 12;
                y = DrawParagraph(g, "UDP тесты", sectionFont, x, y, contentWidth, Color.Black, 24);
                foreach (var line in udpSummaries)
                {
                    y = DrawParagraph(g, "• " + line, bulletFont, x + 20, y, contentWidth - 20, Color.Black, 12);
                }
            }

            if (!string.IsNullOrWhiteSpace(advice))
            {
                y += 12;
                y = DrawParagraph(g, "Рекомендации", sectionFont, x, y, contentWidth, Color.Black, 24);
                foreach (var block in advice.Split(Environment.NewLine))
                {
                    var text = block.Trim();
                    if (string.IsNullOrEmpty(text)) continue;
                    string line = text.StartsWith("—") || text.StartsWith("•") ? text : "• " + text;
                    y = DrawParagraph(g, line, bodyFont, x + 20, y, contentWidth - 20, Color.Black, 12);
                }
            }

            using var msImage = new MemoryStream();
            var codec = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
            using var encParams = new EncoderParameters(1);
            encParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 92L);
            bmp.Save(msImage, codec, encParams);
            return (msImage.ToArray(), width, height);
        }

        private static Font CreateFont(string familyName, float size, FontStyle style)
        {
            try
            {
                var family = new FontFamily(familyName);
                return new Font(family, size, style, GraphicsUnit.Pixel);
            }
            catch
            {
                return new Font(FontFamily.GenericSansSerif, size, style, GraphicsUnit.Pixel);
            }
        }

        private static float DrawParagraph(Graphics g, string text, Font font, int x, float y, int width, Color color, float spacing)
        {
            var flags = TextFormatFlags.WordBreak | TextFormatFlags.NoPadding | TextFormatFlags.Left;
            var size = TextRenderer.MeasureText(g, text, font, new Size(width, int.MaxValue), flags);
            var rect = new Rectangle(x, (int)y, width, size.Height);
            TextRenderer.DrawText(g, text, font, rect, color, flags);
            return y + size.Height + spacing;
        }

        private static byte[] BuildPdfFromImage(byte[] imageData, int width, int height)
        {
            using var ms = new MemoryStream();
            void WriteString(string s)
            {
                var bytes = Encoding.ASCII.GetBytes(s);
                ms.Write(bytes, 0, bytes.Length);
            }

            WriteString("%PDF-1.4\n");
            WriteString("%âãÏÓ\n");

            var offsets = new List<long>();
            void BeginObject(int index)
            {
                offsets.Add(ms.Position);
                WriteString($"{index} 0 obj\n");
            }

            void EndObject()
            {
                WriteString("endobj\n");
            }

            BeginObject(1);
            WriteString("<< /Type /Catalog /Pages 2 0 R >>\n");
            EndObject();

            BeginObject(2);
            WriteString("<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n");
            EndObject();

            BeginObject(3);
            WriteString($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] /Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>\n");
            EndObject();

            var content = $"q {width} 0 0 {height} 0 0 cm /Im0 Do Q";
            var contentLength = Encoding.ASCII.GetByteCount(content);
            BeginObject(4);
            WriteString($"<< /Length {contentLength} >>\nstream\n{content}\nendstream\n");
            EndObject();

            BeginObject(5);
            WriteString($"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {imageData.Length} >>\nstream\n");
            ms.Write(imageData, 0, imageData.Length);
            WriteString("\nendstream\n");
            EndObject();

            long xrefPosition = ms.Position;
            WriteString($"xref\n0 {offsets.Count + 1}\n");
            WriteString("0000000000 65535 f \n");
            foreach (var offset in offsets)
            {
                WriteString($"{offset:0000000000} 00000 n \n");
            }
            WriteString($"trailer << /Size {offsets.Count + 1} /Root 1 0 R >>\n");
            WriteString($"startxref\n{xrefPosition}\n%%EOF");

            return ms.ToArray();
        }

        private static List<string> BuildTargetSummaries(RunReport run)
        {
            var list = new List<string>();
            foreach (var kv in run.targets.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var t = kv.Value;
                bool anyOpen = t.tcp.Any(r => r.open);
                bool httpOk = t.http.Any(h => h.success && h.status is >= 200 and < 400);
                string name = string.IsNullOrWhiteSpace(t.display_name) ? kv.Key : t.display_name;
                list.Add($"{name}: DNS {GetReadableStatus(t.dns_status)}, TCP {(anyOpen ? "доступны" : "закрыты")}, HTTPS {(httpOk ? "отвечает" : "не отвечает")}");
            }
            return list;
        }

        private static List<string> BuildUdpSummaries(RunReport run)
        {
            var list = new List<string>();
            if (run.udp_tests == null) return list;
            foreach (var u in run.udp_tests)
            {
                string status;
                if (!u.success)
                {
                    status = string.IsNullOrWhiteSpace(u.note) ? "ошибка" : u.note;
                }
                else if (u.expect_reply)
                {
                    status = u.reply ? "ответ получен" : "ответ не пришёл";
                }
                else
                {
                    status = "пакет отправлен";
                }
                var name = string.IsNullOrWhiteSpace(u.service) ? u.name : $"{u.name} ({u.service})";
                list.Add($"{name}: {status}");
            }
            return list;
        }

        private static string GetStatusCssClass(string status)
        {
            return status.ToUpperInvariant() switch
            {
                "OK" => "status-ok",
                "WARN" => "status-warn",
                "FAIL" => "status-fail",
                "SUSPECT" => "status-warn",
                "DNS_BOGUS" => "status-fail",
                "DNS_FILTERED" => "status-warn",
                _ => "status-unknown"
            };
        }

        private static string HtmlEncode(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

        private static string PortsToRangeText(IEnumerable<int> ports)
        {
            var ordered = ports?.Distinct().OrderBy(p => p).ToList() ?? new List<int>();
            if (ordered.Count == 0) return "—";
            var parts = new List<string>();
            int start = ordered[0];
            int prev = start;
            for (int i = 1; i < ordered.Count; i++)
            {
                int current = ordered[i];
                if (current == prev + 1)
                {
                    prev = current;
                    continue;
                }
                parts.Add(start == prev ? start.ToString() : $"{start}-{prev}");
                start = prev = current;
            }
            parts.Add(start == prev ? start.ToString() : $"{start}-{prev}");
            return string.Join(",", parts);
        }
    }
}
