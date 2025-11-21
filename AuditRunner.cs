using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IspAudit.Output;
using IspAudit.Tests;

namespace IspAudit
{
    public static class AuditRunner
    {
        public static async Task<RunReport> RunAsync(Config config, IProgress<IspAudit.Tests.TestProgress>? progress = null, System.Threading.CancellationToken ct = default)
        {
            var targetDefinitions = config.ResolveTargets();

            var run = new RunReport
            {
                run_at = DateTime.UtcNow,
                cli = string.Empty,
                ext_ip = await Utils.NetUtils.TryGetExternalIpAsync().ConfigureAwait(false),
                targets = new Dictionary<string, TargetReport>()
            };

            var dnsTest = new DnsTest(config);
            var tcpTest = new TcpTest(config);
            var httpTest = new HttpTest(config);
            var traceTest = new TracerouteTest(config);
            var udpRunner = new Tests.UdpProbeRunner(config);
            var rst = new RstHeuristic(config);

            // Новые диагностические тесты (выполняются перед тестами по целям)
            progress?.Report(new Tests.TestProgress(Tests.TestKind.SOFTWARE, "Software: старт"));
            run.software = await ISP_Audit.Tests.SoftwareTest.RunAsync().ConfigureAwait(false);
            bool softwareOk = run.software.Status == "OK";
            progress?.Report(new Tests.TestProgress(Tests.TestKind.SOFTWARE, "Software: завершено", softwareOk, run.software.Status));

            progress?.Report(new Tests.TestProgress(Tests.TestKind.FIREWALL, "Firewall: старт"));
            var firewallTest = new FirewallTest();
            run.firewall = await firewallTest.RunAsync().ConfigureAwait(false);
            bool firewallOk = run.firewall.Status == "OK";
            progress?.Report(new Tests.TestProgress(Tests.TestKind.FIREWALL, "Firewall: завершено", firewallOk, run.firewall.Status));

            progress?.Report(new Tests.TestProgress(Tests.TestKind.ROUTER, "Router: старт"));
            run.router = await ISP_Audit.Tests.RouterTest.RunAsync().ConfigureAwait(false);
            bool routerOk = run.router.Status == "OK";
            progress?.Report(new Tests.TestProgress(Tests.TestKind.ROUTER, "Router: завершено", routerOk, run.router.Status));

            progress?.Report(new Tests.TestProgress(Tests.TestKind.ISP, "ISP: старт"));
            run.isp = await ISP_Audit.Tests.IspTest.RunAsync().ConfigureAwait(false);
            bool ispOk = run.isp.Status == "OK";
            progress?.Report(new Tests.TestProgress(Tests.TestKind.ISP, "ISP: завершено", ispOk, run.isp.Status));

            bool anyTargetTests = config.EnableDns || config.EnableTcp || config.EnableHttp || (config.EnableTrace && !config.NoTrace);
            if (anyTargetTests)
            {
                foreach (var def in targetDefinitions)
                {
                    ct.ThrowIfCancellationRequested();
                    var profile = TargetServiceProfiles.Resolve(def.Service);
                    
                    // Используем порты цели если есть (захваченный профиль), иначе Config.Ports
                    var basePorts = def.Ports?.Any() == true ? def.Ports : config.Ports;
                    var portsToUse = profile.ResolveTcpPorts(basePorts);
                    
                    var targetReport = new TargetReport
                    {
                        host = def.Host,
                        display_name = def.Name,
                        service = string.IsNullOrWhiteSpace(def.Service) ? profile.DisplayName : def.Service,
                        dns_enabled = config.EnableDns && profile.RunDns,
                        tcp_enabled = config.EnableTcp && profile.RunTcp,
                        http_enabled = config.EnableHttp && profile.RunHttp,
                        trace_enabled = config.EnableTrace && profile.RunTrace && !config.NoTrace,
                        tcp_ports_checked = profile.RunTcp ? portsToUse.Distinct().OrderBy(p => p).ToList() : new List<int>()
                    };

                    if (targetReport.dns_enabled)
                    {
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, $"{def.Name}: старт"));
                        var dnsRes = await dnsTest.ResolveAsync(def.Host).ConfigureAwait(false);
                        targetReport.system_dns = dnsRes.SystemV4;
                        targetReport.doh = dnsRes.DohV4;
                        targetReport.dns_status = dnsRes.Status.ToString();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, $"{def.Name}: завершено", true, targetReport.dns_status));
                    }
                    else
                    {
                        targetReport.dns_status = "SKIPPED";
                        var message = config.EnableDns ? "пропущено: не требуется для этой цели" : "пропущено: тест отключён";
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, $"{def.Name}: пропущено", true, message));
                    }

                    // Early-exit: если DNS полностью провалился (и System и DoH пусты), пропустить TCP/HTTP/Trace
                    bool dnsCompleteFail = targetReport.dns_enabled &&
                        targetReport.system_dns.Count == 0 &&
                        targetReport.doh.Count == 0;

                    if (dnsCompleteFail)
                    {
                        // Проверяем, является ли цель критичной и имеет ли fallback IP
                        var targetProfile = Config.ActiveProfile?.Targets.FirstOrDefault(t => t.Host == def.Host);
                        bool isCritical = targetProfile?.Critical ?? false;
                        string? fallbackIp = targetProfile?.FallbackIp;

                        if (isCritical && !string.IsNullOrWhiteSpace(fallbackIp))
                        {
                            // Критичная цель с fallback IP → добавляем fallback IP и продолжаем тестирование
                            targetReport.system_dns.Add(fallbackIp);
                            progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS,
                                $"{def.Name}: DNS не вернул адресов, используем fallback IP {fallbackIp}",
                                null,
                                $"fallback: {fallbackIp}"));
                        }
                        else
                        {
                            // Некритичная цель ИЛИ нет fallback IP → пропускаем тестирование
                            string reason = !isCritical 
                                ? "домен недоступен (некритичная цель)" 
                                : "домен недоступен (нет fallback IP)";
                            
                            progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS,
                                $"{def.Name}: DNS не вернул адресов, пропускаем TCP/HTTP/Trace",
                                false,
                                reason));

                            targetReport.tcp_enabled = false;
                            targetReport.http_enabled = false;
                            targetReport.trace_enabled = false;
                        }
                    }

                    if (targetReport.tcp_enabled)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, $"{def.Name}: старт"));
                        targetReport.tcp = await tcpTest.CheckAsync(def.Host, targetReport.system_dns, portsToUse).ConfigureAwait(false);
                        bool ok = targetReport.tcp.Exists(r => r.open);
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, $"{def.Name}: завершено", ok, ok?"open найден":"все закрыто"));
                    }
                    else
                    {
                        var message = config.EnableTcp ? "пропущено: тест TCP не требуется" : "пропущено: тест отключён";
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, $"{def.Name}: пропущено", true, message));
                    }

                    if (targetReport.http_enabled)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, $"{def.Name}: старт"));
                        targetReport.http = await httpTest.CheckAsync(def.Host).ConfigureAwait(false);
                        bool ok = targetReport.http.Exists(h => h.success && h.status is >= 200 and < 400);
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, $"{def.Name}: завершено", ok, ok?"2xx/3xx":"ошибки/таймаут"));
                    }
                    else
                    {
                        var message = config.EnableHttp ? "пропущено: HTTPS не применяется" : "пропущено: тест отключён";
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, $"{def.Name}: пропущено", true, message));
                    }

                    if (targetReport.trace_enabled)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, $"{def.Name}: старт"));
                        var hopProgress = new System.Progress<string>(line =>
                        {
                            progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, $"{def.Name}: hop", null, line));
                        });
                        targetReport.traceroute = await traceTest.RunAsync(def.Host, hopProgress, ct).ConfigureAwait(false);
                        bool ok = targetReport.traceroute.hops.Count > 0;
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, $"{def.Name}: завершено", ok));
                    }
                    else
                    {
                        string message;
                        if (!config.EnableTrace)
                            message = "пропущено: тест отключён";
                        else if (config.NoTrace)
                            message = "пропущено: трассировка отключена в настройках";
                        else
                            message = "пропущено: не требуется для этой цели";
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, $"{def.Name}: пропущено", true, message));
                    }

                    run.targets[def.Name] = targetReport;
                }

                // финальные агрегированные статусы по per-target тестам
                if (config.EnableDns && run.targets.Values.Any(t => t.dns_enabled))
                {
                    bool fail = false; bool warn = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.dns_enabled) continue;
                        fail |= t.dns_status == nameof(Tests.DnsStatus.DNS_BOGUS) || t.dns_status == nameof(Tests.DnsStatus.DNS_FILTERED);
                        warn |= t.dns_status == nameof(Tests.DnsStatus.WARN);
                    }
                    var msg = fail ? "обнаружены BOGUS/FILTERED" : (warn ? "есть WARN" : "OK");
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, "сводка", !fail, msg));
                }
                else if (config.EnableDns)
                {
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, "сводка", true, "не требовалось"));
                }

                if (config.EnableTcp && run.targets.Values.Any(t => t.tcp_enabled))
                {
                    bool fail = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.tcp_enabled) continue;
                        bool anyOpen = t.tcp.Exists(r => r.open);
                        if (!anyOpen) { fail = true; break; }
                    }
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, "сводка", !fail, !fail?"порт(ы) открыты":"все закрыто"));
                }
                else if (config.EnableTcp)
                {
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, "сводка", true, "не требовалось"));
                }

                if (config.EnableHttp && run.targets.Values.Any(t => t.http_enabled))
                {
                    bool fail = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.http_enabled) continue;
                        bool httpOk = t.http.Exists(h => h.success && h.status is >= 200 and < 400);
                        if (!httpOk) { fail = true; break; }
                    }
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, "сводка", !fail, !fail?"2xx/3xx есть":"ошибки/таймаут"));
                }
                else if (config.EnableHttp)
                {
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, "сводка", true, "не требовалось"));
                }

                if (config.EnableTrace && !config.NoTrace && run.targets.Values.Any(t => t.trace_enabled))
                {
                    bool fail = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.trace_enabled) continue;
                        if (t.traceroute == null || t.traceroute.hops.Count == 0) { fail = true; break; }
                    }
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, "сводка", !fail));
                }
                else if (config.EnableTrace && !config.NoTrace)
                {
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, "сводка", true, "не требовалось"));
                }
            }

            if (config.EnableUdp && config.UdpProbes.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var udpResults = new List<Output.UdpProbeResult>();
                foreach (var probe in config.UdpProbes)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.UDP, $"{probe.Name}: старт"));
                    var res = await udpRunner.ProbeAsync(probe).ConfigureAwait(false);
                    udpResults.Add(res);

                    // For low-certainty tests (raw probes without reply), don't report as "success"
                    // They are informational only and should be shown as neutral/info
                    bool? ok = res.certainty == "low" ? null : res.success;
                    var message = res.success
                        ? (res.reply ? $"ответ {res.rtt_ms?.ToString() ?? "?"}мс" : "пакет отправлен")
                        : (res.note ?? "ошибка");
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.UDP, $"{probe.Name}: завершено", ok, message));
                }
                run.udp_tests = udpResults;
                bool udpFail = udpResults.Any(r => r.expect_reply && !r.success);
                var summaryMsg = udpFail ? "ожидаемые ответы отсутствуют" : "ожидаемые ответы получены";
                progress?.Report(new Tests.TestProgress(Tests.TestKind.UDP, "сводка", !udpFail, summaryMsg));
            }
            if (config.EnableRst)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report(new Tests.TestProgress(Tests.TestKind.RST, "RST: старт"));
                run.rst_heuristic = await rst.CheckAsync().ConfigureAwait(false);
                progress?.Report(new Tests.TestProgress(Tests.TestKind.RST, "RST: завершено", true));
            }
            run.summary = ReportWriter.BuildSummary(run, config);
            return run;
        }
    }
}
