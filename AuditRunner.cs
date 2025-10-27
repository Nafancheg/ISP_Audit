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

            bool anyTargetTests = config.EnableDns || config.EnableTcp || config.EnableHttp || (config.EnableTrace && !config.NoTrace);
            if (anyTargetTests)
            {
                foreach (var def in targetDefinitions)
                {
                    ct.ThrowIfCancellationRequested();
                    var plan = ServiceTestMatrix.GetPlan(def, config);
                    var targetReport = new TargetReport
                    {
                        host = def.Host,
                        display_name = def.Name,
                        service = def.Service,
                        dns_executed = plan.RunDns,
                        tcp_executed = plan.RunTcp,
                        http_executed = plan.RunHttp,
                        trace_executed = plan.RunTrace
                    };

                    if (plan.RunDns)
                    {
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, $"{def.Name}: старт"));
                        var dnsRes = await dnsTest.ResolveAsync(def.Host).ConfigureAwait(false);
                        targetReport.system_dns = dnsRes.SystemV4;
                        targetReport.doh = dnsRes.DohV4;
                        targetReport.dns_status = dnsRes.Status.ToString();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, $"{def.Name}: завершено", true, targetReport.dns_status));
                    }

                    if (plan.RunTcp)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, $"{def.Name}: старт"));
                        targetReport.tcp = await tcpTest.CheckAsync(def.Host, targetReport.system_dns, plan.TcpPorts).ConfigureAwait(false);
                        bool ok = targetReport.tcp.Exists(r => r.open);
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, $"{def.Name}: завершено", ok, ok?"open найден":"все закрыто"));
                    }

                    if (plan.RunHttp)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, $"{def.Name}: старт"));
                        targetReport.http = await httpTest.CheckAsync(def.Host).ConfigureAwait(false);
                        bool ok = targetReport.http.Exists(h => h.success && h.status is >= 200 and < 400);
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, $"{def.Name}: завершено", ok, ok?"2xx/3xx":"ошибки/таймаут"));
                    }

                    if (plan.RunTrace)
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

                    run.targets[def.Name] = targetReport;
                }

                // финальные агрегированные статусы по per-target тестам
                if (config.EnableDns)
                {
                    bool fail = false; bool warn = false; bool any = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.dns_executed) continue;
                        any = true;
                        fail |= t.dns_status == nameof(Tests.DnsStatus.DNS_BOGUS) || t.dns_status == nameof(Tests.DnsStatus.DNS_FILTERED);
                        warn |= t.dns_status == nameof(Tests.DnsStatus.WARN);
                    }
                    var msg = !any ? "не требуется" : (fail ? "обнаружены BOGUS/FILTERED" : (warn ? "есть WARN" : "OK"));
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, "сводка", !fail, msg));
                }

                if (config.EnableTcp)
                {
                    bool fail = false; bool any = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.tcp_executed) continue;
                        any = true;
                        bool anyOpen = t.tcp.Exists(r => r.open);
                        if (!anyOpen) { fail = true; break; }
                    }
                    var msg = !any ? "не требуется" : (!fail ? "порт(ы) открыты" : "все закрыто");
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, "сводка", !fail, msg));
                }

                if (config.EnableHttp)
                {
                    bool fail = false; bool any = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.http_executed) continue;
                        any = true;
                        bool httpOk = t.http.Exists(h => h.success && h.status is >= 200 and < 400);
                        if (!httpOk) { fail = true; break; }
                    }
                    var msg = !any ? "не требуется" : (!fail ? "2xx/3xx есть" : "ошибки/таймаут");
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, "сводка", !fail, msg));
                }

                if (config.EnableTrace && !config.NoTrace)
                {
                    bool fail = false; bool any = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (!t.trace_executed) continue;
                        any = true;
                        if (t.traceroute == null || t.traceroute.hops.Count == 0) { fail = true; break; }
                    }
                    var msg = !any ? "не требуется" : (!fail ? "готово" : "нет маршрута");
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, "сводка", !fail, msg));
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
                    var ok = res.success;
                    var message = ok
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
            run.summary = ReportWriter.BuildSummary(run);
            return run;
        }
    }
}
