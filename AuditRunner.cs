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
            var targets = config.Targets.Count > 0
                ? config.Targets
                : new List<string> { "youtube.com", "discord.com", "google.com", "example.com" };

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
            var udp = new UdpDnsTest(config);
            var rst = new RstHeuristic(config);

            bool anyTargetTests = config.EnableDns || config.EnableTcp || config.EnableHttp || (config.EnableTrace && !config.NoTrace);
            if (anyTargetTests)
            {
                foreach (var host in targets)
                {
                    ct.ThrowIfCancellationRequested();
                    var targetReport = new TargetReport { host = host };

                    if (config.EnableDns)
                    {
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, $"{host}: старт"));
                        var dnsRes = await dnsTest.ResolveAsync(host).ConfigureAwait(false);
                        targetReport.system_dns = dnsRes.SystemV4;
                        targetReport.doh = dnsRes.DohV4;
                        targetReport.dns_status = dnsRes.Status.ToString();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, $"{host}: завершено", true, targetReport.dns_status));
                    }

                    if (config.EnableTcp)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, $"{host}: старт"));
                        targetReport.tcp = await tcpTest.CheckAsync(host, targetReport.system_dns).ConfigureAwait(false);
                        bool ok = targetReport.tcp.Exists(r => r.open);
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, $"{host}: завершено", ok, ok?"open найден":"все закрыто"));
                    }

                    if (config.EnableHttp)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, $"{host}: старт"));
                        targetReport.http = await httpTest.CheckAsync(host).ConfigureAwait(false);
                        bool ok = targetReport.http.Exists(h => h.success && h.status is >= 200 and < 400);
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, $"{host}: завершено", ok, ok?"2xx/3xx":"ошибки/таймаут"));
                    }

                    if (config.EnableTrace && !config.NoTrace)
                    {
                        ct.ThrowIfCancellationRequested();
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, $"{host}: старт"));
                        var hopProgress = new System.Progress<string>(line =>
                        {
                            progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, $"{host}: hop", null, line));
                        });
                        targetReport.traceroute = await traceTest.RunAsync(host, hopProgress, ct).ConfigureAwait(false);
                        bool ok = targetReport.traceroute.hops.Count > 0;
                        progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, $"{host}: завершено", ok));
                    }

                    run.targets[host] = targetReport;
                }

                // финальные агрегированные статусы по per-target тестам
                if (config.EnableDns)
                {
                    bool fail = false; bool warn = false;
                    foreach (var t in run.targets.Values)
                    {
                        fail |= t.dns_status == nameof(Tests.DnsStatus.DNS_BOGUS) || t.dns_status == nameof(Tests.DnsStatus.DNS_FILTERED);
                        warn |= t.dns_status == nameof(Tests.DnsStatus.WARN);
                    }
                    var msg = fail ? "обнаружены BOGUS/FILTERED" : (warn ? "есть WARN" : "OK");
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.DNS, "сводка", !fail, msg));
                }

                if (config.EnableTcp)
                {
                    bool fail = false;
                    foreach (var t in run.targets.Values)
                    {
                        bool anyOpen = t.tcp.Exists(r => r.open);
                        if (!anyOpen) { fail = true; break; }
                    }
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TCP, "сводка", !fail, !fail?"порт(ы) открыты":"все закрыто"));
                }

                if (config.EnableHttp)
                {
                    bool fail = false;
                    foreach (var t in run.targets.Values)
                    {
                        bool httpOk = t.http.Exists(h => h.success && h.status is >= 200 and < 400);
                        if (!httpOk) { fail = true; break; }
                    }
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.HTTP, "сводка", !fail, !fail?"2xx/3xx есть":"ошибки/таймаут"));
                }

                if (config.EnableTrace && !config.NoTrace)
                {
                    bool fail = false;
                    foreach (var t in run.targets.Values)
                    {
                        if (t.traceroute == null || t.traceroute.hops.Count == 0) { fail = true; break; }
                    }
                    progress?.Report(new Tests.TestProgress(Tests.TestKind.TRACEROUTE, "сводка", !fail));
                }
            }

            if (config.EnableUdp)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report(new Tests.TestProgress(Tests.TestKind.UDP, "UDP: старт"));
                run.udp_test = await udp.ProbeAsync().ConfigureAwait(false);
                progress?.Report(new Tests.TestProgress(Tests.TestKind.UDP, "UDP: завершено", run.udp_test.reply));
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
