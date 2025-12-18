using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Modules;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Utils;

using BypassTransportProtocol = IspAudit.Bypass.TransportProtocol;

namespace TestNetworkApp.Smoke
{
    internal sealed record SmokeRunOptions(bool NoSkip, string? JsonOutputPath = null)
    {
        public static SmokeRunOptions Default => new(NoSkip: false, JsonOutputPath: null);
    }

    internal enum SmokeOutcome
    {
        Pass,
        Fail,
        Skip
    }

    internal sealed record SmokeTestResult(
        string Id,
        string Name,
        SmokeOutcome Outcome,
        TimeSpan Duration,
        string? Details = null);

    internal sealed record SmokeReport(
        DateTimeOffset StartedAt,
        DateTimeOffset FinishedAt,
        int ProcessId,
        bool IsAdmin,
        string Category,
        bool NoSkip,
        IReadOnlyList<SmokeTestResult> Results);

    internal sealed record SmokePlanItem(string Id, string Name);

    internal static class SmokePlan
    {
        public static IReadOnlyList<SmokePlanItem> TryLoadDefaultPlan()
        {
            var candidates = new List<string>();

            // 1) Самый частый случай: запуск из корня репозитория.
            candidates.Add(Path.Combine(Environment.CurrentDirectory, "TestNetworkApp", "smoke_tests_plan.md"));
            candidates.Add(Path.Combine(Environment.CurrentDirectory, "smoke_tests_plan.md"));

            // 2) Запуск из папки проекта.
            candidates.Add(Path.Combine(Environment.CurrentDirectory, "smoke_tests_plan.md"));

            // 3) Запуск из bin/Debug/... — пробуем подняться вверх.
            var baseDir = AppContext.BaseDirectory;
            candidates.Add(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "smoke_tests_plan.md")));
            candidates.Add(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "TestNetworkApp", "smoke_tests_plan.md")));

            foreach (var p in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (!File.Exists(p))
                    {
                        continue;
                    }

                    var items = ParsePlan(File.ReadAllLines(p));
                    if (items.Count > 0)
                    {
                        return items;
                    }
                }
                catch
                {
                    // План — вспомогательный источник. Если не загрузился, просто молча падаем назад.
                }
            }

            return Array.Empty<SmokePlanItem>();
        }

        private static List<SmokePlanItem> ParsePlan(IReadOnlyList<string> lines)
        {
            var items = new List<SmokePlanItem>(capacity: 128);

            string? currentId = null;
            string? currentName = null;

            for (int i = 0; i < lines.Count; i++)
            {
                var line = lines[i].Trim();

                if (line.StartsWith("**Test ID:**", StringComparison.OrdinalIgnoreCase))
                {
                    currentId = ExtractBacktickedToken(line);
                    currentName = null;
                    continue;
                }

                if (currentId is not null && currentName is null && line.StartsWith("**Что проверяет:**", StringComparison.OrdinalIgnoreCase))
                {
                    currentName = line.Substring("**Что проверяет:**".Length).Trim();
                    // Завершаем пункт, как только есть ID и имя.
                    items.Add(new SmokePlanItem(currentId, string.IsNullOrWhiteSpace(currentName) ? currentId : currentName));
                    currentId = null;
                    currentName = null;
                }
            }

            // На всякий случай: если попался Test ID без "Что проверяет".
            if (currentId is not null)
            {
                items.Add(new SmokePlanItem(currentId, currentId));
            }

            // Удаляем дубли по ID, сохраняя порядок (берём первое вхождение).
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var unique = new List<SmokePlanItem>(items.Count);
            foreach (var it in items)
            {
                if (seen.Add(it.Id))
                {
                    unique.Add(it);
                }
            }

            return unique;
        }

        private static string? ExtractBacktickedToken(string line)
        {
            // Ожидаем формат: **Test ID:** `INFRA-001`
            var first = line.IndexOf('`');
            if (first < 0)
            {
                return null;
            }

            var second = line.IndexOf('`', first + 1);
            if (second < 0)
            {
                return null;
            }

            var token = line.Substring(first + 1, second - first - 1).Trim();
            return string.IsNullOrWhiteSpace(token) ? null : token;
        }
    }

    internal sealed class SmokeRunner
    {
        private readonly List<Func<CancellationToken, Task<SmokeTestResult>>> _tests = new();
        private readonly SmokeRunOptions _options;
        private readonly string _category;

        private SmokeRunner(string category, SmokeRunOptions options)
        {
            _category = category;
            _options = options;
        }

        public SmokeRunner() : this(category: "all", SmokeRunOptions.Default)
        {
        }

        public SmokeRunner Add(Func<CancellationToken, Task<SmokeTestResult>> test)
        {
            _tests.Add(test);
            return this;
        }

        public async Task<int> RunAsync(CancellationToken ct)
        {
            var results = new List<SmokeTestResult>();
            var startedAt = DateTimeOffset.Now;

            Console.WriteLine("=== ISP_Audit Smoke Runner ===");
            Console.WriteLine($"Время: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"PID: {Environment.ProcessId}");
            Console.WriteLine($"Admin: {(TrafficEngine.HasAdministratorRights ? "да" : "нет")}");
            Console.WriteLine($"Категория: {_category}");
            Console.WriteLine($"NoSkip: {(_options.NoSkip ? "да" : "нет")}");
            Console.WriteLine($"JSON: {(string.IsNullOrWhiteSpace(_options.JsonOutputPath) ? "нет" : _options.JsonOutputPath)}");
            Console.WriteLine();

            foreach (var test in _tests)
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                SmokeTestResult r;
                try
                {
                    r = await test(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    r = new SmokeTestResult("SMOKE-CANCEL", "Отмена", SmokeOutcome.Skip, TimeSpan.Zero, "Отменено токеном");
                }
                catch (Exception ex)
                {
                    r = new SmokeTestResult("SMOKE-EX", "Непойманное исключение", SmokeOutcome.Fail, TimeSpan.Zero, ex.ToString());
                }

                if (_options.NoSkip && r.Outcome == SmokeOutcome.Skip)
                {
                    r = r with
                    {
                        Outcome = SmokeOutcome.Fail,
                        Details = string.IsNullOrWhiteSpace(r.Details)
                            ? "Режим NoSkip: SKIP запрещён"
                            : $"NoSkip: SKIP запрещён. {r.Details}"
                    };
                }

                results.Add(r);

                var status = r.Outcome switch
                {
                    SmokeOutcome.Pass => "PASS",
                    SmokeOutcome.Fail => "FAIL",
                    SmokeOutcome.Skip => "SKIP",
                    _ => r.Outcome.ToString().ToUpperInvariant()
                };

                Console.WriteLine($"[{status}] {r.Id} {r.Name} ({r.Duration.TotalMilliseconds:F0}ms)");
                if (!string.IsNullOrWhiteSpace(r.Details))
                {
                    Console.WriteLine($"  {r.Details}");
                }
            }

            var pass = results.Count(x => x.Outcome == SmokeOutcome.Pass);
            var fail = results.Count(x => x.Outcome == SmokeOutcome.Fail);
            var skip = results.Count(x => x.Outcome == SmokeOutcome.Skip);

            Console.WriteLine();
            Console.WriteLine("--- Итоги ---");
            Console.WriteLine($"PASS: {pass}");
            Console.WriteLine($"FAIL: {fail}");
            Console.WriteLine($"SKIP: {skip}");

            if (!string.IsNullOrWhiteSpace(_options.JsonOutputPath))
            {
                try
                {
                    var report = new SmokeReport(
                        StartedAt: startedAt,
                        FinishedAt: DateTimeOffset.Now,
                        ProcessId: Environment.ProcessId,
                        IsAdmin: TrafficEngine.HasAdministratorRights,
                        Category: _category,
                        NoSkip: _options.NoSkip,
                        Results: results);

                    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

                    var outPath = _options.JsonOutputPath!;
                    var outDir = Path.GetDirectoryName(outPath);
                    if (!string.IsNullOrWhiteSpace(outDir) && !Directory.Exists(outDir))
                    {
                        Directory.CreateDirectory(outDir);
                    }

                    File.WriteAllText(outPath, json, Encoding.UTF8);
                    Console.WriteLine($"JSON отчёт сохранён: {outPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[WARN] Не удалось сохранить JSON отчёт: {ex.Message}");
                }
            }

            return fail == 0 ? 0 : 1;
        }

        public static SmokeRunner Build(string category, SmokeRunOptions? options = null)
        {
            var cat = (category ?? "all").Trim().ToLowerInvariant();
            var runner = new SmokeRunner(category: cat, options: options ?? SmokeRunOptions.Default);

            // Если есть план — обязуемся прогонять ВСЕ тесты из плана.
            // Не реализованные пока тесты возвращают FAIL (чтобы было 97/97 выполнено, без SKIP).
            var plan = SmokePlan.TryLoadDefaultPlan();
            var implemented = SmokeTests.GetImplementedTests();

            bool all = cat == "all";
            bool MatchesCategory(string id)
            {
                if (all)
                {
                    return true;
                }

                return cat switch
                {
                    "infra" => id.StartsWith("INFRA-", StringComparison.OrdinalIgnoreCase),
                    "pipe" => id.StartsWith("PIPE-", StringComparison.OrdinalIgnoreCase),
                    "insp" => id.StartsWith("INSP-", StringComparison.OrdinalIgnoreCase),
                    "ui" => id.StartsWith("UI-", StringComparison.OrdinalIgnoreCase),
                    "bypass" => id.StartsWith("BYPASS-", StringComparison.OrdinalIgnoreCase),
                    "dpi2" => id.StartsWith("DPI2-", StringComparison.OrdinalIgnoreCase),
                    _ => true
                };
            }

            if (plan.Count > 0)
            {
                foreach (var item in plan)
                {
                    if (string.IsNullOrWhiteSpace(item.Id) || !MatchesCategory(item.Id))
                    {
                        continue;
                    }

                    if (implemented.TryGetValue(item.Id, out var test))
                    {
                        runner.Add(test);
                    }
                    else
                    {
                        runner.Add(ct => SmokeTests.NotImplemented(item.Id, item.Name, ct));
                    }
                }

                return runner;
            }

            // Фолбэк: если план не найден, запускаем только реализованные тесты.
            foreach (var kvp in implemented)
            {
                if (MatchesCategory(kvp.Key))
                {
                    runner.Add(kvp.Value);
                }
            }

            return runner;
        }
    }

    internal static class SmokeTests
    {
        public static IReadOnlyDictionary<string, Func<CancellationToken, Task<SmokeTestResult>>> GetImplementedTests()
            => new Dictionary<string, Func<CancellationToken, Task<SmokeTestResult>>>(StringComparer.OrdinalIgnoreCase)
            {
                ["INFRA-001"] = Infra_WinDivertDriver,
                ["INFRA-002"] = Infra_FilterRegistration,
                ["INFRA-003"] = Infra_FilterOrder,
                ["INFRA-004"] = Infra_AdminRights,
                ["INFRA-005"] = Infra_EncodingCp866,

                ["UI-011"] = Ui_UiReducerSmoke,

                ["PIPE-005"] = Pipe_UnifiedFilter_LoopbackDropped,
                ["PIPE-006"] = Pipe_UnifiedFilter_NoiseOnlyOnDisplay,
                ["PIPE-007"] = Pipe_TrafficCollector_DedupByRemoteIpPortProto_Polling,
                ["PIPE-016"] = Pipe_Classifier_FakeIpRange,

                ["BYPASS-001"] = Bypass_TlsBypassService_RegistersFilter,
                ["BYPASS-002"] = Bypass_TlsBypassService_RemovesFilter,
                ["BYPASS-005"] = Bypass_TlsBypassService_ProfilePresetPresent,
            };

        public static Task<SmokeTestResult> NotImplemented(string id, string name, CancellationToken ct)
            => Task.FromResult(new SmokeTestResult(
                id,
                string.IsNullOrWhiteSpace(name) ? "Не реализовано" : name,
                SmokeOutcome.Fail,
                TimeSpan.Zero,
                "Тест из плана присутствует, но ещё не реализован в SmokeRunner"));

        public static async Task<SmokeTestResult> Infra_WinDivertDriver(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            if (!TrafficEngine.HasAdministratorRights)
            {
                return new SmokeTestResult("INFRA-001", "WinDivert Driver: TrafficEngine стартует/останавливается", SmokeOutcome.Skip, sw.Elapsed,
                    "Пропуск: нет прав администратора (WinDivert требует Elevated)");
            }

            try
            {
                using var engine = new TrafficEngine();

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(2));

                // Важно: StartAsync/StopAsync — минимальная проверка загрузки драйвера/handle.
                await engine.StartAsync(cts.Token).ConfigureAwait(false);
                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("INFRA-001", "WinDivert Driver: TrafficEngine стартует/останавливается", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: WinDivert handle открывается и закрывается");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("INFRA-001", "WinDivert Driver: TrafficEngine стартует/останавливается", SmokeOutcome.Fail, sw.Elapsed,
                    ex.Message);
            }
        }

        public static Task<SmokeTestResult> Infra_FilterRegistration(CancellationToken ct)
            => RunAsync("INFRA-002", "TrafficEngine: регистрация фильтра работает", () =>
            {
                using var engine = new TrafficEngine();

                var dummy = new DummyPacketFilter("SmokeDummy", priority: 123);
                engine.RegisterFilter(dummy);

                var filters = GetEngineFiltersSnapshot(engine);
                var found = filters.Any(f => f.Name == dummy.Name);
                if (!found)
                {
                    return new SmokeTestResult("INFRA-002", "TrafficEngine: регистрация фильтра работает", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Фильтр не найден в списке после RegisterFilter (snapshot/reflection)"
                    );
                }

                return new SmokeTestResult("INFRA-002", "TrafficEngine: регистрация фильтра работает", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: фильтр присутствует в активном списке"
                );
            }, ct);

        public static Task<SmokeTestResult> Infra_FilterOrder(CancellationToken ct)
            => RunAsync("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", () =>
            {
                using var engine = new TrafficEngine();
                var monitor = new TrafficMonitorFilter();
                var bypass = new BypassFilter(BypassProfile.CreateDefault());

                engine.RegisterFilter(bypass);
                engine.RegisterFilter(monitor);

                var filters = GetEngineFiltersSnapshot(engine);
                var order = string.Join(" > ", filters.Select(f => $"{f.Name}({f.Priority})"));

                var idxMonitor = filters.FindIndex(f => f.Name == monitor.Name);
                var idxBypass = filters.FindIndex(f => f.Name == bypass.Name);

                if (idxMonitor < 0 || idxBypass < 0)
                {
                    return new SmokeTestResult("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Не нашли ожидаемые фильтры. Порядок: {order}");
                }

                if (idxMonitor > idxBypass)
                {
                    return new SmokeTestResult("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали TrafficMonitor раньше Bypass. Порядок: {order}");
                }

                return new SmokeTestResult("INFRA-003", "Порядок фильтров: TrafficMonitor раньше Bypass", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {order}");
            }, ct);

        public static Task<SmokeTestResult> Infra_AdminRights(CancellationToken ct)
            => RunAsync("INFRA-004", "Права администратора (WinDivert требует Elevated)", () =>
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("INFRA-004", "Права администратора (WinDivert требует Elevated)", SmokeOutcome.Skip, TimeSpan.Zero,
                        "Пропуск: процесс запущен без прав администратора");
                }

                return new SmokeTestResult("INFRA-004", "Права администратора (WinDivert требует Elevated)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: есть права администратора");
            }, ct);

        public static Task<SmokeTestResult> Infra_EncodingCp866(CancellationToken ct)
            => RunAsync("INFRA-005", "CP866 доступен (CodePagesEncodingProvider)", () =>
            {
                // На .NET нужно зарегистрировать провайдер, иначе Encoding.GetEncoding(866) может бросить.
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

                var enc = Encoding.GetEncoding(866);
                if (enc.CodePage != 866)
                {
                    return new SmokeTestResult("INFRA-005", "CP866 доступен (CodePagesEncodingProvider)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 866, получили {enc.CodePage}");
                }

                return new SmokeTestResult("INFRA-005", "CP866 доступен (CodePagesEncodingProvider)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "Encoding.GetEncoding(866) работает");
            }, ct);

        public static Task<SmokeTestResult> Ui_UiReducerSmoke(CancellationToken ct)
            => RunAsync("UI-011", "UI-Reducer smoke (--ui-reducer-smoke)", () =>
            {
                Program.RunUiReducerSmoke_ForSmokeRunner();
                return new SmokeTestResult("UI-011", "UI-Reducer smoke (--ui-reducer-smoke)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "Выполнено без исключений");
            }, ct);

        public static Task<SmokeTestResult> Pipe_UnifiedFilter_LoopbackDropped(CancellationToken ct)
            => RunAsync("PIPE-005", "UnifiedTrafficFilter отбрасывает loopback", () =>
            {
                var filter = new UnifiedTrafficFilter();
                var host = new HostDiscovered(
                    Key: "127.0.0.1:443:TCP",
                    RemoteIp: IPAddress.Loopback,
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var decision = filter.ShouldTest(host);
                if (decision.Action != FilterAction.Drop)
                {
                    return new SmokeTestResult("PIPE-005", "UnifiedTrafficFilter отбрасывает loopback", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Drop, получили {decision.Action} ({decision.Reason})");
                }

                return new SmokeTestResult("PIPE-005", "UnifiedTrafficFilter отбрасывает loopback", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {decision.Reason}");
            }, ct);

        public static Task<SmokeTestResult> Pipe_UnifiedFilter_NoiseOnlyOnDisplay(CancellationToken ct)
            => RunAsync("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", () =>
            {
                // В GUI этот фильтр инициализируется в DiagnosticOrchestrator.
                // Для smoke-теста делаем то же, иначе singleton NoiseHostFilter работает только на fallback-паттернах.
                var noisePath = Path.Combine(Directory.GetCurrentDirectory(), "noise_hosts.json");
                NoiseHostFilter.Initialize(noisePath);

                var filter = new UnifiedTrafficFilter();

                var host = new HostDiscovered(
                    Key: "203.0.113.10:443:TCP",
                    RemoteIp: IPAddress.Parse("203.0.113.10"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: true,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: "example.com",
                    SniHostname: null,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 10,
                    BlockageType: null,
                    TestedAt: DateTime.UtcNow);

                var ok = new HostBlocked(
                    TestResult: tested,
                    BypassStrategy: PipelineContract.BypassNone,
                    RecommendedAction: BlockageCode.StatusOk);

                var decision = filter.ShouldDisplay(ok);
                if (decision.Action != FilterAction.LogOnly)
                {
                    return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали LogOnly для OK, получили {decision.Action} ({decision.Reason})");
                }

                // noise host: должен быть Drop, если OK и bypass none
                var testedNoise = tested with { Hostname = "dns.google" };
                var okNoise = ok with { TestResult = testedNoise };
                var decisionNoise = filter.ShouldDisplay(okNoise);

                if (decisionNoise.Action != FilterAction.Drop)
                {
                    return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Drop для noise OK, получили {decisionNoise.Action} ({decisionNoise.Reason})");
                }

                return new SmokeTestResult("PIPE-006", "NoiseHostFilter применяется только на этапе отображения", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: обычный OK=LogOnly, noise OK=Drop");
            }, ct);

        public static async Task<SmokeTestResult> Pipe_TrafficCollector_DedupByRemoteIpPortProto_Polling(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            try
            {
                var progress = new Progress<string>(_ => { /* без лишнего шума */ });

                using var connectionMonitor = new ConnectionMonitorService(progress)
                {
                    UsePollingMode = true
                };

                var pidTracker = new PidTrackerService(Environment.ProcessId, progress);
                await pidTracker.StartAsync(ct).ConfigureAwait(false);

                var trafficMonitor = new TrafficMonitorFilter();
                using var dnsParser = new DnsParserService(trafficMonitor, progress);

                using var collector = new TrafficCollector(connectionMonitor, pidTracker, dnsParser, progress, new UnifiedTrafficFilter());

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                await connectionMonitor.StartAsync(cts.Token).ConfigureAwait(false);

                int yielded = 0;

                var collectTask = Task.Run(async () =>
                {
                    await foreach (var _ in collector.CollectAsync(TimeSpan.FromSeconds(5), cts.Token).ConfigureAwait(false))
                    {
                        Interlocked.Increment(ref yielded);
                    }
                }, cts.Token);

                // Делаем две попытки TCP соединения к одному и тому же remote endpoint.
                // Polling даст два события (разные localPort), но TrafficCollector обязан дедупить по RemoteIp:RemotePort:Protocol.
                await Task.Delay(300, cts.Token).ConfigureAwait(false);
                await MakeTcpAttemptAsync(IPAddress.Parse("1.1.1.1"), 443, TimeSpan.FromMilliseconds(800), cts.Token).ConfigureAwait(false);
                await Task.Delay(300, cts.Token).ConfigureAwait(false);
                await MakeTcpAttemptAsync(IPAddress.Parse("1.1.1.1"), 443, TimeSpan.FromMilliseconds(800), cts.Token).ConfigureAwait(false);

                await Task.WhenAny(collectTask, Task.Delay(4500, cts.Token)).ConfigureAwait(false);

                await connectionMonitor.StopAsync().ConfigureAwait(false);
                await pidTracker.StopAsync().ConfigureAwait(false);

                // Ожидаем 1 yielded (дедуп). Если 0 — значит не увидели соединение (возможна среда/политики).
                // Это не должно падать «жёстко»: помечаем как SKIP, чтобы не ломать CI без сети.
                if (yielded == 0)
                {
                    return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Skip, sw.Elapsed,
                        "Не удалось увидеть соединение в snapshot (возможен no-network/политики). Повторите с админом/живой сетью.");
                }

                if (yielded > 1)
                {
                    return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Fail, sw.Elapsed,
                        $"Ожидали 1 уникальную цель, получили {yielded}");
                }

                return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: повторные попытки соединения не порождают новую цель");
            }
            catch (OperationCanceledException)
            {
                return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Skip, sw.Elapsed,
                    "Отменено/таймаут"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("PIPE-007", "TrafficCollector: дедуп по RemoteIp:RemotePort:Protocol (polling)", SmokeOutcome.Fail, sw.Elapsed,
                    ex.Message);
            }
        }

        public static Task<SmokeTestResult> Pipe_Classifier_FakeIpRange(CancellationToken ct)
            => RunAsync("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", () =>
            {
                var classifier = new StandardBlockageClassifier();
                var host = new HostDiscovered(
                    Key: "198.18.0.1:443:TCP",
                    RemoteIp: IPAddress.Parse("198.18.0.1"),
                    RemotePort: 443,
                    Protocol: BypassTransportProtocol.Tcp,
                    DiscoveredAt: DateTime.UtcNow);

                var tested = new HostTested(
                    Host: host,
                    DnsOk: true,
                    TcpOk: true,
                    TlsOk: true,
                    DnsStatus: BlockageCode.StatusOk,
                    Hostname: null,
                    SniHostname: null,
                    ReverseDnsHostname: null,
                    TcpLatencyMs: 10,
                    BlockageType: null,
                    TestedAt: DateTime.UtcNow);

                var blocked = classifier.ClassifyBlockage(tested);
                if (BlockageCode.Normalize(blocked.TestResult.BlockageType) != BlockageCode.FakeIp)
                {
                    return new SmokeTestResult("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали {BlockageCode.FakeIp}, получили '{blocked.TestResult.BlockageType ?? "<null>"}'");
                }

                return new SmokeTestResult("PIPE-016", "Классификация FAKE_IP (198.18.0.0/15)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: адрес из 198.18/15 помечается как FakeIp");
            }, ct);

        public static async Task<SmokeTestResult> Bypass_TlsBypassService_RegistersFilter(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Skip, sw.Elapsed,
                        "Пропуск: нет прав администратора (WinDivert требует Elevated)"
                    );
                }

                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var options = svc.GetOptionsSnapshot() with
                {
                    FragmentEnabled = true,
                    DisorderEnabled = false,
                    FakeEnabled = false,
                    DropRstEnabled = false
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(3));

                await svc.ApplyAsync(options, cts.Token).ConfigureAwait(false);

                var filters = GetEngineFiltersSnapshot(engine);
                if (!filters.Any(f => f.Name == "BypassFilter"))
                {
                    return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Fail, sw.Elapsed,
                        "BypassFilter не найден в списке фильтров TrafficEngine после ApplyAsync"
                    );
                }

                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: BypassFilter зарегистрирован"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Bypass_TlsBypassService_RemovesFilter(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Skip, sw.Elapsed,
                        "Пропуск: нет прав администратора (WinDivert требует Elevated)"
                    );
                }

                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var enable = svc.GetOptionsSnapshot() with
                {
                    FragmentEnabled = true,
                    DisorderEnabled = false,
                    FakeEnabled = false,
                    DropRstEnabled = false
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(4));

                await svc.ApplyAsync(enable, cts.Token).ConfigureAwait(false);
                await svc.DisableAsync(cts.Token).ConfigureAwait(false);

                var filters = GetEngineFiltersSnapshot(engine);
                if (filters.Any(f => f.Name == "BypassFilter"))
                {
                    return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Fail, sw.Elapsed,
                        "BypassFilter всё ещё присутствует после DisableAsync"
                    );
                }

                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: BypassFilter удалён"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Bypass_TlsBypassService_ProfilePresetPresent(CancellationToken ct)
            => RunAsync("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", () =>
            {
                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var names = svc.FragmentPresets.Select(p => p.Name).ToList();

                if (names.Count == 0)
                {
                    return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Список пресетов пуст");
                }

                if (!names.Contains("Профиль"))
                {
                    return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Нет пресета 'Профиль' (размеры из bypass_profile.json)");
                }

                return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {string.Join(", ", names)}");
            }, ct);

        private sealed class DummyPacketFilter : IPacketFilter
        {
            public string Name { get; }
            public int Priority { get; }

            public DummyPacketFilter(string name, int priority)
            {
                Name = name;
                Priority = priority;
            }

            public bool Process(InterceptedPacket packet, PacketContext ctx, IPacketSender sender)
            {
                return true;
            }
        }

        private static async Task MakeTcpAttemptAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
        {
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            try
            {
                await tcp.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            }
            catch
            {
                // Нам не важен успех рукопожатия, важен факт попытки соединения в TCP таблице.
            }
        }

        private static List<IPacketFilter> GetEngineFiltersSnapshot(TrafficEngine engine)
        {
            // Smoke-тест: используем reflection, чтобы проверить реальный порядок после сортировки.
            var fields = typeof(TrafficEngine)
                .GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);

            var listField = fields.FirstOrDefault(f => typeof(List<IPacketFilter>).IsAssignableFrom(f.FieldType));
            if (listField == null)
            {
                return new List<IPacketFilter>();
            }

            var value = listField.GetValue(engine) as List<IPacketFilter>;
            if (value == null)
            {
                return new List<IPacketFilter>();
            }

            lock (value)
            {
                return value.ToList();
            }
        }

        private static Task<SmokeTestResult> RunAsync(string id, string name, Func<SmokeTestResult> body, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                ct.ThrowIfCancellationRequested();
                var result = body();
                sw.Stop();
                return Task.FromResult(result with { Duration = sw.Elapsed });
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                return Task.FromResult(new SmokeTestResult(id, name, SmokeOutcome.Skip, sw.Elapsed, "Отменено"));
            }
            catch (Exception ex)
            {
                sw.Stop();
                return Task.FromResult(new SmokeTestResult(id, name, SmokeOutcome.Fail, sw.Elapsed, ex.Message));
            }
        }
    }
}
