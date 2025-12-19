using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Traffic;

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
                        Console.WriteLine($"[SMOKE] План загружен: {p} (items={items.Count})");
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

                Console.WriteLine($"[SMOKE] Запланировано тестов: {runner._tests.Count} (plan={plan.Count}, implemented={implemented.Count}, category={cat})");

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
}
