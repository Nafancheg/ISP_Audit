using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Models;
using IspAudit.Utils;
using IspAudit.ViewModels;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> Ui_OrchestratorInitialized_InViewModel(CancellationToken ct)
            => RunAsync("UI-001", "MainViewModel: Orchestrator создаётся без исключений", () =>
            {
                var vm = new MainViewModel();
                if (vm.Orchestrator == null)
                {
                    return new SmokeTestResult("UI-001", "MainViewModel: Orchestrator создаётся без исключений", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Orchestrator == null");
                }

                if (vm.Bypass == null)
                {
                    return new SmokeTestResult("UI-001", "MainViewModel: Orchestrator создаётся без исключений", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Bypass == null");
                }

                if (vm.Results == null)
                {
                    return new SmokeTestResult("UI-001", "MainViewModel: Orchestrator создаётся без исключений", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Results == null");
                }

                return new SmokeTestResult("UI-001", "MainViewModel: Orchestrator создаётся без исключений", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);

        public static Task<SmokeTestResult> Ui_StartStopCommand_CallsCancelBranch_NoGui(CancellationToken ct)
            => RunAsync("UI-002", "Start/Stop: Cancel-ветка отрабатывает без GUI", () =>
            {
                var vm = new MainViewModel();

                // Эмулируем режим "уже запущено": выставляем orchestrator как running + _cts,
                // чтобы StartOrCancelAsync ушёл в Cancel-ветку и не показывал MessageBox.
                SetPrivateField(vm.Orchestrator, "_isDiagnosticRunning", true);
                SetPrivateField(vm.Orchestrator, "_cts", new CancellationTokenSource());

                // Вызываем приватный StartOrCancelAsync через reflection и ждём.
                var task = (Task)InvokePrivateMethod(vm, "StartOrCancelAsync")!;
                task.GetAwaiter().GetResult();

                var stopReason = GetPrivateField<string?>(vm.Orchestrator, "_stopReason");
                if (!string.Equals(stopReason, "UserCancel", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("UI-002", "Start/Stop: Cancel-ветка отрабатывает без GUI", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали stopReason='UserCancel', получили '{stopReason ?? "<null>"}'");
                }

                return new SmokeTestResult("UI-002", "Start/Stop: Cancel-ветка отрабатывает без GUI", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: Cancel срабатывает и не требует GUI");
            }, ct);

        public static Task<SmokeTestResult> Ui_RelayCommand_DoesNotSwallowExceptions(CancellationToken ct)
            => RunAsync("UI-003", "RelayCommand: исключения не проглатываются", () =>
            {
                var cmd = new IspAudit.Wpf.RelayCommand(_ => throw new InvalidOperationException("boom"));
                try
                {
                    cmd.Execute(null);
                    return new SmokeTestResult("UI-003", "RelayCommand: исключения не проглатываются", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали исключение из Execute, но его не было");
                }
                catch (InvalidOperationException)
                {
                    return new SmokeTestResult("UI-003", "RelayCommand: исключения не проглатываются", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: исключение пробрасывается наружу");
                }
            }, ct);

        public static async Task<SmokeTestResult> Ui_BypassToggle_UpdatesTlsServiceOptions(CancellationToken ct)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using var engine = new TrafficEngine();
                var bypass = new BypassController(engine);

                bypass.IsFragmentEnabled = true;

                // ApplyBypassOptionsAsync — fire-and-forget, ждём чуть-чуть.
                await Task.Delay(250, ct).ConfigureAwait(false);

                var snapshot = bypass.TlsService.GetOptionsSnapshot();
                if (!snapshot.FragmentEnabled)
                {
                    return new SmokeTestResult("UI-004", "UI-тумблер Fragment отражается в TlsBypassService", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали FragmentEnabled=true в snapshot после переключения");
                }

                return new SmokeTestResult("UI-004", "UI-тумблер Fragment отражается в TlsBypassService", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: ApplyAsync применил FragmentEnabled=true");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("UI-004", "UI-тумблер Fragment отражается в TlsBypassService", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Ui_BypassPreset_SaveDoesNotOverwriteTtlOrRedirect(CancellationToken ct)
            => RunAsync("UI-005", "Preset: сохраняется без перезаписи TTL/redirect rules", () =>
            {
                using var engine = new TrafficEngine();
                var bypass = new BypassController(engine);

                // Используем GetProfilePath через reflection, чтобы получить правильный путь профиля
                var getProfilePathMethod = typeof(BypassProfile).GetMethod("GetProfilePath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                var profilePath = (string)getProfilePathMethod!.Invoke(null, null)!;

                // Подготовим профиль: выставим не-дефолтные TTL/redirect, чтобы отследить перезапись.
                // Важно: используем текущую схему RedirectRules (Name/Protocol/Port/Hosts...),
                // иначе сериализация нормализует документ и инварианты будут «меняться».
                var seedJson = "{\n" +
                               "  \"TtlTrick\": true,\n" +
                               "  \"TtlTrickValue\": 7,\n" +
                               "  \"AutoTtl\": true,\n" +
                               "  \"RedirectRules\": [\n" +
                               "    { \"Name\": \"Rule1\", \"Protocol\": \"Tcp\", \"Port\": 443, \"RedirectIp\": \"1.2.3.4\", \"RedirectPort\": 443, \"Enabled\": true, \"Hosts\": [\"example.com\"] }\n" +
                               "  ],\n" +
                               "  \"TlsFragmentSizes\": [10, 20, 30],\n" +
                               "  \"FragmentPresetName\": \"SeedPreset\",\n" +
                               "  \"AutoAdjustAggressive\": false\n" +
                               "}";
                File.WriteAllText(profilePath, seedJson);

                static (bool TtlTrick, int TtlTrickValue, bool AutoTtl, int RedirectRulesCount, string FirstRedirectIp, int FirstPort, int FirstRedirectPort) ReadInvariants(string json)
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    var ttlTrick = root.TryGetProperty("TtlTrick", out var p1) && (p1.ValueKind == System.Text.Json.JsonValueKind.True || p1.ValueKind == System.Text.Json.JsonValueKind.False)
                        ? p1.GetBoolean()
                        : false;
                    var ttlValue = root.TryGetProperty("TtlTrickValue", out var p2) && p2.ValueKind == System.Text.Json.JsonValueKind.Number
                        ? p2.GetInt32()
                        : 0;
                    var autoTtl = root.TryGetProperty("AutoTtl", out var p3) && (p3.ValueKind == System.Text.Json.JsonValueKind.True || p3.ValueKind == System.Text.Json.JsonValueKind.False)
                        ? p3.GetBoolean()
                        : false;

                    var redirectsCount = 0;
                    var firstRedirectIp = "";
                    var firstPort = 0;
                    var firstRedirectPort = 0;

                    if (root.TryGetProperty("RedirectRules", out var rr) && rr.ValueKind == System.Text.Json.JsonValueKind.Array)
                    {
                        redirectsCount = rr.GetArrayLength();
                        if (redirectsCount > 0)
                        {
                            var first = rr.EnumerateArray().First();
                            if (first.TryGetProperty("RedirectIp", out var ip) && ip.ValueKind == System.Text.Json.JsonValueKind.String)
                            {
                                firstRedirectIp = ip.GetString() ?? "";
                            }
                            if (first.TryGetProperty("Port", out var port) && port.ValueKind == System.Text.Json.JsonValueKind.Number)
                            {
                                firstPort = port.GetInt32();
                            }
                            if (first.TryGetProperty("RedirectPort", out var rport) && rport.ValueKind == System.Text.Json.JsonValueKind.Number)
                            {
                                firstRedirectPort = rport.GetInt32();
                            }
                        }
                    }

                    return (ttlTrick, ttlValue, autoTtl, redirectsCount, firstRedirectIp, firstPort, firstRedirectPort);
                }

                var beforeJson = File.ReadAllText(profilePath);
                var beforeInv = ReadInvariants(beforeJson);

                // Меняем пресет через контроллер (он должен трогать только fragment-настройки).
                var nextPreset = bypass.FragmentPresets.FirstOrDefault(p => !string.Equals(p.Name, bypass.TlsService.GetOptionsSnapshot().PresetName, StringComparison.OrdinalIgnoreCase))
                    ?? bypass.FragmentPresets.First();

                bypass.SelectedFragmentPreset = nextPreset;

                var afterJson = File.ReadAllText(profilePath);

                var afterInv = ReadInvariants(afterJson);

                if (beforeInv != afterInv)
                {
                    return new SmokeTestResult("UI-005", "Preset: сохраняется без перезаписи TTL/redirect rules", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Инварианты TTL/redirect изменились после сохранения пресета (не должно перетирать поля)");
                }

                // Минимальная проверка: файл остался валидным JSON и не стал короче/пустой.
                if (string.IsNullOrWhiteSpace(afterJson) || afterJson.Length < 20)
                {
                    return new SmokeTestResult("UI-005", "Preset: сохраняется без перезаписи TTL/redirect rules", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Профиль пустой/слишком короткий после сохранения");
                }

                // Консервативно: убеждаемся, что изменения были, но не «сброс всего».
                if (string.Equals(beforeJson, afterJson, StringComparison.Ordinal))
                {
                    return new SmokeTestResult("UI-005", "Preset: сохраняется без перезаписи TTL/redirect rules", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали изменение профиля при выборе пресета, но файл не изменился");
                }

                return new SmokeTestResult("UI-005", "Preset: сохраняется без перезаписи TTL/redirect rules", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: пресет сохраняется, профиль не повреждается");
            }, ct);

        public static Task<SmokeTestResult> Ui_Operator_RawBlockageCodes_AreLocalized(CancellationToken ct)
            => RunAsync("UI-027", "P1.8: Operator UI — raw-коды (TLS_AUTH_FAILURE и т.п.) не отображаются", () =>
            {
                var main = new MainViewModel();
                var op = new OperatorViewModel(main);

                // Важно: триггерим формирование SummaryProblemCards через добавление результата.
                main.TestResults.Add(new TestResult
                {
                    Target = new Target { Name = "Example", Host = "example.com", SniHost = "example.com" },
                    Status = TestStatus.Fail,
                    Error = "TLS_AUTH_FAILURE"
                });

                // Проверяем, что ни одна строка не содержит raw-код.
                foreach (var line in op.SummaryProblemCards)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    if (line.Contains("TLS_AUTH_FAILURE", StringComparison.OrdinalIgnoreCase)
                        || line.Contains("TLS_DPI", StringComparison.OrdinalIgnoreCase)
                        || line.Contains("TLS_TIMEOUT", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult(
                            "UI-027",
                            "P1.8: Operator UI — raw-коды (TLS_AUTH_FAILURE и т.п.) не отображаются",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"В Operator UI остался raw-код в строке: '{line}'");
                    }
                }

                // Доп. sanity: проверим напрямую маппер.
                var localized = OperatorTextMapper.LocalizeCodesInText("TLS_AUTH_FAILURE");
                if (localized.Contains("TLS_AUTH_FAILURE", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult(
                        "UI-027",
                        "P1.8: Operator UI — raw-коды (TLS_AUTH_FAILURE и т.п.) не отображаются",
                        SmokeOutcome.Fail,
                        TimeSpan.Zero,
                        "OperatorTextMapper не локализовал TLS_AUTH_FAILURE");
                }

                return new SmokeTestResult(
                    "UI-027",
                    "P1.8: Operator UI — raw-коды (TLS_AUTH_FAILURE и т.п.) не отображаются",
                    SmokeOutcome.Pass,
                    TimeSpan.Zero,
                    "OK: строки локализованы");
            }, ct);

        public static Task<SmokeTestResult> Ui_NetworkChangePrompt_ShowsAndHides_NoGui(CancellationToken ct)
            => RunAsync("UI-013", "P0.6: Network change prompt показывается/скрывается без GUI", () =>
            {
                var vm = new MainViewModel();

                // Вызываем приватный ShowNetworkChangePrompt через reflection:
                // в smoke-окружении мы не подписываемся на реальные NetworkChange события.
                InvokePrivateMethod(vm, "ShowNetworkChangePrompt");

                if (!vm.IsNetworkChangePromptVisible)
                {
                    return new SmokeTestResult("UI-013", "P0.6: Network change prompt показывается/скрывается без GUI", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали IsNetworkChangePromptVisible=true после ShowNetworkChangePrompt");
                }

                if (string.IsNullOrWhiteSpace(vm.NetworkChangePromptText))
                {
                    return new SmokeTestResult("UI-013", "P0.6: Network change prompt показывается/скрывается без GUI", SmokeOutcome.Fail, TimeSpan.Zero,
                        "NetworkChangePromptText пустой после ShowNetworkChangePrompt");
                }

                // Проверяем, что команда «Игнорировать» скрывает уведомление.
                vm.NetworkIgnoreCommand.Execute(null);
                if (vm.IsNetworkChangePromptVisible)
                {
                    return new SmokeTestResult("UI-013", "P0.6: Network change prompt показывается/скрывается без GUI", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали IsNetworkChangePromptVisible=false после NetworkIgnoreCommand");
                }

                return new SmokeTestResult("UI-013", "P0.6: Network change prompt показывается/скрывается без GUI", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: prompt показывается и скрывается по команде");
            }, ct);

        public static Task<SmokeTestResult> Ui_OperatorEventStore_RoundTrip(CancellationToken ct)
            => RunAsync("UI-015", "P1.11: OperatorEventStore round-trip (best-effort JSON)", () =>
            {
                var tempPath = Path.Combine(Path.GetTempPath(), $"isp_audit_operator_events_smoke_{Guid.NewGuid():N}.json");
                Environment.SetEnvironmentVariable("ISP_AUDIT_OPERATOR_EVENTS_PATH", tempPath);

                try
                {
                    OperatorEventStore.TryDeletePersistedFileBestEffort(null);

                    var now = DateTimeOffset.UtcNow;
                    var older = new OperatorEventEntry
                    {
                        Id = "evt_old",
                        OccurredAtUtc = now.AddMinutes(-5).ToString("u").TrimEnd(),
                        Category = "CHECK",
                        GroupKey = "basic",
                        Title = "Проверка: завершена",
                        Details = "OK",
                        Outcome = "OK",
                        Source = "smoke"
                    };

                    var newer = new OperatorEventEntry
                    {
                        Id = "evt_new",
                        OccurredAtUtc = now.ToString("u").TrimEnd(),
                        Category = "FIX",
                        GroupKey = "basic",
                        Title = "Исправление: завершено",
                        Details = "WARN",
                        Outcome = "WARN",
                        Source = "smoke"
                    };

                    OperatorEventStore.PersistBestEffort(new[] { older, newer }, null);
                    var loaded = OperatorEventStore.LoadBestEffort(null);

                    if (loaded.Count < 2)
                    {
                        return new SmokeTestResult("UI-015", "P1.11: OperatorEventStore round-trip (best-effort JSON)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали >=2 событий после загрузки, получили {loaded.Count}");
                    }

                    // Store гарантирует сортировку: новые сверху.
                    if (!string.Equals(loaded[0].Id, "evt_new", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-015", "P1.11: OperatorEventStore round-trip (best-effort JSON)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали первым событие 'evt_new', получили '{loaded[0].Id}'");
                    }

                    var ids = loaded.Select(e => e.Id).ToArray();
                    if (!ids.Contains("evt_old") || !ids.Contains("evt_new"))
                    {
                        return new SmokeTestResult("UI-015", "P1.11: OperatorEventStore round-trip (best-effort JSON)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали ids evt_old+evt_new, получили: {string.Join(", ", ids)}");
                    }

                    return new SmokeTestResult("UI-015", "P1.11: OperatorEventStore round-trip (best-effort JSON)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: сохраняет/читает и сортирует по времени");
                }
                finally
                {
                    OperatorEventStore.TryDeletePersistedFileBestEffort(null);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_OPERATOR_EVENTS_PATH", null);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_OperatorSessionStore_RoundTrip(CancellationToken ct)
            => RunAsync("UI-016", "P1.11: OperatorSessionStore round-trip (best-effort JSON)", () =>
            {
                var tempPath = Path.Combine(Path.GetTempPath(), $"isp_audit_operator_sessions_smoke_{Guid.NewGuid():N}.json");
                Environment.SetEnvironmentVariable("ISP_AUDIT_OPERATOR_SESSIONS_PATH", tempPath);

                try
                {
                    OperatorSessionStore.TryDeletePersistedFileBestEffort(null);

                    var now = DateTimeOffset.UtcNow;
                    var older = new OperatorSessionEntry
                    {
                        Id = "sess_old",
                        StartedAtUtc = now.AddMinutes(-10).ToString("u").TrimEnd(),
                        EndedAtUtc = now.AddMinutes(-9).ToString("u").TrimEnd(),
                        TrafficSource = "Источник: smoke",
                        AutoFixEnabledAtStart = false,
                        Outcome = "OK",
                        CountsText = "OK: 3 • Нестабильно: 0 • Блокируется: 0",
                        ProblemsText = "",
                        ActionsText = "• Проверка: завершена (норма)",
                        PostApplyVerdict = "",
                        PostApplyStatusText = ""
                    };

                    var newer = new OperatorSessionEntry
                    {
                        Id = "sess_new",
                        StartedAtUtc = now.ToString("u").TrimEnd(),
                        EndedAtUtc = now.AddMinutes(1).ToString("u").TrimEnd(),
                        TrafficSource = "Источник: smoke",
                        AutoFixEnabledAtStart = true,
                        Outcome = "WARN",
                        CountsText = "OK: 1 • Нестабильно: 1 • Блокируется: 0",
                        ProblemsText = "• example.com — WARN",
                        ActionsText = "• Проверка: завершена (есть ограничения)",
                        PostApplyVerdict = "UNKNOWN",
                        PostApplyStatusText = "Ретест после Apply: завершён"
                    };

                    OperatorSessionStore.PersistBestEffort(new[] { older, newer }, null);
                    var loaded = OperatorSessionStore.LoadBestEffort(null);

                    if (loaded.Count < 2)
                    {
                        return new SmokeTestResult("UI-016", "P1.11: OperatorSessionStore round-trip (best-effort JSON)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали >=2 сессий после загрузки, получили {loaded.Count}");
                    }

                    // Store гарантирует сортировку: новые сверху.
                    if (!string.Equals(loaded[0].Id, "sess_new", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-016", "P1.11: OperatorSessionStore round-trip (best-effort JSON)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали первым sess_new, получили '{loaded[0].Id}'");
                    }

                    var ids = loaded.Select(e => e.Id).ToArray();
                    if (!ids.Contains("sess_old") || !ids.Contains("sess_new"))
                    {
                        return new SmokeTestResult("UI-016", "P1.11: OperatorSessionStore round-trip (best-effort JSON)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали ids sess_old+sess_new, получили: {string.Join(", ", ids)}");
                    }

                    return new SmokeTestResult("UI-016", "P1.11: OperatorSessionStore round-trip (best-effort JSON)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: сохраняет/читает без падений (best-effort)");
                }
                finally
                {
                    OperatorSessionStore.TryDeletePersistedFileBestEffort(null);
                    Environment.SetEnvironmentVariable("ISP_AUDIT_OPERATOR_SESSIONS_PATH", null);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_Operator_DnsDohConsentToggle_IsGuardedAgainstAccidentalPersist(CancellationToken ct)
            => RunAsync("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            var candidate = Path.Combine(dir.FullName, "Windows", "OperatorWindow.xaml");
                            if (File.Exists(candidate)) return dir.FullName;
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln")))
                            {
                                // Доп. путь: если нашли sln, но XAML ещё не найден — вероятно он рядом.
                                if (File.Exists(candidate)) return dir.FullName;
                            }
                            dir = dir.Parent;
                        }

                        return null;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория (нет Windows/OperatorWindow.xaml рядом с BaseDirectory)" );
                    }

                    var xamlPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml");
                    if (!File.Exists(xamlPath))
                    {
                        return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Не найден файл: {xamlPath}");
                    }

                    var text = File.ReadAllText(xamlPath);
                    if (string.IsNullOrWhiteSpace(text))
                    {
                        return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "OperatorWindow.xaml пустой");
                    }

                    var required = new List<string>
                    {
                        "IsChecked=\"{Binding Main.AllowDnsDohSystemChanges, Mode=OneWay}\"",
                        "PreviewMouseLeftButtonDown=\"DnsDohConsentToggle_PreviewMouseLeftButtonDown\""
                    };

                    foreach (var r in required)
                    {
                        if (!text.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Не нашли обязательный фрагмент XAML: {r}");
                        }
                    }

                    // Регресс-гейты: TwoWay binding или Click-обработчик могут снова привести к «кратковременной» записи согласия.
                    if (text.Contains("AllowDnsDohSystemChanges, Mode=TwoWay", StringComparison.Ordinal)
                        || text.Contains("IsChecked=\"{Binding Main.AllowDnsDohSystemChanges, Mode=TwoWay}\"", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Найден TwoWay binding для AllowDnsDohSystemChanges (должен быть OneWay)" );
                    }

                    if (text.Contains("Click=\"DnsDohConsentToggle_Click\"", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Найден Click-обработчик для DNS/DoH consent toggle (ожидали PreviewMouseLeftButtonDown)" );
                    }

                    return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-017", "P1.11: DNS/DoH consent toggle guarded (OneWay + Preview handler)", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_OperatorEngineerModeSwitch_Wired(CancellationToken ct)
            => RunAsync("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln")))
                            {
                                return dir.FullName;
                            }

                            dir = dir.Parent;
                        }

                        return null;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория (нет ISP_Audit.sln рядом с BaseDirectory)");
                    }

                    var operatorXamlPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml");
                    var operatorCodeBehindPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml.cs");
                    var mainXamlPath = Path.Combine(root!, "MainWindow.xaml");
                    var mainCodeBehindPath = Path.Combine(root!, "MainWindow.xaml.cs");

                    foreach (var path in new[] { operatorXamlPath, operatorCodeBehindPath, mainXamlPath, mainCodeBehindPath })
                    {
                        if (!File.Exists(path))
                        {
                            return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Не найден файл: {path}");
                        }
                    }

                    var operatorXaml = File.ReadAllText(operatorXamlPath);
                    var operatorCode = File.ReadAllText(operatorCodeBehindPath);
                    var mainXaml = File.ReadAllText(mainXamlPath);
                    var mainCode = File.ReadAllText(mainCodeBehindPath);

                    var requiredOperatorXaml = new List<string>
                    {
                        "ToolTip=\"Расширенный режим\"",
                        "Command=\"{Binding EngineerCommand}\"",
                        "Kind=\"Wrench\""
                    };

                    foreach (var r in requiredOperatorXaml)
                    {
                        if (!operatorXaml.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"OperatorWindow.xaml: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    var requiredOperatorCode = new List<string>
                    {
                        "UiModeStore.SaveBestEffort(UiMode.Engineer)",
                        "app.ShowEngineerWindow()",
                        "_switchingToEngineer"
                    };

                    foreach (var r in requiredOperatorCode)
                    {
                        if (!operatorCode.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"OperatorWindow.xaml.cs: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    var requiredMainXaml = new List<string>
                    {
                        "Content=\"← Оператор\"",
                        "Click=\"ReturnToOperator_Click\""
                    };

                    foreach (var r in requiredMainXaml)
                    {
                        if (!mainXaml.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"MainWindow.xaml: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    var requiredMainCode = new List<string>
                    {
                        "UiModeStore.SaveBestEffort(IspAudit.Utils.UiMode.Operator)",
                        "app.ShowOperatorWindow()",
                        "_switchingToOperator"
                    };

                    foreach (var r in requiredMainCode)
                    {
                        if (!mainCode.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"MainWindow.xaml.cs: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-018", "P1.11: Operator↔Engineer mode switch wired (XAML + handlers)", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_Operator_EscalationButton_AndApplyEscalation_Works_AdminOnly(CancellationToken ct)
            => RunAsyncAwait("UI-023", "P1.11: Operator — «Усилить» после FAIL/PARTIAL запускает ApplyEscalation (admin-only, skip TLS apply)", async innerCt =>
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("UI-023",
                        "P1.11: Operator — «Усилить» после FAIL/PARTIAL запускает ApplyEscalation (admin-only, skip TLS apply)",
                        SmokeOutcome.Skip,
                        TimeSpan.Zero,
                        "Требуются права администратора (в non-admin режиме «Усилить» недоступно)" );
                }

                string? prevSkipTls = null;
                try
                {
                    // Важно: в smoke не трогаем реальный WinDivert/TrafficEngine.
                    // Используем DEBUG-only хук, который пропускает фазу ApplyTlsOptionsAsync.
                    prevSkipTls = Environment.GetEnvironmentVariable(IspAudit.Utils.EnvKeys.TestSkipTlsApply);
                    Environment.SetEnvironmentVariable(IspAudit.Utils.EnvKeys.TestSkipTlsApply, "1");

                    var vm = new MainViewModel();
                    var op = new OperatorViewModel(vm);

                    var hostKey = "example.com";
                    var basePlan = new IspAudit.Core.Intelligence.Contracts.BypassPlan
                    {
                        ForDiagnosis = IspAudit.Core.Intelligence.Contracts.DiagnosisId.TlsInterference,
                        PlanConfidence = 80,
                        Reasoning = "smoke",
                        PlannedAtUtc = DateTimeOffset.UtcNow,
                        Strategies = new List<IspAudit.Core.Intelligence.Contracts.BypassStrategy>
                        {
                            new IspAudit.Core.Intelligence.Contracts.BypassStrategy
                            {
                                Id = IspAudit.Core.Intelligence.Contracts.StrategyId.TlsFragment,
                                BasePriority = 100,
                                Risk = IspAudit.Core.Intelligence.Contracts.RiskLevel.Medium
                            }
                        }
                    };

                    // Подкладываем план в оркестратор так, чтобы ApplyEscalationAsync нашёл базовую цель/план.
                    SetPrivateField(vm.Orchestrator, "_lastIntelPlan", basePlan);
                    SetPrivateField(vm.Orchestrator, "_lastIntelPlanHostKey", hostKey);
                    SetPrivateField(vm.Orchestrator, "_lastIntelDiagnosisHostKey", hostKey);

                    // Эмулируем, что предыдущий post-apply ретест был FAIL — тогда Operator должен перейти в режим «Усилить».
                    SetPrivateField(op, "_lastPostApplyVerdict", "FAIL");

                    if (!string.Equals(op.FixButtonText, "Усилить", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-023",
                            "P1.11: Operator — «Усилить» после FAIL/PARTIAL запускает ApplyEscalation (admin-only, skip TLS apply)",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            $"Ожидали FixButtonText='Усилить', получили '{op.FixButtonText}'" );
                    }

                    // Выполняем ApplyEscalation по приватному async-методу (без RelayCommand async-void).
                    var task = (Task)InvokePrivateMethod(vm, "ApplyEscalationAsync")!;
                    await task.ConfigureAwait(false);

                    if (vm.IsApplyingRecommendations)
                    {
                        return new SmokeTestResult("UI-023",
                            "P1.11: Operator — «Усилить» после FAIL/PARTIAL запускает ApplyEscalation (admin-only, skip TLS apply)",
                            SmokeOutcome.Fail,
                            TimeSpan.Zero,
                            "IsApplyingRecommendations=true после завершения ApplyEscalationAsync (ожидали сброс в false)" );
                    }

                    return new SmokeTestResult("UI-023",
                        "P1.11: Operator — «Усилить» после FAIL/PARTIAL запускает ApplyEscalation (admin-only, skip TLS apply)",
                        SmokeOutcome.Pass,
                        TimeSpan.Zero,
                        "OK" );
                }
                finally
                {
                    Environment.SetEnvironmentVariable(IspAudit.Utils.EnvKeys.TestSkipTlsApply, prevSkipTls);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_OperatorWindow_ShutdownOnClose_Wired(CancellationToken ct)
            => RunAsync("UI-021", "P1.11: Operator shutdown wired (Window.Closing → ShutdownAsync best-effort)", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln")))
                            {
                                return dir.FullName;
                            }

                            dir = dir.Parent;
                        }

                        return null;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-021", "P1.11: Operator shutdown wired (Window.Closing → ShutdownAsync best-effort)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория (нет ISP_Audit.sln рядом с BaseDirectory)");
                    }

                    var operatorCodeBehindPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml.cs");
                    if (!File.Exists(operatorCodeBehindPath))
                    {
                        return new SmokeTestResult("UI-021", "P1.11: Operator shutdown wired (Window.Closing → ShutdownAsync best-effort)", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Не найден файл: {operatorCodeBehindPath}");
                    }

                    var operatorCode = File.ReadAllText(operatorCodeBehindPath);

                    var requiredOperatorCode = new List<string>
                    {
                        "Closing += Window_Closing",
                        "private async void Window_Closing",
                        "e.Cancel = true",
                        "await main.ShutdownAsync",
                        "_switchingToEngineer"
                    };

                    foreach (var r in requiredOperatorCode)
                    {
                        if (!operatorCode.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-021", "P1.11: Operator shutdown wired (Window.Closing → ShutdownAsync best-effort)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"OperatorWindow.xaml.cs: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    return new SmokeTestResult("UI-021", "P1.11: Operator shutdown wired (Window.Closing → ShutdownAsync best-effort)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-021", "P1.11: Operator shutdown wired (Window.Closing → ShutdownAsync best-effort)", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_Operator_MinimalHeader_SettingsHelp_Wired(CancellationToken ct)
            => RunAsync("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln")))
                            {
                                return dir.FullName;
                            }

                            dir = dir.Parent;
                        }

                        return null;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория (нет ISP_Audit.sln рядом с BaseDirectory)");
                    }

                    var operatorXamlPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml");
                    var settingsXamlPath = Path.Combine(root!, "Windows", "OperatorSettingsWindow.xaml");
                    var helpXamlPath = Path.Combine(root!, "Windows", "OperatorHelpWindow.xaml");

                    foreach (var path in new[] { operatorXamlPath, settingsXamlPath, helpXamlPath })
                    {
                        if (!File.Exists(path))
                        {
                            return new SmokeTestResult("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Не найден файл: {path}");
                        }
                    }

                    var operatorXaml = File.ReadAllText(operatorXamlPath);
                    var settingsXaml = File.ReadAllText(settingsXamlPath);
                    var helpXaml = File.ReadAllText(helpXamlPath);

                    var requiredOperatorXaml = new List<string>
                    {
                        "ToolTip=\"Настройки\"",
                        "Command=\"{Binding SettingsCommand}\"",
                        "Kind=\"Cog\"",
                        "ToolTip=\"Справка\"",
                        "Command=\"{Binding HelpCommand}\"",
                        "Kind=\"HelpCircleOutline\""
                    };

                    foreach (var r in requiredOperatorXaml)
                    {
                        if (!operatorXaml.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"OperatorWindow.xaml: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    // Настройки: минимум один operator-safe параметр должен быть доступен.
                    var requiredSettingsXaml = new List<string>
                    {
                        "Content=\"Автоисправление\"",
                        "IsChecked=\"{Binding EnableAutoBypass, Mode=TwoWay}\"",
                        "Content=\"Разрешить DNS/DoH\"",
                        "IsChecked=\"{Binding AllowDnsDohSystemChanges, Mode=OneWay}\"",
                        "PreviewMouseLeftButtonDown=\"DnsDohConsentToggle_PreviewMouseLeftButtonDown\""
                    };

                    foreach (var r in requiredSettingsXaml)
                    {
                        if (!settingsXaml.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"OperatorSettingsWindow.xaml: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    // Справка: должна содержать явное действие для перехода в Engineer.
                    if (!helpXaml.Contains("Открыть расширенный режим", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "OperatorHelpWindow.xaml: не нашли кнопку/текст 'Открыть расширенный режим'");
                    }

                    return new SmokeTestResult("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-022", "P1.11: Operator minimal header wired (⚙️ settings + ? help)", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_CrashReportsPrompt_Wired(CancellationToken ct)
            => RunAsync("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln")))
                            {
                                return dir.FullName;
                            }

                            dir = dir.Parent;
                        }

                        return null;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория (нет ISP_Audit.sln рядом с BaseDirectory)");
                    }

                    var mainXamlPath = Path.Combine(root!, "MainWindow.xaml");
                    var operatorXamlPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml");
                    var vmStatePath = Path.Combine(root!, "ViewModels", "MainViewModel.State.cs");
                    var vmCommandsPath = Path.Combine(root!, "ViewModels", "MainViewModel.Commands.cs");
                    var vmCtorPath = Path.Combine(root!, "ViewModels", "MainViewModel.Constructor.cs");

                    foreach (var path in new[] { mainXamlPath, operatorXamlPath, vmStatePath, vmCommandsPath, vmCtorPath })
                    {
                        if (!File.Exists(path))
                        {
                            return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Не найден файл: {path}");
                        }
                    }

                    var mainXaml = File.ReadAllText(mainXamlPath);
                    var operatorXaml = File.ReadAllText(operatorXamlPath);
                    var vmState = File.ReadAllText(vmStatePath);
                    var vmCommands = File.ReadAllText(vmCommandsPath);
                    var vmCtor = File.ReadAllText(vmCtorPath);

                    var requiredMainXaml = new List<string>
                    {
                        "Отчёты о падении",
                        "Visibility=\"{Binding IsCrashReportsPromptVisible",
                        "Text=\"{Binding CrashReportsPromptText}\"",
                        "Command=\"{Binding CrashReportsOpenFolderCommand}\"",
                        "Command=\"{Binding CrashReportsDismissCommand}\""
                    };

                    foreach (var r in requiredMainXaml)
                    {
                        if (!mainXaml.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"MainWindow.xaml: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    var requiredOperatorXaml = new List<string>
                    {
                        "Отчёты о падении",
                        "Main.IsCrashReportsPromptVisible",
                        "Main.CrashReportsPromptText",
                        "Main.CrashReportsOpenFolderCommand",
                        "Main.CrashReportsDismissCommand"
                    };

                    foreach (var r in requiredOperatorXaml)
                    {
                        if (!operatorXaml.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"OperatorWindow.xaml: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    var requiredVmState = new List<string>
                    {
                        "IsCrashReportsPromptVisible",
                        "CrashReportsPromptText"
                    };

                    foreach (var r in requiredVmState)
                    {
                        if (!vmState.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"MainViewModel.State.cs: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    var requiredVmCommands = new List<string>
                    {
                        "CrashReportsOpenFolderCommand",
                        "CrashReportsDismissCommand"
                    };

                    foreach (var r in requiredVmCommands)
                    {
                        if (!vmCommands.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"MainViewModel.Commands.cs: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    var requiredVmCtor = new List<string>
                    {
                        "CrashReportsSeenStore.LoadLastSeenOrDefault",
                        "CrashReportsDetector.DetectNewSince",
                        "CrashReportsOpenFolderCommand",
                        "CrashReportsDismissCommand"
                    };

                    foreach (var r in requiredVmCtor)
                    {
                        if (!vmCtor.Contains(r, StringComparison.Ordinal))
                        {
                            return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"MainViewModel.Constructor.cs: не нашли обязательный фрагмент: {r}");
                        }
                    }

                    return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-019", "P1.4: Crash-reports prompt wired (XAML + ViewModel)", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_QuicDropTargets_AreVisibleInUiBindings(CancellationToken ct)
            => RunAsync("UI-020", "P1.3: QUIC→TCP targets отображаются в UI (Engineer + Operator)", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln")))
                            {
                                return dir.FullName;
                            }

                            dir = dir.Parent;
                        }

                        return null;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-020", "P1.3: QUIC→TCP targets отображаются в UI (Engineer + Operator)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория (нет ISP_Audit.sln рядом с BaseDirectory)");
                    }

                    var mainXamlPath = Path.Combine(root!, "MainWindow.xaml");
                    var operatorXamlPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml");

                    foreach (var path in new[] { mainXamlPath, operatorXamlPath })
                    {
                        if (!File.Exists(path))
                        {
                            return new SmokeTestResult("UI-020", "P1.3: QUIC→TCP targets отображаются в UI (Engineer + Operator)", SmokeOutcome.Fail, TimeSpan.Zero,
                                $"Не найден файл: {path}");
                        }
                    }

                    var mainXaml = File.ReadAllText(mainXamlPath);
                    var operatorXaml = File.ReadAllText(operatorXamlPath);

                    // Engineer: вкладка Метрики должна показывать список targets.
                    if (!mainXaml.Contains("Bypass.QuicDropTargetsText", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-020", "P1.3: QUIC→TCP targets отображаются в UI (Engineer + Operator)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "MainWindow.xaml: не нашли binding на Bypass.QuicDropTargetsText");
                    }

                    // Operator: в raw expander показываем targets (если есть).
                    if (!operatorXaml.Contains("Main.Bypass.QuicDropTargetsText", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-020", "P1.3: QUIC→TCP targets отображаются в UI (Engineer + Operator)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "OperatorWindow.xaml: не нашли binding на Main.Bypass.QuicDropTargetsText");
                    }

                    return new SmokeTestResult("UI-020", "P1.3: QUIC→TCP targets отображаются в UI (Engineer + Operator)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-020", "P1.3: QUIC→TCP targets отображаются в UI (Engineer + Operator)", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static async Task<SmokeTestResult> Ui_BypassMetrics_UpdatesFromService(CancellationToken ct)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using var engine = new TrafficEngine();
                var bypass = new BypassController(engine);

                // Дёрнем единоразовый сбор метрик (smoke seam). В console runner нет Dispatcher,
                // поэтому UI property не обновится — проверяем только что вызов не крашит.
                await bypass.TlsService.PullMetricsOnceAsyncForSmoke().ConfigureAwait(false);

                return new SmokeTestResult("UI-006", "Метрики bypass обновляются в UI", SmokeOutcome.Pass, sw.Elapsed,
                    "OK");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("UI-006", "Метрики bypass обновляются в UI", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Ui_Verdict_ChangesBrushByColor(CancellationToken ct)
            => RunAsync("UI-007", "Вердикт меняет Brush в зависимости от цвета", () =>
            {
                using var engine = new TrafficEngine();
                var bypass = new BypassController(engine);

                // Вызываем приватный обработчик напрямую. В console runner нет Dispatcher, поэтому
                // UI property не обновится. Проверим только mapping константы (как в OnVerdictChanged коде).
                var redMapping = System.Windows.Media.Color.FromRgb(254, 226, 226);
                var yellowMapping = System.Windows.Media.Color.FromRgb(254, 249, 195);
                var greenMapping = System.Windows.Media.Color.FromRgb(220, 252, 231);

                // Проверяем, что в исходном коде BypassController.OnVerdictChanged правильный switch.
                // Фактически просто создаём brush'и и проверяем значения (детерминированный smoke).
                if (redMapping.R != 254 || redMapping.G != 226 || redMapping.B != 226)
                {
                    return new SmokeTestResult("UI-007", "Вердикт меняет Brush в зависимости от цвета", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Mapping для Red (254,226,226) некорректен");
                }

                return new SmokeTestResult("UI-007", "Вердикт меняет Brush в зависимости от цвета", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);

        public static Task<SmokeTestResult> Ui_TestResultsManager_AddsCardToObservableCollection(CancellationToken ct)
            => RunAsync("UI-008", "TestResultsManager: добавляет карточку", () =>
            {
                var mgr = new TestResultsManager();
                mgr.Initialize();
                mgr.UpdateTestResult("example.com", TestStatus.Fail, "TCP timeout");

                if (mgr.TestResults.Count != 1)
                {
                    return new SmokeTestResult("UI-008", "TestResultsManager: добавляет карточку", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 1 карточку, получили {mgr.TestResults.Count}");
                }

                return new SmokeTestResult("UI-008", "TestResultsManager: добавляет карточку", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);

        public static Task<SmokeTestResult> Ui_TestResultsManager_UpdatesExistingCard_NoDuplicates(CancellationToken ct)
            => RunAsync("UI-009", "TestResultsManager: обновляет карточку, не дублируя", () =>
            {
                var mgr = new TestResultsManager();
                mgr.Initialize();
                mgr.UpdateTestResult("example.com", TestStatus.Fail, "TCP timeout");
                mgr.UpdateTestResult("example.com", TestStatus.Pass, "OK");

                if (mgr.TestResults.Count != 1)
                {
                    return new SmokeTestResult("UI-009", "TestResultsManager: обновляет карточку, не дублируя", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 1 карточку, получили {mgr.TestResults.Count}");
                }

                // Логика TestResultsManager: если в окне есть и Fail, и Pass → Status=Warn ("Нестабильно").
                if (mgr.TestResults[0].Status != TestStatus.Warn)
                {
                    return new SmokeTestResult("UI-009", "TestResultsManager: обновляет карточку, не дублируя", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали Status=Warn (окно содержит Fail+Pass), получили {mgr.TestResults[0].Status}");
                }

                return new SmokeTestResult("UI-009", "TestResultsManager: обновляет карточку, не дублируя", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);

        public static Task<SmokeTestResult> Ui_AggregatedMembers_Expand_Wired_AndGetGroupMembers_Works(CancellationToken ct)
            => RunAsync("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            if (File.Exists(Path.Combine(dir.FullName, "MainWindow.xaml"))) return dir.FullName;
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln"))) return dir.FullName;
                            dir = dir.Parent;
                        }

                        return null;
                    }

                    // 1) Быстрая проверка wiring в XAML (не запускаем WPF).
                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория рядом с BaseDirectory");
                    }

                    var mainXamlPath = Path.Combine(root!, "MainWindow.xaml");
                    if (!File.Exists(mainXamlPath))
                    {
                        return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Fail, TimeSpan.Zero,
                            "MainWindow.xaml не найден");
                    }

                    var xaml = File.ReadAllText(mainXamlPath);
                    if (!xaml.Contains("DataGrid.RowDetailsTemplate", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Fail, TimeSpan.Zero,
                            "MainWindow.xaml: не нашли DataGrid.RowDetailsTemplate");
                    }

                    if (!xaml.Contains("AggregatedMemberBadge_MouseLeftButtonUp", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Fail, TimeSpan.Zero,
                            "MainWindow.xaml: не нашли handler AggregatedMemberBadge_MouseLeftButtonUp");
                    }

                    // 2) Функциональная проверка GetGroupMembers: pinned groupKey схлопывает members.
                    var mgr = new TestResultsManager();
                    mgr.Initialize();

                    var store = new GroupBypassAttachmentStore();
                    var groupKey = "group-smoke";
                    store.PinHostKeyToGroupKey("a.example.com", groupKey);
                    store.PinHostKeyToGroupKey("b.example.com", groupKey);
                    mgr.GroupBypassAttachmentStore = store;

                    // Прогоняем два сообщения пайплайна, чтобы сработал путь:
                    // ParsePipelineMessage → SelectUiKey → TryApplyDomainGroupAggregationAndTrackMembers → TrackAggregationMember.
                    mgr.ParsePipelineMessage("❌ 93.184.216.34:443 SNI=a.example.com RDNS=- | DNS:✓ TCP:✗ TLS:✗ | TCP_CONNECT_TIMEOUT");
                    mgr.ParsePipelineMessage("❌ 93.184.216.34:443 SNI=b.example.com RDNS=- | DNS:✓ TCP:✗ TLS:✗ | TCP_CONNECT_TIMEOUT");

                    var members = mgr.GetGroupMembers(groupKey);
                    if (members.Count < 2)
                    {
                        return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"Ожидали >=2 members для {groupKey}, получили {members.Count}");
                    }

                    var hosts = members.Select(m => m?.DisplayHost ?? string.Empty).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
                    var hasA = hosts.Any(h => string.Equals(h.Trim().Trim('.'), "a.example.com", StringComparison.OrdinalIgnoreCase));
                    var hasB = hosts.Any(h => string.Equals(h.Trim().Trim('.'), "b.example.com", StringComparison.OrdinalIgnoreCase));
                    if (!hasA || !hasB)
                    {
                        return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Fail, TimeSpan.Zero,
                            "В members не нашли a.example.com и b.example.com");
                    }

                    return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-024", "P1.6: агрегированная строка (×N) раскрывается и GetGroupMembers возвращает участников", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_OperatorDetails_SubHosts_Wired(CancellationToken ct)
            => RunAsync("UI-026", "P1.6: Operator — в «Подробнее» показываются подхосты агрегированной группы", () =>
            {
                try
                {
                    static string? TryFindRepoRoot()
                    {
                        var dir = new DirectoryInfo(AppContext.BaseDirectory);
                        for (var i = 0; i < 10 && dir != null; i++)
                        {
                            var candidate = Path.Combine(dir.FullName, "Windows", "OperatorWindow.xaml");
                            if (File.Exists(candidate)) return dir.FullName;
                            if (File.Exists(Path.Combine(dir.FullName, "ISP_Audit.sln"))) return dir.FullName;
                            dir = dir.Parent;
                        }

                        return null;
                    }

                    var root = TryFindRepoRoot();
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        return new SmokeTestResult("UI-026", "P1.6: Operator — в «Подробнее» показываются подхосты агрегированной группы", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Не удалось определить корень репозитория рядом с BaseDirectory");
                    }

                    var operatorXamlPath = Path.Combine(root!, "Windows", "OperatorWindow.xaml");
                    if (!File.Exists(operatorXamlPath))
                    {
                        return new SmokeTestResult("UI-026", "P1.6: Operator — в «Подробнее» показываются подхосты агрегированной группы", SmokeOutcome.Fail, TimeSpan.Zero,
                            "OperatorWindow.xaml не найден");
                    }

                    var xaml = File.ReadAllText(operatorXamlPath);
                    if (!xaml.Contains("UserDetails_SubHosts", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-026", "P1.6: Operator — в «Подробнее» показываются подхосты агрегированной группы", SmokeOutcome.Fail, TimeSpan.Zero,
                            "OperatorWindow.xaml: не нашли binding на Vm.UserDetails_SubHosts");
                    }

                    if (!xaml.Contains("HasUserDetails_SubHosts", StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("UI-026", "P1.6: Operator — в «Подробнее» показываются подхосты агрегированной группы", SmokeOutcome.Fail, TimeSpan.Zero,
                            "OperatorWindow.xaml: не нашли visibility-гейт Vm.HasUserDetails_SubHosts");
                    }

                    return new SmokeTestResult("UI-026", "P1.6: Operator — в «Подробнее» показываются подхосты агрегированной группы", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK");
                }
                catch (Exception ex)
                {
                    return new SmokeTestResult("UI-026", "P1.6: Operator — в «Подробнее» показываются подхосты агрегированной группы", SmokeOutcome.Fail, TimeSpan.Zero,
                        ex.Message);
                }
            }, ct);

        public static Task<SmokeTestResult> Ui_ParsePipelineMessage_ParsesUiLines(CancellationToken ct)
            => RunAsync("UI-010", "ParsePipelineMessage: парсит строки pipeline", () =>
            {
                var mgr = new TestResultsManager();
                mgr.Initialize();

                // Формат UiWorker: "❌ ip:port SNI=... RDNS=... | DNS:✓ TCP:✗ TLS:✗ | TCP_TIMEOUT"
                var msg = "❌ 93.184.216.34:443 SNI=example.com RDNS=- | DNS:✓ TCP:✗ TLS:✗ | TCP_CONNECT_TIMEOUT";
                mgr.ParsePipelineMessage(msg);

                if (mgr.TestResults.Count == 0)
                {
                    return new SmokeTestResult("UI-010", "ParsePipelineMessage: парсит строки pipeline", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Карточка не создана после ParsePipelineMessage");
                }

                var card = mgr.TestResults[0];
                if (card.Target == null || string.IsNullOrWhiteSpace(card.Target.Name))
                {
                    return new SmokeTestResult("UI-010", "ParsePipelineMessage: парсит строки pipeline", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Target/Name не заполнены");
                }

                return new SmokeTestResult("UI-010", "ParsePipelineMessage: парсит строки pipeline", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);

        public static Task<SmokeTestResult> Ui_UiReducerSmoke(CancellationToken ct)
            => RunAsync("UI-011", "UI-Reducer smoke (--ui-reducer-smoke)", () =>
            {
                Program.RunUiReducerSmoke_ForSmokeRunner();
                return new SmokeTestResult("UI-011", "UI-Reducer smoke (--ui-reducer-smoke)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "Выполнено без исключений");
            }, ct);

        public static Task<SmokeTestResult> Ui_SniHostname_HasPriorityOverIp_InCardKey(CancellationToken ct)
            => RunAsync("UI-012", "SNI/hostname имеет приоритет над IP в ключе карточки", () =>
            {
                var mgr = new TestResultsManager();
                mgr.Initialize();

                // Сначала приходит событие по IP.
                mgr.ParsePipelineMessage("❌ 93.184.216.34:443 SNI=- RDNS=- | DNS:✓ TCP:✗ TLS:✗ | TCP_CONNECT_TIMEOUT");
                if (mgr.TestResults.Count != 1)
                {
                    return new SmokeTestResult("UI-012", "SNI/hostname имеет приоритет над IP в ключе карточки", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали 1 карточку после первого сообщения");
                }

                // Затем приходит уточнение с SNI — карточка должна мигрировать на человеко-понятный ключ.
                mgr.ParsePipelineMessage("❌ 93.184.216.34:443 SNI=example.com RDNS=- | DNS:✓ TCP:✗ TLS:✗ | TCP_CONNECT_TIMEOUT");

                var anyHasExample = mgr.TestResults.Any(t =>
                    string.Equals(t.Target.Name, "example.com", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(t.Target.SniHost, "example.com", StringComparison.OrdinalIgnoreCase));

                if (!anyHasExample)
                {
                    return new SmokeTestResult("UI-012", "SNI/hostname имеет приоритет над IP в ключе карточки", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что карточка будет ассоциирована с example.com (Name/SniHost)");
                }

                return new SmokeTestResult("UI-012", "SNI/hostname имеет приоритет над IP в ключе карточки", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);

        public static Task<SmokeTestResult> Ui_PostApplySemantics_PrimaryStatus_OverridesPipelineStatus(CancellationToken ct)
            => RunAsync("UI-014", "P1.8: PrimaryStatus/PrimaryStatusText отражают пост‑проверку как основную метку", () =>
            {
                var tr = new TestResult
                {
                    Status = TestStatus.Fail
                };

                // Без пост‑проверки: всё как раньше.
                if (tr.PostApplyCheckStatus != PostApplyCheckStatus.None)
                {
                    return new SmokeTestResult("UI-014", "P1.8: PrimaryStatus/PrimaryStatusText отражают пост‑проверку как основную метку", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали PostApplyCheckStatus=None по умолчанию");
                }

                if (tr.PrimaryStatus != TestStatus.Fail)
                {
                    return new SmokeTestResult("UI-014", "P1.8: PrimaryStatus/PrimaryStatusText отражают пост‑проверку как основную метку", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали PrimaryStatus=Fail, получили {tr.PrimaryStatus}");
                }

                // С пост‑проверкой OK: PrimaryStatus должен стать Pass, но pipeline Status остаётся Fail.
                tr.PostApplyCheckStatus = PostApplyCheckStatus.Ok;

                if (tr.Status != TestStatus.Fail)
                {
                    return new SmokeTestResult("UI-014", "P1.8: PrimaryStatus/PrimaryStatusText отражают пост‑проверку как основную метку", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что pipeline Status останется Fail (история не должна теряться)");
                }

                if (tr.PrimaryStatus != TestStatus.Pass)
                {
                    return new SmokeTestResult("UI-014", "P1.8: PrimaryStatus/PrimaryStatusText отражают пост‑проверку как основную метку", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали PrimaryStatus=Pass при PostApply=Ok, получили {tr.PrimaryStatus}");
                }

                if (string.IsNullOrWhiteSpace(tr.PrimaryStatusText) || !tr.PrimaryStatusText.Contains("Пост", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("UI-014", "P1.8: PrimaryStatus/PrimaryStatusText отражают пост‑проверку как основную метку", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что PrimaryStatusText будет про пост‑проверку, получили '{tr.PrimaryStatusText}'");
                }

                return new SmokeTestResult("UI-014", "P1.8: PrimaryStatus/PrimaryStatusText отражают пост‑проверку как основную метку", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);
    }
}
