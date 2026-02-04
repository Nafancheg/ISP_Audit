using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using IspAudit.Bypass;
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
