# ISP_Audit — TODO

Дата актуализации: 10.02.2026
Выполненное → [CHANGELOG.md](../CHANGELOG.md). Архитектура → [ARCHITECTURE_CURRENT.md](../ARCHITECTURE_CURRENT.md). Аудит → [docs/audit4.md](audit4.md).

---

## Приоритеты
- 🔴 Критический: влияет на корректность детекции/обхода или стабильность рантайма
- 🟡 Важный: повышает точность/надёжность, снижает риск регрессий
- 🟢 Низкий: UX/полиш/интеграции/рефакторинг

---

## 🔴 P0 — Критические

### P0.1 `async void` не-event handler (CRASH RISK)
- [ ] Изменить сигнатуру `CheckAndRetestFailedTargets` → `async Task CheckAndRetestFailedTargetsAsync` в `ViewModels/MainViewModel.Helpers.cs:94`
- [ ] На вызывающей стороне: обернуть в `_ = SafeFireAndForget(CheckAndRetestFailedTargetsAsync(...))` с try/catch + логированием
- [ ] Проверить отсутствие других `async void` не-event handler (grep `async void` по ViewModels/)
- [ ] Smoke reg: убедиться что ретест по-прежнему работает (PASS)
- Источник: audit4 §2.1

### P0.2 Sync-over-async deadlock (App.OnExit)
- [ ] `App.xaml.cs` ~L152: заменить `ShutdownAsync().GetAwaiter().GetResult()` → `Task.Run(() => ShutdownAsync()).Wait(TimeSpan.FromSeconds(10))`
- [ ] `TrafficEngine.cs` Dispose(): аналогичная обёртка `Task.Run(() => StopAsync()).Wait(timeout)`
- [ ] `ConnectionMonitorService.cs` Dispose(): аналогичная обёртка
- [ ] `DnsSnifferService.cs` Dispose(): аналогичная обёртка
- [ ] `PidTrackerService.cs` Dispose(): аналогичная обёртка
- [ ] Smoke strict: убедиться что shutdown не зависает (PASS)
- Источник: audit4 §2.2

### P0.3 `MessageBox.Show` в ViewModel (MVVM нарушение)
- [ ] В `DiagnosticOrchestrator` добавить свойство `Func<string, string, bool> ConfirmAction` (инъекция через конструктор или property)
- [ ] Заменить `MessageBox.Show` ~L76-81 на вызов `ConfirmAction?.Invoke(title, message) ?? false`
- [ ] Заменить `MessageBox.Show` ~L407 аналогично
- [ ] В `MainViewModel` при создании Orchestrator: привязать `ConfirmAction` к `MessageBox.Show` (production) или no-op (тесты)
- [ ] Grep `MessageBox` по проекту — убедиться что нет других вызовов из ViewModel/Service слоёв
- Источник: audit4 §1.4

### P0.4 TrafficEngine — воспроизведение и стресс-тесты
- [ ] Собрать контекст: при следующем краше сохранить ±100 строк лога → issue/docs
- [ ] Написать сценарий воспроизведения: README шаги (профиль, браузер, частота кликов Apply)
- [ ] Stress smoke: `INFRA-010` — 1000 rapid Apply/Rollback за 60с, проверка: нет утечек `GC.GetTotalMemory`, нет падений
- [ ] Perf smoke: `PERF-002` — замерить p50/p95/p99 latency ProcessPacket при 10K пакетов, baseline
- [ ] Unit-тест: concurrent RegisterFilter/RemoveFilter + ProcessPacket из разных потоков

### P0.5 Apply timeout — диагностика причин
- [ ] При следующем реальном зависании: сохранить полный лог с фазовой диагностикой → issue/docs
- [ ] По логу: классифицировать фазу зависания (WinDivert stop / DNS resolve / Dispatcher deadlock / connectivity check)
- [ ] Для найденной фазы: добавить CancellationToken с таймаутом или Task.WhenAny + deadline
- [ ] KPI smoke: `PERF-003` — 10 последовательных Apply/Disable, каждый <3с (95-й перцентиль)
- [ ] Проверить `TrafficEngine.StopAsync`: добавить CTS с таймаутом 5с

### P0.6 Аудит пустых `catch { }`
- [ ] `FixService.cs`: 6 пустых catch → в каждый `Debug.WriteLine` с контекстом операции
- [ ] `DiagnosticOrchestrator.Core.cs`: 3+ пустых catch → `_progress?.Report` с ex.Message
- [ ] `DnsSnifferService.cs`: 2+ пустых catch → `Debug.WriteLine`
- [ ] `TestResultsManager.DnsResolution.cs`: 1 пустой catch → `Debug.WriteLine`
- [ ] `MainViewModel.Logging.cs`: 1 пустой catch → `Debug.WriteLine`
- [ ] `App.xaml.cs`: 1 пустой catch EnsureInitializedAsync → `Debug.WriteLine`
- [ ] `StandardHostTester.cs`: 2 catch в DNS reverse → `Debug.WriteLine`
- [ ] Финальный grep `catch\s*\{?\s*\}` — убедиться что не осталось полностью пустых
- Источник: audit4 §2.3

---

## 🟡 P1 — Важные

### P1.1 `DateTime.UtcNow` на hot path TrafficEngine
- [ ] В `Core/Traffic/TrafficEngine.cs` ~L395: заменить `DateTime.UtcNow.Ticks` → `Stopwatch.GetTimestamp()`
- [ ] ~L396: аналогично для endTicks
- [ ] Пересчёт elapsed: `(endTs - startTs) * 1_000_000 / Stopwatch.Frequency`
- [ ] Добавить `using System.Diagnostics` если отсутствует
- [ ] Smoke strict: PASS
- Источник: audit4 §3.1

### P1.2 Унификация маршалинга в UI-поток
- [ ] Grep `Dispatcher\.Invoke\b` по ViewModels/ — составить список всех 20+ мест
- [ ] Каждый без возвращаемого результата → заменить на `Dispatcher.BeginInvoke`
- [ ] Где нужен результат → оставить Invoke с комментарием `// Invoke: нужен результат`
- [ ] `TestResultsManager.cs`: заменить `Application.Current.Dispatcher` на IProgress или SynchronizationContext
- [ ] Smoke ui + smoke reg: PASS
- Источник: audit4 §7.1

### P1.3 `IDisposable` для MainViewModel
- [ ] Добавить `: IDisposable` к MainViewModel
- [ ] Реализовать Dispose(): `_trafficEngine?.Dispose()`, `_bypassStateManager?.Dispose()`, `_networkChangeMonitor?.Dispose()`
- [ ] В `App.xaml.cs` OnExit: `(_sharedMainViewModel as IDisposable)?.Dispose()` после ShutdownAsync
- [ ] Smoke strict: PASS
- Источник: audit4 §2.4

### P1.4 OperatorViewModel декомпозиция
- [ ] Создать `ViewModels/OperatorViewModel.Wizard.cs` (partial) — wizard flow шаги 1-4 (~300 строк)
- [ ] Создать `ViewModels/OperatorViewModel.History.cs` (partial) — история сессий + фильтры (~400 строк)
- [ ] Создать `ViewModels/OperatorViewModel.Sessions.cs` (partial) — persist/load сессий (~200 строк)
- [ ] Создать `ViewModels/OperatorViewModel.AutoPilot.cs` (partial) — execution policy + escalation (~300 строк)
- [ ] В основном OperatorViewModel.cs оставить: свойства состояния, конструктор, маппинг (<400 строк)
- [ ] Smoke ui + smoke strict: PASS
- Источник: audit4 §1.3

### P1.5 Приоритизация и деградация очередей Pipeline
- [ ] В `LiveTestingPipeline`: второй `Channel<HostDiscovered>` для high-priority (manual retest, профильные цели, повторные фейлы)
- [ ] TesterWorker: читать high первым (TryRead high → затем low)
- [ ] Политика дропа: при low.Count > 50 → discard oldest
- [ ] Degrade mode: PendingCount > 20 три тика → timeout low = timeout/2
- [ ] Метрика QueueAgeMs (Stopwatch на enqueue, diff на dequeue) → лог p95
- [ ] Smoke: `PIPE-010` — высокий enq rate, high-priority проходят за <5с

### P1.6 CDN-подхосты — детали по раскрытию
- [ ] В XAML Engineer таблицы: при клике на строку ×N → раскрыть ItemsControl с подхостами (host, IP, статус)
- [ ] В `TestResultsManager`: метод `GetGroupMembers(string groupKey)` → `IReadOnlyList<TestResult>`
- [ ] В Operator UI: подхосты в Expander «Подробнее» внутри карточки группы
- [ ] Smoke ui: агрегированная карточка с 3+ подхостами рендерится без ошибок

### P1.7 Operator UI — визуальный дизайн
- [ ] Создать `Wpf/Themes/OperatorDarkTheme.xaml` — тёмная палитра MaterialDesign
- [ ] `OperatorWindow.xaml`: применять тёмную тему через MergedDictionaries
- [ ] Hero-элемент: Viewbox + Path (щит SVG) + TextBlock крупный статус-текст, центрирование
- [ ] Компоновка Grid: Header 48px / Hero+Status Star / CTA Auto / Expander / Footer toggle
- [ ] Компактный индикатор: Ellipse 12px с цветом по OperatorStatus (серый/зелёный/жёлтый/красный)

### P1.8 Operator UI — локализация/тексты
- [ ] Создать `Utils/OperatorTextMapper.cs` — static Dictionary код→текст (DNS_ERROR, TCP_RESET, TLS_HANDSHAKE_TIMEOUT, QUIC_INTERFERENCE, HTTP_REDIRECT_DPI, UDP_BLOCKAGE)
- [ ] Каждому коду: человеческая формулировка + краткая рекомендация (1 строка)
- [ ] OperatorViewModel: использовать OperatorTextMapper для сводки вместо raw кодов
- [ ] CTA тексты: единые формулировки (Проверить / Исправить / Усилить / Откатить / Проверить снова)
- [ ] Smoke ui: Operator UI не показывает raw-коды типа TLS_AUTH_FAILURE

### P1.9 Operator UI — wins-библиотека
- [ ] Создать `Models/WinsEntry.cs`: record WinsEntry(Host, Sni, StrategyId, PlanText, WonAt)
- [ ] Создать `Utils/WinsStore.cs`: persist в `state/wins_store.json`, RecordWin, GetWin(host, sni)
- [ ] После post-apply retest OK → WinsStore.RecordWin(...)
- [ ] При повторной встрече хоста: если есть Win → предложить «Применить проверенный обход?»
- [ ] Smoke: `REG-028` — wins round-trip (record + retrieve + apply)

### P1.10 Operator UI — escalation GUI
- [ ] При PostApplyStatus == FAIL/PARTIAL → IsEscalationAvailable = true, CTA = «Усилить»
- [ ] EscalateCommand: ApplyEscalation(currentGroupKey) → более агрессивная стратегия
- [ ] После escalation: авто post-apply retest → обновление статуса
- [ ] Лог: `[ESCALATION] group={key} from={old} to={new} result={OK/FAIL}`
- [ ] Smoke: `UI-024` — escalation flow (apply → FAIL → escalate → retest)

### P1.11 Стабилизация YouTube/Google (эталонные сценарии)
- [ ] Документ `docs/scenarios/youtube_baseline.md`: браузер, провайдер, профиль, QUIC вкл/выкл, ожидаемый результат
- [ ] Прогнать вручную оба сценария, зафиксировать логи + скриншоты → docs
- [ ] По логам: если хуже предыдущей версии — git bisect до коммита
- [ ] При необходимости: режим classic — фиксированный набор (TLS fragment + DNS), env `ISP_AUDIT_CLASSIC_MODE`

### P1.12 Policy-driven — незакрытое
- [ ] Advanced UI: SettingsWindow → вкладка «Политики» — DataGrid для FlowPolicy (add/edit/delete + валидация)
- [ ] Perf: замерить DecisionGraph.Evaluate() при 100/500/1000 политик → smoke `PERF-004`
- [ ] Cap: max 200 политик, при превышении WARN + отказ
- [ ] Async recompile: DecisionGraph.RecompileAsync() на фоновом потоке

### P1.13 Стратегии обхода — долги
- [ ] BadChecksum: tooltip в Engineer UI «Только для фейковых пакетов (TTL=1)» + раздел README
- [ ] QuicObfuscation: stub `Bypass/Strategies/QuicObfuscationStrategy.cs` с TODO
- [ ] HttpHostTricks: метрики applied/matched в наблюдаемость
- [ ] Auto-hostlist: в StandardBlockageClassifier учитывать принадлежность к hostlist при рекомендации

### P1.14 INTEL — доминирование/веса планов
- [ ] В IntelPlanSelector: если новый план ⊂ активного → skip с логом «dominated by {activeId}»
- [ ] PlanWeight = strength × confidence / cost → сортировка при выборе
- [ ] Feedback boost: WinRate > 70% → weight ×1.5; WinRate < 30% → ×0.5
- [ ] Smoke: `REG-029` — dominated plan не применяется повторно

---

## 🟢 P2 — Низкий приоритет / UX / Рефакторинг

### P2.1 AutoRetest debounce
- [ ] В MainViewModel.Helpers.cs: `_lastAutoRetestTime` + минимальный интервал 5с
- [ ] При попытке ретеста раньше интервала: skip + лог `[RETEST] Throttled`
- [ ] ENV override: `ISP_AUDIT_RETEST_DEBOUNCE_MS` (default 5000)

### P2.2 Early noise filter
- [ ] В ClassifierWorker: перед эмитом проверять NoiseHostFilter.IsNoise(host)
- [ ] noise + OK → не эмитить в UI (только детальный лог)
- [ ] noise + FAIL → эмитить как WARN (понизить приоритет)
- [ ] Smoke: `PIPE-011` — шумовой хост с OK не появляется в results

### P2.3 История транзакций для карточки
- [ ] В TestResult: `List<ApplyTransaction> TransactionHistory` (max 10)
- [ ] В BypassController.ApplyIntelPlan: добавлять запись в TransactionHistory
- [ ] В Engineer UI: двойной клик → DataGrid с TransactionHistory (время, план, результат)

### P2.4 Smoke-тесты на fail-path FixService
- [ ] `ERR-010`: RestoreDns при отсутствии snapshot → graceful error, не crash
- [ ] `ERR-011`: ApplyDoH при невалидном URL → graceful error + лог
- [ ] `ERR-012`: RemoveDoH при отсутствии профиля → no-op + лог

### P2.5 `HttpClient` на каждый H3 probe
- [ ] Статический SocketsHttpHandler с PooledConnectionLifetime = 2 min в StandardHostTester
- [ ] Единый static HttpClient с Version30 + этим handler
- [ ] Убрать per-call создание handler+client из ProbeHttp3Async
- [ ] Smoke strict: PASS

### P2.6 Event subscriptions без отписки
- [ ] В ShutdownAsync (или Dispose): отписаться от всех 8 событий (-=)
- [ ] Список: OnLog, PropertyChanged, OnPerformanceUpdate, OnPipelineMessage, OnDiagnosticComplete + остальные
- [ ] Сохранять handler-ы в поля для отписки

### P2.7 State persistence — race conditions
- [ ] Создать `Utils/FileAtomicWriter.cs`: serialize → temp file → File.Move(overwrite: true)
- [ ] Заменить File.WriteAllText в state stores на FileAtomicWriter
- [ ] Stores: operator_sessions, feedback_store, operator_consent, domain_groups, post_apply_checks, ui_mode
- [ ] Smoke reg: PASS (state round-trip)

---

## Phase 4 — Рефакторинг (архитектурный долг)

### 4.1 DI container
- [ ] NuGet: `Microsoft.Extensions.DependencyInjection`
- [ ] `Utils/ServiceCollectionExtensions.cs`: регистрация всех сервисов
- [ ] `App.xaml.cs`: ServiceCollection → ConfigureServices → BuildServiceProvider
- [ ] Постепенно: `new Service()` → `GetRequiredService<T>()`
- [ ] Начать с NoiseHostFilter: AddSingleton → инъекция через конструктор

### 4.2 Устранение глобального состояния
- [ ] Config.ActiveProfile → IProfileService.Current (injectable singleton)
- [ ] Program.Targets → ITargetRegistry (injectable, заполняется через IProfileService)
- [ ] NoiseHostFilter.Instance → убрать static, принимать через конструктор (DI)
- [ ] BypassStateManager.GetOrCreate → registered factory в DI

### 4.3 Декомпозиция DiagnosticOrchestrator
- [ ] Выделить `Core/Pipeline/PipelineManager.cs` — lifecycle LiveTestingPipeline
- [ ] Выделить `Core/Recommendations/RecommendationEngine.cs` — INTEL plan selection/emit
- [ ] Выделить `ViewModels/CardActionHandler.cs` — Apply/Retest/Details по карточкам
- [ ] В Orchestrator оставить: координация фаз (start/stop/warmup/silence) + делегирование
- [ ] Убрать все MessageBox.Show и Dispatcher зависимости из Orchestrator

### 4.4 Разделение документации
- [x] `ARCHITECTURE_CURRENT.md` — теперь чистый архитектурный справочник (725→444 строк: убраны все датированные записи и inline-changelog)
- [x] `docs/full_repo_audit_intel.md` — убрана спам-шапка «Дополнение» (942→891 строк), добавлены перекрёстные ссылки
- [x] Ссылки в README, copilot-instructions, TODO — проверены, без изменений (файл не переименован)

---

## Phase 5 — Native Core (Rust DLL)

### 5.0 Инфраструктура Rust
- [ ] `cargo init native/isp_audit_native --lib` с crate-type = ["cdylib"]
- [ ] В ISP_Audit.csproj: Target BuildRust → cargo build --release
- [ ] Post-build: копировать DLL в output directory
- [ ] CI: Rust toolchain в build pipeline (если есть)

### 5.1 WinDivert FFI обёртка
- [ ] `native/src/windivert.rs`: repr(C) struct DivertIpHdr (IPv4 header fields)
- [ ] repr(C) struct DivertTcpHdr (TCP header fields)
- [ ] no_mangle fn divert_calc_checksums(buf, len) с валидацией bounds
- [ ] `WinDivertNativeRust.cs`: P/Invoke DllImport + feature flag ISP_AUDIT_USE_RUST_NATIVE

### 5.2 Packet parser (zero-copy)
- [ ] `native/src/parser.rs`: parse_ip_header(buf) → Result<IpHeader, ParseError>
- [ ] parse_tcp_header, parse_udp_header аналогично
- [ ] FFI: no_mangle fn parse_packet → заполнение C-struct
- [ ] Интеграция в TrafficEngine hot path через P/Invoke

### 5.3 TLS/SNI parser
- [ ] `native/src/tls.rs`: extract_sni(buf) → Option<str> — ClientHello + SNI extension
- [ ] Bounds checking: не паниковать на malformed TLS, возвращать None
- [ ] FFI: no_mangle fn extract_sni(buf, len, out, out_len) → i32
- [ ] Rust unit тесты: valid ClientHello, truncated, garbage, no SNI

### 5.4 Bypass как отдельная .NET DLL
- [ ] Создать `ISP_Audit.Bypass.csproj` (Class Library)
- [ ] Перенести Bypass/, Core/Traffic/ в новый проект
- [ ] ISP_Audit.csproj → ProjectReference
- [ ] Smoke strict: PASS