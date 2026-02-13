# ISP_Audit — TODO

Дата актуализации: 13.02.2026
Выполненное → [CHANGELOG.md](../CHANGELOG.md). Архитектура → [ARCHITECTURE_CURRENT.md](../ARCHITECTURE_CURRENT.md). Аудит → [docs/audit4.md](audit4.md).

---

## Приоритеты
- 🔴 Критический: влияет на корректность детекции/обхода или стабильность рантайма
- 🟡 Важный: повышает точность/надёжность, снижает риск регрессий
- 🟢 Низкий: UX/полиш/интеграции/рефакторинг

---

## 🔴 P0 — Критические

### P0.4 TrafficEngine — воспроизведение и стресс-тесты
- [ ] Собрать контекст: при следующем краше сохранить ±100 строк лога → issue/docs

### P0.5 Apply timeout — диагностика причин
- Инцидентный чеклист (делается только если/когда поймаем реальное зависание; не блокирует выпуск):
	- [ ] При следующем реальном зависании: сохранить полный лог с фазовой диагностикой → issue/docs
	- [ ] По логу: классифицировать фазу зависания (WinDivert stop / DNS resolve / Dispatcher deadlock / connectivity check)
	- [ ] Для найденной фазы: добавить CancellationToken с таймаутом или Task.WhenAny + deadline

---

## 🟡 P1 — Важные

### P1.1 `DateTime.UtcNow` на hot path TrafficEngine
- [x] В `Core/Traffic/TrafficEngine.cs` ~L395: заменить `DateTime.UtcNow.Ticks` → `Stopwatch.GetTimestamp()`
- [x] ~L396: аналогично для endTicks
- [x] Пересчёт elapsed: `(endTs - startTs) * 1_000_000 / Stopwatch.Frequency`
- [x] Добавить `using System.Diagnostics` если отсутствует
- [x] Smoke strict: PASS
- Источник: audit4 §3.1

### P1.2 Унификация маршалинга в UI-поток
- [x] Grep `Dispatcher\.Invoke\b` по ViewModels/ — составить список всех 20+ мест
- [x] Каждый без возвращаемого результата → заменить на `Dispatcher.BeginInvoke`
- [x] Где нужен результат → оставить Invoke с комментарием `// Invoke: нужен результат`
- [x] `TestResultsManager.cs`: заменить `Application.Current.Dispatcher` на IProgress или SynchronizationContext
- [x] Smoke ui + smoke reg: PASS
- Источник: audit4 §7.1

### P1.3 `IDisposable` для MainViewModel
- [x] Добавить `: IDisposable` к MainViewModel
- [x] Реализовать Dispose(): `_trafficEngine?.Dispose()`, `_bypassStateManager?.Dispose()`, `_networkChangeMonitor?.Dispose()`
- [x] В `App.xaml.cs` OnExit: `(_sharedMainViewModel as IDisposable)?.Dispose()` после ShutdownAsync
- [x] Smoke strict: PASS
- Источник: audit4 §2.4

### P1.4 OperatorViewModel декомпозиция
- [x] Создать `ViewModels/OperatorViewModel.Wizard.cs` (partial) — wizard flow шаги 1-4 (~300 строк)
- [x] Создать `ViewModels/OperatorViewModel.History.cs` (partial) — история сессий + фильтры (~400 строк)
- [x] Создать `ViewModels/OperatorViewModel.Sessions.cs` (partial) — persist/load сессий (~200 строк)
- [x] Создать `ViewModels/OperatorViewModel.AutoPilot.cs` (partial) — execution policy + escalation (~300 строк)
- [x] В основном OperatorViewModel.cs оставить: свойства состояния, конструктор, маппинг (<400 строк)
- [x] Smoke ui + smoke strict: PASS
- Источник: audit4 §1.3

### P1.5 Приоритизация и деградация очередей Pipeline
- [x] В `LiveTestingPipeline`: high/low очереди для хостов (manual retest, профильные цели, повторные фейлы)
- [x] TesterWorker: выбирать high первым (high → low) и брать permit до dequeue
- [x] Политика дропа: low bounded=50 + DropOldest
- [x] Degrade mode: PendingCount > 20 три тика → для low использовать timeout/2 (best-effort)
- [x] Метрика QueueAgeMs (Stopwatch на enqueue, diff на dequeue) → лог p95
- [x] Smoke: `PIPE-020` — высокий enq rate, high-priority начинается <5с
- [x] Auto-apply auto-retest: enqueue в high-priority (чтобы не «тонул» в low)
- [x] Smoke reg + smoke ui + smoke strict: PASS

### P1.6 CDN-подхосты — детали по раскрытию
- [x] В XAML Engineer таблицы: при клике на строку ×N → раскрыть список подхостов (RowDetails)
- [x] В `TestResultsManager`: метод `GetGroupMembers(string groupKey)` → `IReadOnlyList<TestResult>`
- [x] В Operator UI: подхосты в Expander «Подробнее» внутри карточки группы
- [x] Smoke ui: `UI-024` (Engineer ×N) + `UI-026` (Operator «Подробнее»: подхосты)

### P1.8 Operator UI — локализация/тексты
- [x] Создать `Utils/OperatorTextMapper.cs` — static Dictionary код→текст (DNS_ERROR, TCP_RESET, TLS_HANDSHAKE_TIMEOUT, QUIC_INTERFERENCE, HTTP_REDIRECT_DPI, UDP_BLOCKAGE)
- [x] Каждому коду: человеческая формулировка + краткая рекомендация (1 строка)
- [x] OperatorViewModel: использовать OperatorTextMapper для сводки вместо raw кодов
- [x] CTA тексты: единые формулировки (Проверить / Исправить / Усилить / Откатить / Проверить снова)
- [x] Smoke ui: Operator UI не показывает raw-коды типа TLS_AUTH_FAILURE

### P1.9 Operator UI — wins-библиотека
- [x] Создать `Models/WinsEntry.cs`: запись подтверждённого успеха (apply + post-apply OK)
- [x] Создать `Utils/WinsStore.cs`: persist в `state/wins_store.json` + ENV override `ISP_AUDIT_WINS_STORE_PATH`
- [x] После post-apply retest OK (и только при наличии txId) → WinsStore.Persist(...)
- [x] При повторной встрече хоста: если есть Win → кнопка «Исправить» применяет проверенный обход (без подбора) и сразу запускает post-apply ретест
- [x] Smoke: `REG-028` — wins round-trip (persist + load + best-match)

### P1.10 Operator UI — escalation GUI
- [x] При PostApplyStatus == FAIL/PARTIAL → IsEscalationAvailable = true, CTA = «Усилить»
- [x] EscalateCommand: ApplyEscalation(currentGroupKey) → более агрессивная стратегия
- [x] После escalation: авто post-apply retest → обновление статуса
- [x] Лог: `[ESCALATION] group={key} from={old} to={new} result={OK/FAIL}`
- [x] Smoke: `UI-025` — escalation flow (apply → FAIL → escalate → retest)

### P1.11 Стабилизация YouTube/Google (эталонные сценарии)
- [ ] Документ `docs/scenarios/youtube_baseline.md`: браузер, провайдер, профиль, QUIC вкл/выкл, ожидаемый результат
- [ ] Прогнать вручную оба сценария, зафиксировать логи + скриншоты → docs
- [ ] По логам: если хуже предыдущей версии — git bisect до коммита
- [ ] При необходимости: режим classic — фиксированный набор (TLS fragment + DNS), env `ISP_AUDIT_CLASSIC_MODE`

### P1.12 Policy-driven — незакрытое
- [x] Advanced UI: OperatorSettingsWindow → вкладка «Политики» — DataGrid CRUD (add/edit/delete + валидация)
- [x] Perf: замер `DecisionGraphSnapshot.Evaluate()` при 100/500/1000 политик → smoke `PERF-004`
- [x] Cap: max 200 политик, при превышении WARN + отказ
- [x] Async recompile: compile (hard-conflict detection) на фоне + re-apply текущих опций

### P1.13 Стратегии обхода — долги
- [x] BadChecksum: tooltip в Engineer UI «Только для фейковых пакетов (TTL=1)» + раздел README
- [x] QuicObfuscation: финализировать реализацию через `DropUdp443` + вынести apply в `Bypass/Strategies/QuicObfuscationStrategy.cs`
- [x] HttpHostTricks: метрики applied/matched в наблюдаемость
- [x] Auto-hostlist: в StandardBlockageClassifier учитывать принадлежность к hostlist при рекомендации

### P1.14 INTEL — доминирование/веса планов
- [x] В IntelPlanSelector: если новый план ⊂ активного → skip с логом «dominated by {activeId}»
- [x] PlanWeight = strength × confidence / cost → сортировка при выборе
- [x] Feedback boost: WinRate > 70% → weight ×1.5; WinRate < 30% → ×0.5
- [x] Smoke: `REG-029` — dominated plan не применяется повторно
- [x] QUIC fallback SSoT: убрать дублирование `StrategyId.QuicObfuscation` vs `plan.DropUdp443` (оставить один канонический путь)

### P1.15 Шум в логах и повторный init
- [x] ConnectionMonitor (polling): отмена при shutdown не логируется как Error (TaskCanceled)
- [x] MainViewModel.InitializeAsync: идемпотентность (двойной вызов из App + Window_Loaded не перезапускает bypass)
- [x] MainWindow.Loaded: убран дублирующий вызов InitializeAsync (SSoT: App.EnsureInitializedAsync)

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
- [x] NuGet: `Microsoft.Extensions.DependencyInjection`
- [x] `Utils/ServiceCollectionExtensions.cs`: регистрация всех сервисов
- [x] DI: `ITrafficFilter` (singleton) → `UnifiedTrafficFilter`; `AutoHostlistService` (singleton)
- [x] `App.xaml.cs`: ServiceCollection → ConfigureServices → BuildServiceProvider
- [x] Начать с NoiseHostFilter: AddSingleton → инъекция через конструктор
- [x] Переключено (первые потребители NoiseHostFilter):
	- `MainViewModel`: принимает `NoiseHostFilter` (fallback-конструктор оставлен для back-compat)
	- `DiagnosticOrchestrator`: принимает `NoiseHostFilter`, загрузка правил через `LoadFromFile(...)` на том же экземпляре
	- `TestResultsManager`: принимает `NoiseHostFilter`, hot-path логика без глобального состояния
	- `UnifiedTrafficFilter`: принимает `NoiseHostFilter` (в оркестраторе создаётся с инъекцией)
	- `LiveTestingPipeline` (classifier stage): перепроверка шума через `ITrafficFilter.IsNoise(...)`
	- `DomainGroupLearner`: принимает `NoiseHostFilter` (создаётся из `TestResultsManager` с инъекцией)
	- `DnsParserService`: принимает `NoiseHostFilter` (создаётся из оркестратора с инъекцией)
	- `AutoHostlistService`: принимает `NoiseHostFilter` (singleton в DI)
	- `Converters/TestResultGroupConverters`: `NoiseHostFilter` резолвится из DI через `App` (fallback: локальный экземпляр без static)
	- `TestNetworkApp smoke`: CFG-004/CFG-005/PIPE-006 переведены на DI (`ServiceCollection.AddIspAuditServices()`), legacy static API `NoiseHostFilter.Initialize/Instance` удалён
- [ ] Осталось переключить:
	- [x] Убраны обращения к `NoiseHostFilter.Instance` (static singleton API удалён, глобального состояния больше нет)
	- [x] Убрано использование/наличие `NoiseHostFilter.Initialize(...)` (legacy static API удалён)
	- [x] Убраны скрытые fallback-конструкторы/пути создания `NoiseHostFilter` (например, `UnifiedTrafficFilter()` / `AutoHostlistService()` / `DomainGroupLearner(...)` overload)
	- [x] `TrafficCollector` и `LiveTestingPipeline` больше не создают фильтр сами (`?? new ...` удалён) — фильтр передаётся явно
	- [x] Убраны fallback-конструкторы/пути, которые создавали `NoiseHostFilter` внутри `DiagnosticOrchestrator` / `TestResultsManager`
	- [x] `MainViewModel`: граф `TrafficEngine`/`BypassStateManager`/`BypassController`/`DiagnosticOrchestrator`/`TestResultsManager`/`GroupBypassAttachmentStore` переведён на DI (без ручных `new`)
	- [x] `TrafficEngine` и `BypassStateManager` зарегистрированы в DI (SSoT сохраняется через `BypassStateManager.GetOrCreate`)
	- [ ] Дальше по зависимостям с ресурсами: `LiveTestingPipeline`, `StandardHostTester`, etc.

### 4.2 Устранение глобального состояния
- [x] Удалить legacy `Config.ActiveProfile` (Profiles/*.json loader для целей диагностики)
- [x] Удалить legacy `Program.Targets`
- [x] NoiseHostFilter → удалён static singleton API, сервис передаётся через конструктор/DI
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

---

### P1.7 Operator UI — визуальный дизайн
- [ ] Создать `Wpf/Themes/OperatorDarkTheme.xaml` — тёмная палитра MaterialDesign
- [ ] `OperatorWindow.xaml`: применять тёмную тему через MergedDictionaries
- [ ] Hero-элемент: Viewbox + Path (щит SVG) + TextBlock крупный статус-текст, центрирование
- [ ] Компоновка Grid: Header 48px / Hero+Status Star / CTA Auto / Expander / Footer toggle
- [ ] Компактный индикатор: Ellipse 12px с цветом по OperatorStatus (серый/зелёный/жёлтый/красный)
