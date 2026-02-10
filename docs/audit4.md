# ISP_Audit — Полный аудит #4

Дата: 10.02.2026
Контекст: .NET 9 WPF, single-file exe (~164MB), диагностика + обход сетевых блокировок.
Smoke: strict 172/172 PASS, ui 22/22 PASS (1 SKIP), reg 27/27 PASS.

---

## 1. Архитектура и дизайн

### 1.1 Документация vs реальность

Документация (`ARCHITECTURE_CURRENT.md`, `docs/full_repo_audit_intel.md`) **достоверно** описывает архитектуру. Поток данных Pipeline, роли компонентов совпадают с кодом.

**Замечания:**
- Документация содержит десятки «дополнений» (актуализаций), которые превращают её в гибрид architecture reference + changelog. Навигация затруднена.
- Рекомендация: разделить на «Architecture Reference» (стабильная часть) и «Change Log» (дельты).

### 1.2 Глобальное состояние — главный архитектурный долг

| Проблема | Файл | Риск |
|----------|------|------|
| `Config.ActiveProfile` — static property, глобальное на весь процесс | Config.cs | Скрытая связь, нетестируемость |
| `Program.Targets` — static Dictionary, заполняется побочным эффектом `SetActiveProfile` | Config.cs | Скрытая зависимость Config → Program |
| `NoiseHostFilter.Instance` — Singleton, используется из 20+ мест | Utils/NoiseHostFilter.cs | Нельзя мокировать, скрытые зависимости |
| `BypassStateManager.GetOrCreate` — фабрика с кэшированием | Bypass/BypassStateManager.cs | Скрытый lifecycle |
| Нет DI-контейнера: граф собирается вручную в `MainViewModel` | ViewModels/MainViewModel.Constructor.cs | Рост сложности wiring |

Всё задокументировано в TODO Phase 4, но не реализовано. **Рекомендация**: начать с `NoiseHostFilter` — заменить Singleton на инъекцию через конструктор, это даст наибольший эффект при минимальных усилиях.

### 1.3 God classes

| Класс | Строк (суммарно) | Ответственности |
|-------|-------------------|-----------------|
| `DiagnosticOrchestrator` | ~2500+ (8 partial) | UI-логика, WPF Dispatcher, сетевая диагностика, lifecycle, рекомендации |
| `MainViewModel` | ~3000+ (10 partial) | Координация всего: bypass, orchestrator, UI state, logging |
| `OperatorViewModel` | ~1631 (1 файл) | Wizard, история, сессии, фильтры, escalation, маппинг состояний |
| `BypassController` | ~868+ (partial) | Apply/rollback, auto-bypass, telemetry |

**Рекомендация**: `OperatorViewModel` — самый очевидный кандидат на декомпозицию через partial (история/сессии/фильтры/wizard как отдельные partial-файлы).

### 1.4 MVVM нарушения

| Нарушение | Файл | Контекст |
|-----------|------|----------|
| `MessageBox.Show(...)` в ViewModel | DiagnosticOrchestrator.Core.cs | ~L76-81, L407 |
| `Application.Current?.Dispatcher.Invoke(...)` напрямую | 20+ мест в ViewModels/ | — |
| `using Application = System.Windows.Application` в BypassController | BypassController.cs | — |
| `TestResultsManager` зависит от `System.Windows.Application.Current.Dispatcher` | TestResultsManager.cs | — |

**Последствие**: ViewModels нетестируемы без запущенного WPF runtime. Это прямо блокирует внедрение unit-тестов.

**Рекомендация**: заменить `MessageBox.Show` на `Func<string, string, bool>` callback или event. Заменить `Dispatcher.Invoke` на `IProgress<T>` / `SynchronizationContext.Post` (уже частично сделано).

---

## 2. Антипаттерны и баги в коде

### 🔴 2.1 `async void` не-event handler

```
ViewModels/MainViewModel.Helpers.cs:94
private async void CheckAndRetestFailedTargets(...)
```

Это **не** event handler. Любое необработанное исключение внутри немедленно аварийно завершит процесс (`TaskScheduler.UnobservedTaskException` НЕ ловит `async void`).

**Фикс**: сделать `async Task`, а на вызывающей стороне — `_ = CheckAndRetestFailedTargetsAsync(...)` с обёрткой исключений.

### 🔴 2.2 Sync-over-async в `App.OnExit` (deadlock risk)

```
App.xaml.cs:152
_sharedMainViewModel.ShutdownAsync().GetAwaiter().GetResult();
```

`OnExit` вызывается на UI-потоке. `ShutdownAsync` → `DisableAllAsync` → цепочка await-ов. Если где-то внутри цепочки `Dispatcher.Invoke` — **deadlock**. Текущий код полагается на `ConfigureAwait(false)` в цепочке, но это хрупко.

**Аналогичная проблема:**
| Файл | Метод |
|------|-------|
| TrafficEngine.cs ~L471 | `Dispose()` → `StopAsync().GetAwaiter().GetResult()` |
| ConnectionMonitorService.cs ~L269 | `Dispose()` → `StopAsync().GetAwaiter().GetResult()` |
| DnsSnifferService.cs ~L733 | `Dispose()` → `StopAsync().GetAwaiter().GetResult()` |
| PidTrackerService.cs ~L260 | `Dispose()` → `StopAsync().GetAwaiter().GetResult()` |

**Рекомендация**: обернуть в `Task.Run(() => ShutdownAsync()).GetAwaiter().GetResult()` чтобы не захватывать SynchronizationContext. Или реализовать `IAsyncDisposable`.

### 🟡 2.3 Подавленные исключения — 20+ пустых `catch { }`

| Файл | Кол-во | Контекст |
|------|--------|----------|
| FixService.cs | **6** | DNS/DoH операции — особенно опасно, тут модифицируется системный DNS |
| DiagnosticOrchestrator.Core.cs | 3+ | Потеря диагностической информации |
| TestResultsManager.DnsResolution.cs | 1+ | Потеря DNS ошибок |
| MainViewModel.Logging.cs | 1 | Инициализация лога |
| DnsSnifferService.cs | 2+ | Парсинг пакетов |
| App.xaml.cs | 1 | `EnsureInitializedAsync` |
| StandardHostTester.cs | 2 | DNS reverse lookup |

Многие `catch { }` оправданы «best-effort» семантикой, но **нулевое логирование** — плохо. Хотя бы `Debug.WriteLine` или `_progress?.Report` для отлаживаемости.

**Рекомендация**: пройти и в каждый пустой `catch` добавить minimal log. Не меняет поведение, но спасает часы отладки.

### 🟡 2.4 `MainViewModel` не реализует `IDisposable`

`MainViewModel` владеет: `TrafficEngine`, `BypassStateManager`, `NetworkChangeMonitor` — все `IDisposable`. Но сам `MainViewModel` **не реализует** `IDisposable`. Очистка через `ShutdownAsync()`, но нет гарантии вызова при crash/unhandled exception.

### 🟡 2.5 Event subscriptions без отписки

В `MainViewModel.Constructor.cs` (L63-98) выполняется ~8 подписок на события (`OnLog`, `PropertyChanged`, `OnPerformanceUpdate`, `OnPipelineMessage`, `OnDiagnosticComplete`). Нигде в `ShutdownAsync` или `OnAppExit` эти подписки **не снимаются**. Поскольку `MainViewModel` живёт весь lifecycle — на практике утечки нет, но это структурный дефект.

---

## 3. Производительность (hot path)

### 3.1 `DateTime.UtcNow` в TrafficEngine loop

```
Core/Traffic/TrafficEngine.cs ~L395-396:
var startTicks = DateTime.UtcNow.Ticks;
// ... process packet ...
var endTicks = DateTime.UtcNow.Ticks;
```

Два вызова `DateTime.UtcNow` **на каждый пакет**. `DateTime.UtcNow` — syscall; `Stopwatch.GetTimestamp()` или `Environment.TickCount64` — значительно быстрее.

**Рекомендация**: заменить на `Stopwatch.GetTimestamp()` + `Stopwatch.Frequency`.

### 3.2 `HttpClient` создаётся на каждый H3 probe

В `StandardHostTester.ProbeHttp3Async` создаётся `new SocketsHttpHandler()` + `new HttpClient()` **на каждый тест каждого хоста**. При 100+ хостов — 100+ сокетов. `using` корректен, но socket reuse отсутствует.

**Рекомендация (low priority)**: пул или общий `SocketsHttpHandler` с `PooledConnectionLifetime`.

---

## 4. Тестирование

### 4.1 Стратегия

Собственный smoke runner (не xUnit/NUnit). Всего ~172 теста по категориям: `infra`, `pipe`, `insp`, `bypass`, `dpi2`, `orch`, `cfg`, `err`, `e2e`, `perf`, `reg`, `ui`.

**Плюсы:**
- Детерминированные (без реальной сети)
- Покрывают интеграцию: pipeline, diagnosis, strategy selection, serialization
- Строгий режим (`--strict`): SKIP = FAIL

**Минусы:**
- Нет настоящих unit-тестов — нет изоляции через моки
- Нет тестирования конкурентных сценариев (открыто в P0.1)
- Нет property-based тестов для парсеров/фильтров
- Нет тестирования граничных случаев для таймаутов/отмены

### 4.2 Пробелы в покрытии

| Область | Статус |
|---------|--------|
| DNS reverse/forward timeout (зависание) | Исправлено (WithTimeoutAsync), но нет smoke-теста |
| Concurrent apply/cancel race conditions | Нет стресс-тестов (P0.1 TODO) |
| `App.OnExit` deadlock | Нельзя протестировать smoke-ами |
| `FixService` DNS/DoH rollback при ошибке | Нет тестов на fail-path |
| `OperatorViewModel` wizard flow (full cycle) | Частично покрыт UI-018..UI-023 |

### 4.3 Тесты корректности vs «не падает»

- ✅ Детерминированные вычисления (diagnosis, strategy) → ожидаемый результат
- ✅ Serialization round-trip
- ⚠️ Многие тесты — «не упало = PASS», без проверки конечного состояния
- ❌ Нет assertion на побочные эффекты (файлы state/, конфиг)

---

## 5. Bypass и сетевой код

### 5.1 TrafficEngine — позитив

- P0.1 фикс: snapshot iteration `_filtersSnapshot` для `Collection was modified`
- Per-packet catch: единичная ошибка не валит loop
- Crash reporting в `state/crash_reports/traffic_engine/`
- Throttle логов от падающих фильтров

### 5.2 TrafficEngine — проблемы

| Проблема | Риск |
|----------|------|
| `Dispose()` → `StopAsync().GetAwaiter().GetResult()` | Deadlock |
| `_handle?.Dispose()` до `await loopTask` в `StopAsync` | Хрупко (полагается на поведение WinDivert) |
| `DateTime.UtcNow.Ticks` на hot path | Perf деградация |

### 5.3 State persistence — race conditions

Каждый store (sessions, transactions, consent, feedback, groups) реализует чтение/запись файлов самостоятельно, без файловых блокировок. При быстром apply/disable теоретически возможна запись из двух потоков в один файл.

**Рекомендация (low priority)**: ввести `FileAtomicWriter` утилиту (write-to-temp + rename) и единый `IStatePersister<T>`.

---

## 6. Конфигурация

### 6.1 `Config.cs` — смешанная семантика

```
Config.cs содержит:
- Instance: Targets, Timeouts, TestMode
- Static: ActiveProfile, RuntimeFlags
- Static methods: LoadGameProfile, SetActiveProfile
```

Это «God config»: instance и static API смешаны; `SetActiveProfile` имеет побочный эффект (заполнение `Program.Targets`).

### 6.2 Hardcoded значения

| Значение | Файл | Описание |
|----------|------|----------|
| `TcpMaxAttempts = 2` | StandardHostTester.cs | Кол-во попыток TCP |
| `TlsMaxAttempts = 2` | StandardHostTester.cs | Кол-во попыток TLS |
| `MaxRediscoveriesPerKeyPerRun = 3` | TrafficCollector.cs | Лимит редискаверов |
| `RediscoverCooldown = 8s` | TrafficCollector.cs | Кулдаун |
| `WarmupSeconds = 15` | DiagnosticOrchestrator | Прогрев диагностики |
| `SilenceTimeoutSeconds = 60` | DiagnosticOrchestrator | Таймаут тишины |
| `IntelApplyTimeout = 8s` | DiagnosticOrchestrator | Таймаут Apply |
| `MaxHistoryEntries = 256` | OperatorViewModel | Лимит истории |
| Threshold confidence 50/70 | INTEL selector | Пороги решений |

Допустимо на текущем этапе, но при развитии стоит вынести в `appsettings.json` / ENV.

---

## 7. UI / UX код

### 7.1 `Dispatcher.Invoke` vs `Dispatcher.BeginInvoke`

Нет единого паттерна маршалинга в UI-поток:
- `Application.Current?.Dispatcher.Invoke(...)` — синхронный, 20+ мест
- `Application.Current?.Dispatcher.BeginInvoke(...)` — асинхронный, несколько мест
- `IProgress<string>` — через Report, в pipeline

Синхронный `Dispatcher.Invoke` из фонового потока может deadlock-нуть, если UI-поток ждёт тот же ресурс.

**Рекомендация**: унифицировать на `BeginInvoke` или `IProgress<T>`. Синхронный `Invoke` — только где нужен результат.

### 7.2 OperatorWindow bindings

Привязки в OperatorWindow.xaml используют `Vm.` prefix. Стиль корректный: `BoolToVis`, `InverseBoolToVis`. Замечаний к XAML нет.

---

## 8. TODO.md — открытые задачи

### P0 — критические, частично открытые

| ID | Что закрыто | Что открыто |
|----|------------|-------------|
| P0.0 | Основная масса (INTEL, feedback, H3, consent) | Эталонные сценарии YouTube, regression-bisect, «classic» режим |
| P0.1 | Snapshot iteration, crash reporting, correlation | Ручное воспроизведение, stress ≥1000 Apply/мин, perf baseline, unit-тесты concurrency |
| P0.2 | Фазовая диагностика, watchdog, fix services | Сбор логов на реальном зависании, KPI Apply <3с |
| P0.3 | Crash reports, UnobservedTaskException | Аудит всех catch (stack trace + контекст) |

### P1 — важные

| ID | Статус |
|----|--------|
| P1.1 Apply dedup | ✅ Закрыт |
| P1.2 Group domains | ✅ Закрыт |
| P1.7 Post-Apply Retest | ✅ Закрыт |
| P1.8 Семантика «работает» | ✅ Закрыт |
| P1.9 CDN aggregation | Частично (детали по подхостам не реализованы) |
| P1.10 Dedup истории Apply | ✅ Закрыт |
| P1.11 Operator UI | Частично: wizard, wins-библиотека, визуальный дизайн, локализация — открыты |

### Phase 4/5 — не начаты

DI container, устранение глобального состояния, декомпозиция DiagnosticOrchestrator, Native Rust DLL — только в планах.

---

## 9. Сводка: топ-10 рекомендаций

| # | Приоритет | Действие | Файл |
|---|-----------|----------|------|
| 1 | 🔴 | Исправить `async void CheckAndRetestFailedTargets` → `async Task` | MainViewModel.Helpers.cs |
| 2 | 🔴 | Обезопасить `App.OnExit` от deadlock: `Task.Run(() => ShutdownAsync()).Wait(timeout)` | App.xaml.cs |
| 3 | 🔴 | Вынести `MessageBox.Show` из DiagnosticOrchestrator (callback/event) | DiagnosticOrchestrator.Core.cs |
| 4 | 🟡 | Добавить minimal log в 20+ пустых `catch { }` (особенно FixService) | FixService.cs и др. |
| 5 | 🟡 | Заменить `DateTime.UtcNow` на `Stopwatch.GetTimestamp()` в TrafficEngine hot path | TrafficEngine.cs |
| 6 | 🟡 | Унифицировать Dispatcher.Invoke → BeginInvoke/IProgress | ViewModels/*.cs |
| 7 | 🟡 | Декомпозировать OperatorViewModel через partial-файлы | OperatorViewModel.cs |
| 8 | 🟡 | Реализовать `IDisposable` для MainViewModel | MainViewModel.cs |
| 9 | 🟢 | Начать внедрение DI хотя бы для NoiseHostFilter | NoiseHostFilter.cs |
| 10 | 🟢 | Добавить smoke-тесты на fail-path FixService (DNS rollback при ошибке) | SmokeTests.*.cs |

---

## 10. Позитивные моменты

Проект имеет серьёзные сильные стороны:

- **172 smoke теста** с детерминированной верификацией — редкость для проектов такого размера
- **Crash reporting** с best-effort JSON + `UnobservedTaskException` handler
- **Фазовое логирование** Apply и диагностики — отличная наблюдаемость
- **Snapshot iteration** в TrafficEngine — правильный подход к concurrent collections
- **Correlation ID** через apply-транзакции — помогает связывать события
- **Watchdog** для bypass engine — fail-safe при зависании
- **Consent gate** для опасных операций (DNS/DoH) — правильный UX-подход
- **Feedback store** с persist — запоминание «побед» для повторного применения
- **Два UI-режима** (Operator/Engineer) с shared ViewModel — чистая архитектура

Проект зрелый по инфраструктуре наблюдаемости и smoke-тестостроению. Основные долги — в области testability (DI, MVVM purity) и классических .NET антипаттернов (async void, sync-over-async).
