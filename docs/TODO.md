# ISP_Audit — TODO

Дата актуализации: 16.02.2026
Выполненное → [CHANGELOG.md](../CHANGELOG.md). Архитектура → [ARCHITECTURE_CURRENT.md](../ARCHITECTURE_CURRENT.md). Аудит → [docs/audit4.md](audit4.md).

---

## Приоритеты
- 🔴 Критический: влияет на корректность детекции/обхода или стабильность рантайма
- 🟡 Важный: повышает точность/надёжность, снижает риск регрессий
- 🟢 Низкий: UX/полиш/интеграции/рефакторинг

---

## Policy v2.2 — symptom-based execution (финальный план)

### Согласованные операционные уточнения v2.2
- [ ] `VerdictStatus = Ok|Fail|Unknown` + `UnknownReason` (минимум: `InsufficientDns`, `InsufficientIps`, `ProbeTimeoutBudget`, `NoBaseline`, `Cancelled`, `ConcurrentApply`)
- [ ] S-проекция применяется только при `VerdictStatus != Unknown`; `Unknown` не маппится в S0–S4
- [ ] Redirect burst defaults: `N=3` разных eTLD+1, `T=10 минут`, `WindowRetention=30 минут`
- [ ] Guardrail stop-list: не делать rollback/blacklist при `NoBaseline`, `InsufficientIps`, `Cancelled`, `ConcurrentApply`, `ApplyError/partial apply`
- [ ] Blacklist v1: `version=1`, key=`scopeKey+planSig+deltaStep+reason`, поля `createdAtUtc/expiresAtUtc/hitCount/lastSeenUtc`, дедуп по key
- [ ] ClassicMode boundary: `run = baseline → apply/escalate/rollback → retest` на одном `scopeKey`; freeze только within-run
- [ ] UI reason contract: `ReasonCode` (закрытый словарь) + `ReasonText` (стабильный локализованный текст)

### 🔴 P0 (must-have)

#### P0.V22.1 Unknown/InsufficientData как first-class статус
- Depends: none
- Risk: low
- [ ] Ввести `VerdictStatus` и `UnknownReason` в результатах healthcheck/post-apply
- [ ] Запретить fallback в S0 при недостатке данных
- [ ] Зафиксировать детерминированный приоритет `UnknownReason`, если причин несколько

#### P0.V22.2 SSoT healthcheck по профилям целей
- Depends: P0.V22.1
- Risk: medium
- [ ] Канон `web-like`: `DNS → TCP → TLS → HTTP(HEAD->GET fallback)`
- [ ] Канон `tcp-only`: `DNS(if hostname) → TCP`
- [ ] Канон `udp-observe`: `DNS(if hostname) → observe-only` (без ложного FAIL по активному UDP, если probe нет)
- [ ] Исключение `target=IP`: `DnsOk=N/A`, без `FAIL(DNS)`

#### P0.V22.3 HttpRedirect: RedirectNormal vs RedirectSuspicious
- Depends: P0.V22.2
- Risk: medium
- [ ] Оставить `DiagnosisId.HttpRedirect` как HC anomaly channel (не symptom-блокировка по умолчанию)
- [ ] Жёсткие признаки suspicious: `https→http`, redirect на literal IP/RFC1918/.local, смена eTLD+1
- [ ] Soft-score suspicious включать только при burst N/T
- [ ] `RedirectNormal` не должен запускать DPI-эскалацию

#### P0.V22.4 Guardrail TCP regression (анти-флап + stop-list)
- Depends: P0.V22.2
- Risk: high
- [ ] Baseline до apply: `TcpOkBefore`, `successCountBefore`, `M`
- [ ] After retest: `TcpOkAfter`, `successCountAfter`, `M`
- [ ] Анти-флап: rollback/blacklist только по правилу `2/3` или `K-of-M` при `before>=1 && after==0`
- [ ] Явно реализовать stop-list условий, когда rollback запрещён
- [ ] Добавить freshness baseline (TTL сравнения), чтобы не сравнивать устаревшее состояние

#### P0.V22.5 Blacklist v1 (dedup/version/TTL)
- Depends: P0.V22.4
- Risk: medium
- [ ] Store schema v1 + дедуп/апдейт `hitCount/lastSeenUtc/expiresAtUtc`
- [ ] Для multi-action apply банить `planSig`
- [ ] Для escalation банить `deltaStep` (с сохранением `planSig` для трассировки)
- [ ] Проверять blacklist перед auto-apply и escalation

#### P0.V22.6 UI: reason codes + effective + слойный статус
- Depends: P0.V22.1, P0.V22.2, P0.V22.4, P0.V22.5
- Risk: low-medium
- [ ] Показывать `TargetHost`
- [ ] Показывать строку слоя `DNS/TCP/TLS/HTTP` (+ redirect class)
- [ ] Показывать `EffectiveStrategy` + `LastAction/AppliedAt`
- [ ] Показывать `ReasonCode` и стабильный `ReasonText` при skip/fail/rollback

### 🟡 P1 (управляемость/воспроизводимость)

#### P1.V22.1 ClassicMode v1: freeze mutation within-run
- Depends: P0.V22.2, P0.V22.4
- Risk: medium
- [ ] Ввести `ISP_AUDIT_CLASSIC_MODE` и документировать семантику
- [ ] Observe-only для реактивных мутаций within-run
- [ ] Разрешить всегда: `apply/escalate/rollback` и guardrail rollback
- [ ] Между runs разрешить latched update caches/adjust
- [ ] Фиксировать параметры проверок на run (`timeouts/attempts/M-K/order`)

#### P1.V22.2 Redirect burst cache (N/T + retention)
- Depends: P0.V22.3
- Risk: low
- [ ] Сессионный/оконный кэш redirect-host статистики
- [ ] Очистка/retention по `WindowRetention`
- [ ] Детерминированная агрегация по eTLD+1

#### P1.V22.3 Structured events/logging v2
- Depends: P0.V22.1
- Risk: low
- [ ] Единые события: `apply/escalate/rollback/blacklist_hit/skip_reason`
- [ ] Во все события добавить `RunId`, `scopeKey`, `planSig`, `ReasonCode`
- [ ] Логи пригодны для smoke/assert без парсинга «свободного текста»

### 🟢 P2 (улучшения)

#### P2.V22.1 Тюнинг дефолтов N/T/TTL по телеметрии
- [ ] Вынести параметры в runtime-конфиг/ENV
- [ ] Подготовить методику пересмотра дефолтов

#### P2.V22.2 Advanced diagnostics UI (optional)
- [ ] Экран/панель для продвинутой диагностики policy/guardrail

#### P2.V22.3 Тонкая UDP-политика (если появится активный UDP probe)
- [ ] Определить критерии PASS/FAIL/UNKNOWN для UDP-active сценариев

### Acceptance criteria v2.2
- [ ] При одинаковых signals S-проекция (`S4→S3→S2→S1→S0`) детерминирована; при недостатке данных итог `Unknown`, не `S0`
- [ ] `301/302` сам по себе не запускает DPI-эскалацию; `RedirectSuspicious` требует жёстких признаков и/или `N/T` soft-score
- [ ] При TCP regression по анти-флап правилам выполняется rollback и появляется blacklist-запись (dedup) с TTL
- [ ] В ClassicMode нет автоматических мутаций effective within-run; параметры проверок фиксируются на run
- [ ] UI всегда показывает `ReasonCode` для apply/escalation/rollback/skip путей

### Superseded (замещено Policy v2.2)
- `P0.6` замещён: `P0.V22.4` + `P0.V22.5`
- `P1.16` замещён: `P0.V22.6`

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

### P1.17 Auto-apply: если confidence всегда 55%, авто-применение не случится
- Проблема: фиксированный порог (70%) при типичных 55% делает auto-apply практически недостижимым.
	- [ ] Вынести пороги в настройки/ENV (минимум: общий порог и отдельный порог для safe-стратегий)
	- [ ] Ввести tiering: безопасные шаги (например TLS_FRAGMENT, DROP_UDP_443) допускаются при меньшей уверенности, опасные (Fake/NoSNI/и т.п.) — только при высокой
	- [ ] Добавить накопление уверенности от повторяемости (N одинаковых фейлов за окно времени → повышаем confidence)
	- [ ] Логи: всегда печатать причину skip auto-apply (порог/небезопасно/инвариант TCP)

### P1.18 Post-apply ретест: единая семантика "OK" и защита от ложноположительных
	- [ ] Унифицировать критерий OK между режимами enqueue/local (одинаковая логика verdict)
	- [ ] Инвалидация/миграция WinsStore при изменении семантики outcome-probe (старые записи могут быть "фальш-OK")

---

## 🟢 P2 — Низкий приоритет / UX / Рефакторинг

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

### 4.3 Декомпозиция DiagnosticOrchestrator
- [ ] Выделить `Core/Pipeline/PipelineManager.cs` — lifecycle LiveTestingPipeline
- [ ] Выделить `Core/Recommendations/RecommendationEngine.cs` — INTEL plan selection/emit
- [ ] Выделить `ViewModels/CardActionHandler.cs` — Apply/Retest/Details по карточкам
- [ ] В Orchestrator оставить: координация фаз (start/stop/warmup/silence) + делегирование
- [ ] Убрать все MessageBox.Show и Dispatcher зависимости из Orchestrator

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

