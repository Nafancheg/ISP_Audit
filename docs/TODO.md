# ISP_Audit — TODO

Дата актуализации: 16.02.2026
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

### P0.6 Инвариант безопасности: bypass не должен ломать TCP
- Цель: bypass не имеет права превращать результат вида `DNS:✓ TCP:✓ TLS:✗` в `DNS:✓ TCP:✗ ...`.
- Если после apply/эскалации в post-apply ретесте появляется `TCP_CONNECT_TIMEOUT`/`TCP_RESET` там, где до apply TCP был OK — считаем шаг регрессией и исключаем из эскалации.
	- [ ] Добавить правило сравнения pre/post для пост-apply проверки: если TCP ухудшился → verdict=REGRESSION
	- [ ] При REGRESSION: авто-rollback на предыдущий снимок опций + запись в "harmful strategies" (локальный стор)
	- [ ] Протоколирование для расследования: логировать (policyId/targetKey/dstIp) что именно матчится фильтром в момент регрессии
	- [ ] Отбраковка "молча дропаемых" IP: в ретесте проверять несколько IP, различать "все IP молча дропают" vs "частично"
	- [ ] Smoke: apply не ухудшает TCP (минимальный тест на инвариант)

---

## 🟡 P1 — Важные

### P1.16 Семантика стратегии: SelectedStrategy vs EffectiveStrategy
- Проблема: UI показывает "стратегию" (выбор/рекомендация), но пользователь ожидает, что это "что реально применено".
	- [ ] Жёстко разделить в модели состояния: Selected/Recommended (из INTEL/UI) и Effective/Applied (из engine snapshot)
	- [ ] В UI явно подписать оба состояния (например: "Рекомендовано" vs "Активно сейчас")
	- [ ] Для Effective показывать источники: policy-driven snapshot / legacy / disabled + timestamp последнего apply
	- [ ] Smoke ui: покрыть кейс "рекомендовано != применено" (не вводит в заблуждение)

### P1.17 Auto-apply: если confidence всегда 55%, авто-применение не случится
- Проблема: фиксированный порог (70%) при типичных 55% делает auto-apply практически недостижимым.
	- [ ] Вынести пороги в настройки/ENV (минимум: общий порог и отдельный порог для safe-стратегий)
	- [ ] Ввести tiering: безопасные шаги (например TLS_FRAGMENT, DROP_UDP_443) допускаются при меньшей уверенности, опасные (Fake/NoSNI/и т.п.) — только при высокой
	- [ ] Добавить накопление уверенности от повторяемости (N одинаковых фейлов за окно времени → повышаем confidence)
	- [ ] Логи: всегда печатать причину skip auto-apply (порог/небезопасно/инвариант TCP)

### P1.18 Post-apply ретест: единая семантика "OK" и защита от ложноположительных
	- [ ] Унифицировать критерий OK между режимами enqueue/local (одинаковая логика verdict)
	- [ ] Для YouTube/Google: OK только по сильным endpoints (например `generate_204` с ожиданием 204), не по 301/любой строке HTTP
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

### P1.7 Operator UI — визуальный дизайн
- [ ] Создать `Wpf/Themes/OperatorDarkTheme.xaml` — тёмная палитра MaterialDesign
- [ ] `OperatorWindow.xaml`: применять тёмную тему через MergedDictionaries
- [ ] Hero-элемент: Viewbox + Path (щит SVG) + TextBlock крупный статус-текст, центрирование
- [ ] Компоновка Grid: Header 48px / Hero+Status Star / CTA Auto / Expander / Footer toggle
- [ ] Компактный индикатор: Ellipse 12px с цветом по OperatorStatus (серый/зелёный/жёлтый/красный)
