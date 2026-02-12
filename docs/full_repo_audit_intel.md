# Полный аудит репозитория ISP_Audit (INTEL)

Примечание: имя файла историческое (`full_repo_audit_intel.md`). В пользовательском UX и в логах проекта не используется маркировка V1/INTEL; основной префикс рекомендаций — `[INTEL]`.

**Дата**: 09.12.2025 (обновлено 10.12.2025, 17.12.2025, 15.01.2026, 16.01.2026, 29.01.2026, 05.02.2026, 11.02.2026, 12.02.2026)
**Версия проекта**: .NET 9, WPF
**Режим**: GUI-only (WinExe)

> Хронология изменений — в [CHANGELOG.md](../CHANGELOG.md). Архитектурный справочник — в [ARCHITECTURE_CURRENT.md](../ARCHITECTURE_CURRENT.md). Задачи — в [TODO.md](TODO.md).

---

## 1. Карта зависимостей проекта

### 1.1 Архитектура верхнего уровня

```
┌─────────────────────────────────────────────────────────────────┐
│                        ТОЧКА ВХОДА                               │
│                       Program.cs                                 │
│              ↓ new App().Run()                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     UI LAYER (WPF)                              │
│  App.xaml → OperatorWindow.xaml / MainWindow.xaml               │
│                     ↓                                           │
│              MainViewModel (shared)                             │
│                              ↓                                  │
│  ├── BypassController (прокси к BypassStateManager)            │
│  ├── DiagnosticOrchestrator (запуск диагностики)               │
│  └── TestResultsManager (UI коллекция результатов)             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   ORCHESTRATION LAYER                           │
│              DiagnosticOrchestrator                             │
│                              ↓                                  │
│  ├── TrafficCollector (сбор сетевых соединений)                │
│  ├── LiveTestingPipeline (тестирование хостов)                 │
│  ├── BypassStateManager (SSoT для bypass/engine)               │
│  └── TrafficEngine (WinDivert bypass)                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     CORE LAYER                                  │
│  ├── Core/Modules/StandardHostTester                            │
│  ├── Core/Intelligence/Diagnosis/StandardDiagnosisEngine     │
│  ├── Core/Modules/InMemoryBlockageStateStore                    │
│  ├── Core/Modules/TcpRetransmissionTracker                     │
│  ├── Core/Modules/HttpRedirectDetector                         │
│  ├── Core/Modules/RstInspectionService                         │
│  ├── Core/Modules/UdpInspectionService                         │
│  └── Core/Traffic/TrafficEngine + Filters                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    SERVICES LAYER                               │
│  ├── ConnectionMonitorService (WinDivert Socket/Polling)       │
│  ├── DnsParserService (SNI/DNS парсинг; отдельные кеши DNS/SNI; SNI с минимальным реассемблингом ClientHello) │
│  ├── PidTrackerService (отслеживание PID)                      │
│  ├── TcpConnectionWatcher (IP Helper API polling)              │
│  ├── NoiseHostFilter (фильтрация шумных хостов)                │
│  └── FixService (DNS fix через netsh)                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    BYPASS LAYER                                 │
│  ├── BypassCoordinator (выбор стратегии)                       │
│  ├── TlsBypassService (применение опций/пресетов, события метрик)│
│  ├── BypassFilter (TLS fragment/disorder/fake, параметризуемые │
│      размеры)                                                  │
│  ├── BypassProfile (конфигурация)                              │
│  ├── StrategyMapping (блокировка → стратегия)                  │
│  └── WinDivertNative (P/Invoke)                                │
└─────────────────────────────────────────────────────────────────┘
* Панель Bypass Control в UI: тумблеры Fragment/Disorder/Fake/Drop RST/DoH, бейдж статуса/latency, выпадающий список пресетов фрагментации (стандарт/умеренный/агрессивный) и метрики фрагментации/RST.

Актуализация (Dev, 16.01.2026): заготовка Rust DLL для WinDivertNative
- Добавлен Rust cdylib: [native/isp_audit_native/](native/isp_audit_native/)
- DLL экспортирует `divert_*` функции и **проксирует** их в `WinDivert.dll` (динамическая загрузка через `LoadLibraryA/GetProcAddress`)
- Цель: подготовить безопасную/изолированную native-обвязку под будущий feature-flag переключения P/Invoke без переписывания Bypass-логики

Актуализация (Runtime, 26.12.2025): принудительный откат с QUIC на TCP (INTEL)
- TLS-обход в `BypassFilter` применим только к TCP-трафику (ClientHello на 443). YouTube и многие сайты по умолчанию используют QUIC/HTTP3 (UDP/443), поэтому «TLS стратегии включены, а сайт не оживает» может быть просто тем, что трафик не TCP. Для этого есть явный флаг `DropUdp443` (тумблер `QUIC→TCP`), который принудительно переводит клиент на TCP/HTTPS.
- `DropUdp443` поддерживает 2 режима подавления UDP/443:
    - **Селективно (по цели)**: подавление по observed IPv4 адресам цели. `BypassStateManager` держит кэш IP цели с TTL/cap (cold-start через DNS resolve host) и прокидывает его в `TlsBypassService`, а `BypassFilter` увеличивает `Udp443Dropped++` и дропает UDP/443 только к этим IP. Для поддержки нескольких активных сервисов/групп одновременно селективный список может собираться как union по нескольким недавно активным целям. Поведение не привязано к названию пресета фрагментации.
    - **Глобально (DropUdp443Global)**: подавляется весь UDP/443 без привязки к цели. Режим более агрессивный и может затронуть приложения, использующие QUIC/HTTP3.
- Важно: селективный `DropUdp443` требует **цели** (host). В рантайме цель может выставляться из последнего плана (manual apply), а также дополняться оркестратором по событию UDP блокировки (по SNI/DNS кешу, с fallback на IP), чтобы избежать сценария «QUIC→TCP включён, но UDP/443 не глушится из-за пустой цели».
- Практика (стабильность SNI): SNI-кеш по IP ведётся по принципу **first-wins**, чтобы результаты не «плавали» между прогонами из-за смены SNI для одного IP. Разрешена замена только для случая **шум → не шум** (через `NoiseHostFilter`).
- Метрика `Udp443Dropped` отображается в bypass-панели и помогает однозначно проверить, что QUIC действительно глушится.
- Дополнительно есть явный assist-флаг `AllowNoSni` (тумблер `No SNI`): разрешает применять TLS-обход даже при отсутствии распознанного SNI (ECH/ESNI/фрагментация ClientHello).
- В INTEL-контуре assist-флаги могут попадать в рекомендацию как токены `DROP_UDP_443` / `ALLOW_NO_SNI` и применяются при ручном `ApplyIntelPlanAsync`.
    Важно: DNS/DoH считается "верхнеуровневым" системным изменением и выполняется **только при явном согласии пользователя**.
    Согласие хранится в `state\\operator_consent.json`. Если план включает `UseDoh`, но согласия нет — executor репортит фазу `apply_doh_skipped`
    и не выполняет системные команды `FixService`.

- Актуализация (Intel/Tester, 28.01.2026): добавлен активный probe HTTP/3 (QUIC) в `StandardHostTester` (принудительный HTTP/3 запрос с `RequestVersionExact`).
    - Результат фиксируется в `HostTested` (`Http3Ok/Http3Status/Http3LatencyMs/Http3Error`) и агрегируется в `BlockageSignals` как счётчики `Http3*Count`.
    - В `StandardDiagnosisEngine` добавлен диагноз `QuicInterference` (H3 fail без явных TCP/TLS проблем).
    - В `StandardStrategySelector` assist `DropUdp443` приоритизируется по факту H3 (реальная проба) и только затем использует эвристику `UdpUnansweredHandshakes`.

    ### Runtime Adaptation Layer (Reactive Target Sync)

    - Для компенсации задержки между runtime-сигналами (inspection) и фактическим воздействием селективного QUIC→TCP,
      используется слой `ReactiveTargetSyncService`: он принимает события (например UDP blockage) и best-effort синхронизирует
        execution-state (targets / policy snapshot) через `BypassStateManager`, не принимая политических решений и не взаимодействуя с UI.

    - Модель доставки: inbound bounded-очередь + coalescing по (scope, ip, type) + retry-until-delivered (TTL/лимит попыток).
        «Доставлено» означает: legacy filter получил targets и/или обновлён DecisionGraphSnapshot (policy-driven path), а не просто "попробовали".

Практика (после Apply):
- После ручного `Apply` UI запускает короткий **пост-Apply ретест** по цели (активные TCP/TLS проверки), чтобы быстро показать, помог ли обход.
- P1.9 (wins-библиотека): если пост-Apply ретест завершился `OK` и сигнал содержит `txId/correlationId` конкретной операции Apply,
  UI сохраняет подтверждённый «win» (хост + применённая стратегия/план + детали проверки) в `state\\wins_store.json`.
- P2.3 (UX): во время Apply UI показывает индикатор выполнения и текущую фазу (по событиям фаз из `Core/Bypass/BypassApplyService`), чтобы не было ощущения «кнопка не работает».
- Дополнительно есть кнопка **«Рестарт коннекта»**: кратковременно дропает трафик к целевым IP:443, чтобы приложение инициировало новое соединение уже под применённым bypass.
- UX-уточнение (P0.1 Step 10, 19.01.2026): кнопка применения рекомендаций в bypass-панели явно показывает выбранную цель/группу (и подсказку tooltip), чтобы не создавать ощущение «глобального переключателя».
- P0.1 (наблюдаемость): UI ведёт журнал транзакций «применения обхода» и показывает его в bypass-панели (вкладка «Применение») с экспортом JSON в `artifacts/` и копированием в буфер. Последние K транзакций сохраняются рядом с приложением: `state\\apply_transactions.json` и восстанавливаются при старте.
    - P0.1 (наблюдаемость, crash correlation): операции Apply/Disable, а также ретесты (Retest/PostApplyRetest) оборачиваются в `BypassOperationContext` (AsyncLocal). `TrafficEngine` сохраняет `lastMutation` (`SetLastMutationContext`) и печатает его в `Loop crashed`, чтобы связывать редкие падения с последней транзакцией/операцией.
    - Формат транзакции (P0.1 Step 2): добавлены секции `Request/Snapshot/Result` и список `Contributions` (вклады/изменения) при сохранении ключевых v1 полей для совместимости со старым persisted JSON.
    - Snapshot фиксирует activation/outcome, snapshot опций bypass, DoH/DNS пресет, список «активных целей» (Step 1) и policy snapshot (если доступен).
    - Gate (P0.1 Step 14): введён единый источник истины `Core/Bypass/GroupBypassAttachmentStore` для participation/pinning `hostKey -> groupKey` и детерминированного merge EffectiveGroupConfig; состояние сохраняется рядом с приложением: `state\\group_participation.json` и обновляется после успешного Apply.
        - Details: в окне «Детали применения обхода» participation snapshot включает attachments per-hostKey (excluded/endpoints/assist-флаги/updatedAtUtc) для репорта.
        - Regression: `REG-013` — union endpoints + OR assist-флаги, sticky excluded.
        - Regression: `REG-014` — persist+reload excluded/pinning через store (round-trip).
    - Gate (P0.1 Step 12): добавлены regression smoke-тесты `REG-003` (persist+reload apply_transactions без WPF dispatcher) и `REG-004` (per-card ретест очередится во время диагностики и флашится после).
    - Gate (P0.1 Step 1 groundwork): добавлен regression smoke-тест `REG-005` (селективный QUIC fallback поддерживает несколько активных целей и не «забывает» предыдущую при применении новой).
    - Gate (P0.1 Step 1, multi-group): добавлен regression smoke-тест `REG-006` (TCP/443 TLS стратегия выбирается per-target через Decision Graph по dst_ip, чтобы несколько целей могли быть активны одновременно).
        - UI таблица результатов также показывает GroupKey (+ бейдж ACTIVE для текущей группы) и даёт per-row доменную кнопку «🌐 Домен»: если строка относится к SuggestedDomainSuffix — используется она; иначе fallback на базовый домен строки (последние 2 лейбла).
            - Участие в группе отображается явно: бейджи **IN/OUT/EXCLUDED** (включено/исключено вручную/исключено как шумовой хост).
            - Для группы показывается краткий **bundle summary** по последней apply-транзакции (стратегия + признаки/флаги + endpoints/policies).
            - «Детали применения обхода» показываются в окне деталей по double-click по строке: JSON последней apply-транзакции группы + participation snapshot (included/excludedManual/excludedNoise) + кнопка копирования.

Целевое направление (Design target, 15.01.2026):
- Принята модель **Accumulative Attachment Model**: «Группа целей = одна конфигурация обхода» (YouTube/Steam/… состоят из нескольких доменов, которые должны работать одновременно).
- «Применение обхода» оформляется как транзакция с полным снимком: GroupKey + инициатор (карточка/hostKey) + EffectiveGroupConfig (что применили) + Contributions (вклады карточек) + endpoint-ы + assist-флаги/режимы/фильтры.
- UI показывает не только факт применения, но и **состав активной конфигурации группы** (какие карточки участвуют и какой итоговый режим реально активен), чтобы исключить ощущение «переключателя между карточками».
- Действия и статусы (применение/ретест/переподключение) переносятся в сами карточки и работают во время диагностики.

UX: режим `QUIC→TCP` выбирается через контекстное меню на тумблере (`Селективно (по цели)` / `Глобально (весь UDP/443)`).

Актуализация (Design Phase, 16.12.2025):
- Введён дизайн-план “DPI Intelligence INTEL” в docs/phase2_plan.md: слой между диагностикой и обходом.
- Ключевое отличие: сигналы рассматриваются как **цепочки событий во времени** (не разовый снимок), правила диагнозов внедряются поэтапно (сначала только по доступным данным).
- `LiveTestingPipeline` не применяет обход автоматически: пайплайн вычисляет сигналы/диагноз/план и публикует `BypassPlan` наружу.
- Auto-apply может быть включён **на уровне оркестратора** (`EnableAutoBypass=true`): оркестратор принимает `BypassPlan` через `OnPlanBuilt` и может применить его через `BypassController.ApplyIntelPlanAsync(...)`.
    - Execution policy (P1.11): auto-apply консервативный — минимум `PlanConfidence>=70`, запрещены `RiskLevel.High`, применяется allowlist «safe-only» стратегий.
    - DNS/DoH (StrategyId.UseDoh) — системное изменение: auto-apply допускается только при явном consent (`BypassStateManager.AllowDnsDohSystemChanges=true`), иначе фильтруется.
    - Anti-storm: cooldown + gate; если auto-apply уже выполняется — новые задачи не накапливаются (soft-skip).

Актуализация (Runtime, 16.12.2025):
- Step 1 INTEL Signals подключён: `SignalsAdapter` пишет события в `InMemorySignalSequenceStore` на этапе Classification в `LiveTestingPipeline`. Инспекционные факты берутся через `IInspectionSignalsProvider` в виде `InspectionSignalsSnapshot` (INTEL-only, без legacy типов).
    - Есть защиты от роста памяти: debounce одинаковых событий и cap числа событий на HostKey (in-memory store).
    - Политика DoH в INTEL рекомендациях: DoH рекомендуется как low-risk при `DnsHijack` (чисто DNS) и также используется в multi-layer сценариях.
- Step 2 INTEL Diagnosis подключён: `StandardDiagnosisEngine` ставит диагноз по `BlockageSignals` и возвращает пояснения, основанные на фактах (DNS fail, TCP/TLS timeout, TLS auth failure, retx-rate, HTTP redirect, RST TTL/IPID delta + latency) без привязки к стратегиям/обходу. Для RST-кейсов DPI-id (`ActiveDpiEdge/StatefulDpi`) выдаётся только при устойчивости улик (`SuspiciousRstCount >= 2`), чтобы не создавать ложную уверенность по единичному событию. Для TLS-only кейсов добавлен консервативный диагноз `TlsInterference`, чтобы селектор мог сформировать план TLS-стратегий.
- Step 3 INTEL Selector подключён: `StandardStrategySelector` строит `BypassPlan` строго по `DiagnosisResult` (id + confidence) и отдаёт краткую рекомендацию для UI-лога.
    - План может включать `DeferredStrategies` — отложенные техники (если появляются новые/экспериментальные стратегии). Сейчас deferred-техник нет (список пуст; механизм заготовлен на будущее). Phase 3 техники `HttpHostTricks` и `BadChecksum` считаются implemented: попадают в `plan.Strategies` и реально применяются при ручном `ApplyIntelPlanAsync`.
    - QUIC→TCP fallback реализуется как assist-флаг `DropUdp443` (SSoT), без дублирования `StrategyId.QuicObfuscation` в `plan.Strategies`. Применение инкапсулировано в `IspAudit.Bypass.Strategies.QuicObfuscationStrategy` и вызывается из `BypassApplyService`.
    - Для диагноза `HttpRedirect` учитывается `RedirectToHost` (если извлечён из `Location:`); уверенность выше для вероятной заглушки провайдера. Селектор выдаёт минимальную реакцию MVP: стратегию `HttpHostTricks` (TCP/80).
    - Реализация Phase 3 в рантайме:
        - QUIC→TCP (`DropUdp443`) → подавление UDP/443 (селективно по цели/union). В feedback store исход записывается под ключом `StrategyId.QuicObfuscation`, но в `plan.Strategies` этот StrategyId не дублируется.
        - `HttpHostTricks` → `BypassFilter` режет HTTP `Host:` по границе TCP сегментов (исходящий TCP/80) и дропает оригинал.
        - Наблюдаемость: `BypassFilter` считает `HttpHostTricksMatched/Applied` и пробрасывает их в `TlsBypassMetrics` для UI.
        - `BadChecksum` → для фейковых TCP пакетов используется расширенный send без пересчёта checksum и со сбросом checksum-флагов адреса.
- Step 4 INTEL Executor (MVP) подключён: `BypassExecutorMvp` формирует компактный, читаемый пользователем вывод (диагноз + уверенность + 1 короткое объяснение + список стратегий) и **не** применяет обход.
- Реальный executor INTEL: `LiveTestingPipeline` публикует объектный `BypassPlan` через `OnPlanBuilt`, `DiagnosticOrchestrator` хранит план и может применить его либо по клику пользователя, либо автоматически при включённом `EnableAutoBypass`. Применение выполняется через `BypassController.ApplyIntelPlanAsync(...)`, который делегирует apply/timeout/rollback в `Core/Bypass/BypassApplyService`.
- P1.5: критические секции операций `DiagnosticOrchestrator` сериализуются (cts/pipeline/collector lifecycle + обвязка apply), чтобы быстрые клики Start/Cancel/Retest/Apply не создавали две активные операции и не приводили к гонкам.
- P1.1/P1.14: повторный apply по той же цели/домену дедуплицируется по сигнатуре плана (стратегии + assist-флаги). Если bypass уже активен и новый план является подмножеством (dominated) последнего применённого — apply пропускается и возвращается `Status=ALREADY_APPLIED`.
- UX-гейт для корректности: `OnPlanBuilt` публикуется только для хостов, которые реально прошли фильтр отображения как проблема (попали в UI как issue), чтобы кнопка apply не применяла план, построенный по шумовому/успешному хосту.

Актуализация (Runtime, 29.12.2025): Bypass State Manager (2.INTEL.12)
- Введён `BypassStateManager` как single source of truth для управления `TrafficEngine` и `TlsBypassService`.
- P0.3.4 (15.01.2026): `BypassStateManager` декомпозирован на partial-файлы без изменения поведения: `Bypass/BypassStateManager.*.cs`.
- P0.3.5 (16.01.2026): `TlsBypassService` декомпозирован на partial-файлы без изменения поведения: `Bypass/TlsBypassService.*.cs`.
- Добавлен fail-safe слой (Lite Watchdog + crash recovery): журнал сессии bypass + авто-Disable при некорректном завершении/пропаже heartbeat.
- Добавлена Activation Detection (по метрикам): статус `ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN` для наблюдаемости.
- Добавлен Outcome Check для HTTPS: `SUCCESS/FAILED/UNKNOWN` через tagged outcome-probe (активная TCP+TLS+HTTP проверка цели), probe исключается из пользовательских метрик (smoke gate: `DPI2-029`).
- P0.6 Смена сети: при системном событии смены сети UI показывает уведомление «Проверить/Отключить/Игнорировать». «Проверить» запускает staged revalidation (Activation → Outcome) и затем предлагает запустить полную диагностику (без auto-apply; smoke gate: `UI-013`).
- Важное UX/безопасность: при закрытии приложения выполняется shutdown без «хвостов»: диагностика отменяется, bypass выключается, а DNS/DoH восстанавливаются (если были включены через `FixService` и существует backup рядом с приложением: `state\\dns_backup.json`). Fail-safe: если backup отсутствует, но активен один из пресетов DNS, управляемых приложением (например, 1.1.1.1), `FixService` выполняет fallback-возврат DNS в автоматический режим.
- Гарантия отката: `App.OnExit` синхронно дожидается полного `ShutdownAsync`, чтобы откат DNS/DoH успел завершиться до завершения процесса.
- Crash-recovery: при старте, если обнаружен backup от прошлой незавершённой сессии, выполняется попытка восстановления DNS.
- Safety gate: `FixService` не применяет DNS/DoH, если не удалось успешно записать backup-файл на диск (иначе откат после падения был бы невозможен).
- UX: отдельное overlay-окно диагностики отключено (не показываем сервисное окно поверх рабочего стола).
- `BypassController` и `DiagnosticOrchestrator` используют один экземпляр менеджера, чтобы исключить гонки Apply/Disable и рассинхронизацию фильтров/engine.
- Добавлен guard: прямые вызовы методов `TrafficEngine`/`TlsBypassService` вне manager-scope логируются (и могут быть зафиксированы smoke-гейтами).


Актуализация (Refactor, 16.01.2026): LiveTestingPipeline
- P0.3.7 (16.01.2026): `LiveTestingPipeline` декомпозирован на partial-файлы без изменения поведения: `Utils/LiveTestingPipeline.*.cs`.

Актуализация (Runtime, 20.01.2026): ускорение диагностики
- Производительность: этап тестирования (DNS/TCP/TLS) в `LiveTestingPipeline` выполняется параллельно с лимитом.
    - Лимит задаётся через `PipelineConfig.MaxConcurrentTests`.
    - Реализация: `TesterWorker` использует `SemaphoreSlim` и in-flight задачи, чтобы ускорять обработку при высоком входном потоке (активный браузер), не ломая `DrainAndCompleteAsync` и bounded-очереди.

Актуализация (Runtime, 11.02.2026): приоритизация и деградация очередей pipeline (P1.5)
- Вход разделён на две bounded очереди: high/low.
- High обслуживается первым; permit по `MaxConcurrentTests` берётся до dequeue, чтобы high не «тонул» при `maxConcurrency=1`.
- Low ограничен (capacity=50, DropOldest) для защиты от раздувания при активном браузере.
- Degrade mode: при устойчивом backlog (pending>20 несколько тиков) low обрабатывается в best-effort ускоренном режиме (timeout/2 для StandardHostTester).
- Наблюдаемость: health-лог добавляет `qAgeP95` (p95 возраста элементов в очереди) и флаг `degrade=ON/OFF`.
- Smoke gate: `PIPE-020` проверяет, что high-preempts-low при большом low-backlog.


Актуализация (UI, 12.02.2026): раскрытие CDN‑подхостов в Engineer UI (P1.6)
- Для агрегированной строки (бейдж `×N`) добавлено раскрытие списка members (RowDetails).
- UI получает members через `TestResultsManager.GetGroupMembers(groupKey)`.
- Smoke gate: добавлен `UI-024` (wiring RowDetails + клика по `×N` + базовая проверка `GetGroupMembers`).


Актуализация (Runtime, 23.12.2025): контроль применения INTEL
- `Cancel` отменяет не только диагностику, но и ручное применение рекомендаций (отдельный CTS для apply).
- Защита от устаревшего плана: apply пропускается, если `planHostKey` не совпадает с последней INTEL‑целью, извлечённой из текста INTEL‑диагноза в UI.
- UX-гейт кнопки apply: блок «Рекомендации» отображается при `HasAnyRecommendations`, но команда apply активна только при `HasRecommendations` (есть план и есть что применять). Если пользователь уже включил стратегию вручную, она показывается как «ручное действие», чтобы рекомендации не исчезали.
- Важно: bypass-панель в UI скрыта без прав администратора, поэтому кнопка apply также недоступна без elevation.
- Ручной apply поддерживает `AggressiveFragment`: выбирается пресет фрагментации «Агрессивный» и включается `AutoAdjustAggressive`.
- Ручной apply поддерживает параметры `TlsFragment` (например, `TlsFragmentSizes`, `PresetName`, `AutoAdjustAggressive`); парсинг вынесен в `Core/Intelligence/Execution/TlsFragmentPlanParamsParser.cs`.
- Добавлен smoke-тест `DPI2-022`: параметры `TlsFragment` влияют на пресет и флаг `AutoAdjustAggressive`.
- Детерминизм: `StandardStrategySelector` задаёт `TlsFragmentSizes` в `BypassPlan` (иначе executor зависел бы от текущего выбранного пресета пользователя).
- Добавлен smoke-тест `DPI2-023`: селектор INTEL кладёт `TlsFragmentSizes` в план.
- Добавлен smoke-тест `DPI2-024`: e2e проверка `selector → plan → ApplyIntelPlanAsync` (manual apply использует параметры плана детерминированно).
- Для контроля Gate 1→2 в UI-логе используются строки с префиксом `[INTEL][GATE1]` (не чаще 1 раза в минуту на HostKey).

Актуализация (Runtime, 13.01.2026): гибридный доменный UX (общий) + внешний справочник
- Боль (типичный кейс: YouTube/CDN): сервис «лечится» через множество подхостов, поэтому ручной apply по одному хосту создаёт UX-хаос (много карточек/целей).
- Добавлен общий механизм «доменных семейств» (без хардкода конкретных CDN): UI на лету замечает домены, у которых появляется много вариативных подхостов, и может предложить доменную цель (suffix).
- Доменное применение выполняется через `DiagnosticOrchestrator.ApplyRecommendationsForDomainAsync(..., suffix)`: метод выбирает применимый INTEL-план из подхостов, но выставляет `OutcomeTargetHost` на домен.
- Внешний каталог доменов: `state\\domain_families.json`.
    - Поддерживает `PinnedDomains` (ручное закрепление) и `LearnedDomains` (авто-выученные домены).
    - Закрепление доступно из UI (pin/unpin), и ускоряет появление доменной подсказки/агрегации карточек.

Актуализация (Runtime, 29.01.2026): кросс-доменные группы (Domain Groups, pinned)
- Поверх доменных семейств добавлен слой Domain Groups: группа может объединять несколько базовых доменов одного сервиса (пример: YouTube = `youtube.com` + `googlevideo.com` + `ytimg.com` + `ggpht.com`).
- Каталог pinned-групп хранится в `state\\domain_groups.json` (по умолчанию присутствует `group-youtube`).
- Если файла нет, он создаётся автоматически при первом запуске (best-effort).
- UI:
    - `TestResultsManager` определяет подсказку группы по базовому суффиксу.
    - Карточки доменов группы best-effort схлопываются в одну карточку (ключ = groupKey).
    - В панели рекомендаций появляется кнопка «Подключить (группа: …)».
- Apply:
    - `DiagnosticOrchestrator.ApplyRecommendationsForDomainGroupAsync(..., groupKey, anchorDomain, domains)` берёт применимый INTEL-план из любого домена группы и применяет его к anchor-домену (OutcomeTargetHost=anchor).
    - Для селективного `DropUdp443` UI собирает union endpoint snapshot по всем доменам группы.
- Smoke: добавлен `CFG-007` (persist+reload + pinned подсказка).

Актуализация (Runtime, 29.01.2026): learned groups (co-occurrence, suggest-only)
- Добавлено обучение learned-групп в UI-сессии: если домены часто встречаются рядом по времени (co-occurrence окно), создаётся learned-группа.
- Персист: `state\\domain_groups.json` → `LearnedGroups`.
- Безопасность:
    - Это suggest-only (без авто-apply), и не создаёт никаких wildcard правил для фильтрации пакетов.
    - Pinned-группы имеют приоритет над learned.
    - Игнорируются шумовые хосты и IP-цели.
- UX-контроль learned-групп:
    - «Скрыть подсказку (learned)» добавляет learned key в `IgnoredLearnedGroupKeys`, и анализатор перестаёт предлагать её повторно.
    - «Закрепить группу (learned → pinned)» создаёт pinned-группу из доменов learned-группы и удаляет learned-запись.
- Smoke: `CFG-008` (learned подсказка), `CFG-009` (ignore), `CFG-010` (promote).

- Справочник blockpage-hosts (для повышения уверенности `HttpRedirect` и `evidence.redirectKind`): `state\\blockpage_hosts.json`.
    - `PinnedDomains`: ручной «справочник» (можно закреплять домены, чтобы подсказка включалась быстрее).
    - `LearnedDomains`: автокэш доменов, которые система «выучила» по наблюдениям.
- Важно: это не wildcard-мэтчинг в `BypassFilter` (фильтры по доменам не поддерживаются напрямую); домен используется как UX-цель/цель outcome и как вход для резолва IP в селективном `DropUdp443`.

---

## Навигация по состоянию INTEL (As‑Is / Target / Roadmap)

Чтобы не терять контроль над направлением разработки, фиксируем три вещи:

### As‑Is (реально есть в репозитории)
- INTEL контур подключён в рантайм: Signals → Diagnosis → Selector → Plan.
- Auto-apply: пайплайн обход не применяет; решение об auto-apply принимает оркестратор (флаг `EnableAutoBypass`).
- Реальный apply INTEL реализован в `Core/Bypass/BypassApplyService`: таймаут/отмена + безопасный rollback; вызывается через `BypassController.ApplyIntelPlanAsync(...)`.
- P0.1: `ApplyIntelPlanAsync` защищён apply-gate (сериализация) — параллельные apply выполняются последовательно, чтобы исключить гонки.
- Feedback store (MVP) реализован и может влиять на ранжирование в `StandardStrategySelector`.

### Target (реалистичное целевое состояние)
- Рекомендации непротиворечивы и исполнимы: один режим TLS-обхода за раз.
- Понятный UX: «что обнаружено → почему → что применится → что изменилось после apply».
- Безопасность: никакого частично применённого состояния при ошибках/отмене.

### Roadmap (минимальные, практичные шаги)
1) Стабилизировать UX-смысл стратегий и терминов (Fragment vs Disorder и т.д.).
2) Усилить UI-обратную связь после apply/rollback (лог + отображение активных флагов).
3) Параметры стратегий добавлять только если они поддержаны в движке (без "магической" комбинации флагов).

Актуализация (Design, 15.01.2026): Policy‑Driven Execution Plane
- Зафиксировано целевое направление в `ARCHITECTURE_CURRENT.md` (раздел про policy-driven).
- План внедрения инкрементальный (без переписывания WinDivert/TrafficEngine): см. P0.2 в `docs/TODO.md`.
- Реализован P0.2 Этап 0 (zero runtime impact): добавлены базовые типы FlowPolicy/DecisionGraphSnapshot, компилятор hard-конфликтов и smoke-гейт `DPI2-040`.
- Реализован P0.2 Этап 1 (gated runtime): UDP/443 (QUIC→TCP) работает через `DecisionGraphSnapshot` под feature-gate `ISP_AUDIT_POLICY_DRIVEN_UDP443=1`, добавлена минимальная per-policy наблюдаемость и smoke-гейт `DPI2-041`.
- Реализован P0.2 Этап 2 (gated runtime): TTL endpoint block (reconnect-nudge) работает как TTL-политика с максимальным приоритетом под feature-gate `ISP_AUDIT_POLICY_DRIVEN_TTLBLOCK=1`; добавлен UI индикатор `EndpointBlockStatus` и smoke-гейт `DPI2-042`.
- Реализован P0.2 Этап 3 (gated runtime): TCP/80 HTTP Host tricks работает через `DecisionGraphSnapshot` под feature-gate `ISP_AUDIT_POLICY_DRIVEN_TCP80=1` (по умолчанию выключено). Действие описано как strategy (`PolicyAction.HttpHostTricks`, `StrategyId=http_host_tricks`), `BypassFilter` применяет сегментацию `Host:` и drop оригинального пакета по решению графа; smoke-гейт `DPI2-043`.
- Реализован P0.2 Этап 4 (gated runtime): TCP/443 TLS ClientHello выбирает effective TLS стратегию (per-endpoint) через `DecisionGraphSnapshot` под feature-gate `ISP_AUDIT_POLICY_DRIVEN_TCP443=1` (по умолчанию выключено). Действие описано как strategy (`PolicyAction.TlsBypassStrategy`, `StrategyId=tls_bypass_strategy`, параметр `tls_strategy`), `BypassFilter` применяет Fake/Fragment/Disorder в зависимости от выбранной стратегии, с fallback на legacy `BypassProfile.TlsStrategy`; smoke-гейт `DPI2-044`.
- Реализован P0.2 Этап 5 (MVP): введены Semantic Groups как «пакет политик» и детерминированная оценка статуса группы `NO_TRAFFIC / PARTIAL / ENABLED` на основе per-policy метрики `matched_count` (в дополнение к `applied_count`). Добавлены модель `SemanticGroup` и evaluator; smoke-гейт `DPI2-045`. MVP UI-интеграция: статусы выводятся в вкладке «Метрики» bypass-панели (текст `Semantic Groups`).
- Реализован P0.2 Этап 5.4 (интеграция с P0.1, MVP): при записи apply-транзакции observed IPv4 цели засеиваются из `candidateIpEndpoints`, чтобы per-target политики (DstIpv4Set) могли компилироваться сразу (без ожидания DNS resolve). Регресс-гейт: `REG-015`.
- Практическое усиление (P0.0 hardening): `candidateIpEndpoints` сохраняются в `BypassStateManager.ActiveTargetPolicy` (best-effort) и используются как seed observed IPv4 перед компиляцией per-target политик (TCP/443, TCP/80), снижая зависимость от DNS resolve. Smoke-гейты: `DPI2-047`, `DPI2-048`.

Актуализация (Dev, 12.01.2026): базовые analyzers/линт для стабильности
- Добавлены `Directory.Build.props` и `.editorconfig`.
- Включены встроенные .NET analyzers (`EnableNETAnalyzers=true`) без форсирования `AnalysisMode/AnalysisLevel` (оставляем дефолты SDK, чтобы не раздувать шум предупреждений).
- По умолчанию analyzers выставлены как `suggestion` (минимум шума).
- Для non-UI слоёв подняты до `warning` ключевые правила стабильности: `CA2000` (dispose) и `CA2200` (rethrow). `CA2007` (ConfigureAwait) оставлено как `suggestion`.

Актуализация (Dev, 15.01.2026): правило декомпозиции и старт P0.3
- Практическое правило сопровождения: при росте файла до 500–700+ строк делаем вынос (сначала `partial`, потом отдельные сервисы), чтобы не смешивать слои и упростить поддержку.
- Старт P0.3: `BypassController` вынесен в partial-файлы (без изменения поведения): `ViewModels/BypassController.*.cs` (Internal/Metrics/Startup/Core/DnsDoh/Observability/INTEL).
- P0.3 (продолжение): `DiagnosticOrchestrator` вынесен в partial-файлы (без изменения поведения): `ViewModels/DiagnosticOrchestrator.*.cs` (Core/Private + базовый файл).

Актуализация (Dev, 16.01.2026): старт 4.3 (после partial)
- Первый минимальный шаг по снижению сложности `DiagnosticOrchestrator`: состояние пост-Apply ретеста вынесено в отдельный тип `ViewModels/OrchestratorState/PostApplyRetestState.cs` (рефакторинг без изменения поведения).

Актуализация (Runtime, 17.12.2025):
- Добавлен `Core/Diagnostics/BlockageCode.cs` — единая точка нормализации кодов проблем (`BlockageType`) и поддержки legacy алиасов.
- В местах, где раньше сравнивались строки (`TLS_DPI`, `TCP_TIMEOUT`, `TCP_RST`, `TLS_TIMEOUT` и др.), используется `BlockageCode.Normalize/ContainsCode`, чтобы алиасы не расползались по слоям (UI/legacy/INTEL).
- Добавлен `Core/Diagnostics/PipelineContract.cs` — единая точка контрактных строк пайплайна (`BypassNone`/`BypassUnknown`) вместо «магических» `"NONE"`/`"UNKNOWN"` в слоях legacy/INTEL/UI.
- Добавлен периодический health-лог пайплайна (`[PipelineHealth] ...`) с агрегированными счётчиками этапов (enqueue/test/classify/ui) для диагностики потерь данных и узких мест (рост очередей, drop в bounded channels, несходимость enq/deq).
- Уточнено правило noise-фильтрации: `NoiseHostFilter` не должен отбрасывать исходные сигналы (включая SNI) до тестирования/диагностики; «noise» применяется только как правило отображения успешных (OK) результатов, чтобы не терять потенциально важные факты.

Маркер (как отличить INTEL-вывод от legacy): строки рекомендаций INTEL начинаются с префикса `[INTEL]`.

Жёсткие защиты селектора (MVP):
- `confidence < 50` → пустой план.
- `RiskLevel.High` запрещён при `confidence < 70`.
- Нереализованные стратегии: warning + skip (без исключений), без падения пайплайна.

Актуализация (Dev, 22.12.2025): feedback store + ранжирование в StrategySelector
- Добавлен `Core/Intelligence/Feedback/*`: хранилище обратной связи (in-memory) + файловая реализация `JsonFileFeedbackStore`.
    - В рантайме store включён по умолчанию (persist: `state\\feedback_store.json`) и инжектится в `StandardStrategySelector`.
    - Запись исхода выполняется best-effort после Post-Apply ретеста (по строкам `✓/❌`):
        - если виден `SNI=...`, совпадающий с `hostKey`, outcome считается по SNI-matched строкам; иначе по target IP;
        - если одновременно есть `✓` и `❌` по цели → outcome неоднозначный (`Unknown`) и не пишется;
        - при `DropUdp443` outcome также пишется для `StrategyId.QuicObfuscation`.
- `StandardStrategySelector` ранжирует стратегии по весу `PlanWeight = strength × confidence / cost`, где `cost` отражает цену/риск (Low/Medium/High). Feedback влияет множителем: WinRate > 70% → ×1.5, WinRate < 30% → ×0.5 (при достаточном числе выборок).
- Gate: при отсутствии данных поведение полностью как раньше; одинаковый вход + одинаковый feedback → одинаковый план.

Актуализация (Dev, 02.02.2026): UX семантика Post-Apply проверки
- В `Models/TestResult` добавлен отдельный `PostApplyCheckStatus` (badge на карточке), чтобы отражать итог «пост‑проверки» после Apply, не смешивая его с текущим `TestStatus` (Idle/Running/Pass/Fail/Warn).
- `DiagnosticOrchestrator.StartPostApplyRetestAsync(...)` публикует вердикт `OK/FAIL/PARTIAL/UNKNOWN` через событие `OnPostApplyCheckVerdict`, а `MainViewModel` применяет его на карточки apply‑группы.
- P1.7 (персист): последний результат пост‑проверки по groupKey сохраняется в `state/post_apply_checks.json` (время + итог + краткие детали) и поднимается при старте.
- P1.8 (UI-приоритет): в UI введены `PrimaryStatus/PrimaryStatusText` для показа итогов пост‑проверки как основной метки, без изменения `TestStatus`.

Актуализация (Dev, 11.02.2026): perf smoke KPI для Apply/Disable
- Добавлен perf smoke-тест `PERF-005`: 10 последовательных Apply/Disable, проверка `p95 < 3с`.
- Тест выполняется без требований admin/WinDivert (apply-цепочка запускается с `useTrafficEngine:false`) и изолирует state через временные пути (apply-transactions/session) в ENV.

Актуализация (Dev, 11.02.2026): stress smoke для TrafficEngine Apply/Rollback
- Добавлен infra smoke-тест `INFRA-010`: 1000 циклов Apply/Rollback (ApplyTlsOptionsAsync/DisableTlsAsync) за <=60с, параллельно `ProcessPacketForSmoke`.
- Дополнительно: мягкая проверка на явный рост `GC.GetTotalMemory` после полного GC.

Актуализация (Dev, 11.02.2026): perf baseline hot-path для ProcessPacketForSmoke
- Добавлен perf smoke-тест `PERF-006`: 10K вызовов `TrafficEngine.ProcessPacketForSmoke` с расчётом p50/p95/p99 (и мягким порогом на катастрофическую деградацию).

Актуализация (Dev, 11.02.2026): unit-тест конкурентности TrafficEngine
- Добавлен тестовый проект `ISP_Audit.Tests` (xUnit).
- Добавлен unit-тест на конкурентные `RegisterFilter/RemoveFilter` параллельно `ProcessPacketForSmoke`, чтобы ловить регрессии вида `Collection was modified`.

Актуализация (Dev, 11.02.2026): декомпозиция OperatorViewModel (P1.4)
- `ViewModels/OperatorViewModel.cs` сокращён до компактного ядра (состояние/конструктор/маппинг).
- Основная логика вынесена в partial-файлы: Wizard/History/Sessions/AutoPilot.

Актуализация (Dev, 12.02.2026): Operator UI — локализация raw-кодов проблем (P1.8)
- Добавлен `Utils/OperatorTextMapper.cs`: маппинг кодов блокировок/ошибок (например `TLS_AUTH_FAILURE`, `DNS_ERROR`, `UDP_BLOCKAGE`) в человекочитаемые формулировки и короткие рекомендации.
- `OperatorViewModel` локализует коды в строках проблем/итогах и в `PostApplyStatusText`, чтобы в Operator UI не отображались raw-токены.
- Добавлен smoke-тест `UI-027` на отсутствие raw-кодов в `SummaryProblemCards`.

Актуализация (Docs, 11.02.2026): сценарий воспроизведения Apply/Disable
- Добавлен dev-док со сценарием воспроизведения для P0.4: цель-браузер и темп циклов Apply/Disable, а также список артефактов для сохранения при краше: [docs/repro_p0_4_trafficengine_apply_disable.md](repro_p0_4_trafficengine_apply_disable.md).

Примечание (UI/идентификация хостов): карточки результатов привязаны к **человеко‑понятному ключу** (в первую очередь SNI/hostname, если он известен). IP сохраняется как технический атрибут (`FallbackIp`) и может использоваться для корреляции, но не должен быть главным «лицом» карточки для пользователя.
```

Актуализация (Dev, 18.12.2025): добавлен smoke-тест UI-редьюсера (без запуска GUI)
- Цель: быстро воспроизводимо проверить, что UI ведёт себя детерминированно при миграции `IP → hostname/SNI` и что правило “смешанные исходы → Нестабильно” не ломается из‑за смены ключа.
- Команда:
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --ui-reducer-smoke`
- Что проверяет:
    - миграцию карточки по сообщению `[Collector] Hostname обновлен: <ip> → <hostname>`;
    - ключ карточки по `[SNI] Detected: <ip> -> <host>`;
    - правило `UnstableWindow`: если в окне есть и успех, и проблема → статус `Warn` (“Нестабильно”).
    - gate B5: legacy строки рекомендаций не меняют `BypassStrategy`, INTEL строки с префиксом `[INTEL]` — меняют.

Актуализация (Dev, 18.12.2025): добавлен CLI smoke-раннер (выполняет весь план)
- Команда:
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke`
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke infra`
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke pipe`
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke insp`
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke ui`
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke bypass`
- Примечание: smoke runner читает `TestNetworkApp/smoke_tests_plan.md` и прогоняет все Test ID из плана; если тест из плана ещё не реализован, он возвращает `FAIL` с причиной (это сделано намеренно, чтобы было 97/97 выполнено без "пропусков"). Реализации тестов разнесены по файлам `TestNetworkApp/Smoke/SmokeTests.*.cs`, а каркас раннера/плана — в `TestNetworkApp/Smoke/SmokeRunner.cs`.
- Строгий режим (без `SKIP`):
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke --strict`
    - алиас: `--no-skip` (любые `SKIP` считаются `FAIL`).

- JSON-отчёт:
    - `dotnet run -c Debug --project TestNetworkApp/TestNetworkApp.csproj -- --smoke --strict --json artifacts/smoke.json`

- Автозапуск от администратора (сам запросит UAC, сохранит JSON):
    - `dotnet run -c Debug --project SmokeLauncher/SmokeLauncher.csproj`
    - (опционально) собрать EXE: `dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true -p:SelfContained=false --project SmokeLauncher/SmokeLauncher.csproj`

Актуализация (Dev, 18.12.2025): расширено покрытие PIPE в smoke
- Реализованы `PIPE-001..004` (ConnectionMonitor, PID filtering, SNI parsing, endpoint↔PID gating) и `PIPE-017` (health-лог).
- `PIPE-007` приведён к плану: проверяет гейтинг повторных тестов по цели (кулдаун + лимит попыток) в `InMemoryBlockageStateStore`.
- Добавлен контракт `IBlockageStateStore.TryBeginHostTest(...)`: `LiveTestingPipeline` использует его как гейтинг повторных тестов (кулдаун + лимит попыток) до вызова тестера.
- Дополнительно: в runtime `TrafficCollector` дедупит соединения по ключу `RemoteIp:RemotePort:Protocol`, но допускает ограниченные «повторные обнаружения» той же цели с кулдауном/лимитом — иначе повторные попытки физически не попадут в pipeline.
- Для детерминированных smoke-тестов SNI добавлены API в `DnsParserService`:
    - `TryExtractSniFromTlsClientHelloPayload(...)`
    - `TryFeedTlsClientHelloFragmentForSmoke(...)`

Актуализация (Dev, 18.12.2025): реализованы smoke-тесты DPI Intelligence INTEL (категория `dpi2`)
- Добавлен файл `TestNetworkApp/Smoke/SmokeTests.Dpi2.cs` и регистрации в реестре.
- Покрыты тесты `DPI2-001..013`: адаптация legacy сигналов в TTL-store, TTL-очистка при `Append`, агрегация по окнам 30/60 секунд, DiagnosisEngine (фактологическое объяснение без упоминания стратегий), Gate-маркеры `[INTEL][GATE1]`, правила StrategySelector (confidence/risk/unimplemented warning+skip), Executor MVP (компактный 1-строчный вывод с префиксом `[INTEL]` и без auto-apply).

Актуализация (Dev, 18.12.2025): реализованы smoke-тесты Inspection Services (категория `insp`)
- Добавлены файлы `TestNetworkApp/Smoke/SmokeTests.Insp.cs` и `TestNetworkApp/Smoke/SmokeTests.Packets.cs`, регистрации `INSP-001..005` внесены в реестр.
- `INSP-001`: детект RST-инжекции по TTL (на базе 3+ «обычных» пакетов).
- `INSP-002`: добавлена эвристика по IPv4 Identification (IPID) в `RstInspectionService` (аномальный IPID в RST фиксируется как подозрительный; детали события расширены).
- `INSP-003`: QUIC Initial (>=1200 байт, long header) учитывается в `UdpInspectionService`; при 5+ безответных рукопожатиях эмитится сигнал.
- `INSP-004`: `TcpRetransmissionTracker` принимает минимальный TCP пакет (40 байт) и предоставляет `TryGetSuspiciousDrop(...)` (сигнал при доле ретрансмиссий >=10% на выборке >=20 пакетов).
- `INSP-005`: `HttpRedirectDetector` извлекает host из `Location:` для HTTP 3xx.

Актуализация (Dev, 19.12.2025): реализованы smoke-тесты TLS bypass (частично, категория `bypass`)
- Реализованы `BYPASS-003..004` в `TestNetworkApp/Smoke/SmokeTests.Bypass.cs`, добавлена регистрация в реестр.
- `BYPASS-003`: детерминированная проверка публикации `MetricsUpdated` (2+ вызова) и заполненности ключевых полей метрик (`ClientHellosObserved`, `ClientHellosFragmented`, `RstDropped`) на синтетическом трафике.
- `BYPASS-004`: детерминированная проверка порогов вердикта по ratio RST/фрагментации (`Red > 4`, `Yellow > 1.5`, иначе `Green`) через событие `VerdictChanged`.
- Для детерминизма не используется WinDivert: `BypassFilter` кормится синтетическими TCP пакетами (TLS ClientHello + RST), а `TlsBypassService` получает internal-хуки для установки тестового фильтра и принудительного чтения метрик (без таймера и без запуска `TrafficEngine.StartAsync`).

Актуализация (Dev, 19.12.2025): расширено smoke-покрытие TLS bypass (категория `bypass`)
- Реализованы `BYPASS-006..015` (детерминированно) в `TestNetworkApp/Smoke/SmokeTests.Bypass.cs`, добавлена регистрация в реестр.
- `BYPASS-006`: фрагментация ClientHello по пресету `[80,220]` — проверка 2 TCP-сегментов с корректными `seq/len` и валидности данных при реассемблинге.
- `BYPASS-007`: disorder — сегменты отправляются в обратном порядке, но данные остаются валидными при реассемблинге по `seq`.
- `BYPASS-008`: TTL Trick — отправляется фейковый пакет с TTL ниже реального (в smoke-раннере «real» проходит дальше как исходный пакет; фиксируется факт fake-отправки).
- `BYPASS-009`: Drop RST — входящий RST отбрасывается (`Process=false`) и увеличивается метрика `RstDropped`.
- `BYPASS-010`: гейтирование по 443 и наличию SNI — non-443 и 443 без SNI игнорируются и увеличивают метрики `Non443++/NoSni++` без фрагментации.
- `BYPASS-011`: порог `TlsFragmentThreshold` — короткий ClientHello (< threshold) не модифицируется и увеличивает `ShortClientHello++`.
- `BYPASS-012`: совместная работа TTL Trick (manual) + фрагментация — проверка 1 fake-отправки (TTL=10) и 2 фрагментов по пресету `[80,220]` с валидным реассемблингом данных.
- `BYPASS-013`: AutoTTL — детерминированный выбор «лучшего» TTL по синтетическим метрикам и проверка персиста в `bypass_profile.json` (с восстановлением исходного значения после теста).
- `BYPASS-014`: AutoAdjustAggressive — ранний burst RST переводит агрессивный пресет на минимальный chunk (ожидаемо до 4).
- `BYPASS-015`: AutoAdjustAggressive — при устойчивом `Green` > 30s агрессивный пресет «расслабляется» (уменьшение min chunk, ожидаемо 16→12).
- Для воспроизводимости добавлены билдеры минимально-валидного TLS ClientHello (с SNI/без SNI) в `TestNetworkApp/Smoke/SmokeTests.Packets.cs`, чтобы smoke-тесты проходили при гейтировании обхода по наличию SNI.

Рекомендуемые быстрые проверки (перед/после реального браузерного прогона):
- “Проблема не исчезает”: событие `[NOISE]`/noise-hostname не должно удалять карточку со статусом `Fail/Warn`.
- “SNI позже IP”: сначала `❌ <ip>...`, потом `[SNI] Detected...` → карточка должна переехать на hostname и остаться `Warn/Fail`.
- “DNS vs rDNS”: если PTR/rDNS шумовой (например `*.1e100.net`), он не должен отменять диагноз/скрывать карточку.

Актуальные уточнения (runtime):
- `Program.cs` регистрирует `CodePagesEncodingProvider`, чтобы работали OEM-кодировки (например, CP866 для `ipconfig /flushdns` и `tracert` на русской Windows).
- `TrafficCollector` не создаёт UI-события для loopback и применяет `UnifiedTrafficFilter` для минимальной валидации; фильтрация «шумных» хостов применяется на этапе отображения успешных (OK) результатов, чтобы не терять сигнал на браузерных/CDN сценариях.

### 1.2 Ключевые узлы с максимальным числом связей

| Компонент | Входящих | Исходящих | Роль |
|-----------|----------|-----------|------|
| `MainViewModel` | 1 (MainWindow) | 3 (Bypass, Orchestrator, Results) | **Координатор UI** |
| `DiagnosticOrchestrator` | 1 | 12+ | **Центральный оркестратор** |
| `TrafficEngine` | 4 | 3 | **WinDivert менеджер** |
| `LiveTestingPipeline` | 1 | 6 | **Pipeline обработки** |
| `Config` | 10+ | 2 | **Глобальная конфигурация** |
| `NoiseHostFilter` | 5 | 0 | **Singleton фильтр** |

### 1.3 Скрытые/глобальные зависимости

| Глобальный элемент | Используется в | Риск |
|-------------------|----------------|------|
| `NoiseHostFilter.Instance` | TrafficCollector, TestResultsManager, LiveTestingPipeline | Singleton, сложно тестировать |
| `FixService` (файлы бэкапа) | BypassController | Состояние на диске |
| (legacy удалён) `Program.Targets` | - | Статический словарь целей (удалён) |
| (legacy удалён) `Config.ActiveProfile` | - | Статическое свойство (удалено) |

### 1.4 Циклические зависимости

**Обнаружено:** НЕТ явных циклов на уровне классов.

**Потенциальный риск:** `DiagnosticOrchestrator` ↔ `TestResultsManager` — оркестратор обновляет результаты, результаты могут триггерить retest через BypassController.

---

## 2. Мёртвый код

### 2.1 Неиспользуемые файлы (классы полностью мёртвые)

| Файл | Причина | Безопасность удаления |
|------|---------|----------------------|
| `TargetCatalog.cs` | Пустой файл (комментарий "удалён") | ✅ Безопасно |
| `Wpf/ServiceItemViewModel.cs` | 0 usages в коде, только документация | ✅ Безопасно |
| `Windows/CapturedTargetsWindow.xaml(.cs)` | Нигде не открывается | ✅ Безопасно |
| `Utils/GuiProfileStorage.cs` | 0 usages | ✅ Безопасно |
| `Utils/DnsFixApplicator.cs` | Дублирует FixService, 0 usages | ✅ Безопасно |
| `Utils/BypassStrategyPlanner.cs` | 0 usages, заменён StrategyMapping | ✅ Безопасно |
| `Utils/NetworkMonitorService.cs` | Заменён TrafficEngine, 0 usages | ✅ Безопасно |
| `Utils/ProblemClassifier.cs` | 0 usages, заменён StandardBlockageClassifier | ✅ Безопасно |

### 2.2 Мёртвые тестовые классы (Tests/)

**КРИТИЧНО:** Все классы в `Tests/` НЕ вызываются из продакшн кода!

| Файл | Статус | Обоснование |
|------|--------|-------------|
| `Tests/DnsTest.cs` | ❌ МЁРТВЫЙ | `new DnsTest()` нигде не создаётся |
| `Tests/TcpTest.cs` | ❌ МЁРТВЫЙ | `new TcpTest()` нигде не создаётся |
| `Tests/HttpTest.cs` | ❌ МЁРТВЫЙ | `new HttpTest()` нигде не создаётся |
| `Tests/TracerouteTest.cs` | ❌ МЁРТВЫЙ | `new TracerouteTest()` нигде не создаётся |
| `Tests/UdpProbeRunner.cs` | ❌ МЁРТВЫЙ | `new UdpProbeRunner()` нигде не создаётся |
| `Tests/RstHeuristic.cs` | ❌ МЁРТВЫЙ | `new RstHeuristic()` нигде не создаётся |
| `Tests/FirewallTest.cs` | ❌ МЁРТВЫЙ | `new FirewallTest()` нигде не создаётся |
| `Tests/TestProgress.cs` | ⚠️ ЧАСТИЧНО | `TestKind` enum НЕ используется в коде |

**Вывод:** Логика тестирования перенесена в `Core/Modules/StandardHostTester.cs`. Старые тесты — legacy.

### 2.3 Неиспользуемые JSON-файлы

| Файл | Статус | Рекомендация |
|------|--------|--------------|
| `game_targets.json` | Пустой (`"targets": []`) | ❌ Удалить |
| `bypass_profile_fshud_google.json` | 0 usages | ⚠️ Удалить или задокументировать |

### 2.4 Неиспользуемые методы и свойства

| Класс | Метод/Свойство | Причина |
|-------|---------------|---------|
| `Config` | `NoTrace` | Legacy, никогда не читается |
| `Config` | `Ports` | Не используется (порты в профиле) |
| `Config` | `UdpProbes` | Не используется |
| `TargetDefinition` | `Ports`, `Protocols` | Объявлены, но не читаются |
| `TestKind` (enum) | `FIREWALL, ISP, ROUTER, SOFTWARE` | Значения никогда не используются |

### 2.5 Unreachable код

| Файл | Строки | Описание |
|------|--------|----------|
| `FirewallTest.cs` | 450+ | Unit-тесты внутри класса (никогда не вызываются) |

---

## 3. Технический долг

### 3.1 Дублирующаяся логика

| Проблема | Файлы | Рекомендация |
|----------|-------|--------------|
| DNS резолв | `StandardHostTester`, `DnsTest`, `NetUtils` | Унифицировать в `NetUtils` |
| TLS handshake | `StandardHostTester`, `HttpTest` | Использовать только `StandardHostTester` |
| Классификация блокировок | `StandardBlockageClassifier`, `ProblemClassifier` | Удалить `ProblemClassifier` |
| DNS fix | `FixService`, `DnsFixApplicator` | Удалить `DnsFixApplicator` |

### 3.2 Нарушения SRP (Single Responsibility)

| Класс | Проблема | Размер |
|-------|----------|--------|
| `DiagnosticOrchestrator` | Слишком много обязанностей: UI, overlay, процессы, WinDivert | 2162 строки (после P0.3: partial-файлы 258/592/284/266/514/130/118) |
| `TestResultsManager` | Парсинг + хранение + здоровье + UI обновления | после P0.3: partial-файлы 63/35/46/136/14/73/31/89/71/327 + top-level `PipelineMessageParser` (593) (~1478 строк суммарно) |
| `BypassController` | Bypass + DoH + VPN детект + совместимость | ~1848 строк (после P0.3: partial-файлы) |

### 3.3 Хаотичные зависимости

| Проблема | Детали |
|----------|--------|
| Namespace смешивание | `IspAudit`, `ISPAudit`, `ISPAudit.ViewModels`, `IspAudit.Utils` |
| Глобальное состояние | `NoiseHostFilter.Instance` |
| Дублирование моделей | `Target` (Models/), `TargetDefinition` (root), `Target` (ISPAudit.Models) |

### 3.4 Требуют рефакторинга

| Файл | Приоритет | Причина |
|------|-----------|---------|
| `ViewModels/DiagnosticOrchestrator.*.cs` | 🔴 Высокий | Уже разбит на `partial`; следующий шаг — вынос моделей состояния и выделение мониторинга/рекомендаций/управления процессом в отдельные сервисы |
| `ViewModels/TestResultsManager*.cs` | 🟡 Средний | Уже разбит на `partial`; парсер pipeline вынесен в top-level сервис `PipelineMessageParser` с явным контекстом (`ViewModels/PipelineMessageParser.cs`). В `TestResultsManager.PipelineMessageParser.cs` остался только контекст-адаптер |
| Весь `Tests/` | 🟡 Средний | Удалить или перенести в unit-tests |
| `Config.cs` | 🟡 Средний | Убрать неиспользуемые свойства |

---

## 4. Устаревшие элементы (Legacy)

### 4.1 Конфигурационные параметры

| Параметр | Файл | Статус |
|----------|------|--------|
| `Config.NoTrace` | Config.cs | Legacy, не используется |
| `Config.EnableRst` | Config.cs | Отключено, RST через TrafficEngine |
| `TestKind.FIREWALL/ISP/ROUTER/SOFTWARE` | TestProgress.cs | Никогда не используются |

### 4.2 Устаревшие API/паттерны

| Паттерн | Где | Рекомендация |
|---------|-----|--------------|
| `.Result` / `.Wait()` на async | UdpProbeRunner.cs | Заменить на `await` |
| Смешивание sync/async | FixService | Полностью async |
| WMI для Firewall | FirewallTest | Не используется в новой архитектуре |

### 4.3 Документация vs реальность

| Документ | Проблема |
|----------|----------|
| `CLAUDE.md` | Упоминает `DnsTest`, `TcpTest` и др. как активные |
| `.github/copilot-instructions.md` | Ссылки на несуществующий `AuditRunner`, `ReportWriter` |

> ✅ Предыдущий архитектурный документ удалён (10.12.2025), актуальный — `ARCHITECTURE_CURRENT.md`

---

## 5. Потенциальные риски

### 5.1 🔴 Критические runtime проблемы (ПРОВЕРЕНО)

#### 5.1.1 `dnsOk=true` всегда в StandardHostTester

**Файл:** `Core/Modules/StandardHostTester.cs:24-25`

```csharp
bool dnsOk = true;
string dnsStatus = "OK";
// Эти значения НИКОГДА не меняются!
```

**Проблема:** При ошибке DNS (строки 44-60) выполняется `catch { }` без изменения `dnsOk`. Классификатор всегда получает `dnsOk=true`, даже если DNS не работает.

**Влияние:** DNS блокировки не детектируются.

---

#### 5.1.2 `async void` в InitializeOnStartupAsync

**Файл:** `ViewModels/BypassController.cs:291`

```csharp
public async void InitializeOnStartupAsync()
{
    // Включает Disorder + DROP_RST по умолчанию (строки 307-310)
    _isDisorderEnabled = true;
    _isDropRstEnabled = true;
}
```

**Проблемы:**
- Исключения не пробрасываются (проглатываются runtime)
- Вызывающий код не может `await`
- Bypass включается автоматически без подтверждения пользователя

---

#### 5.1.3 Синхронные логи на Desktop

**Файл:** `App.xaml.cs:7-8, 12, 16, 22, 31, 33-34, 42, 46, 49, 53`

```csharp
var logPath = Path.Combine(Environment.GetFolderPath(SpecialFolder.Desktop), "isp_audit_debug.txt");
File.AppendAllText(logPath, "...");  // Синхронно, 10+ вызовов!
```

**Проблемы:**
- Блокировка UI потока при каждом старте
- Мусор на рабочем столе пользователя (`isp_audit_debug.txt`)
- Возможные ошибки доступа (Desktop на сетевом диске, права)

---

### 5.2 🟡 Средние runtime проблемы

#### 5.2.1 Unbounded channels без back-pressure

**Файлы:** `Utils/LiveTestingPipeline.cs:97-99`, `Utils/TrafficCollector.cs:102`

```csharp
_snifferQueue = Channel.CreateUnbounded<HostDiscovered>();
_testerQueue = Channel.CreateUnbounded<HostTested>();
_bypassQueue = Channel.CreateUnbounded<HostBlocked>();
// + TrafficCollector.cs:102
```

**Риск:** При всплеске трафика (тысячи соединений) возможен OOM.
**Митигация:** На практике редко больше 100-200 хостов, но лучше использовать `BoundedChannel`.

---

#### 5.2.2 TLS без hostname считается OK

**Файл:** `Core/Modules/StandardHostTester.cs:148-150`

```csharp
else if (host.RemotePort == 443)
{
    // Не можем проверить TLS без hostname
    tlsOk = tcpOk;
}
```

**Проблема:** TLS DPI для IP-only соединений не детектируется.
**Обоснование:** Без SNI невозможно корректно проверить TLS — частично оправдано.

---

### 5.3 Silent failures

| Риск | Файл | Описание |
|------|------|----------|
| DNS timeout без лога | StandardHostTester.cs:48 | `GetHostEntryAsync` может молча timeout |
| WinDivert errors | TrafficEngine.cs | Ошибки открытия handle проглатываются |
| Backup file corruption | FixService | Не валидируется JSON бэкап |
| Фоновые исключения | DiagnosticOrchestrator, LiveTestingPipeline | `DispatcherUnhandledException` ловит только UI-поток |

### 5.4 Обработчики, которые не вызовутся

| Handler | Причина |
|---------|---------|
| `OnDnsLookupFailed` в DnsParserService | Подписка создаётся, но UI не обрабатывает |
| `OnHostnameResolved` в TrafficCollector | Событие объявлено, но подписчиков нет |

### 5.5 Исключения, которые не могут возникнуть

| Exception | Файл | Причина |
|-----------|------|---------|
| `UnauthorizedAccessException` в FirewallTest | Класс не вызывается |
| Все try/catch в Tests/*.cs | Код мёртвый |

### 5.6 Расхождения типов

| Проблема | Детали |
|----------|--------|
| `Target` vs `TargetDefinition` | Два разных типа для одного и того же |
| `TransportProtocol` дублирование | `Utils/NetworkConnection.cs` и `Bypass/BypassRedirectRule.cs` |
| `BlockageType` дублирование | `ProblemClassifier` и `Core/Models` |

---

## 6. Рекомендации по очистке

### 6.1 Немедленное удаление (низкий риск)

```
Удалить:
├── TargetCatalog.cs (пустой)
├── Wpf/ServiceItemViewModel.cs
├── Windows/CapturedTargetsWindow.xaml(.cs)
├── Utils/GuiProfileStorage.cs
├── Utils/DnsFixApplicator.cs
├── Utils/BypassStrategyPlanner.cs
├── Utils/NetworkMonitorService.cs
├── Utils/ProblemClassifier.cs
├── game_targets.json
└── bypass_profile_fshud_google.json
```

**Влияние:** Нулевое — код не используется.

### 6.2 Миграция Tests/ (средний риск)

```
Tests/ → Варианты:
1. Удалить полностью (логика в Core/Modules)
2. Перенести в ISP_Audit.Tests/ как unit-тесты
3. Оставить как "справочные примеры" в docs/legacy/
```

**Влияние:** Потеря "справочного кода", но он уже не работает.

### 6.3 Рефакторинг Config (низкий риск)

```csharp
// Удалить неиспользуемые:
- NoTrace
- UdpProbes (если не планируется)
- Ports (порты в профилях)
```

### 6.4 Namespace унификация (высокий риск)

```
Текущее:
IspAudit, ISPAudit, ISPAudit.ViewModels, IspAudit.Utils

Рекомендация:
IspAudit.* везде (единый регистр)
```

**Риск:** Требует изменения всех файлов.

### 6.5 Документация

```
Обновить:
- CLAUDE.md — убрать ссылки на мёртвый код
- [x] .github/copilot-instructions.md — актуализировать архитектуру (Выполнено 10.12.2025)
- [x] Добавить ARCHITECTURE_ACTUAL.md с текущим состоянием (Создан ARCHITECTURE_CURRENT.md 10.12.2025)
```

---

## 7. Карта зависимостей (текстовая)

```
Program.cs
└── App.xaml
    └── MainWindow.xaml
        └── MainViewModel
            ├── BypassController
            │   ├── TlsBypassService
            │   │   ├── TrafficEngine
            │   │   │   └── BypassFilter
            │   └── FixService
            ├── DiagnosticOrchestrator
            │   ├── TrafficCollector
            │   │   ├── ConnectionMonitorService
            │   │   │   └── TcpConnectionWatcher
            │   │   ├── PidTrackerService
            │   │   └── DnsParserService
            │   │       └── TrafficMonitorFilter
            │   ├── LiveTestingPipeline
            │   │   ├── StandardHostTester
            │   │   ├── StandardBlockageClassifier
            │   │   │   └── InMemoryBlockageStateStore
            │   │   │       ├── TcpRetransmissionTracker
            │   │   │       ├── HttpRedirectDetector
            │   │   │       ├── RstInspectionService
            │   │   │       └── UdpInspectionService
            │   │   └── UnifiedTrafficFilter
            │   │       └── NoiseHostFilter
            │   └── TrafficEngine (shared)
            └── TestResultsManager
                └── NoiseHostFilter.Instance

ГЛОБАЛЬНЫЕ:
- NoiseHostFilter.Instance (singleton)

Примечание (16.12.2025):
- Добавлен контрактный слой DPI Intelligence (INTEL): `Core/Intelligence/Contracts` (модели Signals/Diagnosis/Strategy).
- Это контракты (DTO/enum/константы), без зависимостей на UI/Bypass/WinDivert; подключение в runtime будет выполняться в следующих шагах (SignalsAdapter → Diagnosis → Selector → Executor).
```

---

## 8. Итоговая статистика

| Метрика | Значение |
|---------|----------|
| Всего .cs файлов | ~86 |
| Мёртвых файлов | **15** (17%) |
| Мёртвых классов | **18+** |
| Дублирующейся логики | **4 области** |
| Legacy параметров | **6+** |
| Runtime проблем | **5** (3 критичные) |
| Рисков silent failure | **3** |

---

## 9. Приоритеты исправлений

### 🔴 НЕМЕДЛЕННО (блокирует функционал)

| # | Проблема | Файл | Исправление |
|---|----------|------|-------------|
| 1 | `dnsOk=true` всегда | StandardHostTester.cs:24-60 | Добавить `dnsOk=false` в catch-блок |
| 2 | `async void` | BypassController.cs:291 | Изменить на `async Task`, убрать автовключение |
| 3 | Логи на Desktop | App.xaml.cs | Удалить или переместить в %TEMP%/logs |

### 🟡 ВЫСОКИЙ ПРИОРИТЕТ (1-2 дня)

| # | Проблема | Файл | Исправление |
|---|----------|------|-------------|
| 4 | Unbounded channels | LiveTestingPipeline.cs | ✅ Уже используется `BoundedChannel` (capacity: 1000) |
| 5 | TLS без hostname | StandardHostTester.cs | Без hostname TLS не проверяется; детерминизм достигается стабилизацией SNI-кеша + VPN-адаптивными таймаутами тестов |

### Фаза 1 (2-3 дня): Очистка мёртвого кода
1. Удалить 100% мёртвых файлов из раздела 6.1
2. Удалить неиспользуемые свойства в `Config`
3. Обновить `CLAUDE.md`

### Фаза 2 (3-5 дней): Рефакторинг
1. Разделить `DiagnosticOrchestrator` на компоненты
2. Унифицировать namespace (`IspAudit` vs `ISPAudit`)
3. Удалить или перенести `Tests/`

### Фаза 3 (опционально): Оптимизация
1. Устранить глобальные синглтоны
2. Добавить DI контейнер
3. Полное покрытие unit-тестами

---

**Статус документа:** Актуален на 12.12.2025 (TLS bypass Phase2)
**Очистка документации:** Выполнена (79 → 25 .md файлов)

---

## 10. Выполненные работы (10.12.2025)

### Критические исправления (Phase 1)
- [x] Исправлена логика DNS в `StandardHostTester.cs` (теперь `dnsOk=false` при ошибке).
- [x] Исправлен `async void` в `BypassController.cs` (заменен на `async Task`).
- [x] Удалено синхронное логирование на Рабочий стол в `App.xaml.cs`.
- [x] Ограничен размер каналов (Channels) в `LiveTestingPipeline.cs` и `TrafficCollector.cs` (BoundedChannel).

### Очистка мёртвого кода (Phase 2)
- [x] Удалены неиспользуемые файлы: `TargetCatalog.cs`, `Wpf/ServiceItemViewModel.cs`, `Windows/CapturedTargetsWindow.xaml`, `Utils/GuiProfileStorage.cs`, `Utils/DnsFixApplicator.cs`, `Utils/BypassStrategyPlanner.cs`, `Utils/NetworkMonitorService.cs`, `Utils/ProblemClassifier.cs`.
- [x] Удалены неиспользуемые ресурсы: `game_targets.json`, `bypass_profile_fshud_google.json`.
- [x] Очищен `Config.cs` (удалены `NoTrace`, `Ports`, `UdpProbes`).
- [x] Удалена папка `Tests/` (логика перенесена в `Core/Modules`).

### Документация (Phase 3)
- [x] Создан `ARCHITECTURE_CURRENT.md` (v3.0 Extended) — полное описание текущей архитектуры.
- [x] Обновлен `README.md`:
    - Заменена ASCII схема на Mermaid диаграмму.
    - Обновлена таблица ключевых компонентов.
    - Исправлена связь `BypassController` (перенесен из Network Layer в UI Layer).
- [x] Обновлен `.github/copilot-instructions.md`:
    - Нормализован язык (русский).
    - Обновлена краткая архитектура.
    - Удалены устаревшие разделы.
- [x] Верификация архитектуры:
- Проверено соответствие диаграммы коду (`MainViewModel`, `DiagnosticOrchestrator`, `LiveTestingPipeline`).
- [x] Унификация пространств имен (Namespaces):
    - Приведено к единому стилю (выбран `IspAudit`).

---

## 11. Обновления TLS bypass (12.12.2025)

- **Архитектура**: `TlsBypassService` — единый источник опций/пресетов, сам регистрирует `BypassFilter`, публикует `MetricsUpdated/VerdictChanged/StateChanged`; `BypassController` стал прокси без таймера (тумблеры + сохранение пресета/автокоррекции).
- **Профиль**: `bypass_profile.json` расширен TTL-настройками (`ttlTrick`/`ttlTrickValue`) и флагом `autoTtl`; сохранение пресета в UI обновляет только поля фрагментации (чтобы не перетирать TTL/redirect rules).
- **AutoTTL**: при включенном `autoTtl` сервис перебирает небольшой набор TTL (2..8) по метрикам bypass и сохраняет лучший TTL обратно в `bypass_profile.json`.
- **Auto-hostlist (кандидаты)**: добавлен `AutoHostlistService`; `LiveTestingPipeline` на этапе классификации передаёт `InspectionSignalsSnapshot` (ретрансмиссии/HTTP-редиректы/RST/UDP) только если Auto-hostlist включён, и пополняет список кандидатов, который показывается в UI (включается/выключается тумблером). Дополнительно, если текущий хост стал кандидатом, контекст auto-hostlist прокидывается в INTEL хвост (evidence/notes) как короткая нота `autoHL hits=… score=…` для UI/QA. Legacy `BlockageSignals` при этом не читаются.
- Для UX: если в intel-хвосте есть `autoHL hits=...`, при построении строки рекомендации рядом добавляется контекст `hostlist=auto`.
- **Метрики**: сервис считает ClientHello (все/короткие/не 443), фрагментации, релевантные RST, план фрагментов, активный пресет, порог и минимальный чанк, время начала; UI читает только события сервиса (план + таймстамп в badge).
- **Вердикты/UX**: добавлены статусы «нет TLS 443», «TLS не на 443», «ClientHello короче threshold», «обход активен, но не применён», «мало данных»; карточка не шумит на серые статусы, tooltip даёт next steps (снизить threshold/сменить пресет/включить Drop RST).
- **Автокоррекция**: флаг `AutoAdjustAggressive` (только пресет «Агрессивный»); ранний всплеск RST -> минимальный чанк=4; зелёный >30с -> лёгкое усиление (не ниже 4); переприменение опций делает сервис.
- **Риски/пробелы**: нет unit-тестов на `TlsBypassService`/вердикты; таймер метрик 2с может лагать в UI; авто-коррекция не сбрасывает флаг при смене пресета (пока пользователь не переключит); обход не применяется к ClientHello без SNI или не на 443; preemptive режим зависит от успешного старта `TrafficEngine`.
- **Примечание (SNI vs bypass)**: `TrafficMonitorFilter` должен обрабатывать пакет до `BypassFilter`, чтобы парсер SNI видел исходный (нефрагментированный/непереставленный) ClientHello; для естественной TCP-сегментации ClientHello в `DnsParserService` используется минимальный реассемблинг первых байт потока.
- **Примечание (SNI vs PID)**: WinDivert Network Layer не даёт PID, поэтому оркестратор гейтит SNI-триггеры через корреляцию remote endpoint → PID по событиям `ConnectionMonitorService` и списку `PidTrackerService.TrackedPids`. Для Steam/attach есть короткий буфер (несколько секунд), чтобы SNI, пришедший до появления PID, мог быть обработан позже.
- **UX-фидбек**: статус auto-bypass и вердикт сервиса показываются в оркестраторе; карточка окрашивается по цвету вердикта (зелёный не считается проблемой); badge включает план фрагментации + активный пресет.

