# ISP_Audit — Архитектура (v3.0 Extended)

**Дата обновления:** 26.12.2025
**Версия:** 3.0 (Comprehensive)
**Технологии:** .NET 9, WPF, WinDivert 2.2.0

---

## 1. Обзор системы

**ISP_Audit** — это инструмент сетевой диагностики, предназначенный для выявления и анализа блокировок трафика на стороне интернет-провайдера (ISP). В отличие от классических утилит (ping/tracert), ISP_Audit работает на уровне перехвата пакетов (DPI), анализируя поведение TCP/UDP соединений в реальном времени.

### Ключевые задачи
1.  **Пассивный мониторинг**: Захват исходящих SYN-пакетов (TCP) и первых датаграмм (UDP) без влияния на работу приложений.
2.  **Активное тестирование**: Проверка доступности хостов через независимые сокеты (DNS, TCP Handshake, TLS ClientHello).
3.  **Классификация блокировок**: Определение типа вмешательства (DNS Spoofing, TCP RST Injection, HTTP Redirect, Packet Drop).
4.  **Обход блокировок (Bypass)**: Применение стратегий модификации трафика (Fragmentation, Disorder, Fake TTL) для восстановления доступа.

---

## 2. Архитектура высокого уровня

Система построена по принципу конвейера (Pipeline), где данные проходят через серию фильтров и анализаторов.

```mermaid
graph TD
    User[Пользователь] --> UI[WPF UI (MainWindow)]
    UI --> VM[MainViewModelRefactored]
    
    subgraph Orchestration [Orchestration Layer]
        VM --> Orchestrator[DiagnosticOrchestrator]
        Orchestrator --> Pipeline[LiveTestingPipeline]
    end
    
    subgraph Core [Core Logic]
        Pipeline --> ConnectionMonitor[ConnectionMonitorService]
        ConnectionMonitor --> Sniffer[TrafficCollector]
        Sniffer --> NoiseFilter[NoiseHostFilter]
        NoiseFilter --> Tester[StandardHostTester]
        Tester --> Classifier[SignalsAdapterV2 + StandardDiagnosisEngineV2 + StandardStrategySelectorV2]
        Classifier --> StateStore[InMemoryBlockageStateStore]
    end
    
    subgraph Inspection [Inspection Services]
        StateStore --> RstInspector[RstInspectionService]
        StateStore --> UdpInspector[UdpInspectionService]
        StateStore --> RetransTracker[TcpRetransmissionTracker]
        StateStore --> RedirectDetector[HttpRedirectDetector]
    end
    
    subgraph Network [Network Layer]
        Sniffer --> WinDivert[WinDivert Driver]
        Tester --> NetworkStack[OS Network Stack]
        VM --> BypassCtrl[BypassController]
        BypassCtrl --> BypassState[BypassStateManager]
        BypassState --> TlsSvc[TlsBypassService]
        BypassState --> TrafficEngine[TrafficEngine]
    end
    
    TrafficEngine --> WinDivert
```

---

## 3. Детальное описание компонентов

### 3.1 UI Layer (WPF)

*   **`MainWindow.xaml`**: Главное окно приложения. Использует библиотеку `MaterialDesignInXaml` для визуализации карточек с проблемами.
*   **`MainViewModelRefactored`**: Центральная ViewModel.
    *   Управляет состоянием UI (загрузка, ошибки, результаты).
    *   Инициализирует `DiagnosticOrchestrator`.
    *   Обрабатывает команды пользователя (Start/Stop, Open Report).
*   **`BypassController`**: ViewModel, отвечающая за настройки обхода.
    *   Связывает UI-тумблеры (Fragment/Disorder/Fake/Drop RST/DoH + assist-флаги `QUIC→TCP` и `No SNI`) с `TlsBypassService` (регистрация фильтра управляется сервисом).
    *   Восстанавливает пресет/автокоррекцию и assist-флаги из `bypass_profile.json`; сохраняет выбранный пресет отдельно (обновляя только поля фрагментации) и assist-флаги отдельно (без перезаписи TTL/redirect rules).
    *   Пресеты фрагментации (стандарт/умеренный/агрессивный/профиль) и логика автокоррекции живут в сервисе, контроллер лишь проксирует выбор без собственного таймера.
    *   Метрики/вердикт приходят из событий `TlsBypassService` (`MetricsUpdated/VerdictChanged/StateChanged`): UI показывает план фрагментации, таймстамп начала метрик, активный пресет/мин. чанк и не подсвечивает карточку при серых статусах «нет данных/не 443».

Важно (runtime): QUIC fallback и режим allow-no-SNI — это явные флаги профиля/опций, а не «пресет». При включённом `DropUdp443` фильтр `BypassFilter` глушит UDP/443 (`Udp443Dropped++`), чтобы клиент откатился на TCP/HTTPS. При включённом `AllowNoSni` обход может применяться даже если SNI не распознан/отсутствует (ECH/ESNI/сегментация ClientHello).

*   **`BypassStateManager`**: единый владелец состояния обхода (SSoT) для `TrafficEngine` и `TlsBypassService`.
    *   **Fail-safe (Lite Watchdog + crash recovery):**
        *   Ведёт журнал сессии bypass (LocalAppData) с флагами `CleanShutdown`/`WasBypassActive`.
        *   При старте, если прошлый shutdown был не clean при активном bypass — выполняет принудительный `Disable`.
        *   При активном bypass и отсутствии heartbeat/метрик дольше окна — выполняет авто-`Disable`.
    *   **Activation Detection (по метрикам):**
        *   Вычисляет статус активации: `ENGINE_DEAD / NOT_ACTIVATED / ACTIVATED / NO_TRAFFIC / UNKNOWN`.
        *   Используется для наблюдаемости (в UI выводится как `ACT: ...`).
    *   Сериализует операции `Apply/Disable` и управляет жизненным циклом `TrafficEngine` и регистрацией фильтров.
    *   Используется одновременно `BypassController` и `DiagnosticOrchestrator`, чтобы избежать гонок/рассинхронизаций.
    *   Включает guard: попытки вызывать `TrafficEngine.*`/`TlsBypassService.*` вне manager-scope логируются и могут считаться ошибкой в smoke.
*   **`TestResultsManager`**: Управляет коллекцией результатов (`ObservableCollection<TestResult>`). Отвечает за обновление UI в потоке диспетчера.

Dev-проверка (smoke): для воспроизводимой проверки детерминизма UI без запуска GUI есть режим `--ui-reducer-smoke` в `TestNetworkApp` (прогон типовых строк пайплайна через `TestResultsManager.ParsePipelineMessage`).

UI-гейт по рекомендациям (v2-only): UI принимает рекомендации/стратегии обхода только из строк с префиксом `[V2]`. Любые legacy строки могут присутствовать в логе, но не обновляют `BypassStrategy` карточек и не попадают в панель рекомендаций.

Примечание (UX рекомендаций): блок «Рекомендации» в bypass-панели отображается при `HasAnyRecommendations` (есть v2-рекомендации **или** зафиксированы «ручные действия»), а кнопка apply фактически доступна только при `HasRecommendations` (есть объектный `BypassPlan` и есть что применять). Если стратегия уже включена пользователем вручную, она отображается как «ручное действие», чтобы рекомендации не «пропадали».

Важно: bypass-панель (и кнопка apply внутри неё) показывается только при запуске приложения с правами администратора.

Guard на legacy в v2 пути: smoke-тест `DPI2-025` проверяет, что в v2 runtime-пути отсутствуют `GetSignals(...)` и `BlockageSignals` (grep/regex по `Core/IntelligenceV2/*` и ключевым runtime-файлам).

Smoke-раннер (CLI): в `TestNetworkApp` есть режим `--smoke [all|infra|pipe|insp|ui|bypass|dpi2|orch|cfg|err|e2e|perf|reg]`, который запускает проверки из плана смоков (без GUI). Для полного покрытия плана smoke runner прогоняет **все** Test ID из `TestNetworkApp/smoke_tests_plan.md`; если тест из плана ещё не реализован, он возвращает `FAIL` с причиной (это сделано намеренно, чтобы было 97/97 выполнено без "SKIP"). По умолчанию часть проверок, завязанных на WinDivert/среду, может падать или помечается как `SKIP` (например, если запуск не от администратора). Для «жёсткого» прогона без `SKIP` используйте `--smoke ... --no-skip` (алиас `--strict`): в этом режиме любые `SKIP` считаются `FAIL`. Для выгрузки результатов добавлен `--json <path>`. Для удобства сопровождения реализации тестов разнесены по файлам `TestNetworkApp/Smoke/SmokeTests.*.cs`, а каркас раннера/плана остаётся в `TestNetworkApp/Smoke/SmokeRunner.cs`.

Категория `dpi2` (DPI Intelligence v2) покрыта детерминированными smoke-тестами `DPI2-001..024` в `TestNetworkApp/Smoke/SmokeTests.Dpi2.cs`: проверяются адаптация legacy сигналов в TTL-store, очистка по TTL, агрегация по окнам 30s/60s, постановка диагноза, жёсткие защиты селектора (confidence/risk/unimplemented), Gate-маркеры `[V2][GATE1]`, форматирование компактного вывода с префиксом `[V2]`, отсутствие auto-apply (MVP), а также контракт параметризации и ручного применения v2-плана (TlsFragment params + e2e selector→plan→manual apply).

Категория `insp` (Inspection Services) покрыта детерминированными smoke-тестами `INSP-001..005` в `TestNetworkApp/Smoke/SmokeTests.Insp.cs`: RST-инжекция по TTL и по IPID, детект QUIC Initial и сигнал «нет ответов», подсчёт ретрансмиссий и сигнал «подозрение на Drop» при доле >10%, извлечение host из HTTP 3xx Location. Для детерминизма используются синтетические IPv4/TCP/UDP пакеты из `TestNetworkApp/Smoke/SmokeTests.Packets.cs`.

Категория `bypass` (TLS bypass) частично покрыта детерминированными smoke-тестами `BYPASS-003..015` в `TestNetworkApp/Smoke/SmokeTests.Bypass.cs`: сбор метрик через событие `MetricsUpdated`, вычисление вердикта через `VerdictChanged` по порогам ratio RST/фрагментации, проверки логики `BypassFilter` (фрагментация/дизордер сегментов, TTL Trick, Drop RST, гейтирование по 443+SNI и порог threshold для коротких ClientHello), а также авто-поведение сервиса (AutoTTL и AutoAdjustAggressive по метрикам). Для детерминизма используется `BypassFilter` + синтетические TCP пакеты (ClientHello/RST) и захват отправленных фрагментов через тестовый sender, а `TlsBypassService` получает internal-хуки/сценарии smoke для прогона автонастроек без запуска WinDivert.

Автозапуск от администратора: отдельный запускатор `SmokeLauncher` сам запросит UAC elevation, выполнит `--smoke all --strict` (алиас `--no-skip`) и сохранит JSON в `artifacts/`.

- Запуск из исходников: `dotnet run -c Debug --project SmokeLauncher/SmokeLauncher.csproj`
- (опционально) Публикация в EXE: `dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true -p:SelfContained=false --project SmokeLauncher/SmokeLauncher.csproj`

### 3.2 Orchestration Layer

*   **`DiagnosticOrchestrator`**: "Дирижер" всего процесса.
    *   Запускает и останавливает `LiveTestingPipeline`.
    *   Управляет жизненным циклом фоновых сервисов (`TrafficEngine`, `ConnectionMonitor`).
    *   Следит за целевыми процессами (если задан фильтр по PID).
    *   Важное правило: события SNI из `DnsParserService` **гейтятся по PID**. Так как WinDivert Network Layer не предоставляет PID, оркестратор сопоставляет SNI с событиями соединений `ConnectionMonitorService` (remote endpoint → PID) и пропускает в пайплайн только то, что относится к `PidTrackerService.TrackedPids`.
        *   Для Steam/attach поддерживается короткий буфер (несколько секунд), чтобы не терять ранний SNI до появления PID.
    *   Важно: SNI не фильтруется по `NoiseHostFilter` на входе (это исходные данные). Фильтрация «шума» применяется только на этапе отображения успешных результатов.
*   **`LiveTestingPipeline`**: Асинхронный конвейер на базе `System.Threading.Channels`.
    *   Связывает этапы: Sniffing → Testing → Classification → Reporting.
    *   Использует `UnifiedTrafficFilter` для минимальной валидации (loopback) и правил отображения (не засорять UI «успешными» целями).
    *   Выполняет гейтинг повторных тестов через `IBlockageStateStore.TryBeginHostTest(...)` (кулдаун + лимит попыток), чтобы не спамить сеть, но при этом дать V2 накопить несколько наблюдений (SignalSequence) по проблемным/заблокированным хостам.
    *   Важно: `TrafficCollector` дедупит соединения по `RemoteIp:RemotePort:Protocol`, но в runtime допускает ограниченные «повторные обнаружения» этой же цели с кулдауном/лимитом — иначе ретесты физически не дойдут до pipeline.
    *   Публикует периодический `[PipelineHealth]` лог со счётчиками этапов (enqueue/test/classify/ui), чтобы диагностировать потери данных и «затыки» очередей без привязки к сценариям.
    *   Обеспечивает параллельную обработку множества хостов.
    *   Опционально принимает `AutoHostlistService`: на этапе Classification добавляет кандидатов хостов в авто-hostlist (для отображения в UI и последующего ручного применения). Auto-hostlist питается `InspectionSignalsSnapshot` (без чтения legacy `BlockageSignals`).

Smoke-хелперы (для детерминированных проверок без WinDivert/реальной сети):
* `DnsParserService.TryExtractSniFromTlsClientHelloPayload(...)` — извлечение SNI из TLS payload.
* `DnsParserService.TryFeedTlsClientHelloFragmentForSmoke(...)` — проверка реассемблинга SNI на фрагментах ClientHello.

### 3.2.1 DPI Intelligence v2

Статус: частично реализовано.
* Контрактный слой v2: `Core/IntelligenceV2/Contracts`.
* Step 1 (Signals): в runtime подключён сбор фактов в TTL-store через `SignalsAdapterV2` (в `LiveTestingPipeline`, этап Classification). Для v2-ветки факты инспекции снимаются через `IInspectionSignalsProvider` в виде `InspectionSignalsSnapshot` (без зависимости от legacy `BlockageSignals`).
    * Legacy-оверлоады `SignalsAdapterV2` с параметром `BlockageSignals` запрещены на уровне компиляции (`[Obsolete(..., error: true)]`).
    * Гейтинг тестов по цели: `InMemoryBlockageStateStore.TryBeginHostTest(...)` использует кулдаун и лимит попыток, чтобы не спамить сеть, но при этом дать V2 накопить несколько наблюдений (SignalSequence) по проблемным/заблокированным хостам.
* Step 2 (Diagnosis): в runtime подключена постановка диагноза через `StandardDiagnosisEngineV2` по агрегированному срезу `BlockageSignalsV2`.
* Step 3 (Selector/Plan): в runtime подключён `StandardStrategySelectorV2`, который строит `BypassPlan` строго по `DiagnosisResult` (id + confidence) и отдаёт краткую рекомендацию для UI (без auto-apply).
* Step 4 (ExecutorMvp): добавлен `Core/IntelligenceV2/Execution/BypassExecutorMvp.cs` — **только** форматирование/логирование (диагноз + уверенность + короткое объяснение + список стратегий), без вызова `TrafficEngine`/`BypassController` и без авто-применения.
* Ручное применение v2 плана (без auto-apply): `LiveTestingPipeline` публикует объектный `BypassPlan` через событие `OnV2PlanBuilt`, `DiagnosticOrchestrator` хранит последний план и применяет его только по клику пользователя через `BypassController.ApplyV2PlanAsync(...)` (таймаут/отмена/безопасный откат).
    * Защита от устаревшего плана: `DiagnosticOrchestrator.ApplyRecommendationsAsync(...)` применяет план только если `planHostKey` совпадает с последней v2-целью, извлечённой из UI‑диагноза (иначе — SKIP в лог).
    * Отмена: команда `Cancel` отменяет не только диагностику, но и текущий ручной apply (через отдельный CTS).
* Step 5 (Feedback/Rerank): добавлен слой обратной связи `Core/IntelligenceV2/Feedback/*` (MVP: in-memory + опциональный JSON persist). `StandardStrategySelectorV2` умеет (опционально) ранжировать стратегии по успешности, **поверх** hardcoded `BasePriority`.

---

## 3.2.2 DPI Intelligence v2 — карта состояния (As‑Is / Target / Roadmap)

Эта секция — «компас», чтобы не терять контроль: что реально есть в коде сейчас, какое целевое состояние мы считаем практичным, и какие следующие шаги логично делать.

### As‑Is (что уже реализовано и работает в рантайме)

1) **Signals → Diagnosis → Selector → Plan**
- `SignalsAdapterV2` пишет события в TTL-store (`InMemorySignalSequenceStore`).
- `StandardDiagnosisEngineV2` ставит диагноз по `BlockageSignalsV2` и формирует фактологичное объяснение.
- Введён консервативный диагноз `TlsInterference` для случаев, когда наблюдаются только TLS-проблемы (timeout/auth failure/reset) без достаточных дополнительных улик — это позволяет селектору предложить TLS-стратегии (manual apply).
- `StandardStrategySelectorV2` строит `BypassPlan` по `DiagnosisId + Confidence` (с защитами confidence/risk/unimplemented) и может учитывать feedback.

2) **Нет auto-apply (безопасность/контроль пользователя)**
- `BypassExecutorMvp` только форматирует/логирует.
- Ручное применение v2-плана: `LiveTestingPipeline.OnV2PlanBuilt` → `DiagnosticOrchestrator` хранит последний `BypassPlan` → пользователь кликает «Применить рекомендации v2» → `BypassController.ApplyV2PlanAsync(...)`.

3) **Исполнитель v2 (реальный apply с безопасным откатом)**
- `BypassController.ApplyV2PlanAsync` поддерживает таймаут/отмену и безопасный rollback на snapshot состояния.
 - Оркестратор не применяет «не тот» план: если рекомендации обновились и `hostKey` изменился, apply будет заблокирован.
 - `StrategyId.AggressiveFragment` при ручном apply выбирает пресет фрагментации «Агрессивный» и включает `AutoAdjustAggressive`.
 - `StrategyId.TlsFragment` может нести параметры (например, `TlsFragmentSizes`, `PresetName`, `AutoAdjustAggressive`). Парсинг параметров вынесен в `Core/IntelligenceV2/Execution/TlsFragmentPlanParamsParser.cs`, применение выполняет `BypassController.ApplyV2PlanAsync`.
 - Детерминизм: `StandardStrategySelectorV2` заполняет `TlsFragmentSizes` в плане, чтобы executor не зависел от текущего состояния UI-панели пресетов.
 - Assist-флаги v2: `BypassPlan` также может включать `DropUdp443` (QUIC→TCP) и `AllowNoSni` (No SNI), выставляемые селектором по наблюдаемым сигналам (UDP unanswered + статистика отсутствия SNI). При ручном apply контроллер включает эти флаги вместе со стратегиями.
 - Smoke: `DPI2-022` проверяет применение параметров из `BypassPlan`, `DPI2-023` проверяет, что селектор кладёт `TlsFragmentSizes` (и PresetName) в план, `DPI2-024` проверяет e2e цепочку `selector → plan → ApplyV2PlanAsync` (параметры из плана реально применяются).

4) **Важное ограничение реализации TLS-обхода (почему “Disorder vs Fragment” не складываются как сумма)**
- В текущей реализации профиль выбирает один режим TLS (`TlsStrategy`) и строится по цепочке `if/else if`.
- При этом `Disorder` в нашем движке **уже означает “фрагментируем ClientHello и меняем порядок отправки”** (т.е. это «усиленная» версия по сравнению с “Fragment only”).

### Target (реалистичное целевое состояние, без фантазий)

Цель v2 в проекте ISP_Audit — не «автоматически лечить интернет», а дать:
- **Объяснимую диагностику** (факты → диагноз + уверенность).
- **Предсказуемые рекомендации** (без противоречий; ровно одна TLS-стратегия за раз).
- **Полный контроль пользователя** (manual apply; понятная кнопка; понятная обратная связь).
- **Безопасность** (cancellation/timeout + rollback, никаких частично применённых состояний).

В терминах лучшей практики это соответствует разделению ответственности:
- Facts/Signals — только наблюдения.
- Diagnosis — только интерпретация.
- Selector/Plan — только выбор стратегии (и параметров, если есть).
- Executor/Apply — только применение (idempotent + rollback), без “умных решений”.

### Roadmap (минимальные шаги к Target, ориентированные на работу приложения)

1) **Стабилизировать UX-смысл стратегий**
- Зафиксировать глоссарий в коде/логах: что означает `TLS_FRAGMENT` и `TLS_DISORDER` (в нашем движке).
- Гарантировать, что селектор не выдаёт взаимоисключающие TLS-режимы одновременно (ровно одна TLS-стратегия в плане).

2) **Сделать рекомендацию “применимой” и проверяемой в UI**
- После клика на apply логировать: выбранный диагноз, выбранная стратегия, применённые ключевые опции (fragment/disorder/drop rst/doh).
- После apply показывать пользователю “что сейчас активно” (уже есть метрики/статусы в bypass-панели — удерживаем это как главный источник обратной связи).

3) **Параметры стратегий — только там, где это реально поддерживается движком**
- Если понадобится «Fragment+Disorder с кастомными размерами» — это отдельная явная стратегия/параметры, а не “включим два тумблера”.

### Глоссарий (чтобы не расползались смыслы)

- **TLS_FRAGMENT**: фрагментация ClientHello по выбранным размерам, отправка в обычном порядке.
- **TLS_DISORDER**: фрагментация ClientHello + отправка сегментов в обратном порядке (в текущем движке это один режим TLS-стратегии).
- **DROP_RST**: отбрасывание входящих TCP RST (релевантных) в фильтре.
- **Manual Apply v2**: применение обхода только по действию пользователя; пайплайн не применяет обход автоматически.

Ограничение (важно): Diagnosis Engine v2 **не знает** про стратегии/обход (нет ссылок на StrategyId/Bypass/TlsBypassService/параметры) и формирует пояснения только из наблюдаемых фактов (timeout, DNS fail, retx-rate, HTTP redirect).

Примечание по RST-уликам (v2):
* `SignalsAdapterV2.BuildSnapshot(...)` извлекает `RstTtlDelta` из `InspectionSignalsSnapshot.SuspiciousRstDetails` (форматы `TTL=.. (обычный=min-max)`/`expected min-max`).
* `RstLatency` берётся как приближённая метрика из `HostTested.TcpLatencyMs` для случая `TCP_CONNECTION_RESET`.
* `StandardDiagnosisEngineV2` использует эти поля, чтобы выдавать `ActiveDpiEdge` (быстрый RST) или `StatefulDpi` (медленный RST) вместо `Unknown`.

Ключевые принципы:
*   Между диагностикой и обходом добавляется слой “интеллекта” (Signals → Diagnosis → Selector → Plan).
*   Signals в v2 строятся как **временные цепочки событий** (SignalEvent/SignalSequence), а агрегированные признаки считаются поверх окна.
*   В MVP запрещён auto-apply: применение обхода остаётся **только ручным действием пользователя** (one-click apply допустим).

Жёсткие защиты селектора (зафиксировано в коде):
*   `confidence < 50` → пустой план.
*   `RiskLevel.High` запрещён при `confidence < 70`.
*   Нереализованные стратегии не ломают пайплайн: выводится warning и стратегия пропускается.
*   При отсутствии feedback-данных поведение идентично MVP (сортировка только по `BasePriority/Risk/Id`).

Контрактные константы v2 (зафиксировано в коде):
*   Окно агрегации: 30 секунд (default) и 60 секунд (extended).
*   TTL событий: 10 минут (очистка должна выполняться при Append в сторе).

Точки интеграции (на текущий момент):
* `LiveTestingPipeline.ClassifierWorker`: legacy `BlockageSignals` остаётся для UI/Auto-hostlist, но v2-ветка вызывает `SignalsAdapterV2.Observe(...)` с `InspectionSignalsSnapshot` (из `IInspectionSignalsProvider`, с фолбэком из legacy).
* Затем строится `BlockageSignalsV2` (агрегация по окну) и вызывается `StandardDiagnosisEngineV2.Diagnose(...)`. Результат используется для формирования компактного «хвоста фактов» в UI-логе.
* Затем вызывается `StandardStrategySelectorV2.Select(diagnosis, ...)`, а Step 4 формирует компактный пользовательский вывод (1–2 строки на хост, без спама) и список стратегий для панели рекомендаций.
* Для ручной проверки Gate 1→2 в UI-логе используются строки с префиксом `[V2][GATE1]`.

Маркер v2-вывода (как отличить от legacy): все строки рекомендаций v2 начинаются с префикса `[V2]`.

### 3.3 Core Modules (`IspAudit.Core`)

*   **`BlockageCode` (`Core/Diagnostics/BlockageCode.cs`)**:
    *   Единая точка нормализации кодов проблем (`BlockageType`): канонические «фактовые» коды + legacy алиасы.
    *   Используется в legacy (например, `StandardBlockageClassifier`, `StrategyMapping`, UI-парсинг) и в v2 (`SignalsAdapterV2`), чтобы алиасы не «размазывались» по слоям.

*   **`PipelineContract` (`Core/Diagnostics/PipelineContract.cs`)**:
    *   Единая точка контрактных строк пайплайна (например, `BypassNone`/`BypassUnknown`).
    *   Используется в слоях legacy/v2/UI, чтобы не сравнивать «магические строки» (`"NONE"`, `"UNKNOWN"`) напрямую.

*   **`TrafficCollector` (`Utils/TrafficCollector.cs`)**:
    *   Слушает события от `ConnectionMonitorService` (который управляется `DiagnosticOrchestrator`).
    *   Фильтрует трафик по PID целевого процесса (через `PidTrackerService`).
    *   До логирования/попадания в UI применяет `UnifiedTrafficFilter` (минимально: loopback), чтобы не создавать «вечные» карточки для заведомо нерелевантных целей.
    *   Передает уникальные `(IP, Hostname)` в пайплайн.
    *   В UI ключ карточки должен быть **человеко‑понятным**: приоритетно SNI/hostname (если известен). IP сохраняется как технический атрибут для корреляции/диагностики, но не должен быть главным «лицом» карточки для пользователя.
*   **`StandardHostTester` (`Core/Modules/StandardHostTester.cs`)**:
    *   Выполняет активные проверки для каждого обнаруженного хоста:
        1.  **DNS**: Резолв домена через системный DNS.
        2.  **TCP**: Попытка установить соединение (Syn -> SynAck).
        3.  **TLS**: Отправка ClientHello и ожидание ServerHello (проверка SNI-блокировок).
        4.  **rDNS (PTR)**: Короткая попытка reverse DNS для IP (как дополнительное поле в UI).
*   **`StandardBlockageClassifier` (`Core/Modules/StandardBlockageClassifier.cs`)**:
    *   Анализирует результаты тестов (`HostTested`) и выносит вердикт.
    *   Логика:
        *   DNS ошибка → `DNS_BLOCKED`.
        *   TCP Timeout → `TCP_CONNECT_TIMEOUT` (legacy: `TCP_TIMEOUT`) (возможно Drop).
        *   TCP Reset → `TCP_RESET` (активная блокировка).
        *   TLS Timeout/Reset → `DPI_FILTER`.
        *   `198.18.0.0/15` → `FAKE_IP` (часто редирект/маршрутизация через роутер/шлюз), рекомендация `ROUTER_REDIRECT` (не предлагается повторно, если уже активна).
*   **`InMemoryBlockageStateStore` (`Core/Modules/InMemoryBlockageStateStore.cs`)**:
    *   Хранит историю проверок за текущую сессию.
    *   Предотвращает повторное тестирование одних и тех же хостов (дедупликация).
    *   Дополнительно реализует `IInspectionSignalsProvider`, чтобы v2-контур мог снимать инспекционные факты без зависимости от legacy `BlockageSignals`.

### 3.4 Inspection Services (Глубокий анализ)

Эти сервисы работают параллельно с основным пайплайном и уточняют диагноз.

*   **`RstInspectionService`**:
    *   Перехватывает входящие TCP RST пакеты.
    *   Сравнивает TTL и IP Identification пакета с эталонными значениями.
    *   Если TTL резко отличается от обычного трафика с этого хоста → **RST Injection** (DPI).
*   **`UdpInspectionService`**:
    *   Анализирует UDP трафик (в основном QUIC и DNS).
    *   Детектирует блокировки протокола QUIC (часто блокируется провайдерами для форсирования HTTP/TLS, которые легче фильтровать).
*   **`TcpRetransmissionTracker`**:
    *   Считает количество повторных отправок (Retransmissions) для каждого соединения.
    *   Высокий % ретрансмиссий (>10%) при отсутствии RST указывает на **Packet Drop** (тихий дроп пакетов).
*   **`HttpRedirectDetector`**:
    *   Анализирует HTTP-ответы на предмет кодов 301/302/307.
    *   Сравнивает URL редиректа со списком известных заглушек провайдеров (blockpage).

### 3.5 Bypass Layer (`IspAudit.Bypass`)

*   **`TrafficEngine` (`Core/Traffic/TrafficEngine.cs`)**:
    *   Обертка над драйвером WinDivert.
    *   Управляет загрузкой фильтров и инъекцией пакетов.
    *   Важный порядок: пассивные наблюдатели (например `TrafficMonitorFilter` для DNS/SNI/инспекций) должны выполняться **раньше** модифицирующих фильтров (`BypassFilter`), чтобы получать исходный (неизменённый) трафик.
*   **`TlsBypassService` (`Bypass/TlsBypassService.cs`)**:
    *   Единственный источник правды для TLS обхода: применяет опции, держит пресеты и автокоррекцию, сам регистрирует/удаляет `BypassFilter` в `TrafficEngine`.
    *   Каждые 2 секунды собирает метрики фильтра: сколько ClientHello увидено/коротких/не 443, сколько фрагментировано, релевантные RST, план фрагментации, активный пресет, порог/минимальный чанк, время начала сбора.
    *   Вычисляет вердикты: нет TLS 443 в трафике, TLS идёт не на 443, ClientHello короче порога (совет снизить threshold/взять агрессивный пресет), обход активен но не применён, мало данных, ratio RST/фрагм >4 (красный) или >1.5 (жёлтый), иначе зелёный; публикует `MetricsUpdated/VerdictChanged/StateChanged` для UI/оркестратора.
    *   Автокоррекция работает только для пресета «Агрессивный» с флагом `AutoAdjustAggressive`: при раннем всплеске RST ужимает минимальный чанк до 4, при стабильном зелёном >30с слегка уменьшает минимальный чанк (не ниже 4) и переприменяет опции.
    *   TTL Trick управляется runtime-опциями (`TtlTrickEnabled/TtlTrickValue`); при включенном `AutoTtlEnabled` сервис выполняет короткий подбор TTL (малый набор значений) по метрикам bypass и сохраняет лучший TTL обратно в `bypass_profile.json`.
*   **`BypassFilter` (`Core/Traffic/Filters/BypassFilter.cs`)**:
    *   Реализует конкретные алгоритмы обхода:
        *   **Fragmentation**: Разбиение ClientHello на 2+ TCP-сегмента по списку размеров из `TlsFragmentSizes`.
        *   **Disorder**: Отправка сегментов в обратном порядке при сохранении корректных seq/len, чтобы сбить DPI.
        *   **Fake TTL**: Отправка "фейкового" пакета с коротким TTL, который дойдет до DPI, но не до сервера.
    *   Собирает метрики (обработанные TLS ClientHello, фрагментации, сброшенные RST, последний план фрагментов) для индикации в UI; обрабатывает только ClientHello на 443 с SNI и длиной ≥ threshold, короткие/не443 считаются отдельно.

---

## 4. Поток данных (Data Flow)

1.  **Захват (Capture)**: `ConnectionMonitorService` (управляемый Оркестратором) фиксирует события/снимки соединений (Socket Layer WinDivert или polling через IP Helper API).
2.  **Идентификация (Identify)**: `PidTrackerService` определяет, какой процесс (PID) инициировал соединение.
3.  **Парсинг (Parse)**: `DnsParserService` пытается извлечь доменное имя (из DNS-кэша или SNI).
    *   Примечание: извлечение SNI делается по исходящему TLS ClientHello и поддерживает сценарий, когда ClientHello разбит на несколько TCP-сегментов (минимальный реассемблинг первых байт потока).
    *   Важно: SNI сам по себе не означает, что трафик относится к целевому процессу. В оркестраторе SNI-триггеры дополнительно фильтруются по PID через корреляцию remote endpoint → PID.
4.  **Фильтрация (Filter)**: `UnifiedTrafficFilter` отбрасывает только заведомо нерелевантное (loopback).
5.  **Очередь (Queue)**: Хост попадает в входную очередь `LiveTestingPipeline`.
6.  **Валидация (Validate)**: Хост проверяется тестером (DNS/TCP/TLS) без pre-check фильтрации «шума», чтобы не терять сигнал на браузерных/CDN-сценариях.
7.  **Тестирование (Test)**: `StandardHostTester` забирает хост из очереди и проводит серию тестов (DNS, TCP, TLS).
8.  **Инспекция (Inspect)**: Параллельно `RstInspectionService` и другие сервисы следят за пакетами этого соединения.
9.  **Агрегация (Aggregate)**: Результаты тестов и инспекций собираются в `HostTested` модель.
10. **Классификация (Classify)**: `StandardBlockageClassifier` выносит вердикт (например, `DPI_REDIRECT`).
11. **Отчет (Report)**: Результат отправляется в UI через `TestResultsManager`.
    *   Примечание: `NoiseHostFilter` используется на этапе отображения, чтобы не засорять UI «успешными» результатами (Status OK), но не скрывать реальные проблемы.
12. **Реакция (React)**: Если включен авто-обход, `DiagnosticOrchestrator` включает преемптивный TLS bypass через `BypassController.TlsService.ApplyPreemptiveAsync` (обычно `TLS_DISORDER + DROP_RST`); сам `TlsBypassService` регистрирует/удаляет `BypassFilter` в `TrafficEngine` и через события отдаёт план/метрики/вердикт в UI и оркестратору.

---

## 5. Структура проекта

```
ISP_Audit/
├── Program.cs                  # Точка входа (инициализация WPF, регистрация CodePages для OEM866)
├── App.xaml                    # Ресурсы приложения
├── MainWindow.xaml             # Разметка UI
├── Config.cs                   # Глобальные настройки (Singleton-like)
│
├── Core/                       # ЯДРО СИСТЕМЫ
│   ├── Interfaces/             # Интерфейсы (IHostTester, IBlockageClassifier)
│   ├── IntelligenceV2/          # DPI Intelligence v2
│   │   ├── Contracts/           # Контракты v2 (Signals/Diagnosis/Strategy), без зависимостей на UI/Bypass/WinDivert
│   │   ├── Diagnosis/            # DiagnosisEngine v2 (StandardDiagnosisEngineV2)
│   │   ├── Execution/            # ExecutorMvp (BypassExecutorMvp)
│   │   ├── Signals/              # SignalsAdapterV2 + TTL store
│   │   └── Strategies/           # Selector/Plan (StandardStrategySelectorV2)
│   ├── Models/                 # Модели данных (HostDiscovered, TestResult)
│   ├── Modules/                # Реализация логики
│   │   ├── StandardHostTester.cs          # Активные тесты
│   │   ├── StandardBlockageClassifier.cs  # Классификатор
│   │   ├── InMemoryBlockageStateStore.cs  # Хранилище состояния
│   │   ├── RstInspectionService.cs        # Анализ RST
│   │   └── ...
│   └── Traffic/                # Работа с сетью
│       ├── TrafficEngine.cs    # Управление WinDivert
│       └── Filters/            # Логика модификации пакетов
│
├── ViewModels/                 # MVVM (UI Logic)
│   ├── MainViewModelRefactored.cs
│   ├── DiagnosticOrchestrator.cs
│   ├── BypassController.cs
│   └── TestResultsManager.cs
│
├── Utils/                      # Вспомогательные классы
│   ├── LiveTestingPipeline.cs  # Конвейер обработки
│   ├── TrafficCollector.cs     # Сниффер
│   ├── ConnectionMonitorService.cs
│   ├── DnsSnifferService.cs    # содержит DnsParserService (DNS + SNI)
│   ├── PidTrackerService.cs
│   └── FixService.cs           # Системные исправления (DNS)
│
├── Bypass/                     # Логика обхода (Legacy & Helpers)
│   ├── StrategyMapping.cs      # Подбор стратегии по типу ошибки
│   └── WinDivertNative.cs      # P/Invoke обертка
│
└── docs/                       # Документация
    ├── ARCHITECTURE_CURRENT.md # Этот файл
    ├── WORK_PLAN.md            # План работ
    └── full_repo_audit_v2.md   # Полный аудит кода
```

---

## 6. Известные ограничения (Known Issues)

| Компонент | Ограничение | Влияние на пользователя |
|-----------|-------------|-------------------------|
| **WinDivert** | Требует права Администратора | Приложение не запустится без UAC elevation. |
| **VPN** | Конфликт с TAP/TUN адаптерами | При включенном VPN трафик может идти в обход WinDivert или дублироваться. Возможны ложные срабатывания. |
| **Локализация** | CP866 (OEM) в консоли | `tracert.exe` в русской Windows выдает кракозябры, если не установить кодировку 866. |
| **Размер** | Single-file ~160MB | Из-за включения .NET Runtime и WPF библиотек в один файл. |
| **DNS** | DoH (DNS over HTTPS) | Приложение пока не умеет перехватывать и расшифровывать DoH трафик браузеров. |

---

## 7. Технический долг (Technical Debt)

1.  **Глобальное состояние**:
    *   Использование статических свойств `Config.ActiveProfile` и `Program.Targets` делает код хрупким и сложным для тестирования.
    *   Singleton `NoiseHostFilter.Instance` создает скрытые зависимости между модулями.
2.  **Отсутствие DI**:
    *   Граф объектов создаётся вручную внутри `MainViewModelRefactored` (DataContext создаётся в XAML). Это усложняет замену компонентов (например, для мок-тестирования).
3.  **Жесткие пути**:
    *   Пути к логам и профилям иногда формируются конкатенацией строк, что может вызвать проблемы на нестандартных конфигурациях ОС.
4.  **Обработка ошибок**:
    *   В некоторых `async void` методах (особенно в старых ViewModel) исключения могут "проглатываться".

---

## 8. План развития (Roadmap)

### Phase 4: Refactoring (Q1 2026)
*   [ ] **Внедрение DI Container**: Переход на `Microsoft.Extensions.DependencyInjection` для управления зависимостями.
*   [ ] **Устранение глобального состояния**: Рефакторинг `Config` и `Program` в инжектируемые сервисы `IConfigurationService`.
*   [ ] **Unit Tests**: Покрытие тестами критической логики (`StandardBlockageClassifier`, `BypassFilter`).

### Phase 5: Advanced Bypass
*   [ ] **Geneva Strategy**: Реализация стратегии, используемой в Geneva (TCP Window manipulation).
*   [ ] **Auto-Tune**: Автоматический подбор параметров (TTL, размер фрагмента) на основе реакции DPI.

### Phase 6: UI/UX Improvements
*   [ ] **Real-time Graphs**: Визуализация задержек и потерь пакетов.
*   [ ] **History Export**: Возможность сохранения истории проверок в PDF/HTML отчет.
