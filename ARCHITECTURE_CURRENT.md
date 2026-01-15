# ISP_Audit — Архитектура (v3.0 Extended)

**Дата обновления:** 15.01.2026
**Версия:** 3.0 (Comprehensive)
**Технологии:** .NET 9, WPF, WinDivert 2.2.0

---

## 1. Обзор системы

**ISP_Audit** — это инструмент сетевой диагностики, предназначенный для выявления и анализа блокировок трафика на стороне интернет-провайдера (ISP). В отличие от классических утилит (ping/tracert), ISP_Audit работает на уровне перехвата пакетов (DPI), анализируя поведение TCP/UDP соединений в реальном времени.

Смежный архитектурный набросок (draft): модель «сетевого портрета приложения» и подход к минимизации побочных эффектов (например, чтобы QUIC→TCP не ломал другие приложения): см. `docs/network_portrait_architecture.md`.

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
    *   Левая панель управления работает как drawer (`DrawerHost`) с возможностью закрепления (PIN) и автосворачиванием во время диагностики.
    *   Таблица результатов упрощена до 4 колонок (статус-иконка / SNI-домен / иконки стратегии / действие). Детали доступны по double-click по строке.
*   **`MainViewModelRefactored`**: Центральная ViewModel.
    *   Управляет состоянием UI (загрузка, ошибки, результаты).
    *   Инициализирует `DiagnosticOrchestrator`.
    *   Обрабатывает команды пользователя (Start/Stop, Open Report).
    *   **P0.6 Смена сети (staged revalidation):** подписывается на системные события смены сети (через `NetworkChangeMonitor`) и показывает уведомление «Проверить/Отключить/Игнорировать». «Проверить» запускает staged-проверку `Activation → Outcome` и затем предлагает запустить полную диагностику (без auto-apply).
    *   При закрытии приложения выполняет безопасный shutdown: отменяет диагностику, отключает bypass и восстанавливает DNS/DoH (если был включён через `FixService` и существует backup в `%LocalAppData%\ISP_Audit\dns_backup.json`). Важно: `App.OnExit` синхронно дожидается `ShutdownAsync`, чтобы откат успел завершиться до завершения процесса.
    *   Crash-recovery: при старте `BypassController.InitializeOnStartupAsync` пытается восстановить DNS из backup, если он остался от прошлой незавершённой сессии (например, после падения процесса).
*   **`BypassController`**: ViewModel, отвечающая за настройки обхода.
    *   Связывает UI-тумблеры (Fragment/Disorder/Fake/Drop RST/DoH + assist-флаги `QUIC→TCP` и `No SNI`) с `TlsBypassService` (регистрация фильтра управляется сервисом).
    *   Восстанавливает пресет/автокоррекцию и assist-флаги из `bypass_profile.json`; сохраняет выбранный пресет отдельно (обновляя только поля фрагментации) и assist-флаги отдельно (без перезаписи TTL/redirect rules).
    *   Пресеты фрагментации (стандарт/умеренный/агрессивный/профиль) и логика автокоррекции живут в сервисе, контроллер лишь проксирует выбор без собственного таймера.
    *   Метрики/вердикт приходят из событий `TlsBypassService` (`MetricsUpdated/VerdictChanged/StateChanged`): UI показывает план фрагментации, таймстамп начала метрик, активный пресет/мин. чанк и не подсвечивает карточку при серых статусах «нет данных/не 443».

Важно (runtime): QUIC fallback и режим allow-no-SNI — это явные флаги профиля/опций, а не «пресет».

- `DropUdp443` (тумблер `QUIC→TCP`) включает откат с QUIC/HTTP3 (UDP/443) на TCP/HTTPS.
- По умолчанию это **селективный** режим: `BypassStateManager` поддерживает observed IPv4 адреса цели (TTL/cap, cold-start через DNS resolve host) и прокидывает их в `TlsBypassService`, а `BypassFilter` глушит UDP/443 (`Udp443Dropped++`) **только** для пакетов на эти IP — так уменьшаются побочные эффекты на другие приложения/сервисы.
- `DropUdp443Global` включает **глобальный** режим (дропать весь UDP/443 без привязки к цели). Это более агрессивно и может влиять на приложения, использующие QUIC/HTTP3.
- Для IPv6 трафика селективность пока недоступна (адреса не парсятся), поэтому сохраняется прежнее поведение drop при включённом `DropUdp443`.

При включённом `AllowNoSni` обход может применяться даже если SNI не распознан/отсутствует (ECH/ESNI/сегментация ClientHello).

*   **`BypassStateManager`**: единый владелец состояния обхода (SSoT) для `TrafficEngine` и `TlsBypassService`.
    *   **Fail-safe (Lite Watchdog + crash recovery):**
        *   Ведёт журнал сессии bypass (LocalAppData) с флагами `CleanShutdown`/`WasBypassActive`.
        *   При старте, если прошлый shutdown был не clean при активном bypass — выполняет принудительный `Disable`.
        *   При активном bypass и отсутствии heartbeat/метрик дольше окна — выполняет авто-`Disable`.
    *   **Activation Detection (по метрикам):**
        *   Вычисляет статус активации: `ENGINE_DEAD / NOT_ACTIVATED / ACTIVATED / NO_TRAFFIC / UNKNOWN`.
        *   Используется для наблюдаемости (в UI выводится как `ACT: ...`).
    *   **Outcome Check (HTTPS):**
        *   Отдельно от activation вычисляет outcome `SUCCESS / FAILED / UNKNOWN`.
        *   Для HTTPS outcome основан на **активном tagged probe** (TCP+TLS+HTTP к цели) и не опирается на пассивный анализ HTTPS.
        *   Probe-поток исключается из пользовательских метрик bypass (чтобы не создавать ложную «активацию» только из-за probe).
    *   Сериализует операции `Apply/Disable` и управляет жизненным циклом `TrafficEngine` и регистрацией фильтров.
    *   Используется одновременно `BypassController` и `DiagnosticOrchestrator`, чтобы избежать гонок/рассинхронизаций.
    *   Включает guard: попытки вызывать `TrafficEngine.*`/`TlsBypassService.*` вне manager-scope логируются и могут считаться ошибкой в smoke.

#### Модель B (Design target): Policy‑Driven Group Model (группа = пакет политик)

Ключевой тезис (Design, 15.01.2026): **обход — это не «состояние системы», а функция от пакета**. На уровне WinDivert мы всегда обрабатываем конкретный пакет с конкретными полями (IP/порт/протокол/маркеры), поэтому любые «семантические» понятия (сервис, группа, карточка) должны в итоге компилироваться в правила выбора действия для пакета.

Ограничения платформы перехвата (как «законы природы», которые нельзя обойти архитектурой):
- пакет перехватывается один раз и требует одного атомарного решения (PASS/BLOCK/MODIFY);
- фильтры и обработчики не знают «YouTube/Steam», они видят только признаки пакета;
- стратегии могут быть взаимоисключающими (нельзя одновременно и «дроп», и «модификацию» одного и того же потока);
- современные сервисы распределены и состоят из множества доменов/эндпоинтов, которые должны работать одновременно.

Отсюда целевая декомпозиция (модель исполнения):
- **Semantic Layer (UI/группы/карточки)**: то, что понимает пользователь (Service Group, вклад карточки).
- **Policy Layer (FlowPolicy)**: декларативные правила «если match → action».
- **Decision Graph (Snapshot)**: детерминированный, быстрый lookup решения по признакам пакета.
- **Execution Plane (WinDivert handlers/filters)**: обработка пакета + применение одного решения.

Практическое следствие для ISP_Audit: даже если движок физически один и глобальный, управление и наблюдаемость должны быть описаны как «набор политик», а не как «переключатель стратегии». Инкрементальный план внедрения policy-driven модели — в `docs/TODO.md` (P0.2).

Контекст: реальные сервисы (YouTube/Steam/и т.п.) состоят из нескольких доменов/хостов, которые **должны работать одновременно**. Если считать «одна карточка = одна активная конфигурация», получаем UX-поломку: применили обход к CDN → «интерфейс» стал INACTIVE, хотя для пользователя это один сервис.

Поэтому базовая единица управления обходом — **группа целей (Service Group)**, а карточки/hostKey являются участниками этой группы.
Целевая семантика: **группа = пакет политик (per-domain/per-endpoint)**, где разные домены внутри одной группы могут иметь разные стратегии.

Требования к «применению обхода» в этой модели:
- привязка к группе и к конкретной карточке-инициатору;
- аккумулятивность (добавление новых целей в группу не выключает предыдущие);
- сериализация транзакций (без гонок и частично применённых состояний);
- наблюдаемость (видно состав конфигурации и вклад каждой карточки).

Важно: аккумуляция применяется **к endpoints/флагам/политикам**, но не обязана означать «одна общая TLS‑стратегия на всех». Для TCP/443 правильнее модель policy‑выбора: стратегия выбирается как функция от пакета (dst_ip/proto/port/tls_stage).

##### Источник истины

- Низкий уровень остаётся глобальным: WinDivert/TrafficEngine и регистрация фильтров — это одно состояние процесса, владелец которого `BypassStateManager`.
- UX/семантика становится «per-group»: группа хранит **набор attachments** (вкладов) от карточек/hostKey и последнюю транзакцию применения.
- Каждая карточка хранит:
    - принадлежность к группе (GroupKey),
    - свой вклад (Attachment) в конфигурацию группы,
    - статус своего ретеста/переподключения,
    - ссылку на последнюю транзакцию группы, в которой она участвовала.

##### Правило объединения (ключевое отличие от single-owner)

Группа целей держит набор вкладов (attachments), но итоговая «эффективная конфигурация» представляется как:
- **Policy bundle** (набор правил, выбирающих действие для пакета);
- плюс аккумулятивные части, которые естественно объединяются (например, endpoints для селективного QUIC→TCP и временных блокировок).

Пример (YouTube):
- Группа: `YouTube.com`.
- Участники (карточки): `youtube.com`, `googlevideo.com`, `ytimg.com`, `gstatic.com`, …
- Пользователь применяет обход к `googlevideo.com` → это **добавляет/обновляет вклад** в группу, не выключая `youtube.com`.

Правила мержа (целевые, чтобы не было «хаоса»):
- Endpoints: объединение (union) endpoint-наборов (IPv4/IPv6) по всем attachments группы, с TTL/cap и источником (DNS/SNI/resolve/observed).
- Assist-флаги: объединение (OR). Если хотя бы одному участнику нужен `QUIC→TCP`, он включается для группы.
- TLS‑стратегия: **не одна на группу**, а выбирается policy‑движком по признакам пакета (dst_ip/proto/port/tls_stage) — так разные домены одной группы могут использовать разные стратегии одновременно.

Важно: даже если движок физически один и работает глобально, в UI это показывается как «активная конфигурация группы», а не «активна только карточка X».

Опционально (после стабилизации): поддержка нескольких активных групп возможна только если итоговая конфигурация определяется как объединение активных групп и это явно показано пользователю как расширение blast radius.

##### Транзакция «применения обхода» (что должен видеть пользователь)

Каждое применение оформляется транзакцией с идентификатором и снимком:
- Request: GroupKey, инициатор (hostKey карточки + тип: ручное действие / автоматическое правило), причина, таймаут/отмена.
- Snapshot:
    - EffectiveGroupConfig: итоговые флаги/endpoint-наборы/цель outcome.
    - PolicyBundle: список активных политик (per-domain/per-port) и их приоритеты.
    - Contributions: список вкладов (какие карточки/hostKey участвовали, какой endpoint-набор/флаги/политики принесли).
    - FiltersActive: какие фильтры активны (имя + приоритет) и почему.
    - InputFacts: источники данных (DNS/SNI/resolve/observed), возраст/TTL, отбрасывания по cap/ttl.
- Result: Applied/Failed/RolledBack + ошибка + тайминги.

##### Отражение в UI/логах

- В карточке: краткое резюме «в группе <GroupKey>», статус последней транзакции группы, и “EffectiveGroupConfig” (в 1 строку: стратегия + флаги + endpoints=N).
- В деталях (панель/expander): полный снимок последней транзакции и кнопка «Скопировать» (для репорта).
- В логе: компактная строка на транзакцию (TransactionId + GroupKey + initiatorHostKey + strategy + flags + endpoint-count) и возможность разворота деталей.
*   **`TestResultsManager`**: Управляет коллекцией результатов (`ObservableCollection<TestResult>`). Отвечает за обновление UI в потоке диспетчера.

Dev-проверка (smoke): для воспроизводимой проверки детерминизма UI без запуска GUI есть режим `--ui-reducer-smoke` в `TestNetworkApp` (прогон типовых строк пайплайна через `TestResultsManager.ParsePipelineMessage`).

Качество кода (analyzers/линт):
* В корне репозитория используются `Directory.Build.props` и `.editorconfig`.
* Включены встроенные .NET analyzers (`EnableNETAnalyzers=true`), без форсирования `AnalysisMode/AnalysisLevel` (оставляем дефолты SDK, чтобы не раздувать шум предупреждений).
* По умолчанию диагностические сообщения analyzers имеют уровень `suggestion` (чтобы не тонуть в шуме).
* Для non-UI слоёв (`Core/`, `Bypass/`, `Utils/`, `TestNetworkApp/`, `SmokeLauncher/`) подняты до `warning` ключевые правила стабильности:
    * `CA2000` (dispose объектов)
    * `CA2200` (корректный rethrow)
    * `CA2007` (ConfigureAwait) оставлено как `suggestion` (подсказка, без давления)

Правило декомпозиции (code health):
* Если файл стабильно разрастается до **500–700+ строк**, это сигнал к выносу: сначала `partial` (без изменения публичного API), затем отдельные классы/сервисы.
* Не смешиваем слои: `ViewModels/` не должен накапливать бизнес-логику bypass/диагностики, а `Core/` не должен зависеть от WPF.
* Любое вынесение должно сохранять семантику и не менять поведение (рефакторинг без функциональных правок).

Статус (P0.3): `BypassController` декомпозирован через partial-файлы (без изменения поведения): [ViewModels/BypassController.Internal.cs](ViewModels/BypassController.Internal.cs), [ViewModels/BypassController.Metrics.cs](ViewModels/BypassController.Metrics.cs), [ViewModels/BypassController.Startup.cs](ViewModels/BypassController.Startup.cs), [ViewModels/BypassController.Core.cs](ViewModels/BypassController.Core.cs), [ViewModels/BypassController.DnsDoh.cs](ViewModels/BypassController.DnsDoh.cs), [ViewModels/BypassController.Observability.cs](ViewModels/BypassController.Observability.cs), [ViewModels/BypassController.V2.cs](ViewModels/BypassController.V2.cs).

Статус (P0.3): `DiagnosticOrchestrator` декомпозирован через partial-файлы (без изменения поведения): [ViewModels/DiagnosticOrchestrator.cs](ViewModels/DiagnosticOrchestrator.cs), [ViewModels/DiagnosticOrchestrator.Core.cs](ViewModels/DiagnosticOrchestrator.Core.cs), [ViewModels/DiagnosticOrchestrator.Monitoring.cs](ViewModels/DiagnosticOrchestrator.Monitoring.cs), [ViewModels/DiagnosticOrchestrator.Recommendations.cs](ViewModels/DiagnosticOrchestrator.Recommendations.cs), [ViewModels/DiagnosticOrchestrator.Recommendations.Apply.cs](ViewModels/DiagnosticOrchestrator.Recommendations.Apply.cs), [ViewModels/DiagnosticOrchestrator.System.cs](ViewModels/DiagnosticOrchestrator.System.cs), [ViewModels/DiagnosticOrchestrator.Private.cs](ViewModels/DiagnosticOrchestrator.Private.cs).

UI-гейт по рекомендациям (v2-only): UI принимает рекомендации/стратегии обхода только из строк с префиксом `[V2]`. Любые legacy строки могут присутствовать в логе, но не обновляют `BypassStrategy` карточек и не попадают в панель рекомендаций.

Примечание (UX рекомендаций): блок «Рекомендации» в bypass-панели отображается при `HasAnyRecommendations` (есть v2-рекомендации **или** зафиксированы «ручные действия»), а кнопка apply фактически доступна только при `HasRecommendations` (есть объектный `BypassPlan` и есть что применять). Если стратегия уже включена пользователем вручную, она отображается как «ручное действие», чтобы рекомендации не «пропадали».

Важно: bypass-панель (и кнопка apply внутри неё) показывается только при запуске приложения с правами администратора.

Guard на legacy в v2 пути: smoke-тест `DPI2-025` проверяет, что в v2 runtime-пути отсутствуют `GetSignals(...)`, `legacySignals.*` и любые упоминания `BlockageSignals` (grep/regex по `Core/IntelligenceV2/*` и ключевым runtime-файлам).

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
    *   Практика для QUIC→TCP: при детекте UDP/QUIC блокировки (`UdpInspectionService.OnBlockageDetected`) оркестратор может установить цель outcome (по SNI/DNS кешу, с fallback на IP), чтобы селективный `DropUdp443` не оставался «включён, но без цели».
    *   UX: отдельное оверлей-окно диагностики отключено (не показываем сервисное окно поверх рабочего стола).
*   **`LiveTestingPipeline`**: Асинхронный конвейер на базе `System.Threading.Channels`.
    *   Связывает этапы: Sniffing → Testing → Classification → Reporting.
    *   Использует `UnifiedTrafficFilter` для минимальной валидации (loopback) и правил отображения (не засорять UI «успешными» целями).
    *   Выполняет гейтинг повторных тестов через `IBlockageStateStore.TryBeginHostTest(...)` (кулдаун + лимит попыток), чтобы не спамить сеть, но при этом дать V2 накопить несколько наблюдений (SignalSequence) по проблемным/заблокированным хостам.
    *   Важно: `TrafficCollector` дедупит соединения по `RemoteIp:RemotePort:Protocol`, но в runtime допускает ограниченные «повторные обнаружения» этой же цели с кулдауном/лимитом — иначе ретесты физически не дойдут до pipeline.
    *   Публикует периодический `[PipelineHealth]` лог со счётчиками этапов (enqueue/test/classify/ui), чтобы диагностировать потери данных и «затыки» очередей без привязки к сценариям.
    *   Обеспечивает параллельную обработку множества хостов.
    *   Опционально принимает `AutoHostlistService`: на этапе Classification добавляет кандидатов хостов в авто-hostlist (для отображения в UI и последующего ручного применения). Auto-hostlist питается `InspectionSignalsSnapshot` (v2-only). Дополнительно, если хост стал кандидатом, этот контекст прокидывается в v2 хвост (evidence/notes) как короткая нота `autoHL hits=… score=…`.
    *   v2 UX-гейт: событие `OnV2PlanBuilt` публикуется только для хостов, которые реально прошли фильтр отображения как проблема (`FilterAction.Process`), чтобы кнопка apply не применяла план, сформированный по шумовому/успешному хосту.

Smoke-хелперы (для детерминированных проверок без WinDivert/реальной сети):
* `DnsParserService.TryExtractSniFromTlsClientHelloPayload(...)` — извлечение SNI из TLS payload.
* `DnsParserService.TryFeedTlsClientHelloFragmentForSmoke(...)` — проверка реассемблинга SNI на фрагментах ClientHello.

### 3.2.1 DPI Intelligence v2

Статус: частично реализовано.
* Контрактный слой v2: `Core/IntelligenceV2/Contracts`.
* Step 1 (Signals): в runtime подключён сбор фактов в TTL-store через `SignalsAdapterV2` (в `LiveTestingPipeline`, этап Classification). Факты инспекции снимаются через `IInspectionSignalsProvider` в виде `InspectionSignalsSnapshot` (v2-only).
    * Гейтинг тестов по цели: `InMemoryBlockageStateStore.TryBeginHostTest(...)` использует кулдаун и лимит попыток, чтобы не спамить сеть, но при этом дать V2 накопить несколько наблюдений (SignalSequence) по проблемным/заблокированным хостам.
* Step 2 (Diagnosis): в runtime подключена постановка диагноза через `StandardDiagnosisEngineV2` по агрегированному срезу `BlockageSignalsV2`.
* Step 3 (Selector/Plan): в runtime подключён `StandardStrategySelectorV2`, который строит `BypassPlan` строго по `DiagnosisResult` (id + confidence) и отдаёт краткую рекомендацию для UI (без auto-apply).
    * План может содержать `DeferredStrategies` — отложенные техники (если появляются новые/экспериментальные стратегии). В текущем состоянии Phase 3 стратегии `HttpHostTricks`, `QuicObfuscation` и `BadChecksum` считаются **implemented** и попадают в `plan.Strategies`.
* Step 4 (ExecutorMvp): добавлен `Core/IntelligenceV2/Execution/BypassExecutorMvp.cs` — **только** форматирование/логирование (диагноз + уверенность + короткое объяснение + список стратегий), без вызова `TrafficEngine`/`BypassController` и без авто-применения.
* Ручное применение v2 плана (без auto-apply): `LiveTestingPipeline` публикует объектный `BypassPlan` через событие `OnV2PlanBuilt`, `DiagnosticOrchestrator` хранит последний план и применяет его только по клику пользователя через `BypassController.ApplyV2PlanAsync(...)` (таймаут/отмена/безопасный откат).
    * Защита от устаревшего плана: `DiagnosticOrchestrator.ApplyRecommendationsAsync(...)` применяет план только если `planHostKey` совпадает с последней v2-целью, извлечённой из UI‑диагноза (иначе — SKIP в лог).
    * Гибридный доменный режим (MVP, общий): `TestResultsManager` использует анализатор доменных семейств (без хардкода CDN), чтобы на лету замечать домены с большим числом вариативных подхостов (типичный кейс: CDN/шардинг).
        * При достаточных наблюдениях UI может схлопывать карточки подхостов в одну доменную карточку (ключ = доменный суффикс).
        * В панели рекомендаций появляется отдельная кнопка «Подключить (домен: <suffix>)».
        * Команда вызывает `DiagnosticOrchestrator.ApplyRecommendationsForDomainAsync(..., suffix)`, который выбирает применимый v2-план из подхостов, но выставляет `OutcomeTargetHost = suffix`.
        * Каталог доменов хранится во внешнем JSON (`%LocalAppData%\ISP_Audit\domain_families.json`): можно вручную закреплять домены (pinned), а также смотреть/использовать автоматически выученные (learned).
        * Это **не** wildcard-мэтчинг в `BypassFilter`: домен используется как UX-цель/цель outcome (и как вход для резолва IP в селективном `DropUdp443`).
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
 - Phase 3 стратегии:
     - `QuicObfuscation` реализована как включение `DropUdp443` (чтобы клиент ушёл с QUIC/HTTP3 на TCP/HTTPS).
     - `HttpHostTricks` реализована в `BypassFilter` для исходящего HTTP (TCP/80): разрезает заголовок `Host:` на два TCP сегмента и дропает оригинальный пакет.
     - `BadChecksum` реализована для фейковых TCP пакетов: инжект выполняется через расширенный send-путь без пересчёта checksum и со сбросом checksum-флагов адреса.
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
* `SignalsAdapterV2.BuildSnapshot(...)` извлекает `RstIpIdDelta` из `InspectionSignalsSnapshot.SuspiciousRstDetails` (формат `IPID=.. (обычный=min-max, last=..)` / `expected ...`).
* `SuspiciousRstCount` — число событий `SuspiciousRstObserved` в окне агрегации (если событие есть только в «последнем снимке», фолбэк даёт минимум 1).
* `RstLatency` берётся как приближённая метрика из `HostTested.TcpLatencyMs` для случая `TCP_CONNECTION_RESET`.
* `StandardDiagnosisEngineV2` использует эти поля, чтобы выдавать `ActiveDpiEdge` (быстрый RST) или `StatefulDpi` (медленный RST) вместо `Unknown`, но только при «устойчивых уликах» (`SuspiciousRstCount >= 2`).

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
* `LiveTestingPipeline.ClassifierWorker`: v2-ветка вызывает `SignalsAdapterV2.Observe(...)` с `InspectionSignalsSnapshot` (из `IInspectionSignalsProvider`, с фолбэком `Empty`).
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
    *   Дополнительно реализует `IInspectionSignalsProvider`, чтобы v2-контур мог снимать инспекционные факты без legacy типов.

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
    *   Важно (стабильность): SNI-кеш ведётся по принципу **first-wins**, чтобы результат тестов не «плавал» (youtube.com → youtube-ui.l.google.com → …) из-за гонок. Разрешена замена только в случае **шум → не шум** по `NoiseHostFilter`.
4.  **Фильтрация (Filter)**: `UnifiedTrafficFilter` отбрасывает только заведомо нерелевантное (loopback).
5.  **Очередь (Queue)**: Хост попадает в входную очередь `LiveTestingPipeline`.
6.  **Валидация (Validate)**: Хост проверяется тестером (DNS/TCP/TLS) без pre-check фильтрации «шума», чтобы не терять сигнал на браузерных/CDN-сценариях.
7.  **Тестирование (Test)**: `StandardHostTester` забирает хост из очереди и проводит серию тестов (DNS, TCP, TLS).
    *   Примечание (VPN): при `BypassController.IsVpnDetected=true` оркестратор увеличивает `PipelineConfig.TestTimeout`, чтобы снизить случайные TCP/TLS таймауты на VPN и сделать результаты более повторяемыми.
8.  **Инспекция (Inspect)**: Параллельно `RstInspectionService` и другие сервисы следят за пакетами этого соединения.
9.  **Агрегация (Aggregate)**: Результаты тестов и инспекций собираются в `HostTested` модель.
10. **Классификация (Classify)**: `StandardBlockageClassifier` выносит вердикт (например, `DPI_REDIRECT`).
11. **Отчет (Report)**: Результат отправляется в UI через `TestResultsManager`.
    *   Примечание: `NoiseHostFilter` используется на этапе отображения, чтобы не засорять UI «успешными» результатами (Status OK), но не скрывать реальные проблемы.
12. **Реакция (React)**: Если включен авто-обход, `DiagnosticOrchestrator` включает преемптивный TLS bypass через `BypassController.TlsService.ApplyPreemptiveAsync` (обычно `TLS_DISORDER + DROP_RST`); сам `TlsBypassService` регистрирует/удаляет `BypassFilter` в `TrafficEngine` и через события отдаёт план/метрики/вердикт в UI и оркестратору.
    *   Примечание (практика): после ручного `Apply` в UI запускается короткий **пост-Apply ретест** (чтобы быстро увидеть эффект), а также доступна кнопка **«Рестарт коннекта»** — кратковременный drop трафика к целевым IP:443, чтобы приложение переподключилось уже под новым режимом.

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
│   ├── DiagnosticOrchestrator.*.cs
│   ├── BypassController.*.cs
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
