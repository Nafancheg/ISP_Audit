# Полный аудит репозитория ISP_Audit v2

**Дата**: 09.12.2025 (обновлено 10.12.2025, 17.12.2025)
**Версия проекта**: .NET 9, WPF
**Режим**: GUI-only (WinExe)

Дополнение (draft, 13.01.2026): архитектурные заметки по модели «сетевого портрета приложения» и контролю blast radius для QUIC→TCP и других “тяжёлых” мер — `docs/network_portrait_architecture.md`.

Дополнение (13.01.2026): UI упрощён — левая панель управления переведена в drawer (с PIN), таблица результатов сведена к 4 колонкам, детали открываются по double-click по строке.

---

## 1. Карта зависимостей проекта

### 1.1 Архитектура верхнего уровня

```
┌─────────────────────────────────────────────────────────────────┐
│                        ТОЧКА ВХОДА                               │
│                       Program.cs                                 │
│              ↓ Config.SetActiveProfile("Default")               │
│              ↓ new App().Run()                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     UI LAYER (WPF)                              │
│  App.xaml → MainWindow.xaml → MainViewModelRefactored           │
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
│  ├── Core/IntelligenceV2/Diagnosis/StandardDiagnosisEngineV2     │
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

Актуализация (Runtime, 26.12.2025): принудительный откат с QUIC на TCP для v2
- TLS-обход в `BypassFilter` применим только к TCP-трафику (ClientHello на 443). YouTube и многие сайты по умолчанию используют QUIC/HTTP3 (UDP/443), поэтому «TLS стратегии включены, а сайт не оживает» может быть просто тем, что трафик не TCP. Для этого есть явный флаг `DropUdp443` (тумблер `QUIC→TCP`), который принудительно переводит клиент на TCP/HTTPS.
- `DropUdp443` поддерживает 2 режима подавления UDP/443:
    - **Селективно (по цели)**: подавление по observed IPv4 адресам цели. `BypassStateManager` держит кэш IP цели с TTL/cap (cold-start через DNS resolve host) и прокидывает его в `TlsBypassService`, а `BypassFilter` увеличивает `Udp443Dropped++` и дропает UDP/443 только к этим IP. Поведение не привязано к названию пресета фрагментации.
    - **Глобально (DropUdp443Global)**: подавляется весь UDP/443 без привязки к цели. Режим более агрессивный и может затронуть приложения, использующие QUIC/HTTP3.
- Важно: селективный `DropUdp443` требует **цели** (host). В рантайме цель может выставляться из последнего v2 плана (manual apply), а также дополняться оркестратором по событию UDP блокировки (по SNI/DNS кешу, с fallback на IP), чтобы избежать сценария «QUIC→TCP включён, но UDP/443 не глушится из-за пустой цели».
- Практика (стабильность SNI): SNI-кеш по IP ведётся по принципу **first-wins**, чтобы результаты не «плавали» между прогонами из-за смены SNI для одного IP. Разрешена замена только для случая **шум → не шум** (через `NoiseHostFilter`).
- Метрика `Udp443Dropped` отображается в bypass-панели и помогает однозначно проверить, что QUIC действительно глушится.
- Дополнительно есть явный assist-флаг `AllowNoSni` (тумблер `No SNI`): разрешает применять TLS-обход даже при отсутствии распознанного SNI (ECH/ESNI/фрагментация ClientHello).
- В v2 контуре эти assist-флаги могут попадать в рекомендацию как токены `DROP_UDP_443` / `ALLOW_NO_SNI` и применяются при ручном `ApplyV2PlanAsync`.

Практика (после Apply):
- После ручного `Apply` UI запускает короткий **пост-Apply ретест** по цели (активные TCP/TLS проверки), чтобы быстро показать, помог ли обход.
- Дополнительно есть кнопка **«Рестарт коннекта»**: кратковременно дропает трафик к целевым IP:443, чтобы приложение инициировало новое соединение уже под применённым bypass.

Целевое направление (Design target, 15.01.2026):
- Принята модель **Accumulative Attachment Model**: «Группа целей = одна конфигурация обхода» (YouTube/Steam/… состоят из нескольких доменов, которые должны работать одновременно).
- «Применение обхода» оформляется как транзакция с полным снимком: GroupKey + инициатор (карточка/hostKey) + EffectiveGroupConfig (что применили) + Contributions (вклады карточек) + endpoint-ы + assist-флаги/режимы/фильтры.
- UI показывает не только факт применения, но и **состав активной конфигурации группы** (какие карточки участвуют и какой итоговый режим реально активен), чтобы исключить ощущение «переключателя между карточками».
- Действия и статусы (применение/ретест/переподключение) переносятся в сами карточки и работают во время диагностики.

UX: режим `QUIC→TCP` выбирается через контекстное меню на тумблере (`Селективно (по цели)` / `Глобально (весь UDP/443)`).

Актуализация (Design Phase, 16.12.2025):
- Введён дизайн-план “DPI Intelligence v2” в docs/phase2_plan.md: слой между диагностикой и обходом.
- Ключевое отличие: сигналы рассматриваются как **цепочки событий во времени** (не разовый снимок), правила диагнозов внедряются поэтапно (сначала только по доступным данным).
- В MVP запрещён auto-apply: допускается только ручное применение рекомендаций пользователем.

Актуализация (Runtime, 16.12.2025):
- Step 1 v2 Signals подключён: `SignalsAdapterV2` пишет события в `InMemorySignalSequenceStore` на этапе Classification в `LiveTestingPipeline`. Инспекционные факты берутся через `IInspectionSignalsProvider` в виде `InspectionSignalsSnapshot` (v2-only, без legacy типов).
    - Есть защиты от роста памяти: debounce одинаковых событий и cap числа событий на HostKey (in-memory store).
    - Политика DoH в v2 рекомендациях: DoH рекомендуется как low-risk при `DnsHijack` (чисто DNS) и также используется в multi-layer сценариях.
- Step 2 v2 Diagnosis подключён: `StandardDiagnosisEngineV2` ставит диагноз по `BlockageSignalsV2` и возвращает пояснения, основанные на фактах (DNS fail, TCP/TLS timeout, TLS auth failure, retx-rate, HTTP redirect, RST TTL/IPID delta + latency) без привязки к стратегиям/обходу. Для RST-кейсов DPI-id (`ActiveDpiEdge/StatefulDpi`) выдаётся только при устойчивости улик (`SuspiciousRstCount >= 2`), чтобы не создавать ложную уверенность по единичному событию. Для TLS-only кейсов добавлен консервативный диагноз `TlsInterference`, чтобы селектор мог сформировать план TLS-стратегий.
- Step 3 v2 Selector подключён: `StandardStrategySelectorV2` строит `BypassPlan` строго по `DiagnosisResult` (id + confidence) и отдаёт краткую рекомендацию для UI-лога (без auto-apply).
    - План может включать `DeferredStrategies` — отложенные техники (если появляются новые/экспериментальные стратегии). В текущем состоянии Phase 3 стратегии `HttpHostTricks`, `QuicObfuscation` и `BadChecksum` считаются implemented: попадают в `plan.Strategies` и реально применяются при ручном `ApplyV2PlanAsync`.
    - Реализация Phase 3 в рантайме:
        - `QuicObfuscation` → включает assist-флаг `DropUdp443` (QUIC→TCP fallback).
        - `HttpHostTricks` → `BypassFilter` режет HTTP `Host:` по границе TCP сегментов (исходящий TCP/80) и дропает оригинал.
        - `BadChecksum` → для фейковых TCP пакетов используется расширенный send без пересчёта checksum и со сбросом checksum-флагов адреса.
- Step 4 v2 Executor (MVP) подключён: `BypassExecutorMvp` формирует компактный, читаемый пользователем вывод (диагноз + уверенность + 1 короткое объяснение + список стратегий) и **не** применяет обход.
- Реальный executor v2 (ручной apply, без auto-apply): `LiveTestingPipeline` публикует объектный `BypassPlan` через `OnV2PlanBuilt`, `DiagnosticOrchestrator` хранит последний план и применяет его только по клику пользователя через `BypassController.ApplyV2PlanAsync(...)` (таймаут/отмена/безопасный откат).
- UX-гейт для корректности: `OnV2PlanBuilt` публикуется только для хостов, которые реально прошли фильтр отображения как проблема (попали в UI как issue), чтобы кнопка apply не применяла план, построенный по шумовому/успешному хосту.

Актуализация (Runtime, 29.12.2025): Bypass State Manager (2.V2.12)
- Введён `BypassStateManager` как single source of truth для управления `TrafficEngine` и `TlsBypassService`.
- Добавлен fail-safe слой (Lite Watchdog + crash recovery): журнал сессии bypass + авто-Disable при некорректном завершении/пропаже heartbeat.
- Добавлена Activation Detection (по метрикам): статус `ENGINE_DEAD/NOT_ACTIVATED/ACTIVATED/NO_TRAFFIC/UNKNOWN` для наблюдаемости.
- Добавлен Outcome Check для HTTPS: `SUCCESS/FAILED/UNKNOWN` через tagged outcome-probe (активная TCP+TLS+HTTP проверка цели), probe исключается из пользовательских метрик (smoke gate: `DPI2-029`).
- P0.6 Смена сети: при системном событии смены сети UI показывает уведомление «Проверить/Отключить/Игнорировать». «Проверить» запускает staged revalidation (Activation → Outcome) и затем предлагает запустить полную диагностику (без auto-apply; smoke gate: `UI-013`).
- Важное UX/безопасность: при закрытии приложения выполняется shutdown без «хвостов»: диагностика отменяется, bypass выключается, а DNS/DoH восстанавливаются (если были включены через `FixService` и существует backup в `%LocalAppData%\ISP_Audit\dns_backup.json`). Fail-safe: если backup отсутствует, но активен один из пресетов DNS, управляемых приложением (например, 1.1.1.1), `FixService` выполняет fallback-возврат DNS в автоматический режим.
- Гарантия отката: `App.OnExit` синхронно дожидается полного `ShutdownAsync`, чтобы откат DNS/DoH успел завершиться до завершения процесса.
- Crash-recovery: при старте, если обнаружен backup от прошлой незавершённой сессии, выполняется попытка восстановления DNS.
- Safety gate: `FixService` не применяет DNS/DoH, если не удалось успешно записать backup-файл на диск (иначе откат после падения был бы невозможен).
- UX: отдельное overlay-окно диагностики отключено (не показываем сервисное окно поверх рабочего стола).
- `BypassController` и `DiagnosticOrchestrator` используют один экземпляр менеджера, чтобы исключить гонки Apply/Disable и рассинхронизацию фильтров/engine.
- Добавлен guard: прямые вызовы методов `TrafficEngine`/`TlsBypassService` вне manager-scope логируются (и могут быть зафиксированы smoke-гейтами).


Актуализация (Runtime, 23.12.2025): контроль применения v2
- `Cancel` отменяет не только диагностику, но и ручное применение рекомендаций (отдельный CTS для apply).
- Защита от устаревшего плана: apply пропускается, если `planHostKey` не совпадает с последней v2‑целью, извлечённой из текста v2‑диагноза в UI.
- UX-гейт кнопки apply: блок «Рекомендации» отображается при `HasAnyRecommendations`, но команда apply активна только при `HasRecommendations` (есть план и есть что применять). Если пользователь уже включил стратегию вручную, она показывается как «ручное действие», чтобы рекомендации не исчезали.
- Важно: bypass-панель в UI скрыта без прав администратора, поэтому кнопка apply также недоступна без elevation.
- Ручной apply поддерживает `AggressiveFragment`: выбирается пресет фрагментации «Агрессивный» и включается `AutoAdjustAggressive`.
- Ручной apply поддерживает параметры `TlsFragment` (например, `TlsFragmentSizes`, `PresetName`, `AutoAdjustAggressive`); парсинг вынесен в `Core/IntelligenceV2/Execution/TlsFragmentPlanParamsParser.cs`.
- Добавлен smoke-тест `DPI2-022`: параметры `TlsFragment` влияют на пресет и флаг `AutoAdjustAggressive`.
- Детерминизм: `StandardStrategySelectorV2` задаёт `TlsFragmentSizes` в `BypassPlan` (иначе executor зависел бы от текущего выбранного пресета пользователя).
- Добавлен smoke-тест `DPI2-023`: селектор v2 кладёт `TlsFragmentSizes` в план.
- Добавлен smoke-тест `DPI2-024`: e2e проверка `selector → plan → ApplyV2PlanAsync` (manual apply использует параметры плана детерминированно).
- Для контроля Gate 1→2 в UI-логе используются строки с префиксом `[V2][GATE1]` (не чаще 1 раза в минуту на HostKey).

Актуализация (Runtime, 13.01.2026): гибридный доменный UX (общий) + внешний справочник
- Боль (типичный кейс: YouTube/CDN): сервис «лечится» через множество подхостов, поэтому ручной apply по одному хосту создаёт UX-хаос (много карточек/целей).
- Добавлен общий механизм «доменных семейств» (без хардкода конкретных CDN): UI на лету замечает домены, у которых появляется много вариативных подхостов, и может предложить доменную цель (suffix).
- Доменное применение выполняется через `DiagnosticOrchestrator.ApplyRecommendationsForDomainAsync(..., suffix)`: метод выбирает применимый v2-план из подхостов, но выставляет `OutcomeTargetHost` на домен.
- Внешний каталог доменов: `%LocalAppData%\ISP_Audit\domain_families.json`.
    - `PinnedDomains`: ручной «справочник» (можно закреплять домены, чтобы подсказка включалась быстрее).
    - `LearnedDomains`: автокэш доменов, которые система «выучила» по наблюдениям.
- Важно: это не wildcard-мэтчинг в `BypassFilter` (фильтры по доменам не поддерживаются напрямую); домен используется как UX-цель/цель outcome и как вход для резолва IP в селективном `DropUdp443`.

---

## Навигация по состоянию v2 (As‑Is / Target / Roadmap)

Чтобы не терять контроль над направлением разработки, фиксируем три вещи:

### As‑Is (реально есть в репозитории)
- v2 контур подключён в рантайм: Signals → Diagnosis → Selector → Plan.
- Auto-apply запрещён: применяется только по ручному действию пользователя (manual apply).
- Реальный apply v2 реализован в `BypassController.ApplyV2PlanAsync(...)`: таймаут/отмена + безопасный rollback.
- Feedback store (MVP) реализован и может влиять на ранжирование в `StandardStrategySelectorV2`.

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

Актуализация (Dev, 12.01.2026): базовые analyzers/линт для стабильности
- Добавлены `Directory.Build.props` и `.editorconfig`.
- Включены встроенные .NET analyzers (`EnableNETAnalyzers=true`) без форсирования `AnalysisMode/AnalysisLevel` (оставляем дефолты SDK, чтобы не раздувать шум предупреждений).
- По умолчанию analyzers выставлены как `suggestion` (минимум шума).
- Для non-UI слоёв подняты до `warning` ключевые правила стабильности: `CA2000` (dispose) и `CA2200` (rethrow). `CA2007` (ConfigureAwait) оставлено как `suggestion`.

Актуализация (Dev, 15.01.2026): правило декомпозиции и старт P0.3
- Практическое правило сопровождения: при росте файла до 500–700+ строк делаем вынос (сначала `partial`, потом отдельные сервисы), чтобы не смешивать слои и упростить поддержку.
- Старт P0.3: `BypassController` вынесен в partial-файлы (без изменения поведения): `ViewModels/BypassController.*.cs` (Internal/Metrics/Startup/Core/DnsDoh/Observability/V2).
- P0.3 (продолжение): `DiagnosticOrchestrator` вынесен в partial-файлы (без изменения поведения): `ViewModels/DiagnosticOrchestrator.*.cs` (Core/Private + базовый файл).

Актуализация (Runtime, 17.12.2025):
- Добавлен `Core/Diagnostics/BlockageCode.cs` — единая точка нормализации кодов проблем (`BlockageType`) и поддержки legacy алиасов.
- В местах, где раньше сравнивались строки (`TLS_DPI`, `TCP_TIMEOUT`, `TCP_RST`, `TLS_TIMEOUT` и др.), используется `BlockageCode.Normalize/ContainsCode`, чтобы алиасы не расползались по слоям (UI/legacy/v2).
- Добавлен `Core/Diagnostics/PipelineContract.cs` — единая точка контрактных строк пайплайна (`BypassNone`/`BypassUnknown`) вместо «магических» `"NONE"`/`"UNKNOWN"` в слоях legacy/v2/UI.
- Добавлен периодический health-лог пайплайна (`[PipelineHealth] ...`) с агрегированными счётчиками этапов (enqueue/test/classify/ui) для диагностики потерь данных и узких мест (рост очередей, drop в bounded channels, несходимость enq/deq).
- Уточнено правило noise-фильтрации: `NoiseHostFilter` не должен отбрасывать исходные сигналы (включая SNI) до тестирования/диагностики; «noise» применяется только как правило отображения успешных (OK) результатов, чтобы не терять потенциально важные факты.

Маркер (как отличить v2-вывод от legacy): строки рекомендаций v2 начинаются с префикса `[V2]`.

Жёсткие защиты селектора (MVP):
- `confidence < 50` → пустой план.
- `RiskLevel.High` запрещён при `confidence < 70`.
- Нереализованные стратегии: warning + skip (без исключений), без падения пайплайна.

Актуализация (Dev, 22.12.2025): feedback store + ранжирование в StrategySelector
- Добавлен `Core/IntelligenceV2/Feedback/*`: MVP-хранилище обратной связи (in-memory) + опциональная файловая реализация `JsonFileFeedbackStoreV2`.
- `StandardStrategySelectorV2` умеет (опционально) добавлять вес по успешности **поверх** hardcoded `BasePriority`.
- Gate: при отсутствии данных поведение полностью как раньше; одинаковый вход + одинаковый feedback → одинаковый план.

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
    - gate B5: legacy строки рекомендаций не меняют `BypassStrategy`, v2 строки с префиксом `[V2]` — меняют.

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

Актуализация (Dev, 18.12.2025): реализованы smoke-тесты DPI Intelligence v2 (категория `dpi2`)
- Добавлен файл `TestNetworkApp/Smoke/SmokeTests.Dpi2.cs` и регистрации в реестре.
- Покрыты тесты `DPI2-001..013`: адаптация legacy сигналов в TTL-store, TTL-очистка при `Append`, агрегация по окнам 30/60 секунд, DiagnosisEngine (фактологическое объяснение без упоминания стратегий), Gate-маркеры `[V2][GATE1]`, правила StrategySelector (confidence/risk/unimplemented warning+skip), Executor MVP (компактный 1-строчный вывод с префиксом `[V2]` и без auto-apply).

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
| `MainViewModelRefactored` | 1 (MainWindow) | 3 (Bypass, Orchestrator, Results) | **Координатор UI** |
| `DiagnosticOrchestrator` | 1 | 12+ | **Центральный оркестратор** |
| `TrafficEngine` | 4 | 3 | **WinDivert менеджер** |
| `LiveTestingPipeline` | 1 | 6 | **Pipeline обработки** |
| `Config` | 10+ | 2 | **Глобальная конфигурация** |
| `NoiseHostFilter` | 5 | 0 | **Singleton фильтр** |

### 1.3 Скрытые/глобальные зависимости

| Глобальный элемент | Используется в | Риск |
|-------------------|----------------|------|
| `NoiseHostFilter.Instance` | TrafficCollector, TestResultsManager, LiveTestingPipeline | Singleton, сложно тестировать |
| `Program.Targets` | Config.SetActiveProfile | Статический словарь целей |
| `FixService` (файлы бэкапа) | BypassController | Состояние на диске |
| `Config.ActiveProfile` | Многие компоненты | Статическое свойство |

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
| Глобальное состояние | `Program.Targets`, `Config.ActiveProfile`, `NoiseHostFilter.Instance` |
| Дублирование моделей | `Target` (Models/), `TargetDefinition` (root), `Target` (ISPAudit.Models) |

### 3.4 Требуют рефакторинга

| Файл | Приоритет | Причина |
|------|-----------|---------|
| `ViewModels/DiagnosticOrchestrator.*.cs` | 🔴 Высокий | Уже разбит на `partial`; следующий шаг — выделить мониторинг/рекомендации/управление процессом в отдельные сервисы |
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

> ✅ `ARCHITECTURE_V2.md` удалён (10.12.2025), актуальный — `ARCHITECTURE_CURRENT.md`

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
└── Config.SetActiveProfile
    └── DiagnosticProfile (Profiles/Default.json)
└── App.xaml
    └── MainWindow.xaml
        └── MainViewModelRefactored
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
- Config.ActiveProfile (static)
- Program.Targets (static)
- NoiseHostFilter.Instance (singleton)

Примечание (16.12.2025):
- Добавлен контрактный слой DPI Intelligence v2: `Core/IntelligenceV2/Contracts` (модели Signals/Diagnosis/Strategy).
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
    - Проверено соответствие диаграммы коду (`MainViewModelRefactored`, `DiagnosticOrchestrator`, `LiveTestingPipeline`).
- [x] Унификация пространств имен (Namespaces):
    - Приведено к единому стилю (выбран `IspAudit`).

---

## 11. Обновления TLS bypass (12.12.2025)

- **Архитектура**: `TlsBypassService` — единый источник опций/пресетов, сам регистрирует `BypassFilter`, публикует `MetricsUpdated/VerdictChanged/StateChanged`; `BypassController` стал прокси без таймера (тумблеры + сохранение пресета/автокоррекции).
- **Профиль**: `bypass_profile.json` расширен TTL-настройками (`ttlTrick`/`ttlTrickValue`) и флагом `autoTtl`; сохранение пресета в UI обновляет только поля фрагментации (чтобы не перетирать TTL/redirect rules).
- **AutoTTL**: при включенном `autoTtl` сервис перебирает небольшой набор TTL (2..8) по метрикам bypass и сохраняет лучший TTL обратно в `bypass_profile.json`.
- **Auto-hostlist (кандидаты)**: добавлен `AutoHostlistService`; `LiveTestingPipeline` на этапе классификации передаёт `InspectionSignalsSnapshot` (ретрансмиссии/HTTP-редиректы/RST/UDP) только если Auto-hostlist включён, и пополняет список кандидатов, который показывается в UI (включается/выключается тумблером). Дополнительно, если текущий хост стал кандидатом, контекст auto-hostlist прокидывается в v2 хвост (evidence/notes) как короткая нота `autoHL hits=… score=…` для UI/QA. Legacy `BlockageSignals` при этом не читаются.
- **Метрики**: сервис считает ClientHello (все/короткие/не 443), фрагментации, релевантные RST, план фрагментов, активный пресет, порог и минимальный чанк, время начала; UI читает только события сервиса (план + таймстамп в badge).
- **Вердикты/UX**: добавлены статусы «нет TLS 443», «TLS не на 443», «ClientHello короче threshold», «обход активен, но не применён», «мало данных»; карточка не шумит на серые статусы, tooltip даёт next steps (снизить threshold/сменить пресет/включить Drop RST).
- **Автокоррекция**: флаг `AutoAdjustAggressive` (только пресет «Агрессивный»); ранний всплеск RST -> минимальный чанк=4; зелёный >30с -> лёгкое усиление (не ниже 4); переприменение опций делает сервис.
- **Риски/пробелы**: нет unit-тестов на `TlsBypassService`/вердикты; таймер метрик 2с может лагать в UI; авто-коррекция не сбрасывает флаг при смене пресета (пока пользователь не переключит); обход не применяется к ClientHello без SNI или не на 443; preemptive режим зависит от успешного старта `TrafficEngine`.
- **Примечание (SNI vs bypass)**: `TrafficMonitorFilter` должен обрабатывать пакет до `BypassFilter`, чтобы парсер SNI видел исходный (нефрагментированный/непереставленный) ClientHello; для естественной TCP-сегментации ClientHello в `DnsParserService` используется минимальный реассемблинг первых байт потока.
- **Примечание (SNI vs PID)**: WinDivert Network Layer не даёт PID, поэтому оркестратор гейтит SNI-триггеры через корреляцию remote endpoint → PID по событиям `ConnectionMonitorService` и списку `PidTrackerService.TrackedPids`. Для Steam/attach есть короткий буфер (несколько секунд), чтобы SNI, пришедший до появления PID, мог быть обработан позже.
- **UX-фидбек**: статус auto-bypass и вердикт сервиса показываются в оркестраторе; карточка окрашивается по цвету вердикта (зелёный не считается проблемой); badge включает план фрагментации + активный пресет.
