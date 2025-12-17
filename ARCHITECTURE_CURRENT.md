# ISP_Audit — Архитектура (v3.0 Extended)

**Дата обновления:** 17.12.2025
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
        BypassCtrl --> TlsSvc[TlsBypassService]
        TlsSvc --> TrafficEngine[TrafficEngine]
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
    *   Связывает UI-тумблеры (Fragment/Disorder/Fake/Drop RST/DoH) с `TlsBypassService` (регистрация фильтра управляется сервисом).
    *   Восстанавливает пресет/автокоррекцию из `bypass_profile.json`, но сами опции включаются вручную или через auto-bypass; сохраняет выбранный пресет обратно в профиль, обновляя только поля фрагментации (без перезаписи TTL/redirect rules).
    *   Пресеты фрагментации (стандарт/умеренный/агрессивный/профиль) и логика автокоррекции живут в сервисе, контроллер лишь проксирует выбор без собственного таймера.
    *   Метрики/вердикт приходят из событий `TlsBypassService` (`MetricsUpdated/VerdictChanged/StateChanged`): UI показывает план фрагментации, таймстамп начала метрик, активный пресет/мин. чанк и не подсвечивает карточку при серых статусах «нет данных/не 443».
*   **`TestResultsManager`**: Управляет коллекцией результатов (`ObservableCollection<TestResult>`). Отвечает за обновление UI в потоке диспетчера.

### 3.2 Orchestration Layer

*   **`DiagnosticOrchestrator`**: "Дирижер" всего процесса.
    *   Запускает и останавливает `LiveTestingPipeline`.
    *   Управляет жизненным циклом фоновых сервисов (`TrafficEngine`, `ConnectionMonitor`).
    *   Следит за целевыми процессами (если задан фильтр по PID).
    *   Важное правило: события SNI из `DnsParserService` **гейтятся по PID**. Так как WinDivert Network Layer не предоставляет PID, оркестратор сопоставляет SNI с событиями соединений `ConnectionMonitorService` (remote endpoint → PID) и пропускает в пайплайн только то, что относится к `PidTrackerService.TrackedPids`.
        *   Для Steam/attach поддерживается короткий буфер (несколько секунд), чтобы не терять ранний SNI до появления PID.
*   **`LiveTestingPipeline`**: Асинхронный конвейер на базе `System.Threading.Channels`.
    *   Связывает этапы: Sniffing → Testing → Classification → Reporting.
    *   Использует `UnifiedTrafficFilter` для валидации, дедупликации и фильтрации шума.
    *   Обеспечивает параллельную обработку множества хостов.
    *   Опционально принимает `AutoHostlistService`: на этапе Classification считывает `BlockageSignals` из `InMemoryBlockageStateStore` и добавляет кандидатов хостов в авто-hostlist (для отображения в UI и последующего ручного применения).

### 3.2.1 DPI Intelligence v2

Статус: частично реализовано.
* Контрактный слой v2: `Core/IntelligenceV2/Contracts`.
* Step 1 (Signals): в runtime подключён сбор фактов в TTL-store через `SignalsAdapterV2` (в `LiveTestingPipeline`, этап Classification).
* Step 2 (Diagnosis): в runtime подключена постановка диагноза через `StandardDiagnosisEngineV2` по агрегированному срезу `BlockageSignalsV2`.
* Step 3 (Selector/Plan): в runtime подключён `StandardStrategySelectorV2`, который строит `BypassPlan` строго по `DiagnosisResult` (id + confidence) и отдаёт краткую рекомендацию для UI (без auto-apply).
* Step 4 (ExecutorMvp): добавлен `Core/IntelligenceV2/Execution/BypassExecutorMvp.cs` — **только** форматирование/логирование (диагноз + уверенность + короткое объяснение + список стратегий), без вызова `TrafficEngine`/`BypassController` и без авто-применения.

Ограничение (важно): Diagnosis Engine v2 **не знает** про стратегии/обход (нет ссылок на StrategyId/Bypass/TlsBypassService/параметры) и формирует пояснения только из наблюдаемых фактов (timeout, DNS fail, retx-rate, HTTP redirect).

Ключевые принципы:
*   Между диагностикой и обходом добавляется слой “интеллекта” (Signals → Diagnosis → Selector → Plan).
*   Signals в v2 строятся как **временные цепочки событий** (SignalEvent/SignalSequence), а агрегированные признаки считаются поверх окна.
*   В MVP запрещён auto-apply: применение обхода остаётся **только ручным действием пользователя** (one-click apply допустим).

Жёсткие защиты селектора (зафиксировано в коде):
*   `confidence < 50` → пустой план.
*   `RiskLevel.High` запрещён при `confidence < 70`.
*   Нереализованные стратегии не ломают пайплайн: выводится warning и стратегия пропускается.

Контрактные константы v2 (зафиксировано в коде):
*   Окно агрегации: 30 секунд (default) и 60 секунд (extended).
*   TTL событий: 10 минут (очистка должна выполняться при Append в сторе).

Точки интеграции (на текущий момент):
* `LiveTestingPipeline.ClassifierWorker`: после снятия legacy `BlockageSignals` вызывается `SignalsAdapterV2.Observe(...)`.
* Затем строится `BlockageSignalsV2` (агрегация по окну) и вызывается `StandardDiagnosisEngineV2.Diagnose(...)`. Результат используется для формирования компактного «хвоста фактов» в UI-логе.
* Затем вызывается `StandardStrategySelectorV2.Select(diagnosis, ...)`, а Step 4 формирует компактный пользовательский вывод (1–2 строки на хост, без спама) и список стратегий для панели рекомендаций.
* Для ручной проверки Gate 1→2 в UI-логе используются строки с префиксом `[V2][GATE1]`.

Маркер v2-вывода (как отличить от legacy): все строки рекомендаций v2 начинаются с префикса `[V2]`.

### 3.3 Core Modules (`IspAudit.Core`)

*   **`BlockageCode` (`Core/Diagnostics/BlockageCode.cs`)**:
    *   Единая точка нормализации кодов проблем (`BlockageType`): канонические «фактовые» коды + legacy алиасы.
    *   Используется в legacy (например, `StandardBlockageClassifier`, `StrategyMapping`, UI-парсинг) и в v2 (`SignalsAdapterV2`), чтобы алиасы не «размазывались» по слоям.

*   **`TrafficCollector` (`Utils/TrafficCollector.cs`)**:
    *   Слушает события от `ConnectionMonitorService` (который управляется `DiagnosticOrchestrator`).
    *   Фильтрует трафик по PID целевого процесса (через `PidTrackerService`).
    *   До логирования/попадания в UI применяет `UnifiedTrafficFilter` (loopback, шум, дедупликация), чтобы не создавать «вечные» карточки для отброшенных целей.
    *   Передает уникальные `(IP, Hostname)` в пайплайн.
    *   В UI и сообщениях пайплайна ключом для карточек считается **IP** (стабильная идентичность); дополнительные варианты имени (SNI / reverse DNS) передаются отдельно.
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
    *   Уведомляет инспекционные сервисы о новых событиях.

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
4.  **Фильтрация (Filter)**: `NoiseHostFilter` проверяет, не является ли хост "шумом" (Microsoft, Google Update).
5.  **Очередь (Queue)**: Хост попадает в входную очередь `LiveTestingPipeline`.
6.  **Валидация (Validate)**: `UnifiedTrafficFilter` проверяет хост перед тестом (дедупликация, фильтрация шума).
7.  **Тестирование (Test)**: `StandardHostTester` забирает хост из очереди и проводит серию тестов (DNS, TCP, TLS).
8.  **Инспекция (Inspect)**: Параллельно `RstInspectionService` и другие сервисы следят за пакетами этого соединения.
9.  **Агрегация (Aggregate)**: Результаты тестов и инспекций собираются в `HostTested` модель.
10. **Классификация (Classify)**: `StandardBlockageClassifier` выносит вердикт (например, `DPI_REDIRECT`).
11. **Отчет (Report)**: Результат отправляется в UI через `TestResultsManager`.
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
