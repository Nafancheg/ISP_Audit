# [RED] Research Agent: Findings для Live Testing Pipeline (Фаза 1)

**Дата:** 22 ноября 2025 г.  
**Ветка:** feature/live-testing-pipeline  
**Задача:** Подготовка к реализации шагов 1–4 Фазы 1 из bypass_architecture_deep_dive.md

**Контекст:** Упрощение модели аудита до единого пайплайна, диагностика Flow-слоя, привязка PID, стабилизация RST-блокера.

---

## Затронутые файлы

### 1. Bypass/WinDivertBypassManager.cs (1008 строк)
**Network-слой обхода: TLS-фрагментация, RST-блокер, редиректы**

Содержит:
- `EnableAsync()` / `DisableAsync()` — жизненный цикл bypass
- `Initialize()` (строки 432-502) — инициализация 3 WinDivert handles:
  - **RST blocker**: `priority=0`, `Sniff|Drop`, фильтр `"tcp.Rst == 1"`
  - **TLS fragmenter**: `priority=200`, `None`, фильтр `"outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0"`
  - **Redirector**: `priority=0`, `None`, фильтр по профилю (TCP/UDP ports)
- `RunTlsFragmenter()` (строки 606-709) — обработчик TLS fragmentation (ClientHello → 2 фрагмента)
- `PumpPackets()` (строки 561-604) — обработчик RST blocker (дроп RST)
- `ApplyBypassStrategyAsync()` (строки 312-430) — динамическое применение стратегий (DROP_RST/TLS_FRAGMENT/DOH/PROXY)

**Ключевые флаги:**
- RST blocker: `OpenFlags.Sniff | OpenFlags.Drop` — попытка снифить И дропать одновременно
- TLS fragmenter: `OpenFlags.None` — классический capture/modify/reinject
- Приоритеты: TLS=200 (выше), RST=0 (ниже)

**Проблемные зоны:**
- Строки 466-472: RST blocker graceful degradation — если не открылся (конфликт с Flow), продолжаем без него
- Строка 468: WARNING логируется, но никакой метрики/статуса в UI
- Строки 473-484: TLS fragmenter — exception если не открылся (критично), НО RST blocker НЕ критичен
- `TryOpenWinDivert()` (строки 67-95) — диагностика при открытии, но результат не возвращается в вызывающий код

### 2. Utils/TrafficAnalyzer.cs (791 строка)
**Flow-only слой: сниф соединений процесса (Stage1)**

Содержит:
- `AnalyzeProcessTrafficAsync()` (строки 18-129) — главный entry point для захвата
- `RunFlowMonitor()` (строки 289-406) — обработчик Flow layer (`WINDIVERT_EVENT_FLOW_ESTABLISHED`)
- `RunDnsSniffer()` (строки 410-505) — парсинг DNS-ответов (Network layer, UDP port 53)
- `UpdateTargetPidsAsync()` (строки 244-287) — динамический трекинг дочерних процессов

**Ключевые флаги:**
- Flow handle: `Layer.Flow, priority=0, Sniff | RecvOnly` (строка 318)
- DNS sniffer: `Layer.Network, priority=0, Sniff` (строка 431)

**Проблемные зоны:**
- Строки 318-327: Flow handle открывается с фильтром `"true"` (всё) → может конфликтовать с RST blocker
- Строки 97-98: LiveTestingPipeline инициализируется ВНУТРИ TrafficAnalyzer (tight coupling)
- Строка 354: Flow событие обрабатывается только для `FLOW_ESTABLISHED`, но не для `FLOW_DELETED`
- НЕТ привязки PID через `GetExtendedTcpTable` — вся привязка идёт через Flow layer ProcessId

### 3. Utils/TrafficAnalyzerDualLayer.cs (834 строки)
**Dual-layer: Flow для PID + Network для пакетов (Stage2, экспериментальный)**

Содержит:
- `AnalyzeProcessTrafficAsync()` (строки 24-156) — комбинирует Flow и Network
- `RunFlowMonitor()` (строки 266-343) — аналог из TrafficAnalyzer, но с обработкой `FLOW_DELETED`
- `RunPacketCapture()` (строки 345-432) — захват пакетов через Network layer (`Sniff`)
- `PopulateExistingFlows()` (строки 512-569) — снапшот активных соединений через `GetExtendedTcpTable`

**Ключевые флаги:**
- Flow handle: `Layer.Flow, priority=0, Sniff | RecvOnly` (строка 287)
- Network handle: `Layer.Network, priority=0, Sniff` (строка 360)

**Проблемные зоны:**
- Строка 287: Flow filter `"true"` (всё) → аналогичный конфликт с RST blocker
- Строки 512-569: `PopulateExistingFlows()` использует `GetExtendedTcpTable` для начального снапшота, НО дальше полагается на Flow
- Строки 352-370: Network capture ограничен 50 уникальными IP и 10 пакетами на IP (early exit) — может не захватить проблемные соединения

### 4. Utils/LiveTestingPipeline.cs (510 строк)
**Модульный пайплайн: Sniffer → Tester → Classifier → Bypass**

Содержит:
- `PipelineConfig` (строки 53-59) — настройки (EnableLiveTesting, EnableAutoBypass, MaxConcurrentTests, TestTimeout)
- `LiveTestingPipeline` (строки 68-105) — конструктор, инициализация 3 Channel и 3 воркеров
- `TesterWorker()` (строки 116-130) — тестирует хосты (DNS/TCP/TLS)
- `ClassifierWorker()` (строки 135-166) — классифицирует блокировки и выбирает стратегию
- `UiWorker()` (строки 171-209) — выводит результаты и применяет bypass (если EnableAutoBypass=true)
- `TestHostAsync()` (строки 214-291) — выполняет reverse DNS, TCP connect, TLS handshake
- `ClassifyBlockage()` (строки 296-338) — мапит симптомы на стратегии (DROP_RST/TLS_FRAGMENT/DOH/PROXY)
- `ApplyBypassAsync()` (строки 343-502) — применяет стратегию через WinDivertBypassManager

**Ключевые флаги:**
- `EnableAutoBypass=true` по умолчанию (строка 57)
- `TestTimeout=3s` (строка 58)
- `MaxConcurrentTests=5` (строка 56)

**Проблемные зоны:**
- Строка 99: `_bypassManager` создаётся ВНУТРИ пайплайна (tight coupling)
- Строки 427-452: `ApplyBypassAsync()` для TLS_FRAGMENT — комбинированная стратегия (TLS_FRAGMENT + DROP_RST), но не документировано как это взаимодействует с Flow
- Строка 426: 3-секундная задержка после активации bypass — эмпирическая, не объяснена
- НЕТ обработки конфликта Flow vs RST blocker — bypass применяется "вслепую"

### 5. AuditRunner.cs (400 строк)
**Orchestrator для профильного аудита: DNS → TCP → HTTP → Trace → UDP → RST**

Содержит:
- `RunAsync()` (строки 10-295) — главный пайплайн для CLI/GUI аудита
- Порядок: Software → Firewall → Router → ISP → per-target (DNS/TCP/HTTP/Trace) → UDP → RST
- Интеграция с `IProgress<TestProgress>` для GUI

**Ключевые зоны:**
- Строки 36-55: Глобальные тесты (Software/Firewall/Router/ISP) пропускаются для одиночных хостов (isSingleHostMode)
- Строки 96-133: Early-exit для DNS fail + fallback IP логика (критичные цели)
- Строки 278-283: `TestKind.UDP` финальное резюме

**Проблемные зоны:**
- НЕТ интеграции с LiveTestingPipeline — профильный аудит и exe-scenario работают независимо
- НЕТ упоминания Flow/Network конфликта — AuditRunner не запускает bypass напрямую

### 6. ViewModels/MainViewModel.cs (фрагменты Stage)
**GUI orchestrator для exe-scenario**

Содержит (по grep_search):
- Stage1/Stage2 свойства: `Stage1Status`, `Stage2Status`, `Stage1HostsFound`, `Stage2ProblemsFound`, `Stage1Progress`, `Stage2Progress`
- Флаги завершения: `Stage1Complete`, `Stage2Complete`
- Режимы: `EnableLiveTesting` (по умолчанию true), `IsStage1ContinuousMode`

**Ключевые зоны:**
- Stage1 запускает TrafficAnalyzer с LiveTestingPipeline (если EnableLiveTesting=true)
- Stage2 запускает AuditRunner для диагностики захваченного профиля
- Stage3 (отсутствует в grep, но предположительно есть) — применение bypass

**Проблемные зоны:**
- НЕТ явного контроля за конфликтом Flow (Stage1) vs Network (Stage3 bypass)
- НЕТ UI-индикации конфликта или fallback-режима

### 7. Отсутствующие компоненты
**TcpConnectionWatcher — НЕ НАЙДЕН**

По grep и file_search: `TcpConnectionWatcher` упоминается в deep_dive.md (шаг 3 Фазы 1), НО не реализован в коде.

Текущая привязка PID:
- TrafficAnalyzer: через `Flow.ProcessId` (Network-independent)
- TrafficAnalyzerDualLayer: через `Flow.ProcessId` + `GetExtendedTcpTable` (для снапшота)

**Вывод:** Привязка PID через Flow работает, НО зависит от стабильности Flow layer. Если Flow отключён (Вариант A из deep_dive) — привязка ломается.

---

## Текущая реализация

### Архитектура слоёв WinDivert

**Сейчас активны 3-4 handle одновременно:**

1. **TrafficAnalyzer Flow** (Stage1 / continuous mode):
   - Layer: `Flow`
   - Priority: `0`
   - Flags: `Sniff | RecvOnly`
   - Filter: `"true"` (всё)
   - Цель: получить PID соединений для снифера

2. **TrafficAnalyzer DNS Sniffer** (Stage1):
   - Layer: `Network`
   - Priority: `0`
   - Flags: `Sniff`
   - Filter: `"udp.DstPort == 53 or udp.SrcPort == 53"`
   - Цель: парсить DNS-ответы для hostname resolution

3. **WinDivertBypassManager TLS Fragmenter** (Stage3 / bypass):
   - Layer: `Network`
   - Priority: `200`
   - Flags: `None` (capture/modify/reinject)
   - Filter: `"outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0"`
   - Цель: фрагментировать ClientHello для обхода DPI

4. **WinDivertBypassManager RST Blocker** (Stage3 / bypass):
   - Layer: `Network`
   - Priority: `0`
   - Flags: `Sniff | Drop`
   - Filter: `"tcp.Rst == 1"`
   - Цель: дропать RST-инъекции DPI

**Конфликт:**
- Flow handle (priority=0) и RST blocker (priority=0) на разных слоях, НО оба захватывают TCP события
- По документации WinDivert: Flow layer показывает те же события, что и Network layer, но в агрегированном виде
- Комбинация `Sniff | Drop` на Network при активном Flow может вызвать `ERROR_INVALID_PARAMETER` или просто не открываться

**Текущее поведение:**
- RST blocker часто НЕ открывается (строка 468 WinDivertBypassManager.cs: "RST blocker failed to open (likely conflict with Flow layer)")
- Graceful degradation: bypass продолжает работу БЕЗ RST blocker → TLS fragmentation активна, но RST-инъекции доходят до клиента

### Текущий workflow exe-scenario (будет заменён на unified pipeline)

**Сейчас (Stage-модель, требует удаления):**
1. Пользователь выбирает .exe (FsHud, игра)
2. MainViewModel вызывает `TrafficAnalyzer.AnalyzeProcessTrafficAsync()`
3. TrafficAnalyzer открывает 2 handle: Flow (PID tracking) + Network (DNS parsing)
4. Если `EnableLiveTesting=true` (по умолчанию), создаётся `LiveTestingPipeline` внутри TrafficAnalyzer
5. LiveTestingPipeline тестирует обнаруженные хосты → классифицирует → применяет bypass автоматически (конфликтует с Flow!)
6. ЗАТЕМ пользователь вручную запускает Stage2 → `AuditRunner.RunAsync()` повторно тестирует те же хосты (дублирование!)
7. ЗАТЕМ пользователь вручную запускает Stage3 → `WinDivertBypassManager` пытается открыть RST blocker (не открывается из-за Flow)

**Проблемы текущей архитектуры:**
- Ручное переключение Stage1 → Stage2 → Stage3 (перегруженный UI)
- Дублирование тестов (LiveTestingPipeline в Stage1 + AuditRunner в Stage2)
- Конфликт Flow vs RST blocker (bypass неполноценный)
- НЕТ явного отключения Flow handle перед применением bypass
- НЕТ индикации в UI, что bypass работает без RST protection

### LiveTestingPipeline интеграция

**Когда активен:**
- Создаётся внутри `TrafficAnalyzer.AnalyzeProcessTrafficAsync()` (строка 97) при `EnableLiveTesting=true` (по умолчанию)
- Lifetime: continuous mode — работает пока пользователь не остановит захват

**Workflow:**
1. `TrafficAnalyzer.RunFlowMonitor()` обнаруживает соединение (IP:Port:Proto)
2. Создаёт `ConnectionInfo`, добавляет в `connections` ConcurrentDictionary
3. Отправляет `HostDiscovered` в pipeline queue
4. `TesterWorker` вычитывает из queue, запускает `TestHostAsync()` (reverse DNS, TCP connect, TLS handshake)
5. Результат `HostTested` отправляется в следующий queue
6. `ClassifierWorker` анализирует, формирует `HostBlocked` с bypass strategy
7. `UiWorker` применяет bypass через `WinDivertBypassManager.ApplyBypassStrategyAsync()`

**Проблемы:**
- Bypass применяется **во время** работы Flow handle → конфликт
- `ApplyBypassStrategyAsync("TLS_FRAGMENT")` вызывает `EnableAsync(profile)`, который пытается открыть RST blocker → не открывается → graceful degradation, но логи замусорены WARNING
- Пользователь видит "✓ BYPASS АКТИВЕН", но реально работает только TLS fragmentation БЕЗ RST blocking

### Приоритеты и фильтры (детально)

**Как WinDivert обрабатывает пакет:**
1. Пакет приходит от стека → WinDivert перехватывает на нужном Layer (Flow/Network)
2. Все handle сортируются по **Priority** (от большего к меньшему)
3. Пакет проходит через каждый handle с подходящим фильтром **по порядку приоритетов**
4. Если handle имеет `Sniff` флаг → пакет копируется, но продолжает идти дальше
5. Если handle имеет `None` флаг → пакет **захватывается** (не идёт дальше, пока не будет реинжектирован)
6. Если handle имеет `Drop` флаг → пакет дропается (не реинжектируется)

**Текущий порядок обработки исходящего ClientHello:**
1. **TLS fragmenter (priority=200, Network, None)**: захватывает пакет, фрагментирует на 2, реинжектирует оба фрагмента
2. Фрагменты проходят через стек снова → WinDivert перехватывает их повторно
3. **RST blocker (priority=0, Network, Sniff|Drop)**: должен был бы видеть фрагменты, НО не открыт → пропускается
4. **Flow handle (priority=0, Flow, Sniff|RecvOnly)**: видит FLOW_ESTABLISHED событие, НО не видит отдельных пакетов
5. Фрагменты уходят в сеть

**Порядок обработки входящего RST:**
1. **RST blocker (priority=0, Network, Sniff|Drop)**: должен захватить RST и дропнуть, НО не открыт → пропускается
2. **Flow handle (priority=0, Flow, Sniff|RecvOnly)**: видит FLOW_DELETED событие (если RST привёл к закрытию соединения)
3. RST доходит до стека → соединение обрывается

**Вывод:** Приоритеты выставлены ПРАВИЛЬНО (TLS=200, RST=0), НО RST blocker не работает из-за конфликта флагов с Flow.

### Логирование и диагностика

**Где логируется:**
- `DebugLogger.Log()` — кастомный логгер, пишет в `debug_trace.log`
- TrafficAnalyzer: строки 60, 118, 176, 318-327
- WinDivertBypassManager: строки 41-45, 93, 468, 606, 658-663
- LiveTestingPipeline: progress callbacks в UI (не в файл)

**Что логируется:**
- TrafficAnalyzer Flow: "Flow layer открыт успешно", "Обнаружено N соединений", "Захват завершен"
- WinDivertBypassManager RST: "RST blocker started" (если открылся), "RST DROPPED: srcIP:port -> dstIP:port" (при дропе)
- WinDivertBypassManager TLS: "ClientHello detected", "ClientHello fragmented successfully", "Обработано пакетов: N"

**Что НЕ логируется:**
- Результат `TryOpenWinDivert()` — возвращает bool, но НЕ записывает в лог причину неудачи (только GetLastWin32Error внутри)
- Конфликт Flow vs RST: WARNING логируется (строка 468), НО не возвращается в caller (graceful degradation молчалива)
- Количество RST, которые "пробились" — логируются только те, что были дропнуты (если RST blocker работал)

---

## Риски и зависимости

### Риск 1: Конфликт Flow layer и RST blocker (КРИТИЧНО)

**Симптомы:**
- Логи: "RST blocker failed to open (likely conflict with Flow layer)"
- RST-инъекции доходят до приложения → TLS handshake обрывается
- Bypass НЕ полноценный (только TLS fragmentation, без RST protection)

**Root cause:**
- Комбинация `Sniff | Drop` флагов на Network layer при активном Flow layer
- Flow layer регистрируется на те же TCP события, что и Network RST blocker
- Драйвер WinDivert отказывается открывать RST blocker (ERROR_INVALID_PARAMETER или просто возвращает invalid handle)

**Зависимости:**
- TrafficAnalyzer ДОЛЖЕН работать для Stage1 (сниф соединений процесса)
- WinDivertBypassManager ДОЛЖЕН работать для Stage3 (bypass)
- ОБА используют одни и те же ресурсы WinDivert

**Варианты решения (по deep_dive.md):**

**Вариант A (жёсткий, рекомендованный для применения обхода):**
- Перед включением bypass останавливать захват (Flow handle) и закрывать Flow
- Преимущества: максимальная совместимость, минимальный риск конфликтов
- Недостатки: GUI теряет live updates по новым соединениям во время активного обхода
- Реализация: добавить `TrafficAnalyzer.StopAsync()` и вызывать его перед `WinDivertBypassManager.EnableAsync()` / `ApplyBypassAsync()`

**Вариант B (мягкий, экспериментальный):**
- Оставить Flow handle, но изменить флаги RST blocker с `Sniff|Drop` на `0` (только capture)
- Преимущества: GUI продолжает работать
- Недостатки: требует активного потребления RST пакетов (PumpPackets), иначе очередь переполнится
- Реализация: заменить флаги в строке 460, убедиться что PumpPackets НЕ вызывает WinDivertSend

**Вариант C (разведение приоритетов, экспериментальный):**
- Установить Flow priority=-1000 (минимальный), Network priority=0..200 (как сейчас)
- Преимущества: минимальные изменения кода
- Недостатки: не гарантирует отсутствие конфликта (priority влияет на порядок, НЕ на конкуренцию за ресурсы)
- Реализация: изменить строку 318 в TrafficAnalyzer, но НЕТ гарантий что это поможет

**Рекомендация:** Начать с Вариант C (самый простой), если не поможет → Вариант A (самый надёжный). Вариант B оставить на экспериментальную фазу.

### Риск 1a: Диагностика Flow-слоя и момент старта (связан с Риск 1)

**Проблема:**
- Сейчас `TrafficAnalyzer` стартует неявно из GUI, и нет гарантии, что Flow-хэндл успевает подняться **до** запуска целевого процесса (FsHud/игра).
- Фильтр Flow = `"true"` даёт много шума и мешает понять, видим ли мы вообще нужные соединения.

**Что нужно зафиксировать (из `bypass_architecture_deep_dive.md` 15.1 / шаг 2):**
- Явно проверить, что Flow-хэндл создаётся **раньше**, чем пользователь запускает игру в LiveTesting.
- Сузить фильтр Flow до нужных протоколов/портов (минимизировать шум, не ловить весь интернет).
- Добавить логи: момент старта Flow, первый перехваченный flow, задержку между запуском процесса и первым событием.

**Последствия для плана:**
- В группу D (Flow-диагностика) уже входит D1 (логирование Flow). Нужно расширить её, чтобы покрыть именно тайминг старта и фильтр.
- Без этого мы не можем честно сказать, что Flow вообще видит игру, а конфликт с RST blocker диагностируем вслепую.

### Риск 2: Отсутствие TcpConnectionWatcher (средний приоритет)

**Симптомы:**
- Если Flow handle отключён (Вариант A), привязка соединений к PID теряется
- GUI не может показать "какой процесс к какому хосту подключился"

**Root cause:**
- Текущая архитектура полагается на `Flow.ProcessId` для привязки PID
- Нет fallback через `GetExtendedTcpTable` (системный API)

**Зависимости:**
- TrafficAnalyzerDualLayer использует `GetExtendedTcpTable` для НАЧАЛЬНОГО снапшота (строка 512), НО дальше полагается на Flow
- Нужен ПОСТОЯННЫЙ polling `GetExtendedTcpTable` для поддержки привязки без Flow

**Варианты решения:**
1. Реализовать `TcpConnectionWatcher` как отдельный компонент (polling GetExtendedTcpTable каждые 500ms)
2. Интегрировать в TrafficAnalyzer как fallback режим (если Flow отключён)
3. Использовать ETW (Event Tracing for Windows) для получения PID событий (сложнее, но эффективнее)

**Рекомендация:** Реализовать TcpConnectionWatcher (вариант 1) в рамках шага 3 Фазы 1. Это даст независимость от Flow layer.

### Риск 3: LiveTestingPipeline bypass во время активного захвата (средний приоритет)

**Симптомы:**
- Bypass применяется СРАЗУ при обнаружении соединения (если EnableAutoBypass=true)
- Flow handle ещё активен → RST blocker не открывается → bypass неполноценный
- Логи замусорены WARNING "RST blocker failed to open"

**Root cause:**
- LiveTestingPipeline создаётся ВНУТРИ TrafficAnalyzer (tight coupling)
- `UiWorker` применяет bypass через `WinDivertBypassManager.ApplyBypassStrategyAsync()` БЕЗ проверки на конфликт

**Варианты решения:**
1. Отключить auto-bypass в LiveTestingPipeline (установить `EnableAutoBypass=false` по умолчанию)
2. Реализовать "создание профиля" вместо "применения bypass" (pipeline классифицирует проблемы → создаёт BypassProfile → пользователь применяет вручную)
3. Применять bypass ТОЛЬКО после остановки захвата и закрытия Flow handle

**Рекомендация:** Вариант 2 (создание профиля) — соответствует утверждённому двухфазному подходу.

### Риск 4: GUI "ослепнет" при отключении Flow (Вариант A)

**Симптомы:**
- Захват останавливается → Flow handle закрывается
- Bypass применяется → Flow НЕ активен
- Нет live updates "Обнаружено N соединений" (GUI показывает статичные результаты захвата)

**Root cause:**
- GUI показывает соединения ТОЛЬКО из TrafficAnalyzer (Flow layer)
- WinDivertBypassManager (Network layer) НЕ умеет отчитываться о новых соединениях (он только модифицирует пакеты)

**Варианты решения:**
1. Добавить в WinDivertBypassManager callback для "пакет обработан" → GUI показывает "Bypass активен: N пакетов обработано"
2. Переключить GUI в режим "Active Bypass" → показывать pulse/статус, НЕ список соединений
3. Реализовать TcpConnectionWatcher (polling GetExtendedTcpTable) → GUI показывает соединения БЕЗ Flow layer

**Рекомендация:** Вариант 2 (режим "Active Bypass") для быстрой реализации. Вариант 3 (TcpConnectionWatcher) для полноценного UX.

### Риск 5: Единый пайплайн vs Stage-модель (архитектурный, КРИТИЧНО)

**Симптомы:**
- Пользователь должен вручную переключаться между 3 шагами (Capture → Diagnose → Apply Bypass)
- Нарушает концепцию "единого пайплайна" из deep_dive.md (шаг 1 Фазы 1)
- Перегруженный интерфейс с множеством кнопок и статусов

**Root cause:**
- GUI спроектирован как 3 отдельных шага с кнопками
- Нет автоматического workflow
- Дублирование функционала: LiveTestingPipeline тестирует хосты во время захвата, потом AuditRunner тестирует повторно

**РЕШЕНИЕ (утверждено пользователем):**
- **УБРАТЬ** ручные Stage1/Stage2/Stage3 кнопки
- **ОСТАВИТЬ** только одну кнопку "Запустить диагностику"
- Автоматический пайплайн: Захват → Тестирование → Анализ → Bypass (если нужно)
- Разгрузить интерфейс: показывать только текущий этап и его прогресс
- LiveTestingPipeline становится ЕДИНСТВЕННЫМ механизмом тестирования (убрать дублирование через AuditRunner)

**Реализация:**
1. Одна кнопка запускает TrafficAnalyzer с LiveTestingPipeline
2. Захват работает в continuous mode (пользователь видит прогресс: "Захват трафика... Обнаружено N соединений")
3. Pipeline автоматически тестирует обнаруженные хосты (DNS/TCP/TLS) в фоне
4. Pipeline автоматически классифицирует проблемы
5. **Pipeline СОЗДАЁТ bypass-профиль** (НЕ применяет на лету):
   - Собирает список заблокированных хостов/портов
   - Формирует `BypassProfile` с правилами для каждого проблемного хоста
   - Сохраняет профиль в `bypass_profile_game.json`
   - **ЗАТЕМ** предлагает пользователю применить профиль (кнопка "Применить обход")
6. Применение bypass — ОТДЕЛЬНАЯ операция:
   - Закрывает Flow handle (TrafficAnalyzer.StopAsync)
   - Запускает WinDivertBypassManager с созданным профилем
   - Требует перезапуск приложения (FsHud/игра) для активации обхода
7. GUI показывает: прогресс захвата → статистика тестов → **предложение применить обход** → итоговый отчёт
8. Убрать Stage2 (AuditRunner больше не вызывается для exe-scenario)
9. Убрать Stage3 как отдельный шаг (заменён на "Применить обход" после диагностики)

**Почему НЕ на лету:**
- **Конфликт Flow vs Network:** Bypass требует закрытия Flow handle, но захват может быть ещё активен
- **Холодный старт соединений:** Уже установленные TCP-соединения НЕ получат bypass (TLS handshake уже прошёл)
- **Игровая логика:** Приложение должно ПЕРЕПОДКЛЮЧИТЬСЯ с bypass-ом, иначе обход бесполезен
- **Реалистичный workflow:** Диагностика (continuous mode) → Пользователь останавливает → Анализ → Применение обхода → Перезапуск приложения

**Преимущества:**
- Упрощение UX: один клик → автоматическая диагностика + готовый профиль обхода
- Нет дублирования тестов (было: Stage1 тестирует → Stage2 тестирует повторно)
- Разгруженный интерфейс (нет 3 кнопок, 6 статусов, 3 прогресс-баров)
- Соответствие концепции deep_dive.md (единый пайплайн)
- **Реалистичность:** профиль создаётся автоматически, но применяется осознанно

---

## Рекомендации для Planning Agent

### 1. Приоритизация подзадач (Roadmap)

**Группа A: Диагностика и стабилизация RST blocker (КРИТИЧНО, шаг 4 Фазы 1)**
- **Подзадача A1:** Эксперименты с приоритетами Flow layer
  - Изменить `TrafficAnalyzer.RunFlowMonitor()` priority с `0` на `-1000`
  - Проверить, открывается ли RST blocker рядом с Flow (приоритет ≠ конкуренция, но стоит попробовать)
  - Оценка: 30 минут
- **Подзадача A2:** Эксперименты с флагами RST blocker
  - Изменить `WinDivertBypassManager.Initialize()` флаги RST с `Sniff|Drop` на `0` (capture only)
  - Убедиться, что `PumpPackets()` НЕ вызывает `WinDivertSend` (дроп происходит молча)
  - Оценка: 1 час
- **Подзадача A3:** Graceful degradation → явное UI оповещение
  - Если RST blocker не открылся → вернуть ошибку в caller (НЕ graceful degradation молча)
  - MainViewModel показывает warning: "Bypass активен БЕЗ RST protection (конфликт с Flow layer)"
  - Оценка: 1-2 часа
- **Подзадача A4:** Реализовать Вариант A (отключение Flow при bypass)
  - Добавить `TrafficAnalyzer.StopAsync()` → закрывает Flow handle
  - MainViewModel вызывает `StopAsync()` перед применением bypass
  - Оценка: 2-3 часа

**Группа B: Привязка PID через TcpConnectionWatcher (средний приоритет, шаг 3 Фазы 1)**
- **Подзадача B1:** TcpConnectionWatcher — контракт и нагрузка
  - Входы: `bypass_architecture_deep_dive.md` 15.1.3, API `GetExtendedTcpTable`/`GetExtendedUdpTable`, папка `Utils/`.
  - Выходы:
    - Чёткий формат ключа соединения: `(LocalIP, LocalPort, RemoteIP, RemotePort, Protocol)` → `Pid`.
    - Оценка времени одного снапшота `GetExtendedTcpTable` при ~1000 соединениях и периоде опроса 500 мс.
    - Предложение по хранению: `ConcurrentDictionary<ConnectionKey,int>` + стратегия очистки стейта.
    - Черновой интерфейс `ITcpConnectionWatcher`:
      - `Task<Dictionary<ConnectionKey,int>> GetSnapshotAsync(CancellationToken)` или эквивалент.
  - Критерии приёмки:
    - Для тестового процесса (FsHud/игра) в снапшоте видно его основные TCP‑соединения **без** участия Flow‑слоя.
    - Погрешность появления записи по времени ≤ 1–2 секунд после установления соединения.
    - Нет заметных UI/CPU лагов при периоде опроса 500 мс (зафиксировано в логах/замерах).
  - Оценка: 3-4 часа (исследование + черновой дизайн).
- **Подзадача B2:** Сценарий использования TcpConnectionWatcher в exe‑сценарии
  - Входы: `Utils/TrafficAnalyzer.cs`, `ViewModels/MainViewModel.cs`, результаты B1.
  - Выходы:
    - Описание двух режимов:
      - `diag only`: Flow + TcpConnectionWatcher работают вместе для кросс‑проверки PID.
      - `active bypass`: Flow отключен, GUI и диагностика используют только TcpConnectionWatcher.
    - Карта полей, которые можно полностью перестать брать из Flow (PID/endpoint), заменив на TcpConnectionWatcher.
  - Критерии приёмки:
    - Для целевого процесса можно получить список его соединений и в режиме без Flow.
    - Понятно, какие части GUI/LiveTesting зависят только от TcpConnectionWatcher и не ломаются при отключении Flow.
  - Оценка: 1-2 часа (архитектурное описание + обновление findings для Planning).

**Группа C: Единый пайплайн (КРИТИЧНО, шаг 1 Фазы 1)**
- **Подзадача C1:** Убрать Stage-модель из GUI
  - УДАЛИТЬ Stage1/Stage2/Stage3 кнопки и все связанные свойства
  - Оставить ОДНУ кнопку "Запустить диагностику" + кнопку "Применить обход" (только при наличии проблем)
  - Упростить UI: один прогресс-бар, один статус, один список хостов
  - Оценка: 3-4 часа
- **Подзадача C2:** Интегрировать LiveTestingPipeline как механизм диагностики + создания профиля
  - TrafficAnalyzer запускает LiveTestingPipeline автоматически (EnableLiveTesting=true, continuous mode)
  - Pipeline тестирует, классифицирует, **СОЗДАЁТ BypassProfile** (НЕ применяет)
  - УБРАТЬ вызов AuditRunner из exe-scenario (дублирование)
  - УБРАТЬ EnableAutoBypass из LiveTestingPipeline (bypass не на лету)
  - ДОБАВИТЬ метод `BuildBypassProfile()` в LiveTestingPipeline → формирует профиль из HostBlocked событий
  - Оценка: 3-4 часа
- **Подзадача C3:** Реализовать применение bypass как отдельную операцию
  - Кнопка "Применить обход" → останавливает захват, закрывает Flow → запускает WinDivertBypassManager с профилем
  - Показывает инструкцию: "Обход активен. Перезапустите [название приложения] для активации"
  - Оценка: 2-3 часа
- **Подзадача C4:** Упростить отчётность
  - GUI: "Захват: N соединений" → "Тестирование: M/N" → "Итог: X OK, Y заблокировано"
  - Если Y > 0 → показывает кнопку "Применить обход" + краткое описание проблем
  - Финальный список хостов с иконками (✓ OK, ✗ BLOCKED, ⚠ WARNING)
  - Оценка: 2-3 часа

**Группа D: Flow-слой диагностика (низкий приоритет, шаг 2 Фазы 1)**
- **Подзадача D1:** Диагностика тайминга и шума Flow
  - Входы: `Utils/TrafficAnalyzer.cs`, `DebugLogger`, `bypass_architecture_deep_dive.md` 15.1.2.
  - Выходы:
    - Лог‑метрики по одной LiveTesting‑сессии:
      - `FlowHandleOpenedUtc`, `FirstTargetFlowUtc` (первый flow для целевого PID).
      - `FlowStartToFirstTargetMs` (дельта старта Flow → первый нужный flow).
      - `TotalFlows`, `TargetPidFlows`, `TargetPidFlowsPercent`.
    - Конфигурируемый `FlowFilter` (строка фильтра из профиля, а не жёстко `"true"`).
  - Критерии приёмки:
    - В логах чётко видно, стартует ли Flow **до** того, как игра/FsHud начинают устанавливать соединения.
    - Есть численная оценка шума (напр. после настройки фильтра `TargetPidFlowsPercent ≥ 80%`).
  - Оценка: 1 час.
- **Подзадача D2:** UI-индикация активности Flow/захвата
  - Входы: `ViewModels/MainViewModel.cs`, `MainWindow.xaml`, результаты D1.
  - Выходы:
    - Свойство `FlowEventsCount` и, при необходимости, производное `ConnectionsDiscovered`.
    - Простейшая индикация в diagnostic‑панели: "Обнаружено соединений: N" + признак, что Flow вообще что-то видит.
  - Критерии приёмки:
    - Пользователь в GUI видит, что Flow‑слой реально активен и ловит соединения (а не молчит).
    - Значения в UI коррелируют с метриками из логов D1.
  - Оценка: 1 час.

### 2. Файлы, требующие изменений

**Для группы A (RST blocker fix):**
- `Bypass/WinDivertBypassManager.cs`:
  - Строки 460-472: изменить флаги RST blocker
  - Строки 67-95: вернуть ошибку в caller (не graceful degradation)
- `Utils/TrafficAnalyzer.cs`:
  - Строка 318: изменить priority на -1000 (эксперимент)
  - Добавить метод `StopAsync()` для закрытия handle
- `ViewModels/MainViewModel.cs`:
  - ApplyBypassAsync метод: вызывать `TrafficAnalyzer.StopAsync()` перед bypass
  - Показывать warning, если RST blocker не открылся

**Для группы B (TcpConnectionWatcher):**
- Новый файл `Utils/TcpConnectionWatcher.cs` (создать)
- `Utils/TrafficAnalyzer.cs`:
  - Интегрировать TcpConnectionWatcher как fallback (если Flow НЕ активен)

**Для группы C (единый пайплайн):**
- `ViewModels/MainViewModel.cs`:
  - УДАЛИТЬ: все Stage-команды и свойства
  - ДОБАВИТЬ: `RunDiagnosticPipelineAsync()` — запускает TrafficAnalyzer + LiveTestingPipeline, создаёт BypassProfile
  - ДОБАВИТЬ: `ApplyBypassAsync()` — останавливает захват, закрывает Flow, запускает WinDivertBypassManager с профилем
  - ДОБАВИТЬ: свойства (DiagnosticStatus, DiagnosticProgress, HostsTested, ProblemsFound, BypassProfileReady, BypassProfilePath)
- `Utils/LiveTestingPipeline.cs`:
  - УДАЛИТЬ: EnableAutoBypass-логику из UiWorker
  - ДОБАВИТЬ: `BuildBypassProfile()` — собирает HostBlocked события, формирует BypassProfile
- `MainWindow.xaml`:
  - УДАЛИТЬ: все Stage-кнопки и панели
  - ДОБАВИТЬ: кнопку "Запустить диагностику" (RunDiagnosticPipelineCommand)
  - ДОБАВИТЬ: кнопку "Применить обход" (видна, когда BypassProfileReady=true)
  - Оставить: один прогресс-бар, один статус TextBlock, список хостов с иконками ✓/✗/⚠

**Для группы D (Flow диагностика):**
- `Utils/TrafficAnalyzer.cs`:
  - Добавить счётчики событий, логирование
- `ViewModels/MainViewModel.cs`:
  - Добавить свойство `FlowEventsCount`, обновлять из TrafficAnalyzer
- `MainWindow.xaml`:
  - Показывать FlowEventsCount в diagnostic panel

### 3. Варианты реализации по приоритетам

**Минимальный MVP (8-10 часов работы):**
- C1 (убрать Stage-модель) + C2 (диагностика + создание профиля) + D1 (логирование Flow)
- Результат: упрощённый UI, единая кнопка "Запустить диагностику", continuous mode, автоматическое создание bypass-профиля, детальные логи

**Средний MVP (14-18 часов работы):**
- Минимальный MVP + C3 (применение bypass) + A4 (отключение Flow) + A3 (UI warning)
- Результат: полный цикл диагностика → остановка → профиль → кнопка "Применить обход", стабильный RST blocker, явные предупреждения

**Полный MVP (20-26 часов работы):**
- Средний MVP + C4 (отчётность) + B1 (TcpConnectionWatcher) + D2 (UI индикация) + A2 (эксперименты с флагами)
- Результат: полированный UX, независимость от Flow, прозрачная диагностика, максимальная эффективность bypass

**Рекомендация:** Начать с минимального MVP (упрощение UI + автоматическое создание профиля — самое важное по требованию пользователя), затем средний MVP (добавить применение bypass), затем полный MVP (polish + TcpConnectionWatcher).

### 4. Риски для каждого варианта

**Вариант C (приоритеты) → минимальный риск, но НЕ решит проблему конфликта:**
- Если не поможет → потерянное время (30 минут)
- НО: легко откатить (изменить одну строку обратно)

**Вариант B (флаги RST) → средний риск, может потребовать доработки PumpPackets:**
- Если `0` флаги не дропают пакеты → нужно явно НЕ реинжектить в PumpPackets
- Риск: RST пройдут, если PumpPackets не успеет обработать (очередь заполнена)

**Вариант A (отключение Flow) → высокий риск для UX, НО низкий риск для bypass:**
- GUI потеряет live updates → нужно компенсировать TcpConnectionWatcher или режим "Active Bypass"
- НО: bypass гарантированно заработает (RST blocker откроется без конкуренции)

**Рекомендация:** Последовательная проверка: C → B → A (от меньшего к большему риску/усилий).

### 5. Зависимости между задачами

**A4 (отключение Flow) зависит от B1 (TcpConnectionWatcher):**
- Если Flow отключён, привязка PID ломается
- TcpConnectionWatcher должен быть реализован ДО отключения Flow

**C3 (применение bypass) зависит от A4 (отключение Flow):**
- Кнопка "Применить обход" вызывает ApplyBypassAsync() → пользователь останавливает захват → закрывает Flow → запускает WinDivertBypassManager
- Логика отключения встраивается в MainViewModel.ApplyBypassAsync()
- Иначе конфликт будет воспроизводиться при каждом применении bypass

**C2 (создание профиля) НЕ зависит от A4:**
- Диагностика работает С Flow handle (обнаружение + тестирование + создание профиля)
- Применение профиля — отдельная операция (требует остановки захвата)

**C1 (убрать Stage-модель) разблокирует всё:**
- Упрощение UI позволяет встроить двухфазный подход (диагностика/профиль → применение)
- Убирает дублирование (TrafficAnalyzer+LiveTestingPipeline вместо связки Stage1/Stage2/AuditRunner в exe-сценарии)
- Даёт единую точку входа для управления lifecycle WinDivert handles

**D2 (UI индикация) адаптируется под единый пайплайн:**
- Вместо "FlowEventsCount" показывать "Обнаружено соединений: N"
- Вместо "Stage1Progress/Stage2Progress" показывать "Протестировано: M/N хостов"
- Финальный статус диагностики: "Готово: X OK, Y заблокировано"
- Финальный статус bypass: "Обход активен для Y хостов. Перезапустите приложение."

---

## Промпт для Planning Agent

```
Planning Agent. Работаешь в изолированном контексте.

Цель: Сформировать детальный план реализации Фазы 1 (шаги 1-4) из docs/bypass_architecture_deep_dive.md на основе findings.md от Research Agent.

Твой вход:
- agents/research_agent/findings.md — результаты исследования текущей архитектуры
- docs/bypass_architecture_deep_dive.md — техническая спецификация (особенно раздел 15.1)

Задачи планирования:

1. Разбить Фазу 1 на атомарные подзадачи (subtasks) с учётом:
   - Зависимостей между задачами (граф зависимостей)
   - Рисков и fallback-стратегий (что делать если подзадача провалится)
   - Приоритетов (критично/средний/низкий)
   - Оценок трудозатрат (часы работы для Coding Agent на Haiku)

2. Для каждой подзадачи описать:
   - Входные данные (какие файлы читать, какие компоненты изучить)
   - Выходные данные (какие файлы изменить/создать, какие строки кода затронуть)
   - Критерии приёмки (как проверить что задача выполнена корректно)
   - Риски (что может пойти не так, как минимизировать)

3. Учесть рекомендации Research Agent:
   - **ПРИОРИТЕТ #1:** Группа C (единый пайплайн) — убрать Stage-модель, упростить UI, двухфазный workflow (диагностика → профиль → применение)
   - **ВАЖНО:** Bypass НЕ применяется "на лету" — сначала создаётся профиль, затем пользователь применяет его осознанно
   - Группировка A/B/D (RST blocker, TcpConnectionWatcher, диагностика) — после C
   - Варианты реализации (A/B/C из deep_dive) с приоритизацией
   - Минимальный MVP НАЧИНАЕТСЯ с группы C (по требованию пользователя): C1 + C2 (диагностика + профиль)

4. Сформировать итоговый план в виде:
   - Линейная последовательность подзадач (с ветвлениями для экспериментов)
   - Для каждой подзадачи: ID, название, описание, файлы, оценка, зависимости, риски
   - Чек-лист для QA Agent (как проверять результаты каждой подзадачи)

Оформи результат в agents/planning_agent/plan.md со структурой:

## Граф зависимостей (Mermaid)
[диаграмма последовательности подзадач с зависимостями]

## Подзадачи Фазы 1

### [ID] Название подзадачи (Группа X, приоритет)
**Описание:** [что делаем]
**Входы:** [файлы для чтения]
**Выходы:** [файлы для изменения, конкретные строки если известны]
**Оценка:** [часы работы]
**Зависимости:** [ID других подзадач]
**Риски:** [что может сломаться]
**Критерии приёмки:** [как проверить]

[... повторить для всех подзадач]

## Чек-лист для QA Agent
[список проверок после каждой подзадачи и после полной Фазы 1]

## Fallback-стратегия
[что делать если критичные подзадачи провалятся]

По завершению работы дай промпт для следующего агента — Coding (ОДИН subtask за раз, используй Haiku для экономии).
```
