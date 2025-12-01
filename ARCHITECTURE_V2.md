# ISP_Audit — Архитектура приложения

Документация по текущей реализации с описанием проблем и планируемых изменений.

**Дата:** 27.11.2025  
**Цель приложения:** Обход блокировок провайдера (DPI, DNS-фильтрация, TCP RST injection) для доступа к заблокированным ресурсам.

---

## Оглавление

1. [Точка входа (Program.cs)](#1-точка-входа-programcs)
2. [WPF приложение (App.xaml → MainWindow)](#2-wpf-приложение)
3. [MainViewModel — центр управления](#3-mainviewmodel--центр-управления)
4. [Состояния UI (ScreenState)](#4-состояния-ui-screenstate)
5. [Bypass Control Panel](#5-bypass-control-panel)
6. [Диагностика приложения](#6-диагностика-приложения)
7. [Мониторинговые сервисы](#7-мониторинговые-сервисы)
8. [TrafficAnalyzer — сбор трафика](#8-trafficanalyzer--сбор-трафика)
9. [LiveTestingPipeline — тестирование хостов](#9-livetestingpipeline--тестирование-хостов)
10. [WinDivertBypassManager — обход блокировок](#10-windivertbypassmanager--обход-блокировок)
11. [OverlayWindow — оверлей диагностики](#11-overlaywindow--оверлей-диагностики)
12. [Модели данных](#12-модели-данных)
13. [UI/UX](#13-uiux)
14. [Файловая структура](#14-файловая-структура)
15. [Системные особенности](#15-системные-особенности)

---

## 1. Точка входа (Program.cs)

### Описание

`Program.Main(args)` — единственная точка входа. Определяет режим работы по наличию аргументов командной строки:

```
Program.Main(args)
├── args.Length == 0 → GUI Mode
│   ├── Config.SetActiveProfile("Default")
│   ├── TryHideConsoleWindow()
│   └── new App().Run() → запуск WPF
│
└── args.Length > 0 → CLI Mode
    └── RunCliAsync(args) → парсинг, тесты, JSON-отчёт
```

### Связи

- **→ Блок 2:** В GUI режиме создаёт `App`, который создаёт `MainWindow`
- **→ Блок 3:** `MainWindow` инициализирует `MainViewModel`

### Проблемы

**ПРОБЛЕМА: OutputType=Exe**  
Сейчас в `.csproj` стоит `OutputType=Exe`, поэтому при запуске мелькает консольное окно, которое потом скрывается через `ShowWindow(hWnd, 0)`. Это костыль.  
**Решение:** Изменить на `OutputType=WinExe` — чистый WPF без консоли.

**ПРОБЛЕМА: CLI режим не нужен**  
`RunCliAsync`, `Config.ParseArgs`, профили — всё это legacy от CLI-версии. Сейчас приложение только GUI.  
**Решение:** Удалить весь CLI функционал:
- `RunCliAsync()` метод
- `Config.ParseArgs()` 
- `Config.SetActiveProfile()` — не нужен без CLI
- Связанные классы и файлы

**ПРОБЛЕМА: Config.SetActiveProfile("Default")**  
Загружает `Profiles/Default.json` при каждом запуске. Зачем? Что там? Используется ли?  
**Решение:** Разобраться и удалить если не нужно.

---

## 2. WPF приложение (App.xaml → MainWindow)

### Описание

```csharp
// App.xaml.cs
protected override void OnStartup(StartupEventArgs e)
{
    var mainWindow = new MainWindow();
    mainWindow.Show();
}
```

`MainWindow.xaml.cs`:
- `InitializeComponent()` — загрузка XAML
- `Window_Loaded` — позиционирование окна (50px от левого края, центр по вертикали)
- `DataContext` привязан к `MainViewModel` через XAML

### Связи

- **← Блок 1:** Создаётся из `Program.Main()` через `App.Run()`
- **→ Блок 3:** `DataContext = new MainViewModel()` — вся логика в ViewModel

### Проблемы и вопросы

**ВОПРОС: Window_Loaded позиционирование**  
"50px от левого края, центр по вертикали" — почему такое позиционирование? Не стандартное поведение Windows. Что если окно не влезает? Что на мульти-мониторе?

**ВОПРОС: Обработка ошибок при старте**  
Что если MainViewModel.constructor бросит исключение? Показывается ли пользователю понятная ошибка или просто крэш?

**ВОПРОС: Размер окна**  
Фиксированный или адаптивный? Что если контент не влезает? MinWidth/MinHeight заданы?

**ВОПРОС: DPI awareness**  
Правильно ли работает на High DPI мониторах (4K, 150% scaling)?

---

## 3. MainViewModel — центр управления

### Описание

`MainViewModel` (~2400 строк) — главный класс, управляет всем:
- UI состоянием
- Bypass опциями
- Диагностикой
- Результатами

### Инициализация (конструктор)

```
MainViewModel()
├── InitializeTestResults()
├── Создание команд (StartCommand, CancelCommand, etc.)
├── LoadFixHistory() — ??? история исправлений
├── InitializeBypassOnStartupAsync() — АВТО-ВКЛЮЧЕНИЕ BYPASS
└── CheckVpnStatus() — проверка VPN
```

### Авто-включение Bypass при старте

При запуске с правами администратора автоматически включаются методы обхода:

```csharp
// InitializeBypassOnStartupAsync()
if (WinDivertBypassManager.HasAdministratorRights)
{
    _isFragmentEnabled = true;   // TLS фрагментация
    _isDropRstEnabled = true;    // Блокировка TCP RST
    _isDoHEnabled = true;        // DNS-over-HTTPS
    
    await ApplyBypassOptionsAsync();  // → Блок 10
    await ApplyDoHAsync();
}
```

### Связи

- **← Блок 2:** Создаётся как DataContext для MainWindow
- **→ Блок 5:** Управляет флагами bypass (IsFragmentEnabled, etc.)
- **→ Блок 6:** `RunLivePipelineAsync()` запускает диагностику
- **→ Блок 10:** `ApplyBypassOptionsAsync()` применяет bypass через WinDivertBypassManager
- **→ Блок 11:** Создаёт и показывает OverlayWindow

### Проблемы

**ПРОБЛЕМА: Порядок инициализации**  
Сейчас: `LoadFixHistory()` → `InitializeBypassOnStartupAsync()` → `CheckVpnStatus()`  
Bypass включается ДО проверки VPN. Если VPN активен, bypass может конфликтовать.  
**Решение:** Сначала `CheckVpnStatus()`, потом решать включать ли bypass.

**ПРОБЛЕМА: LoadFixHistory() — что это?**  
Загружает "историю исправлений". Каких исправлений? Откуда? Зачем?  
**Решение:** Разобраться. Возможно удалить.

**ПРОБЛЕМА: Нет предупреждения без админа**  
Если нет прав админа — bypass просто не включается, кнопки неактивны, но пользователь не понимает почему.  
**Решение:** Показать явное предупреждение "Запустите от администратора для обхода блокировок".

**ПРОБЛЕМА: Кнопка диагностики доступна без админа**  
Диагностика требует WinDivert (админ). Но кнопка "Начать" активна.  
**Решение:** Если нет админа — задисейблить кнопку или показать предупреждение при нажатии.

---

## 4. Состояния UI (ScreenState)

### Описание

Три состояния UI, управляются через `ScreenState`:

```
"start"   → IsStart=true,   IsRunning=false, IsDone=false  — начальный экран
"running" → IsStart=false,  IsRunning=true,  IsDone=false  — диагностика идёт
"done"    → IsStart=false,  IsRunning=false, IsDone=true   — результаты
```

### Переходы

```
start ──[Начать]──→ running ──[Завершение]──→ done
                       ↑                        │
                       └────[Новая диагностика]─┘
```

### Связи

- **← Блок 3:** `MainViewModel` меняет состояние
- **→ Блок 13:** UI элементы привязаны к IsStart/IsRunning/IsDone

### Проблемы и вопросы

**ВОПРОС: Состояние "error"**  
Есть только start/running/done. А если диагностика завершилась с ошибкой? Сейчас это тоже "done"? Как пользователь различит успех и ошибку?

**ВОПРОС: Состояние "cancelled"**  
Если пользователь нажал "Остановить" — это "done"? Или должно быть отдельное состояние?

**ВОПРОС: Переход start → start**  
Можно ли сбросить состояние не запуская диагностику? Например, изменить exe путь?

**ВОПРОС: Персистентность состояния**  
Что если закрыть приложение во время "running"? При следующем запуске — "start"? Теряются ли данные?

---

## 5. Bypass Control Panel

### Описание

Панель с toggle-кнопками для включения/выключения методов обхода:

| Кнопка | Свойство | Что делает |
|--------|----------|------------|
| Fragment | `IsFragmentEnabled` | TLS фрагментация (порядок: 1→2) |
| Disorder | `IsDisorderEnabled` | TLS фрагментация (порядок: 2→1) |
| Fake | `IsFakeEnabled` | Fake TTL пакет |
| DROP RST | `IsDropRstEnabled` | Блокировка TCP RST от провайдера |
| DoH | `IsDoHEnabled` | DNS-over-HTTPS (Cloudflare 1.1.1.1) |

### Взаимоисключение

Fragment и Disorder — взаимоисключающие (оба делают фрагментацию, но в разном порядке).

### Логика применения

```csharp
// ApplyBypassOptionsAsync()
// 1. Определяем TLS стратегию (приоритет: Disorder > Fragment)
if (IsDisorderEnabled && IsFakeEnabled) → TlsBypassStrategy.FakeDisorder
else if (IsFragmentEnabled && IsFakeEnabled) → TlsBypassStrategy.FakeFragment
else if (IsDisorderEnabled) → TlsBypassStrategy.Disorder
// ... и т.д.

// 2. Создаём профиль
var profile = new BypassProfile {
    DropTcpRst = IsDropRstEnabled,
    TlsStrategy = tlsStrategy,
    ...
};

// 3. Применяем через WinDivert
await _bypassManager.EnableAsync(profile);  // → Блок 10
```

### Связи

- **← Блок 3:** MainViewModel хранит флаги и обрабатывает команды
- **→ Блок 10:** `WinDivertBypassManager.EnableAsync()` применяет bypass

### Проблемы

**ПРОБЛЕМА: Визуальное взаимоисключение**  
Fragment и Disorder взаимоисключающие, но визуально это не очевидно. Обе кнопки выглядят одинаково.  
**Решение:** Когда одна активна — вторую показывать приглушённой/неактивной (не ярко-красной disabled, а серой).

**ПРОБЛЕМА: Ручное отключение при конфликте**  
Если Fragment активен и нажали Disorder — нужно вручную выключить Fragment.  
**Решение:** Автоматически отключать конфликтующую опцию при включении другой.

**ВОПРОС: Терминология для пользователя**  
"Fragment", "Disorder", "Fake TTL", "DROP RST" — понятно ли обычному пользователю?  
**Решение:** Добавить tooltips с объяснением простым языком. Например: "Fragment — разбивает запрос на части, чтобы провайдер не мог его распознать".

---

## 6. Диагностика приложения

### Описание

`RunLivePipelineAsync()` — основной метод диагностики. Запускает мониторинг трафика целевого приложения, тестирует соединения, показывает результаты.

### Основной flow

```
RunLivePipelineAsync()
│
├── 1. Проверка прав админа
├── 2. Определение targetExePath (выбранный exe или TestNetworkApp)
├── 3. ScreenState = "running"
├── 4. Создание CancellationTokenSource
├── 5. RunFlushDnsAsync() — сброс DNS кеша
│
├── 6. Создание OverlayWindow → Блок 11
│
├── 7. Запуск мониторинговых сервисов → Блок 7
│   ├── FlowMonitorService
│   ├── NetworkMonitorService
│   └── DnsParserService
│
├── 8. Запуск целевого процесса
├── 9. Запуск PidTrackerService
│
├── 10. Преемптивное включение bypass (если admin)
│
├── 11. TrafficAnalyzer.AnalyzeProcessTrafficAsync() → Блок 8
│       (БЛОКИРУЮЩИЙ ВЫЗОВ — ждём завершения захвата)
│
├── 12. Закрытие overlay
├── 13. Сохранение профиля в Profiles/
└── 14. ScreenState = "done"
```

### Сценарии завершения диагностики

1. **Таймаут** — 10 минут (hardcoded)
2. **Пользователь нажал "Остановить"** — через CancellationToken
3. **Все процессы завершились** — целевое приложение закрыто
4. **Silence Detection** — нет трафика 60 сек + пользователь подтвердил завершение

### Связи

- **← Блок 3:** Вызывается из MainViewModel по команде StartLiveTestingCommand
- **→ Блок 7:** Создаёт и запускает мониторинговые сервисы
- **→ Блок 8:** Вызывает TrafficAnalyzer.AnalyzeProcessTrafficAsync()
- **→ Блок 10:** Включает bypass перед захватом
- **→ Блок 11:** Создаёт OverlayWindow

### Проблемы

**ПРОБЛЕМА: Проверка админа дублируется**  
Проверка прав админа есть и при старте (блок 3), и здесь. Достаточно одной проверки при старте.  
**Решение:** Убрать проверку админа из диагностики — если дошли сюда, значит права есть (кнопка была бы disabled).

**ПРОБЛЕМА: DNS flush после bypass**  
Сейчас порядок: bypass → DNS flush. Но если bypass ещё не полностью инициализировался, DNS запросы могут пойти через обычный DNS.  
**Решение:** Сначала DNS flush, потом bypass. Или flush после полной инициализации bypass.

**ВОПРОС: Таймаут 10 минут hardcoded**  
Почему 10 минут? Можно ли настроить?  
**Решение:** Вынести в настройки или хотя бы в константу с комментарием.

**ВОПРОС: Сохранение профиля в Profiles/**  
Что сохраняется? Зачем? Используется ли потом?  
**Решение:** Разобраться и документировать или удалить.

---

## 7. Мониторинговые сервисы

### Описание

Четыре сервиса работают параллельно во время диагностики:

### FlowMonitorService

**Назначение:** Мониторинг TCP/UDP соединений процесса.

**Два режима работы:**
1. **WinDivert Flow Layer** — событийная модель, получает уведомления о новых соединениях
2. **IP Helper API polling** — периодический опрос системной таблицы соединений

```csharp
// Выбор режима
if (bypass активен || EnableAutoBypass) {
    UseWatcherMode = true;  // IP Helper API
} else {
    UseWatcherMode = false; // WinDivert Flow
}
```

**Событие:** `OnFlowEvent(pid, protocol, remoteIp, remotePort, localPort)`

### NetworkMonitorService

**Назначение:** Захват DNS трафика через WinDivert.

**Фильтр:** `"udp.DstPort == 53 or udp.SrcPort == 53"`

Перехватывает DNS запросы/ответы для построения карты hostname→IP.

### DnsParserService

**Назначение:** Парсинг DNS пакетов, построение кеша hostname→IP.

**События:**
- `OnHostnameUpdated(ip, hostname)` — IP разрешён в hostname
- `OnDnsLookupFailed(hostname, error)` — DNS lookup не удался

### PidTrackerService

**Назначение:** Отслеживание PID'ов целевого процесса (включая дочерние).

**Логика:**
1. Инициализация с начальным PID
2. Поиск процессов с тем же именем
3. Поиск дочерних через WMI
4. Обновление каждые 0.5 сек

**Событие:** `OnNewPidsDiscovered(newPids)`

### Связи

- **← Блок 6:** Создаются и запускаются в `RunLivePipelineAsync()`
- **→ Блок 8:** TrafficAnalyzer подписывается на события сервисов
- **→ Блок 10:** FlowMonitor переключает режим если bypass активен (конфликт WinDivert handles)

### Проблемы

**ПРОБЛЕМА: Конфликт WinDivert handles**  
FlowMonitorService и WinDivertBypassManager оба используют WinDivert. Одновременная работа вызывает конфликт.  
**Текущее решение:** Переключение FlowMonitor в polling режим (IP Helper API) когда bypass активен.  
**Вопрос:** Это костыль? Можно ли решить архитектурно? Или polling достаточно надёжен?

**ПРОБЛЕМА: Два режима FlowMonitor**  
Код сложнее из-за поддержки двух режимов. Если polling работает стабильно — зачем WinDivert Flow?  
**Решение:** Проверить стабильность polling с bypass. Если ОК — убрать WinDivert Flow режим, упростить код.

**ВОПРОС: WMI для дочерних процессов**  
Используется WMI для поиска дочерних процессов. WMI медленный и может давать ложные срабатывания.  
**Решение:** Проверить надёжность. Возможно есть альтернативы (Job Objects, ETW).

---

## 8. TrafficAnalyzer — сбор трафика

### Описание

`TrafficAnalyzer.AnalyzeProcessTrafficAsync()` — собирает информацию о сетевых соединениях целевого процесса.

**Роль:** ТОЛЬКО сбор данных. НЕ координатор, НЕ принимает решения о bypass.

### Входные параметры

```csharp
AnalyzeProcessTrafficAsync(
    int targetPid,
    TimeSpan? captureTimeout,       // 10 минут
    FlowMonitorService flowMonitor,
    PidTrackerService pidTracker,
    DnsParserService dnsParser,
    IProgress<string>? progress,
    CancellationToken cancellationToken,
    bool enableLiveTesting = false,  // → Блок 9
    bool enableAutoBypass = false,
    WinDivertBypassManager? bypassManager = null,
    Func<Task<bool>>? onSilenceDetected = null
)
```

### Основной цикл

```
1. Подписка на события:
   ├── pidTracker.OnNewPidsDiscovered → обновление списка PID
   ├── flowMonitor.OnFlowEvent → новое соединение
   └── dnsParser.OnHostnameUpdated → hostname для IP

2. Status Reporter (каждую секунду):
   ├── Проверка: живы ли процессы?
   ├── Репорт статуса (раз в 10 сек)
   └── Silence Detection (нет соединений > 60 сек)

3. При новом соединении (если enableLiveTesting):
   pipeline.EnqueueHostAsync(host) → Блок 9

4. Ожидание завершения (таймаут/отмена/процессы завершились)

5. Обогащение hostname для собранных соединений

6. Генерация GameProfile
```

### Фильтрация событий

```csharp
void OnFlowEvent(..., int pid, ...) {
    // Только PID'ы из PidTracker
    if (!pidTracker.TrackedPids.Contains(pid))
        return;
    
    connections.Add(...);
}
```

### Связи

- **← Блок 6:** Вызывается из `RunLivePipelineAsync()`
- **← Блок 7:** Получает события от мониторинговых сервисов
- **→ Блок 9:** Создаёт LiveTestingPipeline, передаёт туда хосты

### Проблемы и вопросы

**ВОПРОС: Параметр enableAutoBypass**  
Что делает `enableAutoBypass = false`? Если bypass уже включён при старте — зачем этот параметр? Дублирование логики?

**ВОПРОС: GameProfile — зачем генерируется?**  
В конце создаётся GameProfile. Где он используется? Сохраняется ли? Или это мёртвый код?

**ВОПРОС: Status Reporter каждую секунду**  
Оверхед? Почему не event-driven? Нужен ли polling?

**ВОПРОС: Обогащение hostname**  
Пункт 5 — "обогащение hostname для соединений". Что если DNS недоступен? Таймауты?

**ВОПРОС: Много параметров**  
10 параметров в методе — сложно использовать. Нужен ли рефакторинг в объект-конфигурацию?

**ВОПРОС: LiveTestingPipeline создаётся внутри**  
Tight coupling — TrafficAnalyzer создаёт LiveTestingPipeline внутри себя. Тестируемость? Подменяемость?

---

## 9. LiveTestingPipeline — тестирование хостов

### Описание

Pipeline из трёх worker'ов для тестирования обнаруженных хостов:

```
                    ┌─────────────┐
  SnifferQueue ────→│ TesterWorker│────→ TesterQueue
                    └─────────────┘
                           ↓
                    ┌──────────────────┐
  TesterQueue ─────→│ ClassifierWorker │────→ BypassQueue
                    └──────────────────┘
                           ↓
                    ┌───────────┐
  BypassQueue ─────→│ UiWorker  │────→ Progress Reports
                    └───────────┘
```

### TesterWorker

Тестирует каждый хост:
1. **Reverse DNS** — получение hostname по IP
2. **TCP connect** — проверка доступности порта (таймаут 3 сек)
3. **TLS handshake** — проверка TLS (только для порта 443)

```csharp
// StandardHostTester.TestHostAsync()
var result = new HostTested {
    DnsOk = true/false,
    TcpOk = true/false,
    TlsOk = true/false,
    BlockageType = "TCP_RST" | "TCP_TIMEOUT" | "TLS_DPI" | "PORT_CLOSED" | null
};
```

### ClassifierWorker

Классифицирует тип блокировки и выбирает стратегию:

```csharp
// StandardBlockageClassifier.ClassifyBlockage()
// Использует StrategyMapping.GetStrategiesFor()

if (DnsOk && TcpOk && TlsOk) → "NONE", "OK"
if (!DnsOk) → "DOH" (ручное)
if (TcpOk && !TlsOk) → "DROP_RST", "TLS_FRAGMENT", "TLS_FAKE"
if (!TcpOk && быстрый ответ) → "DROP_RST" (RST injection)
if (!TcpOk && таймаут) → "PROXY" (ручное)
```

### UiWorker

Формирует сообщения для UI:
- `✓ host:port (latency)` — успех
- `❌ host:port | DNS:✓/✗ TCP:✓/✗ TLS:✓/✗ | BlockageType` — проблема
- `→ Рекомендуемая стратегия: X`

### Связи

- **← Блок 8:** Создаётся в TrafficAnalyzer, получает хосты через `EnqueueHostAsync()`
- **→ Блок 10:** Должен вызывать WinDivertBypassManager для применения bypass... **НО НЕ ВЫЗЫВАЕТ!**

### КРИТИЧЕСКАЯ ПРОБЛЕМА

**`_bypassEnforcer` создаётся, но НИКОГДА не вызывается!**

```csharp
// LiveTestingPipeline конструктор
_bypassEnforcer = new WinDivertBypassEnforcer(_bypassManager, _tester, progress);
// ... и больше НИГДЕ не используется!
```

**Комментарий в коде объясняет:**
```csharp
// ⚠️ НЕ переключаем bypass динамически!
// Bypass (TLS_DISORDER + DROP_RST) уже активирован при старте.
// Динамическое переключение стратегий ломает работающие соединения,
// т.к. bypass глобальный, а тесты параллельные.
```

**Проблема:**
1. При старте включается Fragment + DROP_RST — фиксированный набор
2. Pipeline тестирует хосты, классифицирует, ВЫБИРАЕТ стратегию
3. Но стратегия НЕ ПРИМЕНЯЕТСЯ — только логируется!
4. Если YouTube нужна другая стратегия (Disorder, FakeFragment) — она не применится

**Существующий код который не используется:**
- `BypassCoordinator` — умеет пробовать стратегии по очереди, кешировать работающие
- `WinDivertBypassEnforcer` — умеет применять стратегии с ретестом

### Варианты решения

**Вариант A (простой):** Отказаться от динамического bypass
- При старте включать ВСЁ: Fragment + Disorder + Fake + DROP_RST + DoH
- Pipeline только диагностирует и показывает результаты
- Минус: избыточная нагрузка, не все стратегии совместимы

**Вариант B (правильный):** Интегрировать BypassCoordinator
- После ClassifierWorker вызывать `BypassCoordinator.AutoFixAsync(host, testResult)`
- Координатор пробует стратегии по одной, кеширует работающие
- Проблема "глобальный bypass" — решить через очередь операций или per-host фильтр WinDivert

**Вариант C (компромисс):** Двухфазная диагностика
- Фаза 1: Тестируем БЕЗ bypass, собираем список проблемных хостов
- Фаза 2: Для каждого проблемного хоста пробуем стратегии последовательно
- Результат: персональный профиль bypass для приложения

### Вопросы для проработки

- [ ] TesterWorker — таймауты (3 сек) оптимальны? Retry при ошибке?
- [ ] ClassifierWorker — логика классификации корректна? Все типы блокировок учтены?
- [ ] Очереди unbounded — что если TesterWorker не успевает? Backpressure?
- [ ] Нужен ли вообще pipeline из 3 worker'ов или можно упростить до простого foreach?

---

## 10. WinDivertBypassManager — обход блокировок

### Описание

Низкоуровневое управление обходом через драйвер WinDivert.

### Состояния

```csharp
enum BypassState { 
    Disabled,   // Выключен
    Enabling,   // Включается
    Enabled,    // Работает
    Disabling,  // Выключается
    Faulted     // Ошибка
}
```

### TLS стратегии

```csharp
enum TlsBypassStrategy {
    None,          // Без TLS манипуляций
    Fragment,      // Фрагменты в порядке 1→2
    Disorder,      // Фрагменты в порядке 2→1 (иногда эффективнее)
    Fake,          // Fake пакет с коротким TTL
    FakeFragment,  // Fake + Fragment
    FakeDisorder   // Fake + Disorder
}
```

### Внутренние Worker'ы

1. **RstBlockerWorker** (приоритет 0) — перехватывает TCP RST пакеты от провайдера, не пропускает их
2. **TlsFragmenterWorker** (приоритет 200) — перехватывает TLS ClientHello, разбивает на фрагменты
3. **RedirectorWorker** (приоритет 0) — перенаправление трафика (для DoH?)

### Применение bypass

```csharp
// Вызывается из MainViewModel.ApplyBypassOptionsAsync()
await _bypassManager.EnableAsync(profile);

// profile содержит:
// - DropTcpRst: bool
// - TlsStrategy: TlsBypassStrategy
// - TlsFirstFragmentSize: int (по умолчанию 2 байта)
```

### Связи

- **← Блок 3:** MainViewModel создаёт и хранит экземпляр
- **← Блок 5:** `ApplyBypassOptionsAsync()` вызывает `EnableAsync()`
- **← Блок 7:** FlowMonitor переключает режим при активном bypass
- **← Блок 9:** Pipeline ДОЛЖЕН вызывать для динамического bypass (но не вызывает)

### Проблемы

**ВОПРОС: Фильтр WinDivert**  
На какой трафик срабатывает? Весь HTTPS или только определённые IP/порты?  
**Нужно проверить:** Если весь — это может ломать другие приложения.

**ВОПРОС: TlsFirstFragmentSize = 2**  
Почему 2 байта? Это оптимально? Разные провайдеры могут требовать разные размеры.  
**Нужно проверить:** Экспериментировать с размерами.

**ВОПРОС: Приоритеты worker'ов**  
Что значит приоритет 0 vs 200? Кто первый обрабатывает пакет?  
**Нужно документировать.**

**ВОПРОС: Fake TTL**  
Как работает? Какой TTL? Почему это обманывает DPI?  
**Нужно документировать.**

**ВОПРОС: Состояние Faulted**  
Когда возникает? Как восстанавливаться? Показывается ли пользователю?  
**Нужно проверить обработку ошибок.**

---

## 11. OverlayWindow — оверлей диагностики

### Описание

Отдельное окно поверх всех, показывает прогресс диагностики:
- Текущий статус
- Количество соединений
- Количество событий
- Кнопка "Остановить"

Позиционируется в правом нижнем углу экрана.

### Silence Detection

Если нет новых соединений больше 60 секунд:
```csharp
var continueCapture = await overlay.ShowSilencePromptAsync(60);
// true = продолжить, false = завершить
```

### Связи

- **← Блок 6:** Создаётся в `RunLivePipelineAsync()`
- **→ Блок 8:** `onSilenceDetected` callback для TrafficAnalyzer

### Проблемы

**ВОПРОС: Нужен ли отдельный overlay?**  
Почему не показывать прогресс в главном окне? Overlay загораживает другие приложения.  
**Решение:** Рассмотреть отказ от overlay, встроить прогресс в MainWindow.

**ВОПРОС: Позиционирование на мульти-мониторе**  
"Правый нижний угол" — какого монитора? Основного? Где целевое приложение?  
**Нужно проверить поведение.**

**ВОПРОС: Silence 60 сек hardcoded**  
Почему 60? Можно ли настроить?  
**Решение:** Вынести в константу/настройки.

---

## 12. Модели данных

### Основные модели

**HostDiscovered** — обнаруженное соединение (из FlowMonitor)
```csharp
record HostDiscovered(IPAddress RemoteIp, ushort RemotePort, ...);
```

**HostTested** — результат тестирования
```csharp
record HostTested(
    HostDiscovered Host,
    bool DnsOk, bool TcpOk, bool TlsOk,
    string? DnsStatus, string? Hostname,
    int? TcpLatencyMs, string? BlockageType,
    DateTime TestedAt
);
```

**HostBlocked** — классифицированная блокировка
```csharp
record HostBlocked(
    HostTested TestResult,
    string BypassStrategy,    // "DROP_RST", "TLS_FRAGMENT", etc.
    string RecommendedAction  // "OK", описание проблемы
);
```

**BypassProfile** — профиль bypass для WinDivert
```csharp
class BypassProfile {
    bool DropTcpRst;
    bool FragmentTlsClientHello;
    TlsBypassStrategy TlsStrategy;
    int TlsFirstFragmentSize;
    int TlsFragmentThreshold;
    IReadOnlyList<BypassRedirectRule> RedirectRules;
}
```

**GameProfile** — профиль приложения (результат диагностики)
```csharp
class GameProfile {
    string Name;
    string ExePath;
    List<TargetEndpoint> Targets;
}
```

### Связи

- **Блок 8:** TrafficAnalyzer создаёт HostDiscovered, генерирует GameProfile
- **Блок 9:** Pipeline преобразует HostDiscovered → HostTested → HostBlocked
- **Блок 10:** WinDivertBypassManager принимает BypassProfile

### Проблемы

**ПРОБЛЕМА: Дублирование моделей**  
`TestResult` (UI), `HostTested` (pipeline), `TargetReport` (output) — похожие модели для разных целей.  
**Вопрос:** Можно ли консолидировать? Или разделение оправдано?

**ВОПРОС: GameProfile vs BypassProfile**  
Что куда сохраняется? Как связаны? Используется ли GameProfile после диагностики?

**ВОПРОС: Profiles/Default.json**  
Что в нём? Загружается при старте, но зачем?

---

## 13. UI/UX

### Текущий интерфейс

Material Design через MaterialDesignInXaml. Основные элементы:
- Bypass Control Panel (toggle кнопки)
- Выбор exe файла
- Кнопка "Начать диагностику"
- Лог результатов
- Overlay окно во время диагностики

### Проблемы юзабилити

**ПРОБЛЕМА: Терминология**  
"Fragment", "Disorder", "DROP RST", "DoH" — непонятно обычному пользователю.  
**Решение:** Tooltips с объяснениями, или режим "для новичков" с простыми описаниями.

**ПРОБЛЕМА: Нет режима "одна кнопка"**  
Пользователь хочет: "Сделай чтобы YouTube работал". Сейчас: выбери exe, нажми диагностику, смотри результаты, включи нужные опции...  
**Решение:** Режим "Автоматический обход" — включить всё и не спрашивать.

**ПРОБЛЕМА: Что делать с "❌"?**  
Диагностика показывает `❌ host:port | TCP:✗ | TCP_RST`. И что? Как пользователю это исправить?  
**Решение:** После ❌ показывать кнопку "Исправить" или автоматически применять рекомендуемую стратегию.

**ВОПРОС: Результаты диагностики**  
Что пользователь должен делать после диагностики? Сейчас просто показываем лог.  
**Решение:** Чёткий call-to-action: "Обнаружены блокировки. [Применить обход]"

**ВОПРОС: Первый запуск**  
Что видит новый пользователь? Понятно ли что делать?  
**Решение:** Wizard или onboarding с объяснением.

---

## 14. Файловая структура

### Текущая структура

```
ISP_Audit/
├── Program.cs                    # Точка входа
├── App.xaml(.cs)                 # WPF Application
├── MainWindow.xaml(.cs)          # Главное окно
├── Config.cs                     # CLI конфиг (удалить?)
├── AuditRunner.cs                # CLI runner (удалить?)
│
├── ViewModels/
│   └── MainViewModel.cs          # Главная логика (~2400 строк)
│
├── Bypass/
│   ├── WinDivertBypassManager.cs # Управление WinDivert
│   ├── BypassProfile.cs          # Профиль bypass
│   ├── BypassCoordinator.cs      # Координатор (НЕ ИСПОЛЬЗУЕТСЯ!)
│   ├── StrategyMapping.cs        # Маппинг стратегий
│   └── WinDivertNative.cs        # P/Invoke
│
├── Core/
│   ├── Interfaces/               # IHostTester, IBlockageClassifier, etc.
│   ├── Models/                   # HostDiscovered, HostTested, etc.
│   └── Modules/
│       ├── StandardHostTester.cs
│       ├── StandardBlockageClassifier.cs
│       └── WinDivertBypassEnforcer.cs  # (НЕ ИСПОЛЬЗУЕТСЯ!)
│
├── Utils/
│   ├── TrafficAnalyzer.cs        # Анализ трафика
│   ├── LiveTestingPipeline.cs    # Pipeline тестирования
│   ├── FlowMonitorService.cs     # Мониторинг соединений
│   ├── NetworkMonitorService.cs  # Захват DNS
│   ├── DnsParserService.cs       # Парсинг DNS
│   └── PidTrackerService.cs      # Отслеживание PID
│
├── Windows/
│   ├── OverlayWindow.xaml(.cs)   # Оверлей
│   └── TestDetailsWindow.xaml(.cs)
│
├── Controls/                     # WPF контролы
├── Converters/                   # WPF конвертеры
├── Wpf/                          # Ещё WPF? Дублирование?
│
├── Models/                       # Ещё модели? Дублирование с Core/Models?
├── Output/                       # Что здесь?
│
├── Profiles/
│   └── Default.json              # Профиль (нужен?)
│
├── native/
│   ├── WinDivert64.sys           # Драйвер
│   └── WinDivert.dll             # Библиотека
│
├── TestNetworkApp/               # Тестовое приложение (нужно?)
├── agents/                       # Dev инструменты (нужны в репо?)
└── docs/                         # Документация (актуальна?)
```

### Проблемы

**ПРОБЛЕМА: Мёртвый код**  
- `BypassCoordinator` — существует, не используется
- `WinDivertBypassEnforcer` — создаётся, не вызывается
- `AuditRunner`, `Config` — CLI legacy

**ПРОБЛЕМА: Дублирование папок**  
- `Models/` и `Core/Models/`
- `Controls/`, `Converters/`, `Wpf/` — три папки для WPF

**ПРОБЛЕМА: Неясное назначение**  
- `Output/` — что там?
- `TestNetworkApp/` — тестовое приложение в основном проекте?
- `agents/` — dev tools в репозитории?

### Задачи по очистке

- [ ] Удалить CLI код: `AuditRunner`, `Config.ParseArgs`, `RunCliAsync`
- [ ] Решить: интегрировать `BypassCoordinator` или удалить
- [ ] Решить: исправить `WinDivertBypassEnforcer` или удалить
- [ ] Консолидировать папки моделей
- [ ] Консолидировать WPF папки
- [ ] Проверить и почистить `Output/`, `TestNetworkApp/`, `agents/`

---

## 15. Системные особенности

### VPN детекция

```csharp
NetUtils.LikelyVpnActive()  // Проверяет TAP/TUN адаптеры
```

**Проблема:** Не детектирует WireGuard, встроенный Windows VPN, корпоративные VPN.

### Права администратора

WinDivert требует прав администратора. Без них:
- Bypass не работает
- FlowMonitor в WinDivert режиме не работает

**Текущее поведение:** Тихо не включаем bypass, кнопки неактивны.  
**Проблема:** Пользователь не понимает почему не работает.

### WinDivert драйвер

- Автоматически устанавливается при первом использовании
- Требует подписи (может блокироваться Secure Boot)
- Может триггерить антивирусы

### Windows Defender / Антивирусы

Потенциальные проблемы:
- Блокировка exe как подозрительного
- Блокировка WinDivert как rootkit-подобного
- Предупреждения SmartScreen

### Вопросы для проработки

- [ ] VPN детекция — добавить WireGuard, Windows VPN?
- [ ] UAC — правильно ли настроен manifest?
- [ ] Антивирусы — нужны ли инструкции для пользователей?
- [ ] Подпись exe — нужна ли для избежания предупреждений?
- [ ] Удаление — как полностью удалить драйвер WinDivert?

---

## Резюме: Главные проблемы

### Критические

1. **Bypass не применяется динамически** (Блок 9)  
   Pipeline выбирает стратегию, но не применяет. `_bypassEnforcer` не используется.  
   **Результат:** Если при старте включённые стратегии не подходят — YouTube не работает.

2. **Мёртвый код** (Блок 14)  
   `BypassCoordinator`, `WinDivertBypassEnforcer` написаны, но не интегрированы.

### Важные

3. **Порядок инициализации** (Блок 3)  
   Bypass включается до проверки VPN.

4. **Нет обратной связи пользователю** (Блок 13)  
   Диагностика показывает проблемы, но не предлагает решений.

5. **CLI legacy** (Блок 1)  
   Ненужный код усложняет проект.

### Требуют уточнения

6. **Конфликт WinDivert handles** (Блок 7)  
   Костыль с переключением режимов FlowMonitor.

7. **Терминология UI** (Блок 13)  
   Непонятно обычному пользователю.

8. **Дублирование структуры** (Блок 14)  
   Несколько папок для одного и того же.
