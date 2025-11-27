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
**ОТВЕТ:** Проверил `Profiles/Default.json` — содержит список тестовых целей (YouTube, Google DNS, Cloudflare, Discord) для режима "базовый тест сервисов". Используется ТОЛЬКО если включить CheckBox "Тест базовых сервисов" в UI.  
**Решение:** 
1. Переименовать `Default.json` → `BasicTestTargets.json` (более понятное название)
2. Загружать ТОЛЬКО при включении режима базового теста, а не при каждом запуске
3. Удалить `Config.SetActiveProfile()` из `Program.Main()` — это CLI legacy

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
"50px от левого края, центр по вертикали" — почему такое позиционирование?  
**ОТВЕТ:** Проверил код:
```csharp
this.Left = workArea.Left + 50; // Отступ 50px от левого края
this.Top = workArea.Top + (workArea.Height - this.Height) / 2;
```
Использует `SystemParameters.WorkArea` — это область без taskbar. На мульти-мониторе вернёт только основной монитор.
**Решение:** Оставить как есть — простое решение работает. Но добавить проверку границ:
```csharp
if (this.Left + this.Width > workArea.Right) 
    this.Left = workArea.Right - this.Width - 10;
```

**ВОПРОС: Обработка ошибок при старте**  
Что если MainViewModel.constructor бросит исключение?  
**ОТВЕТ:** Проверил — нет try/catch вокруг создания MainViewModel в XAML. Будет необработанное исключение и крэш.  
**План:** Добавить global exception handler в `App.xaml.cs`:
```csharp
protected override void OnStartup(StartupEventArgs e)
{
    DispatcherUnhandledException += (s, args) => {
        MessageBox.Show($"Ошибка: {args.Exception.Message}", "ISP Audit");
        args.Handled = true;
    };
    base.OnStartup(e);
}
```

**ВОПРОС: Размер окна**  
Фиксированный или адаптивный?  
**ОТВЕТ:** Проверил `MainWindow.xaml`:
```xml
Height="800" Width="1400"
MinHeight="600" MinWidth="1000"
```
Фиксированный размер 1400x800, но с минимумом 1000x600. Пользователь может изменять размер.  
**Решение:** OK, адекватные значения.

**ВОПРОС: DPI awareness**  
Правильно ли работает на High DPI?  
**ОТВЕТ:** WPF автоматически поддерживает DPI awareness. В `app.manifest` явно указано:
```xml
<supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />  <!-- Windows 10 -->
```
Плюс WPF использует device-independent pixels по умолчанию.  
**Решение:** OK, DPI должен работать корректно.

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
**ОТВЕТ:** Проверил `Models/FixHistory.cs`:
- `FixHistoryManager.Load()` — загружает из `%APPDATA%\ISP_Audit\fix_history.json`
- Хранит `AppliedFix` записи: тип исправления (DNS, Firewall, Hosts, Bypass), время, оригинальные настройки для rollback
- Используется для кнопки "Откатить изменения"

```csharp
public enum FixType {
    DnsChange,    // Смена DNS серверов + DoH
    FirewallRule, // Правила Windows Firewall
    HostsFile,    // Изменение hosts файла
    Bypass        // WinDivert обход
}
```
**Решение:** Функционал полезный, оставить. Но нужно проверить:
- [ ] Работает ли rollback реально?
- [ ] Показывается ли история пользователю где-то в UI?

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
Есть только start/running/done. А если диагностика завершилась с ошибкой?  
**ОТВЕТ:** Проверил `RunLivePipelineAsync()`:
```csharp
catch (OperationCanceledException) {
    ScreenState = "done";
    UpdateUserMessage("Диагностика отменена пользователем.");
}
catch (Exception ex) {
    MessageBox.Show($"Ошибка: {ex.Message}");
    ScreenState = "done";
    UpdateUserMessage($"Ошибка диагностики: {ex.Message}");
}
```
Ошибки обрабатываются, но состояние всё равно "done". Различие — в `UserMessage`.  
**Решение:** OK для простого приложения. Но можно добавить `IsError` флаг для другого стиля UI.

**ВОПРОС: Состояние "cancelled"**  
Если пользователь нажал "Остановить" — это "done"?  
**ОТВЕТ:** Да, это "done" с сообщением "Диагностика отменена пользователем."  
**Решение:** OK, дополнительное состояние не нужно.

**ВОПРОС: Переход start → start**  
Можно ли сбросить состояние не запуская диагностику?  
**ОТВЕТ:** Да, через команду `SetStateCommand` с параметром "start". Используется в кнопке "Новая диагностика".  
**Решение:** OK.

**ВОПРОС: Персистентность состояния**  
Что если закрыть приложение во время "running"?  
**ОТВЕТ:** Состояние не сохраняется. При следующем запуске — всегда "start". Данные диагностики теряются.  
**План:** Опционально — автосохранение частичных результатов в `%APPDATA%\ISP_Audit\last_session.json`

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
**ОТВЕТ:** Проверил XAML — уже есть tooltips! Например:
```xml
ToolTip="TLS Fragment&#x0a;Фрагментация ClientHello (обычный порядок)"
ToolTip="TLS Disorder&#x0a;Фрагменты в ОБРАТНОМ порядке&#x0a;(сначала 2-й, потом 1-й) — эффективнее против DPI"
```
**Решение:** OK, tooltips есть. Можно сделать их ещё понятнее для обычных пользователей, но базовая информация присутствует.

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
**ОТВЕТ:** Hardcoded в `RunLivePipelineAsync()`. 10 минут — разумный дефолт для запуска игры и начала игровой сессии.  
**План:** Вынести в константу с комментарием. Настройки пользователя не нужны — усложнит UI.

**ВОПРОС: Сохранение профиля в Profiles/**  
Что сохраняется? Зачем? Используется ли потом?  
**ОТВЕТ:** Проверил `MainViewModel.cs` (строки 1680-1700):
```csharp
var profilePath = Path.Combine(profilesDir, $"{exeName}_{timestamp}.json");
profile.ExePath = targetExePath;
profile.Name = $"{exeName} (Captured {DateTime.Now:g})";
var json = JsonSerializer.Serialize(profile, jsonOptions);
await File.WriteAllTextAsync(profilePath, json);
```
Сохраняется `GameProfile` — список обнаруженных целей (IP:Port) для повторного использования.  
**Используется ли:** НЕТ! Файлы создаются, но нигде не загружаются для повторного использования.  
**План:**
1. Либо удалить сохранение профилей (мёртвый код)
2. Либо добавить функционал "Загрузить предыдущую диагностику" в UI

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
**ОТВЕТ:** Проверил `FlowMonitorService.cs`:
```csharp
public bool UseWatcherMode { get; set; }

if (UseWatcherMode) {
    _monitorTask = Task.Run(() => RunWatcherLoop(_cts.Token)); // TcpConnectionWatcher (polling)
} else {
    _monitorTask = Task.Run(() => RunMonitorLoop(_cts.Token)); // WinDivert Flow Layer
}
```
Конфликт происходит когда оба используют Network layer. Решение — polling через IP Helper API.  
**Текущее решение:** Переключение FlowMonitor в polling режим когда bypass активен. Это костыль, но работает.  
**План:** Оставить как есть — polling достаточно надёжен (опрос таблицы соединений раз в 1 сек).

**ПРОБЛЕМА: Два режима FlowMonitor**  
Код сложнее из-за поддержки двух режимов. Если polling работает стабильно — зачем WinDivert Flow?  
**ОТВЕТ:** WinDivert Flow точнее и быстрее (событийная модель vs polling). Но с bypass активным — нельзя использовать.  
**План:** Оставить оба режима:
- WinDivert Flow — когда bypass выключен (редкий сценарий "только диагностика")  
- Polling — когда bypass включён (основной сценарий)

**ВОПРОС: WMI для дочерних процессов**  
Используется WMI для поиска дочерних процессов. WMI медленный.  
**ОТВЕТ:** Проверил `PidTrackerService.cs` — использует WMI query `SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = X`.  
**План:** Оставить как есть. WMI вызывается раз в 0.5 сек, это приемлемо. Альтернативы (Job Objects, ETW) сложнее.

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
Что делает `enableAutoBypass = false`? Если bypass уже включён при старте — зачем этот параметр?  
**ОТВЕТ:** Проверил код — `enableAutoBypass` передаётся в `LiveTestingPipeline`, но там игнорируется (bypass_enforcer не вызывается). Это legacy параметр от задуманного, но не реализованного функционала "авто-обход при обнаружении блокировки".  
**План:** Удалить параметр как мёртвый код после решения проблемы с _bypassEnforcer (блок 9).

**ВОПРОС: GameProfile — зачем генерируется?**  
В конце создаётся GameProfile. Где он используется?  
**ОТВЕТ:** `GameProfile` — результат диагностики (список `TargetDefinition` с хостами и портами). Сохраняется в `Profiles/{exeName}_{timestamp}.json`, но **нигде не загружается** для повторного использования.  
**План:** См. вопрос "Сохранение профиля в Profiles/" выше — либо удалить, либо добавить функционал загрузки.

**ВОПРОС: Status Reporter каждую секунду**  
Оверхед? Почему не event-driven?  
**ОТВЕТ:** Polling каждую секунду нужен для:
1. Проверки что целевые процессы ещё живы
2. Silence detection (60 сек без новых соединений)
Это не оверхед — простой цикл без тяжёлых операций.  
**План:** OK, оставить.

**ВОПРОС: Обогащение hostname**  
Пункт 5 — "обогащение hostname для соединений". Что если DNS недоступен?  
**ОТВЕТ:** Используется `NetUtils.ResolveWithFallbackAsync()` — сначала системный DNS, потом DoH (Cloudflare). Если оба не работают — IP остаётся без hostname.  
**План:** OK, fallback есть.

**ВОПРОС: Много параметров**  
10 параметров в методе — сложно использовать.  
**ОТВЕТ:** Да, это code smell. Метод принимает:
```csharp
AnalyzeProcessTrafficAsync(
    targetPid, captureTimeout, flowMonitor, pidTracker, dnsParser, 
    progress, cancellationToken, enableLiveTesting, enableAutoBypass, 
    bypassManager, onSilenceDetected)
```
**План:** Рефакторинг в объект-конфигурацию:
```csharp
record AnalyzerConfig(
    int TargetPid,
    TimeSpan? CaptureTimeout,
    FlowMonitorService FlowMonitor,
    // ...
);
```

**ВОПРОС: LiveTestingPipeline создаётся внутри**  
Tight coupling — TrafficAnalyzer создаёт LiveTestingPipeline внутри себя.  
**ОТВЕТ:** Да, это нарушение DI/IoC. Pipeline создаётся внутри:
```csharp
if (enableLiveTesting) {
    pipeline = new LiveTestingPipeline(pipelineConfig, progress, bypassManager, dnsParser);
}
```
**План:** Передавать pipeline как параметр или использовать factory. Но это низкий приоритет — код работает.

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

- [x] TesterWorker — таймауты (3 сек) оптимальны? **ОТВЕТ:** Да, 3 сек — стандартный TCP connect timeout. Retry не нужен — одна неудача уже информативна.
- [ ] ClassifierWorker — логика классификации корректна? Все типы блокировок учтены? **ПЛАН:** Проверить `StandardBlockageClassifier.cs` отдельной задачей.
- [x] Очереди unbounded — что если TesterWorker не успевает? **ОТВЕТ:** Очереди на основе `Channel<T>` без лимита. В реальности хостов немного (10-50), backpressure не нужен.
- [ ] Нужен ли вообще pipeline из 3 worker'ов? **ПЛАН:** Если упростить до foreach — потеряем параллельность. Оставить pipeline, но ИСПОЛЬЗОВАТЬ `_bypassEnforcer`!

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
**ОТВЕТ:** Проверил `WinDivertBypassManager.cs`:
```csharp
// Глобальный HTTPS фильтр (по умолчанию)
return "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0";

// Хост-специфичный фильтр (если указан targetIp)
return $"outbound and ip.DstAddr == {targetIp} and tcp.DstPort == {targetPort} and tcp.PayloadLength > 0";
```
Сейчас используется **глобальный фильтр** — все исходящие HTTPS соединения.  
**Проблема:** Может влиять на другие приложения (браузер, антивирус, обновления Windows).  
**План:** Рассмотреть per-process фильтрацию через `processId` параметр WinDivert (если поддерживается).

**ВОПРОС: TlsFirstFragmentSize = 2**  
Почему 2 байта? Это оптимально?  
**ОТВЕТ:** 2 байта — "ультра-экстремальная фрагментация" по комментарию в коде. Идея: ClientHello разбивается на фрагменты, первый содержит только тип записи (2 байта). DPI не может собрать полный SNI.  
**План:** Оставить как есть. Если 2 не работает для какого-то провайдера — это другая стратегия (Disorder, Fake).

**ВОПРОС: Приоритеты worker'ов**  
Что значит приоритет 0 vs 200? Кто первый обрабатывает пакет?  
**ОТВЕТ:** Из кода:
```csharp
const short PriorityRstBlocker = 0;     // Высокий приоритет
const short PriorityTlsFragmenter = 200; // Низкий приоритет (после RST blocker)
```
WinDivert: меньший приоритет = раньше обработка. Т.е. RST blocker (0) обрабатывает пакеты РАНЬШЕ TLS fragmenter (200).  
**План:** OK, логично — сначала дропаем RST, потом фрагментируем TLS.

**ВОПРОС: Fake TTL**  
Как работает? Какой TTL? Почему это обманывает DPI?  
**ОТВЕТ:** Проверил `FakeStrategy` в коде:
- Отправляет поддельный пакет с коротким TTL (обычно 1-3)
- Пакет "умирает" на первом хопе, не доходит до сервера
- Но DPI видит этот пакет и может на него среагировать, "забывая" про настоящий
**План:** Документировать в README для пользователей.

**ВОПРОС: Состояние Faulted**  
Когда возникает? Как восстанавливаться?  
**ОТВЕТ:** Проверил код:
```csharp
catch (Exception ex) {
    _state = BypassState.Faulted;
    _lastError = ex;
    OnStateChanged();
}
```
Faulted при любой ошибке WinDivert (нет драйвера, нет прав, конфликт handles).  
**Показывается ли пользователю:** Нет, только через `_lastError`. UI не реагирует на Faulted.  
**План:** Добавить UI индикацию ошибки bypass — красный бейдж или уведомление.

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
**ОТВЕТ:** Overlay нужен чтобы:
1. Пользователь видел статус даже когда главное окно свёрнуто
2. Кнопка "Остановить" всегда доступна
3. Silence prompt показывается поверх игры
**План:** Оставить overlay, но добавить возможность его скрыть (кнопка "Свернуть в трей").

**ВОПРОС: Позиционирование на мульти-мониторе**  
"Правый нижний угол" — какого монитора?  
**ОТВЕТ:** Проверил `OverlayWindow.xaml.cs`:
```csharp
var desktop = SystemParameters.WorkArea;
this.Left = desktop.Right - width - 20;
this.Top = desktop.Bottom - height - 20;
```
`SystemParameters.WorkArea` — область основного монитора.  
**План:** OK для большинства случаев. Если нужно — можно позиционировать на том же мониторе где запущена игра.

**ВОПРОС: Silence 60 сек hardcoded**  
Почему 60? Можно ли настроить?  
**ОТВЕТ:** 60 секунд — разумный дефолт. Если игра загружается дольше — пользователь нажмёт "Продолжить".  
**План:** Вынести в константу. Настройки пользователя не нужны.

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
**ОТВЕТ:** Проверил:
- `TestResult` (Models/) — UI модель с `INotifyPropertyChanged` для DataGrid
- `HostTested` (Core/Models/) — pipeline модель с результатами тестов
- `TargetDefinition` (TargetModels.cs) — определение цели (host, port, service)
**План:** Консолидация сложна — разные модели для разных слоёв. Оставить как есть, но добавить маппинг-методы между ними.

**ВОПРОС: GameProfile vs BypassProfile**  
Что куда сохраняется? Как связаны?  
**ОТВЕТ:**
- `GameProfile` — список обнаруженных целей (хосты, порты). Сохраняется в `Profiles/{exeName}_{timestamp}.json`. НЕ используется повторно.
- `BypassProfile` — настройки WinDivert (стратегия TLS, DROP_RST, redirect rules). В память, не сохраняется.
**План:** Это разные сущности. Но `GameProfile` — мёртвый код (см. выше).

**ВОПРОС: Profiles/Default.json**  
Что в нём? Загружается при старте, но зачем?  
**ОТВЕТ:** Содержит список тестовых целей для "базового теста сервисов" (YouTube, Google DNS, Discord).  
**План:** Переименовать в `BasicTestTargets.json`, загружать только при включении checkbox.

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
Пользователь хочет: "Сделай чтобы YouTube работал". Сейчас: выбери exe, нажми диагностику...  
**ОТВЕТ:** Частично решено — bypass включается автоматически при старте с админ правами:
```csharp
// InitializeBypassOnStartupAsync()
_isFragmentEnabled = true;
_isDropRstEnabled = true;
_isDoHEnabled = true;
await ApplyBypassOptionsAsync();
```
**План:** Добавить режим "Быстрый старт" — одна большая кнопка "Обход блокировок" без диагностики.

**ПРОБЛЕМА: Что делать с "❌"?**  
Диагностика показывает проблемы, но как пользователю это исправить?  
**ОТВЕТ:** Частично решено — есть кнопка "Исправить" и автоматическое определение стратегии:
```csharp
if (strategy != "NONE" && strategy != "UNKNOWN") {
    result.Fixable = true;
    result.FixType = FixType.Bypass;
    result.FixInstructions = $"Применить стратегию обхода: {strategy}";
}
```
**План:** Проверить что `_bypassEnforcer` действительно применяет стратегию при нажатии "Исправить".

**ВОПРОС: Результаты диагностики**  
Что пользователь должен делать после диагностики?  
**ОТВЕТ:** Сейчас показывается DataGrid с результатами и счётчики Pass/Fail/Warn. Кнопки "Исправить" для проблемных строк.  
**План:** Добавить summary-блок с рекомендацией: "Обнаружено X проблем. Рекомендация: [Применить автоисправление]"

**ВОПРОС: Первый запуск**  
Что видит новый пользователь?  
**ОТВЕТ:** Видит главное окно в состоянии "start" с текстом "Готов к диагностике". Bypass panel видна если есть админ права.  
**План:** Добавить краткую инструкцию или wizard для первого запуска (низкий приоритет).

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

**ОТВЕТ:**
- `Output/` — модели результатов для CLI отчётов: `FirewallTestResult.cs`, `IspTestResult.cs`, `ReportWriter.cs` и т.д. **Это CLI legacy — можно удалить.**
- `TestNetworkApp/` — тестовое консольное приложение для диагностики. Делает запросы к YouTube, Google, Discord. **Используется** в `WarmupFlowWithTestNetworkAppAsync()` для "прогрева" Flow layer и baseline тестов.
- `agents/` — инструменты для multi-agent разработки (task owner, research, planning, coding agents). **Dev tools — в .gitignore или отдельный репо.**

### Задачи по очистке

- [ ] Удалить CLI код: `AuditRunner.cs`, `Config.ParseArgs()`, `RunCliAsync()`
- [ ] Удалить `Output/` папку (CLI legacy)
- [ ] Решить: интегрировать `BypassCoordinator` или удалить **→ ИНТЕГРИРОВАТЬ (блок 9)**
- [ ] Решить: исправить `WinDivertBypassEnforcer` или удалить **→ ИСПОЛЬЗОВАТЬ (блок 9)**
- [ ] Консолидировать папки моделей (`Models/` + `Core/Models/`) — низкий приоритет
- [ ] `TestNetworkApp/` — оставить, используется
- [ ] `agents/` — перенести в .gitignore или отдельный репо

---

## 15. Системные особенности

### VPN детекция

```csharp
NetUtils.LikelyVpnActive()  // Проверяет TAP/TUN адаптеры
```

**ОТВЕТ:** Проверил `NetUtils.cs` — детектирует по описанию адаптера:
```csharp
bool looksVpn = type == NetworkInterfaceType.Tunnel
    || name.Contains("vpn") || desc.Contains("vpn")
    || desc.Contains("wintun") || desc.Contains("wireguard")
    || desc.Contains("openvpn") || desc.Contains("tap-") || desc.Contains("tap ")
    || desc.Contains("tun") || desc.Contains("ikev2");
```
**Уже включает:** WireGuard, OpenVPN, IKEv2, TAP/TUN адаптеры.  
**Не детектирует:** Встроенный Windows VPN (PPTP/L2TP без TAP), некоторые корпоративные VPN.  
**План:** OK для большинства случаев. Полная детекция VPN невозможна.

### Права администратора

**ОТВЕТ:** В `app.manifest` настроено:
```xml
<requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
```
Приложение **требует** админ прав. При запуске без админа — UAC prompt.  
**План:** OK, WinDivert требует админ.

**Текущее поведение:** Если нет прав — bypass не работает, кнопки задисейблены, но нет явного сообщения.  
**План:** Добавить предупреждение в UI "Запустите от администратора для полного функционала".

### Вопросы для проработки

- [x] VPN детекция — добавить WireGuard, Windows VPN? **ОТВЕТ:** WireGuard уже есть. Windows VPN детектируется частично.
- [x] UAC — правильно ли настроен manifest? **ОТВЕТ:** Да, `requireAdministrator`.
- [ ] Антивирусы — нужны ли инструкции для пользователей? **ПЛАН:** Добавить FAQ в README.
- [ ] Подпись exe — нужна ли для избежания предупреждений? **ПЛАН:** Да, для release версии нужен code signing certificate.
- [ ] Удаление — как полностью удалить драйвер WinDivert? **ПЛАН:** Документировать: `sc delete WinDivert` или использовать `WinDivertNative.WinDivertUnload()`

---

## Резюме: Главные проблемы и план действий

### Критические (блокируют работу)

1. **Bypass не применяется динамически** (Блок 9)  
   Pipeline выбирает стратегию, но не применяет. `_bypassEnforcer` не используется.  
   **Результат:** Если при старте включённые стратегии не подходят — сайт не работает.  
   **ПЛАН:**
   - [ ] Вызвать `_bypassEnforcer.EnforceAsync()` в UiWorker после классификации
   - [ ] Либо выбрать Вариант B (интеграция BypassCoordinator)
   - [ ] Тестировать на YouTube, Discord

2. **Мёртвый код занимает место** (Блок 14)  
   `BypassCoordinator`, `WinDivertBypassEnforcer` написаны, но не интегрированы. CLI legacy код.  
   **ПЛАН:**
   - [ ] Удалить CLI: `AuditRunner.cs`, `Config.ParseArgs()`, `Output/`
   - [ ] Интегрировать `BypassCoordinator` и `WinDivertBypassEnforcer` в pipeline (см. п.1)

### Важные (улучшение UX)

3. **Нет обратной связи при ошибках bypass** (Блок 10)  
   Состояние `Faulted` не показывается пользователю.  
   **ПЛАН:** Добавить UI индикацию ошибки (красный бейдж, notification).

4. **GameProfile сохраняется, но не используется** (Блок 8, 12)  
   Файлы `Profiles/{exeName}_{timestamp}.json` создаются, но не загружаются.  
   **ПЛАН:** Либо удалить сохранение, либо добавить "Загрузить предыдущую диагностику".

5. **Глобальный HTTPS фильтр WinDivert** (Блок 10)  
   Влияет на все приложения, не только целевое.  
   **ПЛАН:** Исследовать per-process фильтрацию (низкий приоритет).

### Технический долг (низкий приоритет)

6. **OutputType=Exe вместо WinExe** (Блок 1)  
   Мелькает консоль при запуске.  
   **ПЛАН:** Изменить в `.csproj`.

7. **10 параметров в TrafficAnalyzer** (Блок 8)  
   Code smell, сложно использовать.  
   **ПЛАН:** Рефакторинг в объект-конфигурацию.

8. **Нет global exception handler** (Блок 2)  
   Необработанные исключения → крэш.  
   **ПЛАН:** Добавить в `App.xaml.cs`.

### Документация

9. **Fake TTL стратегия не документирована** (Блок 10)  
   **ПЛАН:** Добавить описание в README.

10. **Удаление WinDivert не документировано** (Блок 15)  
    **ПЛАН:** Добавить инструкцию в README/FAQ.
