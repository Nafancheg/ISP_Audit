# Полный аудит репозитория ISP_Audit v2

**Дата**: 09.12.2025  
**Версия проекта**: .NET 9, WPF  
**Режим**: GUI-only (WinExe)  

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
│  ├── BypassController (toggle bypass)                           │
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
│  └── TrafficEngine (WinDivert bypass)                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     CORE LAYER                                  │
│  ├── Core/Modules/StandardHostTester                            │
│  ├── Core/Modules/StandardBlockageClassifier                    │
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
│  ├── DnsParserService (SNI/DNS парсинг)                        │
│  ├── PidTrackerService (отслеживание PID)                      │
│  ├── TcpConnectionWatcher (IP Helper API polling)              │
│  ├── NoiseHostFilter (фильтрация шумных хостов)                │
│  └── FixService (DNS fix через netsh)                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    BYPASS LAYER                                 │
│  ├── BypassCoordinator (выбор стратегии)                       │
│  ├── BypassFilter (TLS fragment/disorder/fake)                 │
│  ├── BypassProfile (конфигурация)                              │
│  ├── StrategyMapping (блокировка → стратегия)                  │
│  └── WinDivertNative (P/Invoke)                                │
└─────────────────────────────────────────────────────────────────┘
```

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
| `DiagnosticOrchestrator` | Слишком много обязанностей: UI, overlay, процессы, WinDivert | 824 строки |
| `TestResultsManager` | Парсинг + хранение + здоровье + UI обновления | 717 строк |
| `BypassController` | Bypass + DoH + VPN детект + совместимость | 647 строк |

### 3.3 Хаотичные зависимости

| Проблема | Детали |
|----------|--------|
| Namespace смешивание | `IspAudit`, `ISPAudit`, `ISPAudit.ViewModels`, `IspAudit.Utils` |
| Глобальное состояние | `Program.Targets`, `Config.ActiveProfile`, `NoiseHostFilter.Instance` |
| Дублирование моделей | `Target` (Models/), `TargetDefinition` (root), `Target` (ISPAudit.Models) |

### 3.4 Требуют рефакторинга

| Файл | Приоритет | Причина |
|------|-----------|---------|
| `DiagnosticOrchestrator.cs` | 🔴 Высокий | Разделить на StartupManager, OverlayManager, ProcessMonitor |
| `TestResultsManager.cs` | 🔴 Высокий | Выделить парсер сообщений в отдельный класс |
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
| `ARCHITECTURE_V2.md` | Описывает планируемую архитектуру, не текущую |

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
- .github/copilot-instructions.md — актуализировать архитектуру
- Добавить ARCHITECTURE_ACTUAL.md с текущим состоянием
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
            │   ├── TrafficEngine
            │   │   └── BypassFilter
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
| 4 | Unbounded channels | LiveTestingPipeline.cs | Заменить на `BoundedChannel` (capacity: 1000) |
| 5 | TLS без hostname | StandardHostTester.cs:148 | Добавить `tlsStatus = "SKIPPED (no hostname)"` |

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

**Статус документа:** Актуален на 09.12.2025  
**Объединён с:** full_repo_audit.md (runtime проблемы верифицированы)
