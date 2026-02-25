# ISP_Audit Copilot Instructions

## 1) Общие правила работы (СТРОГО)

### 1.1 Язык
**Язык общения**: Только русский язык. Все ответы, объяснения и диалоги вести исключительно на русском языке.

### 1.2 Комментарии в коде
Все комментарии в коде должны быть на русском языке.
Исключение: общепринятые технические термины (DNS, TCP, HTTP, WPF, GUI, CLI, WinDivert, P/Invoke и т.д.), которые не требуют перевода.

### 1.3 Документация
Используй MCP сервер Context7 для получения актуальной документации по библиотекам (.NET, WPF, MaterialDesign и т.д.).

### 1.4 Запрет самоуправства
- Запрещено менять архитектуру, публичные контракты и структуру каталогов без прямой необходимости для решаемой задачи.
- Запрещено “на всякий случай” рефакторить, переименовывать, разносить по папкам, вводить новые абстракции.
- Любые изменения, попадающие под критерии архитектурных (см. раздел 3.2), должны быть отражены в документации.

---

## 2) Качество и контроль (ОБЯЗАТЕЛЬНО)

### 2.1 Коммиты и пуши
**Один коммит = одна завершённая причина изменения** (feature/fix/refactor/docs).

**Запрещены сообщения коммита**: `fix`, `wip`, `tmp`, `update`, `changes`, `minor`, `edit`.

**Перед commit ОБЯЗАТЕЛЬНО**:
1) выполнить `git diff --stat`
2) написать краткое резюме изменений (2–4 строки) в отчёте агента

**Push**:
- `git push` делать только после смыслового коммита.
- Микро-итерации не пушить.

### 2.2 Обязательные проверки перед commit (без согласования)
После каждой итерации редактирования кода выполнять:

1) `dotnet build` (зелёный результат)
2) если в репозитории есть тестовые проекты: `dotnet test` (зелёный результат)
3) если настроен форматтер: `dotnet format --verify-no-changes` (или `dotnet format`)

Только после этого:
`git add -A` → `git commit -m "<кратко и по делу>"` → при необходимости `git push`.

---

## 3) Документация и актуализация (ОБЯЗАТЕЛЬНО)

### 3.1 Обновление документов
**При всех изменениях** фиксировать прогресс и задачи в `docs\TODO.md`.

**При изменении архитектуры, создании новых файлов, классов или процедур ОБЯЗАТЕЛЬНО обновлять**:
- `ARCHITECTURE_CURRENT.md`
- `docs\full_repo_audit_intel.md`

### 3.2 Что считается архитектурным изменением (без обсуждений)
Архитектурные изменения = любое из:
- новый `public` класс/интерфейс в Core/Services/Pipeline/Engine
- новый файл в ключевых папках (ViewModels, Orchestrator, TrafficEngine, LiveTestingPipeline)
- изменение потоков данных (progress/reporting/results)
- изменение жизненного цикла WinDivert (start/stop/attach/detach)

При любом из них: обновить `ARCHITECTURE_CURRENT.md` и `docs\full_repo_audit_intel.md`.

### 3.3 Формат `docs\TODO.md` (СТРОГО)
`docs\TODO.md` должен иметь разделы:
- `[NOW]` задачи в работе (до 5 пунктов)
- `[NEXT]` ближайшие
- `[LATER]` отложенные

Каждая задача: кратко + критерий готовности (1 строка).
Запрещены задачи вида “подумать”, “исследовать”, “посмотреть”.

---

## 4) Контекст проекта

Windows-native .NET 9 WPF приложение для диагностики блокировок сети на уровне провайдера (DNS фильтрация, DPI, инъекция TCP RST). Основной сценарий: проблемы с подключением к игровым и прочим сетевым сервисам. Поставка: single-file executable (~164MB), только GUI режим.

**Технологии**:
- .NET 9
- WPF
- MaterialDesignInXaml 5.1.0
- WinDivert 2.2.0 (модуль обхода блокировок)

---

## 5) Архитектура (кратко)

```
Program.cs → [GUI: App.xaml + MainWindow]
                           ↓
              MainViewModel ───────────┬──→ BypassController (TrafficEngine)
                                        ↓
                           DiagnosticOrchestrator
                                        ↓
                           LiveTestingPipeline (Sniffer → Tester → Classifier)
                                        ↓
                           Results → UI Updates (Live)
```

### 5.1 Точка входа
`Program.Main()`:
- инициализирует GUI режим
- скрывает консоль
- загружает профиль по умолчанию из `Profiles/`

### 5.2 Компоненты
- **MainViewModel**: Связывает UI, оркестратор и контроллер обхода.
- **BypassController**: Управляет стратегиями обхода (DPI/RST) через `TrafficEngine`.
- **DiagnosticOrchestrator**: Управляет жизненным циклом диагностики.

### 5.3 Поток тестирования
`LiveTestingPipeline` (Sniffer → Tester → Classifier) → `DiagnosticOrchestrator` обновляет GUI через `IProgress`.

- **Sniffer**: `TrafficCollector` (WinDivert) захватывает новые соединения.
- **Tester**: `StandardHostTester` проверяет DNS, TCP, TLS.
- **Classifier**: `StandardBlockageClassifier` определяет тип блокировки (DPI, RST, DNS).

### 5.4 GUI
MVVM (`ViewModels/MainViewModel.*.cs`), карточки Material Design показываются ТОЛЬКО при обнаружении проблем.

---

## 6) Критические паттерны кода

### 6.1 Async/await (СТРОГО)

**Core/Services/Diagnostics/TrafficEngine/Tests: ConfigureAwait(false) ОБЯЗАТЕЛЕН**
```csharp
// ✅ В Core/Services/Tests: всегда ConfigureAwait(false)
var result = await DoWorkAsync(cancellationToken).ConfigureAwait(false);
```

**UI (Views/ViewModels): ConfigureAwait(false) ЗАПРЕЩЕН**, если после await идёт работа с UI/Bindings.
```csharp
// ✅ В ViewModel: обычный await, если дальше обновление bindable-состояния
var result = await DoWorkAsync(cancellationToken);
StatusText = result.ToString();
```

**Запрещено блокировать async**
```csharp
// ❌ НИКОГДА
var result = DoWorkAsync().Result;
DoWorkAsync().Wait();
```

**CancellationToken**
- Любой новый async-метод принимает `CancellationToken`, кроме UI event handlers.

---

### 6.2 Отчет о прогрессе (Контракт GUI)

**Формат лог-сообщений (СТРОГО)**:
`[{LEVEL}][{COMP}][{PHASE}] <сообщение>`

LEVEL: `INFO | WARN | ERROR | DEBUG`
COMP: `SNIFFER | TESTER | CLASSIFIER | ENGINE | ORCH | UI`
PHASE: `START | STEP | END`

```csharp
progress?.Report("[INFO][TESTER][STEP] Checking TLS for api.steampowered.com");
```

---

### 6.3 Исключения (СТРОГО)
- Запрещены пустые `catch`.
- В `catch` логировать:
  - тип исключения (`GetType().Name`)
  - `Message`
  - `HResult` (если доступно)
  - контекст (host/timeout/strategy/stage)
  - действие: `continue/abort/fallback`

---

### 6.4 Кодировка Traceroute (КРИТИЧНО для русской Windows)
```csharp
// System tracert.exe использует OEM866 (CP866) для кириллицы
process.StandardOutput.CurrentEncoding = Encoding.GetEncoding(866);
// Без этого: русские хопы → ?????
```

---

### 6.5 Material Design UI (Карточки)

**Показывать карточки ТОЛЬКО когда `result.Status != "OK"`**.

**Контракт UI (СТРОГО)**:
- Visibility карточек управляется **только через Binding** (свойство ViewModel).
- В code-behind запрещены прямые изменения `Visibility`/`Content` карточек.

```xaml
<!-- По умолчанию: скрыто -->
<materialDesign:Card x:Name="FirewallCard" Visibility="Collapsed">
  <TextBlock Text="• Problem 1&#x0a;• Problem 2&#x0a;&#x0a;Рекомендация: ..." />
</materialDesign:Card>
```

---

### 6.6 Обнаружение VPN (Адаптивные таймауты)
```csharp
if (NetUtils.LikelyVpnActive()) { // проверяет TAP/TUN адаптеры
    config.HttpTimeoutSeconds = 12; // норма: 6
    config.TcpTimeoutSeconds = 8;   // норма: 3
    config.UdpTimeoutSeconds = 4;   // норма: 2
}
```

---

## 7) WinDivert и права (ОБЯЗАТЕЛЬНЫЙ контракт)

Перед любым использованием WinDivert:
- Проверить запуск от администратора.
- Если не администратор:
  - не пытаться запускать/инициализировать драйвер,
  - показать карточку в UI с причиной и инструкцией,
  - залогировать: `[ERROR][ENGINE][STEP] ...`

Запрещено “тихо падать” при отсутствии прав.

---

## 8) NuGet и размер single-file (~164MB)

Любое добавление NuGet пакета требует:
1) коротко: зачем нужен пакет
2) подтверждение, что это не ломает single-file/publish и не раздувает размер без причины
3) если пакет тянет крупные зависимости: запрещено добавлять без прямой необходимости для задачи

---

## 9) Workflow (сводно)

После каждой итерации редактирования кода:
`dotnet build` → (если есть тесты) `dotnet test` → (если настроен формат) `dotnet format --verify-no-changes`
→ `git add -A` → `git commit -m "<кратко и по делу>"` → при необходимости `git push`.

Параллельно:
- `docs\TODO.md` обновлять всегда
- при архитектурных изменениях обновлять `ARCHITECTURE_CURRENT.md` и `docs\full_repo_audit_intel.md`
