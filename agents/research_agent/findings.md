# [RED] Research Agent: Findings для E2E Testing + UX Polish задачи

**Дата:** 20 ноября 2025 г.  
**Ветка:** feature/wpf-new-migration  
**Задача:** End-to-End Testing + UX Polish для Exe-scenario

---

## Затронутые файлы

### 1. ViewModels/MainViewModel.cs (1546 строк)
**Основной файл с бизнес-логикой**

Содержит:
- Все команды для Exe-scenario: `AnalyzeTrafficCommand`, `DiagnoseCommand`, `ApplyBypassCommand`, `ViewStage1ResultsCommand`, `BrowseExeCommand`
- State management: `ScreenState` ("start", "running", "done"), Stage флаги (`Stage1Complete`, `Stage2Complete`, `Stage3Complete`)
- Private поля для workflow: `_capturedProfile`, `_detectedProblems`, `_plannedBypass`, `_cts`
- Computed properties: `IsRunning`, `CanRunStage2`, `CanRunStage3`
- RelayCommand implementation (строки 1527-1546)
- Все 3 Stage методы: `RunStage1AnalyzeTrafficAsync()` (строки 1077-1255), `RunStage2DiagnoseAsync()` (строки 1260-1408), `RunStage3ApplyBypassAsync()` (строки 1413-1493)

**Проблемные зоны:**
- MessageBox вызовы на строках: 1092-1098, 1169-1180, 1216-1231, 1276-1282, 1368-1382, 1392-1400
- IsRunning зависит только от `ScreenState == "running"`, но Stage команды **не меняют** ScreenState
- CommandManager.InvalidateRequerySuggested() вызывается только в SetStateCommand (строка 302), но **не вызывается** после изменения Stage флагов

### 2. MainWindow.xaml (446 строк)
**XAML разметка UI для Exe-scenario**

Содержит:
- Кнопки Stage 1/2/3 с Command bindings (строки 321, 375, 420)
- IsEnabled привязки: Stage2 кнопка → `CanRunStage2`, Stage3 кнопка → `CanRunStage3`
- TextBlock для статусов: `Stage1Status`, `Stage2Status`, `Stage3Status`
- Visibility привязки для результатов: `Stage1Complete`, `Stage2Complete`

**Особенности:**
- Кнопки НЕ используют Command.CanExecute напрямую, вместо этого Stage2/3 используют `IsEnabled="{Binding CanRunStage2/3}"`
- Это означает что WPF **не переоценивает** CanExecute автоматически через CommandManager

### 3. Utils/TrafficAnalyzer.cs
**Захват трафика через WinDivert**

Содержит:
- `AnalyzeProcessTrafficAsync()` - 30-секундный захват с IProgress<string> для отчетов
- Использует async Task.Run для blocking WinDivert loop
- Возвращает GameProfile с захваченными целями

**Особенности:**
- Уже есть progress reporting каждые 2 секунды (можно усилить для GUI)
- Не требует изменений для UX задачи

### 4. Utils/ProblemClassifier.cs
**Классификация проблем сети**

Содержит:
- `ClassifyProblems()` - анализ TestResult и возврат List<BlockageProblem>
- Определяет типы блокировок: DNS filtering, DPI, TCP RST, ISP blocks

**Особенности:**
- Используется в Stage 2 для анализа
- Не требует изменений для UX задачи

### 5. Utils/BypassStrategyPlanner.cs
**Планирование стратегии обхода**

Содержит:
- `PlanBypassStrategy()` - генерация BypassProfile
- `RequiresDnsChange()`, `CanBypassWithWinDivert()`, `RequiresVpn()` - проверки

**Особенности:**
- Используется в Stage 2 для планирования
- Используется в Stage 3 для применения
- Не требует изменений для UX задачи

### 6. Utils/DnsFixApplicator.cs
**Применение DNS исправлений**

Содержит:
- `ApplyDnsFixAsync()` - тестирует DoH провайдеры и применяет через netsh
- Использует IProgress<string> для отчетов

**Особенности:**
- Используется в Stage 3
- Уже есть progress reporting
- Не требует изменений для UX задачи

### 7. Windows/CapturedTargetsWindow.xaml + .cs
**Окно результатов Stage 1**

Содержит:
- Отображение захваченных целей из GameProfile
- Вызывается по кнопке "Просмотр результатов"

**Особенности:**
- Не требует изменений для UX задачи

---

## Текущая реализация

### Команды и их CanExecute логика

```csharp
// Строки 315-318 в MainViewModel.cs
BrowseExeCommand = new RelayCommand(_ => BrowseExe(), _ => !IsRunning);
AnalyzeTrafficCommand = new RelayCommand(async _ => await RunStage1AnalyzeTrafficAsync(), 
    _ => !string.IsNullOrEmpty(ExePath) && !IsRunning);
DiagnoseCommand = new RelayCommand(async _ => await RunStage2DiagnoseAsync(), 
    _ => CanRunStage2 && !IsRunning);
ApplyBypassCommand = new RelayCommand(async _ => await RunStage3ApplyBypassAsync(), 
    _ => CanRunStage3 && !IsRunning);
```

**Проблема:** IsRunning зависит от ScreenState, но Stage команды **НЕ меняют** ScreenState!

```csharp
// Строка 126
public bool IsRunning => ScreenState == "running";
```

ScreenState меняется только в:
1. `RunAuditAsync()` (профильный сценарий) - строка 345: `ScreenState = "running"`
2. Completion в `RunAuditAsync()` - строки 390, 398, 407: `ScreenState = "done"`

**Stage методы НЕ трогают ScreenState**, поэтому IsRunning всегда false во время их выполнения!

### Workflow MessageBox прерывания

#### Stage 1 → Stage 2 (строки 1216-1231)
```csharp
var result = System.Windows.MessageBox.Show(
    $"Захват успешно завершен!\n\n" +
    $"Обнаружено целей: {Stage1HostsFound}\n" +
    $"Профиль сохранен: {profilePath}\n\n" +
    $"Перейти к Stage 2 (анализ проблем)?",
    "Stage 1: Завершено",
    System.Windows.MessageBoxButton.YesNo,
    System.Windows.MessageBoxImage.Information
);

if (result == System.Windows.MessageBoxResult.Yes)
{
    _ = RunStage2DiagnoseAsync();
}
```

#### Stage 2 → Stage 3 (строки 1368-1382)
```csharp
var result = System.Windows.MessageBox.Show(
    $"Диагностика завершена!\n\n" +
    $"Обнаружено проблем: {Stage2ProblemsFound}\n" +
    $"Стратегия обхода сформирована.\n\n" +
    $"Перейти к Stage 3 (применение исправлений)?",
    "Stage 2: Завершено",
    System.Windows.MessageBoxButton.YesNo,
    System.Windows.MessageBoxImage.Information
);

if (result == System.Windows.MessageBoxResult.Yes)
{
    _ = RunStage3ApplyBypassAsync();
}
```

**Проблема:** Модальные окна прерывают flow, требуют клика от пользователя.

### Progress Reporting

**Stage 1:**
- Есть IProgress<string> callback в TrafficAnalyzer (строки 1145-1149)
- Обновляется `Stage1Status` property
- НЕТ процента выполнения (только текст статуса)

**Stage 2:**
- Есть IProgress<TestProgress> callback в AuditRunner (строка 1320)
- Обновляется через HandleTestProgress() (существующий метод для профильного сценария)
- НЕТ специфичного Stage2 процента

**Stage 3:**
- Есть IProgress<string> callback в DnsFixApplicator (строка 1437)
- Обновляется `Stage3Status` property
- НЕТ процента выполнения

### Блокировка кнопок

**Текущий механизм:**
1. RelayCommand.CanExecuteChanged подписан на CommandManager.RequerySuggested (строка 1542)
2. WPF автоматически переоценивает CanExecute при:
   - Focus change
   - Mouse move
   - Property change (если есть INotifyPropertyChanged)

**Но:** Stage флаги НЕ триггерят переоценку CanExecute!

Причины:
- `Stage1Complete` setter вызывает `OnPropertyChanged(nameof(CanRunStage2))` (строка 235) ✅
- `Stage2Complete` setter вызывает `OnPropertyChanged(nameof(CanRunStage3))` (строка 241) ✅
- НО: PropertyChanged для CanRunStage2/3 **не переоценивает Command.CanExecute** автоматически
- XAML использует прямой IsEnabled binding для Stage2/3 (строки 381, 426 в XAML)

**Stage1 кнопка:**
- НЕТ IsEnabled override в XAML
- Использует только Command.CanExecute → `!string.IsNullOrEmpty(ExePath) && !IsRunning`
- **!IsRunning всегда true** (потому что ScreenState никогда не "running" для Stage команд)

---

## Проблемы в текущей реализации

### 1. Кнопки НЕ блокируются во время выполнения

**Root cause:**
- IsRunning = ScreenState == "running", но Stage методы **не меняют** ScreenState
- Значит IsRunning всегда false во время Stage1/2/3
- Значит CanExecute всегда true (если другие условия выполнены)
- Пользователь может нажать Stage1 кнопку повторно пока идет захват

**Доказательство:**
- Строка 315: `_ => !string.IsNullOrEmpty(ExePath) && !IsRunning`
- IsRunning зависит от ScreenState (строка 126)
- Stage методы НЕ меняют ScreenState (поиск по файлу показывает 0 изменений ScreenState в Stage методах)

### 2. CommandManager.InvalidateRequerySuggested не вызывается

**Root cause:**
- Единственный вызов в строке 302 (в SetStateCommand)
- После изменения `Stage1Complete = true` (строка 1159) - НЕТ InvalidateRequerySuggested
- После изменения `Stage2Complete = true` (строка 1361) - НЕТ InvalidateRequerySuggested

**Эффект:**
- CanRunStage2 меняется на true, но DiagnoseCommand.CanExecute **не переоценивается**
- Кнопка "Диагностировать" остается заблокированной пока пользователь не подвигает мышкой

**Workaround в XAML:**
- Stage2/3 кнопки используют прямой `IsEnabled` binding (строки 381, 426) вместо Command.CanExecute
- Это работает, НО только для Stage2/3
- Stage1 кнопка **не защищена** от повторного нажатия

### 3. MessageBox прерывают workflow

**Stage 1 → 2 transition:**
- Строки 1216-1231: MessageBox.Show с YesNo
- Блокирует UI пока пользователь не нажмет кнопку
- Нарушает "плавный flow" из задачи

**Stage 2 → 3 transition:**
- Строки 1368-1382: MessageBox.Show с YesNo
- Аналогичная проблема

**Критичные MessageBox (должны остаться):**
- Строки 1092-1098: Требуются admin права (критично)
- Строки 1169-1180: Соединения не обнаружены (информационное, но полезно)
- Строки 1276-1282: Профиль не захвачен (ошибка пользователя)
- Строка 1392-1400: Проблем не обнаружено (информационное)

### 4. Нет progress индикации в процентах

**Stage 1:**
- TrafficAnalyzer имеет 30-секундный timeout
- Можно добавить progress callback с "Захвачено N соединений..." каждые 2 секунды
- Процент: `elapsedSeconds / 30.0 * 100`

**Stage 2:**
- AuditRunner уже отчитывается через TestProgress
- HandleTestProgress() обновляет TestResults
- Процент: `CompletedTests / TotalTargets * 100`

**Stage 3:**
- DnsFixApplicator тестирует 3 DoH провайдера (1.1.1.1, 8.8.8.8, 9.9.9.9)
- Можно добавить "Тестирование провайдера X из 3..."
- WinDivert bypass - мгновенная операция (сохранение JSON)

### 5. Нет кнопки "Сбросить"

**Текущее состояние:**
- После завершения Stage1/2/3 пользователь не может начать заново
- Нужно перезапускать приложение

**Что нужно сбросить:**
- `_capturedProfile = null`
- `_detectedProblems = null`
- `_plannedBypass = null`
- `_exePath = ""`
- `Stage1Complete = false`
- `Stage2Complete = false`
- `Stage3Complete = false`
- `Stage1HostsFound = 0`
- `Stage2ProblemsFound = 0`
- `Stage1Status = ""`
- `Stage2Status = ""`
- `Stage3Status = ""`
- `TestResults.Clear()`

---

## Риски и зависимости

### Риск 1: Конфликт со ScreenState механизмом

**Описание:**
- ScreenState используется для профильного сценария (Start → Running → Done)
- Exe-scenario НЕ использует ScreenState
- Если добавить IsRunning флаг для Exe-scenario, может возникнуть конфликт

**Решение:**
- Добавить отдельный флаг `_isExeScenarioRunning` (bool)
- Изменить IsRunning: `ScreenState == "running" || _isExeScenarioRunning`
- Устанавливать `_isExeScenarioRunning = true` в начале Stage методов
- Сбрасывать `_isExeScenarioRunning = false` в finally блоках

### Риск 2: Async/await deadlock в Dispatcher.Invoke

**Описание:**
- Stage методы используют `Dispatcher.InvokeAsync()` (строки 1167, 1214, 1274, 1366, 1390)
- MessageBox.Show вызывается внутри Dispatcher
- Если Stage метод вызван из UI thread → потенциальный deadlock

**Решение:**
- Stage методы уже async Task
- Используется RelayCommand с async lambda: `async _ => await RunStage1AnalyzeTrafficAsync()`
- НО: RelayCommand выполняет async void (execute(_ => {...}))
- **Требуется:** Убедиться что RelayCommand корректно обрабатывает async operations
- Если нет - заменить на AsyncRelayCommand (из CommunityToolkit.Mvvm или свой)

### Риск 3: CancellationToken отсутствует в Stage методах

**Описание:**
- `_cts` используется только в RunAuditAsync (профильный сценарий)
- Stage методы НЕ принимают CancellationToken
- Нет способа отменить Stage 1 (30-секундный захват)

**Решение:**
- Добавить `_stageCts` отдельный CancellationTokenSource
- Создавать в начале каждого Stage метода
- Передавать в TrafficAnalyzer, AuditRunner, DnsFixApplicator
- Добавить кнопку "Остановить" (показывается только когда `_isExeScenarioRunning == true`)

### Риск 4: Race condition при быстрых кликах

**Описание:**
- Пользователь может нажать Stage1 кнопку несколько раз подряд (до того как IsRunning станет true)
- Каждый клик запустит новый async Task
- Несколько параллельных WinDivert handles могут конфликтовать

**Решение:**
- Установить `_isExeScenarioRunning = true` **перед** любым await
- Вызвать `CommandManager.InvalidateRequerySuggested()` сразу после установки флага
- Добавить проверку `if (_isExeScenarioRunning) return;` в начале Stage методов

### Риск 5: Регрессия в профильном сценарии

**Описание:**
- Профильный сценарий использует те же TestResults, ScreenState, IsRunning
- Изменения для Exe-scenario могут сломать профильный flow

**Решение:**
- Тестировать оба сценария после изменений
- Добавить условие `if (SelectedScenario == "exe") { /* exe logic */ } else { /* profile logic */ }`
- Убедиться что IsRunning работает для обоих сценариев

### Риск 6: MessageBox в non-UI thread

**Описание:**
- Stage методы используют ConfigureAwait(false) (строка 1156)
- После await продолжение может быть в background thread
- MessageBox.Show требует UI thread

**Решение:**
- Использовать `Dispatcher.InvokeAsync()` для всех MessageBox (уже сделано для большинства)
- Проверить строки 1092-1098: MessageBox БЕЗ Dispatcher (потенциальная проблема)

---

## Рекомендации для Planning Agent

### 1. Группировка подзадач

**Рекомендуемые группы:**

**Группа A: Command blocking fix (1-2 подзадачи)**
- Добавить `_isExeScenarioRunning` флаг
- Изменить IsRunning property
- Установить флаг в начале Stage методов (try block)
- Сбросить флаг в finally block
- Добавить `CommandManager.InvalidateRequerySuggested()` после изменения флага

**Группа B: Убрать MessageBox переходы (1 подзадача)**
- Удалить MessageBox на строках 1216-1231 (Stage 1→2)
- Удалить MessageBox на строках 1368-1382 (Stage 2→3)
- Автоматически вызывать RunStage2DiagnoseAsync() после успешного Stage1
- Автоматически вызывать RunStage3ApplyBypassAsync() после успешного Stage2
- **Сохранить** критичные MessageBox (admin права, ошибки)

**Группа C: Progress индикация (2-3 подзадачи)**
- Stage1: добавить Stage1Progress property (0-100), обновлять каждые 2 секунды
- Stage2: добавить Stage2Progress property, вычислять из CompletedTests/TotalTargets
- Stage3: добавить Stage3Progress property, обновлять при тестировании DoH провайдеров
- Обновить XAML: добавить ProgressBar для каждого Stage

**Группа D: Кнопка "Сбросить" (1 подзадача)**
- Добавить ResetExeScenarioCommand
- Создать метод ResetExeScenario() - сбросить все Stage поля
- Добавить кнопку в XAML (Visibility="{Binding Stage1Complete или Stage2Complete или Stage3Complete}")

**Группа E: CancellationToken support (опциональная)**
- Добавить `_stageCts` (CancellationTokenSource)
- Передавать в Stage методы
- Добавить кнопку "Остановить" (Visibility="{Binding IsExeScenarioRunning}")
- Bind на команду CancelStageCommand

**Группа F: E2E Test Checklist (1 подзадача)**
- Создать docs/e2e_test_checklist.md
- Описать 15-20 шагов для ручного тестирования
- Включить TestNetworkApp.exe инструкции

### 2. Минимизация изменений

**Что НЕ трогать:**
- TrafficAnalyzer.cs - уже работает
- ProblemClassifier.cs - не требует изменений
- BypassStrategyPlanner.cs - не требует изменений
- DnsFixApplicator.cs - уже есть progress reporting
- CapturedTargetsWindow.xaml - не требует изменений
- Профильный сценарий logic (RunAuditAsync, HandleTestProgress для профиля)

**Что изменить минимально:**
- MainViewModel.cs:
  - Добавить 1 поле: `_isExeScenarioRunning`
  - Изменить 1 property: `IsRunning`
  - Добавить 3 properties: `Stage1Progress`, `Stage2Progress`, `Stage3Progress`
  - Изменить 3 метода: Stage1/2/3 - добавить try/finally с флагом
  - Удалить 2 MessageBox блока (auto-transition)
  - Добавить 1 метод: `ResetExeScenario()`
  - Добавить 1 команду: `ResetExeScenarioCommand`

- MainWindow.xaml:
  - Добавить 3 ProgressBar для Stage1/2/3
  - Добавить 1 кнопку "Сбросить"

### 3. Порядок выполнения

**Критический путь (sequential):**
1. Группа A (command blocking) - ПЕРВОЕ (блокер для остального)
2. Группа B (убрать MessageBox) - после A (зависит от корректной блокировки)
3. Группа C (progress) - после A (может быть параллельно B)
4. Группа D (Reset кнопка) - после A+B (использует те же флаги)
5. Группа F (E2E checklist) - после всех (документация)

**Можно параллельно:**
- Группа C (progress) и Группа B (MessageBox) - независимые
- Группа E (CancellationToken) - опциональная, можно отложить

### 4. Тестирование

**Критичные сценарии:**
1. Запустить Stage1 → кнопка заблокирована → завершается → Stage2 автоматически
2. Stage2 → Stage3 автоматически → завершается → кнопка "Сбросить" появляется
3. Нажать "Сбросить" → все поля очищены → можно начать заново
4. Проверить профильный сценарий: выбрать "Star Citizen" → запустить → работает как раньше

**Регрессионные тесты:**
- Профильный сценарий НЕ сломан
- Host scenario НЕ сломан (если используется)
- Критичные MessageBox остались (admin права, ошибки)

### 5. Потенциальные edge cases

**Edge Case 1: Нет admin прав**
- Stage1 показывает MessageBox → возвращается рано
- Флаг `_isExeScenarioRunning` должен быть сброшен (используй finally)

**Edge Case 2: Процесс завершился сразу**
- Stage1 обнаружит 0 соединений
- MessageBox с предупреждением → **НЕ удалять**, это информационный
- Stage2 НЕ должен запускаться автоматически (проверить `Stage1HostsFound > 0`)

**Edge Case 3: Stage2 не нашел проблем**
- `_detectedProblems` пустой список
- MessageBox "Проблем не обнаружено" → **НЕ удалять**, это информационный
- Stage3 НЕ должен запускаться (CanRunStage3 проверяет `_detectedProblems.Any()`)

**Edge Case 4: Пользователь закрыл приложение во время Stage1**
- WinDivert handle должен быть освобожден (TrafficAnalyzer использует using)
- Process должен быть убит (строка 1240-1243)

---

## Итого

**Основные проблемы:**
1. ✅ Кнопки НЕ блокируются (IsRunning всегда false для Exe-scenario)
2. ✅ MessageBox прерывают flow (Stage1→2 и Stage2→3)
3. ✅ Нет progress индикации в процентах
4. ✅ Нет кнопки "Сбросить"
5. ✅ CommandManager.InvalidateRequerySuggested не вызывается

**Количество подзадач:** 6-8 (в зависимости от группировки и CancellationToken)

**Критичность:** HIGH (пользователи могут запустить несколько операций одновременно → краш)

**Сложность:** MEDIUM (изменения локализованы в MainViewModel + XAML, но требуют внимания к async/await)

**Рекомендуемая модель для всех агентов:** Claude Sonnet 4.5 (согласно задаче)

---

**Готов к передаче [BLUE] Planning Agent.**
