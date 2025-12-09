# [PURPLE] Task Owner: Рефакторинг сетевого ядра (TrafficEngine Pipeline)

> Цель: Объединить конфликтующие сервисы мониторинга и обхода блокировок в единый конвейер обработки пакетов (Pipeline Architecture), работающий через один хэндл WinDivert.

---

## Проблема

**Текущая архитектура**:
- `NetworkMonitorService` (диагностика) открывает WinDivert хэндл (Layer: Network, Priority: 1000, Sniff).
- `WinDivertBypassManager` (обход) открывает WinDivert хэндл (Layer: Network, Priority: 0-200, Active).

**Конфликт**:
Два хэндла конкурируют за пакеты. В режиме Sniff диагностика получает копии, но иногда это мешает активному хэндлу корректно модифицировать или дропать пакеты (особенно RST) из-за особенностей драйвера WinDivert и гонок обработки. Это приводит к нестабильности обхода DPI.

---

## Решение: TrafficEngine (Middleware Pipeline)

Переход на архитектуру "Цепочка обязанностей" (как в Nginx, ASP.NET Core, Linux Netfilter).

**Новая архитектура**:
1. **TrafficEngine**: Единственный владелец хэндла WinDivert. Читает пакеты в бесконечном цикле.
2. **IPacketFilter**: Интерфейс для модулей обработки.
   ```csharp
   interface IPacketFilter {
       bool Process(ref Packet packet, PacketContext ctx); // return false = DROP
   }
   ```
3. **Фильтры**:
   - `TrafficMonitorFilter`: Собирает статистику (бывший NetworkMonitorService). Всегда возвращает `true` (Pass).
   - `BypassFilter`: Реализует логику обхода (бывший WinDivertBypassManager). Может вернуть `false` (Drop) для RST или модифицировать пакет (TLS split).

**Поток данных**:
`WinDivert -> TrafficEngine -> [MonitorFilter] -> [BypassFilter] -> Network`

---

## План работ

### Фаза 1: Фундамент (Scaffolding)
1. [x] Создать интерфейс `IPacketFilter` и контекст `PacketContext`.
2. [x] Реализовать класс `TrafficEngine` (основной цикл WinDivertRecv -> Filter -> WinDivertSend).
3. [x] Интегрировать `TrafficEngine` в DI контейнер или `DiagnosticOrchestrator`.

### Фаза 2: Миграция Мониторинга
1. [x] Создать `TrafficMonitorFilter`.
2. [x] Перенести логику сбора статистики из `NetworkMonitorService` в фильтр.
3. [x] Адаптировать подписчиков (`TcpRetransmissionTracker`, `UdpInspectionService`) к новому источнику событий.

### Фаза 3: Миграция Байпаса
1. [ ] Создать `BypassFilter`.
2. [ ] Перенести логику `WinDivertBypassManager` (RstBlocker, TlsFragmenter) в фильтр.
3. [ ] Обеспечить корректную передачу состояния (BypassProfile) в фильтр.

### Фаза 4: Интеграция и Тесты
1. [ ] Заменить старые сервисы на `TrafficEngine` в `DiagnosticOrchestrator`.
2. [ ] Проверить работу диагностики (графики, счетчики).
3. [ ] Проверить работу обхода (RST drop, TLS fragmentation).
4. [ ] Убедиться в отсутствии регрессий производительности.

---

## Ограничения

- Работаем в ветке `refactor/traffic-engine`.
- Сохраняем обратную совместимость с `ConnectionMonitorService` (он работает через IP Helper и не конфликтует).
- Не ломаем существующий UI.

---

## Схема работы агентов

- [PURPLE] Task Owner: Управление задачей.
- [GREEN] Coding Agent: Реализация классов Engine и Filters.
- [YELLOW] QA Agent: Проверка работоспособности.

# [PURPLE] Task Owner: End-to-End Testing + UX Polish для Exe-scenario

**Дата:** 20 ноября 2025 г.  
**Ветка:** feature/wpf-new-migration  
**Статус:** Формирование задачи

---

## Проблема

**Краткое описание**:
Exe-scenario (Stage 1→2→3) работает функционально, но имеет проблемы с UX: кнопки не блокируются во время выполнения операций, модальные MessageBox окна прерывают workflow, нет визуальной обратной связи о прогрессе. Нужен плавный, непрерывный flow без "спотыканий".

**Как проявляется**:
```
1. Запускаем Stage 1 "Analyze Traffic" → кнопка остаётся активной (можно нажать повторно)
2. После Stage 1 → MessageBox "Перейти к Stage 2?" → прерывает flow (требует клика)
3. После Stage 2 → MessageBox "Перейти к Stage 3?" → ещё одно прерывание
4. Во время длительных операций (30 сек capture) → нет индикации прогресса
5. Можно нажать "Диагностика" пока уже идёт другая операция
6. Нет кнопки "Сбросить" для начала нового анализа
```

**Контекст**:
- Критичность: **HIGH** (блокер для комфортного использования)
- Текущий код: `ViewModels/MainViewModel.cs` (1547 строк), `MainWindow.xaml`
- Проблемные места: `AnalyzeTrafficCommand`, `DiagnoseCommand`, `ApplyBypassCommand`

---

## Желаемый результат (Definition of Done)

После выполнения:

1. **Кнопки блокируются корректно:**
   - Во время Stage 1/2/3 все команды кроме "Остановить" заблокированы
   - `CanExecute` проверяет `IsRunning` флаг для всех команд
   - `CommandManager.InvalidateRequerySuggested()` вызывается после изменения состояния

2. **Модальные окна заменены на автоматический flow:**
   - Убрать MessageBox "Перейти к Stage 2?" → автоматически запускать Stage 2 после Stage 1
   - Убрать MessageBox "Перейти к Stage 3?" → автоматически запускать Stage 3 после Stage 2
   - Оставить ТОЛЬКО критичные MessageBox (ошибки, предупреждения об admin правах)

3. **Прогресс индикация улучшена:**
   - Stage 1: показывать "Захвачено N соединений..." каждые 2 секунды
   - Stage 2: показывать "Тестирование цели X из Y..."
   - Stage 3: показывать "Применение DNS fix..." / "Активация WinDivert..."
   - Процент выполнения для каждой стадии (0-100%)

4. **Кнопка "Сбросить" добавлена:**
   - Появляется после завершения любой Stage
   - Очищает _capturedProfile, _exePath, TestResults
   - Сбрасывает Stage1/2/3Complete флаги
   - Возвращает UI в начальное состояние

5. **Ручное тестирование задокументировано:**
   - Чеклист из 15-20 шагов для полного E2E теста
   - Описание ожидаемого поведения на каждом шаге
   - Файл `docs/e2e_test_checklist.md` создан

Критерии приёмки:
- ✅ Нельзя запустить две операции одновременно (команды блокируются)
- ✅ Workflow Stage 1→2→3 выполняется без MessageBox прерываний
- ✅ Прогресс показывается в реальном времени (не indeterminate spinner)
- ✅ Кнопка "Сбросить" работает и возвращает UI в начальное состояние
- ✅ E2E checklist выполнен с TestNetworkApp.exe без ошибок
- ✅ Нет регрессий: профильная диагностика (Star Citizen) работает как раньше

---

## Ограничения

**Технические**:
- .NET 9, WPF + MaterialDesign
- Async/await + CancellationToken для всех длительных операций
- MVVM pattern: вся логика в MainViewModel, UI binding в XAML
- Обратная совместимость: **ДА** (профильный сценарий не трогать)

**Что НЕ делать**:
- НЕ переписывать TrafficAnalyzer.cs (захват трафика работает)
- НЕ менять логику Stage 1/2/3 (только UX улучшения)
- НЕ трогать CapturedTargetsWindow.xaml (окно результатов отдельное)
- НЕ добавлять автоматические тесты (будет использоваться ручное тестирование)
- НЕ переводить на английский (весь UI на русском)

**Оценка**: **MEDIUM** (6-8 подзадач)

**Рекомендуемая модель для ВСЕХ агентов**: **Claude Sonnet 4.5**

---

## Схема работы агентов

**ВАЖНО**: Каждый агент работает в ОТДЕЛЬНОМ контексте (новый чат/сессия)!
- Агенты НЕ видят друг друга
- Связь только через файлы: `current_task.md`, `findings.md`, `plan.md`, `test_report.md`, `changelog.md`
- Task Owner координирует работу, передавая результаты между агентами

**Цветовая маркировка агентов**:
```
[PURPLE] - Task Formulation / Task Owner
[RED]    - Research Agent
[BLUE]   - Planning Agent
[GREEN]  - Coding Agent
[YELLOW] - QA Agent
[CYAN]   - Delivery Agent
```

**Поток работы**:
```
[0] [PURPLE] Task Owner            → current_task.md (этот файл)
                         ↓
[1] [RED] Research Agent           → Исследование кода → findings.md
                         ↓
[2] [BLUE] Planning Agent          → Детальный план → plan.md
                         ↓
[3] [GREEN] Coding Agent           → Реализация (N раз, быстрая модель)
                         ↓
[4] [YELLOW] QA Agent              → Тестирование → test_report.md
                         ↓
[5] [CYAN] Delivery Agent          → Коммит + changelog
```

---

## [1] [RED] Research Agent

**Статус**: [ ] TODO / [ ] IN PROGRESS / [ ] DONE

**Агент работает в отдельном контексте!** Он НЕ видит этот файл и предыдущую переписку.

**Входные файлы** (агент должен прочитать сам):
- `agents/task_owner/current_task.md` - полное описание задачи

**Выходной файл** (агент должен создать):
- `agents/research_agent/findings.md`

**Промпт для нового чата**:
```
Ты [RED] Research Agent. Работаешь в изолированном контексте. Используй модель Claude Sonnet 4.5.

Прочитай файл agents/task_owner/current_task.md и исследуй проблему:
1. Найди все затронутые файлы и компоненты
2. Изучи текущую реализацию команд (AnalyzeTrafficCommand, DiagnoseCommand, ApplyBypassCommand)
3. Найди где используются MessageBox и как организован workflow
4. Изучи как реализован IsRunning флаг и блокировка команд
5. Выяви риски и зависимости

Создай файл agents/research_agent/findings.md со структурой:

## Затронутые файлы
[список с описанием что делает каждый]

## Текущая реализация
[как работают команды, где MessageBox, как блокируются кнопки]

## Проблемы в текущей реализации
[что именно не работает, почему кнопки не блокируются]

## Риски и зависимости
[что может сломаться, от чего зависит]

## Рекомендации для Planning Agent
[что важно учесть при планировании]
```

**После завершения**: Task Owner переходит к [2]

---

## [2] [BLUE] Planning Agent

**Статус**: [ ] TODO / [ ] IN PROGRESS / [ ] DONE

**Агент работает в отдельном контексте!**

**Входные файлы** (агент должен прочитать сам):
- `agents/task_owner/current_task.md` - описание задачи
- `agents/research_agent/findings.md` - результаты исследования от [RED] агента

**Выходной файл** (агент должен создать):
- `agents/planning_agent/plan.md`

**Промпт для нового чата**:
```
Ты [BLUE] Planning Agent. Работаешь в изолированном контексте. Используй модель Claude Sonnet 4.5.

Прочитай:
1. agents/task_owner/current_task.md (задача)
2. agents/research_agent/findings.md (результаты исследования)

Создай детальный план в agents/planning_agent/plan.md:

ВАЖНО: 
- Каждая подзадача = 1-2 файла максимум
- Группируй связанные изменения
- Минимизируй количество подзадач без потери качества
- НЕ давай готовый код, только описание что нужно сделать

Формат каждой подзадачи:

## Подзадача N: [Название]
- Файлы: path/to/file.cs, path/to/file.xaml
- Описание: [что именно изменить, какую логику добавить/удалить/заменить]
- Зависимости: нет / после подзадачи M
- Риски: [если есть]

В конце добавь секцию:

## Итого
- Количество подзадач: N
- Порядок выполнения: [последовательно / можно параллельно задачи X,Y,Z]
- Основные риски: [общие риски]
```

**После завершения**: Task Owner переходит к [3]

---

## [3] [GREEN] Coding Agent (повторить N раз)

**Статус по подзадачам**:
- [ ] Подзадача 1
- [ ] Подзадача 2
- [ ] Подзадача 3
- [ ] ...

**Каждый Coding Agent = новый контекст!** Они НЕ видят работу предыдущих Coding Agent.

**Входные файлы** (агент должен прочитать сам):
- `agents/planning_agent/plan.md` - читает только свою подзадачу N
- Файлы кода, указанные в подзадаче

**Выходной файл** (агент должен изменить):
- Файлы, указанные в подзадаче

**Промпт для каждой подзадачи N**:
```
Ты [GREEN] Coding Agent #N. Работаешь в изолированном контексте. Используй модель Claude Sonnet 4.5.

1. Прочитай agents/planning_agent/plan.md
2. Найди в нём подзадачу N: [НАЗВАНИЕ ПОДЗАДАЧИ]
3. Прочитай указанные файлы
4. Внеси изменения согласно описанию в подзадаче
5. Убедись что синтаксис правильный

НЕ создавай промежуточные файлы!
Результат: изменённый код, готовый к тестированию.
```

**Повторить для каждой подзадачи** из `plan.md`

**После завершения всех подзадач**: Task Owner переходит к [4]

---

## [4] [YELLOW] QA Agent

**Статус**: [ ] TODO / [ ] IN PROGRESS / [ ] DONE

**Агент работает в отдельном контексте!**

**Входные файлы** (агент должен прочитать сам):
- `agents/task_owner/current_task.md` - критерии приёмки из секции "Желаемый результат"
- Изменённые файлы кода (для проверки)

**Выходной файл** (агент должен создать):
- `agents/qa_agent/test_report.md`

**Промпт для нового чата**:
```
Ты [YELLOW] QA Agent. Работаешь в изолированном контексте. Используй модель Claude Sonnet 4.5.

1. Прочитай agents/task_owner/current_task.md (секция "Желаемый результат")
2. Запусти `dotnet build -c Debug` для проверки компиляции
3. Если есть GUI изменения: запусти `dotnet run` и проверь визуально
4. Проверь каждый критерий приёмки
5. Проверь на регрессии (старые сценарии работают)
6. Создай E2E test checklist в docs/e2e_test_checklist.md с 15-20 шагами

Создай agents/qa_agent/test_report.md в формате:

## Результаты тестирования
[список проверенных критериев с PASS/FAIL]

## Найденные проблемы
[список проблем или 'Проблем не найдено']

## E2E Test Checklist
[краткое описание созданного чеклиста в docs/]

## Рекомендации
[нужны ли фиксы, можно ли коммитить]
```

**Если есть проблемы**: Task Owner возвращается к [3] и создаёт Coding Agent для фиксов

**Если OK**: Task Owner переходит к [5]

---

## [5] [CYAN] Delivery Agent

**Статус**: [ ] TODO / [ ] IN PROGRESS / [ ] DONE

**Агент работает в отдельном контексте!**

**Входные файлы** (агент должен прочитать сам):
- `agents/task_owner/current_task.md` - название задачи
- `agents/planning_agent/plan.md` - все подзадачи для changelog

**Выходные файлы** (агент должен создать/изменить):
- `agents/delivery_agent/changelog.md` - добавить новую запись
- Git commit

**Промпт для нового чата**:
```
Ты [CYAN] Delivery Agent. Работаешь в изолированном контексте. Используй модель Claude Sonnet 4.5.

1. Прочитай agents/task_owner/current_task.md и agents/planning_agent/plan.md
2. Создай краткий changelog (что изменилось, зачем)
3. Добавь запись в agents/delivery_agent/changelog.md
4. Создай git commit с сообщением:

[Краткое название задачи]

[Описание изменений 2-3 предложения]

Основные изменения:
- [изменение 1]
- [изменение 2]
- [изменение 3]

Generated with AI Assistant

5. (Опционально) Обнови README.md если изменился функционал
```

**После завершения**: Задача готова!

---

## Заметки

**Ключевые области для исследования:**
- `ViewModels/MainViewModel.cs` - команды, IsRunning флаг, workflow
- `MainWindow.xaml` - UI bindings, кнопки, прогресс индикаторы
- `Utils/TrafficAnalyzer.cs` - возможность добавить progress callback
- RelayCommand implementation - как работает CanExecute

**Важно:**
- Агенты должны сами найти все проблемные места в коде
- Агенты должны сами разработать архитектуру решения
- Task Owner только координирует, НЕ пишет код
- Все агенты используют Claude Sonnet 4.5

# [PURPLE] Task Owner: Live Testing Pipeline Refactoring

**Дата:** 22 ноября 2025 г.
**Ветка:** feature/live-testing-pipeline
**Статус:** В работе

---

## Выполненные подзадачи

### C1. Убрать Stage-модель из GUI
**Статус:** COMPLETED
**Изменения:**
1.  **ViewModels/MainViewModel.cs**:
    -   Добавлен единый entry-point `RunDiagnosticPipelineCommand` и метод `RunDiagnosticPipelineAsync`.
    -   Добавлены свойства `DiagnosticStatus` и `IsDiagnosticRunning` для управления состоянием единого пайплайна.
    -   Удалена автоматическая цепочка вызовов (`_ = RunStage...`) из методов `RunStage1AnalyzeTrafficAsync` и `RunStage2DiagnoseAsync`. Теперь оркестрация выполняется в `RunDiagnosticPipelineAsync`.
    -   Сохранены существующие методы этапов для обратной совместимости и использования внутри пайплайна.

2.  **MainWindow.xaml**:
    -   Удалены отдельные карточки для Stage 1, Stage 2, Stage 3.
    -   Интерфейс Exe-сценария заменён на упрощённую панель с одной кнопкой "Запустить диагностику".
    -   Добавлена визуализация статуса диагностики и спиннер активности.
    -   Сохранены настройки (Live Testing, Auto Bypass) и кнопка сброса.

**Результат:**
GUI переведен на одноступенчатую модель запуска. Пользователь видит одну кнопку, которая запускает последовательное выполнение всех этапов диагностики.

### D2. UI-индикация активности Flow/захвата
**Статус:** COMPLETED
**Изменения:**
1.  **ViewModels/MainViewModel.cs**:
    -   Добавлены свойства `FlowEventsCount` и `ConnectionsDiscovered`.
    -   В `RunLivePipelineAsync` добавлена подписка на `_flowMonitor.OnFlowEvent` для обновления счетчиков в реальном времени.
2.  **MainWindow.xaml**:
    -   Добавлен блок статистики ("Соединений: X | Событий Flow: Y") в заголовок диагностики.

### A1. Эксперимент с приоритетами Flow layer
**Статус:** COMPLETED
**Изменения:**
1.  **Utils/FlowMonitorService.cs**:
    -   Приоритет Flow handle изменен с 0 на -1000 для минимизации конфликтов с Network layer.

### A2. Эксперимент с флагами RST-blocker
**Статус:** COMPLETED
**Изменения:**
1.  **Bypass/WinDivertBypassManager.cs**:
    -   Флаги открытия RST blocker изменены с `Sniff | Drop` на `None` (0).
    -   Дроп пакетов осуществляется путем их перехвата и отсутствия реинжекта в `PumpPackets`.

### A3. Явная деградация и UI-warning при отсутствии RST-blocker
**Статус:** COMPLETED
**Изменения:**
1.  **Bypass/WinDivertBypassManager.cs**:
    -   Добавлено свойство `IsRstBlockerActive`.
2.  **ViewModels/MainViewModel.cs**:
    -   Добавлено свойство `BypassWarningText`.
    -   Добавлена логика проверки: если стратегия требует RST (DROP_RST), а блокер не активен -> показываем предупреждение.
3.  **MainWindow.xaml**:
    -   Добавлен красный баннер предупреждения в `FixStatusBar`.

### A4. Вариант A — отключение Flow при включении bypass
**Статус:** COMPLETED
**Изменения:**
1.  **ViewModels/MainViewModel.cs**:
    -   В `RunLivePipelineAsync` добавлена проверка `_bypassManager.State == Enabled`.
    -   Если Bypass активен, `_flowMonitor` не запускается (Flow layer skipped), чтобы избежать конфликта с RST blocker.
    -   Пользователю выводится предупреждение в статус.

### B1. TcpConnectionWatcher
**Статус:** COMPLETED
**Изменения:**
1.  **Utils/TcpConnectionWatcher.cs**:
    -   Реализован компонент для получения снапшотов TCP/UDP соединений через IP Helper API (`GetExtendedTcpTable`).
    -   Поддержка IPv4 и IPv6.
    -   Заменяет функционал Flow layer для маппинга PID.

## План (оставшиеся задачи)

### B2. Integration
**Статус:** COMPLETED
**Изменения:**
1.  **Utils/TcpConnectionWatcher.cs**:
    -   Добавлен метод `ToInfo()` для конвертации нативных структур в управляемые.
    -   Обновлен `GetSnapshotAsync` для возврата списка `TcpConnectionInfo`.
2.  **Utils/FlowMonitorService.cs**:
    -   Добавлено свойство `UseWatcherMode`.
    -   Реализован цикл опроса `RunWatcherLoop` (1000ms polling).
    -   Событие `OnFlowEvent` нормализовано для использования `IPAddress` вместо raw uint.
3.  **Utils/TrafficAnalyzer.cs**:
    -   Обновлен подписчик `OnFlowEvent` для соответствия новой сигнатуре.
4.  **ViewModels/MainViewModel.cs**:
    -   В `RunLivePipelineAsync` добавлена логика: если Bypass активен, включаем `UseWatcherMode = true` для `FlowMonitorService`.

### C2. Basic Test Mode Refactoring
**Статус:** COMPLETED
**Изменения:**
1.  **TestNetworkApp**:
    -   Обновлен список целей (добавлены RuTube, Twitch, GoogleVideo).
    -   Собран как single-file executable и помещен в папку сборки.
2.  **MainViewModel**:
    -   Исправлена логика поиска `TestNetworkApp.exe`.
    -   Реализовано скрытие "DNS: OK" для IP-целей.
    -   Реализована поддержка динамического обновления хостнеймов (YouTube fix).
3.  **TrafficAnalyzer**:
    -   Добавлена поддержка повторной проверки хостов при обновлении DNS-имени.

### D3. UX Refinements & Advanced Heuristics
**Статус:** COMPLETED
**Изменения:**
1.  **OverlayWindow**:
    -   Реализован немедленный показ оверлея при старте диагностики.
    -   Добавлен режим "Silence Prompt" (таймер 60с) при отсутствии активности.
    -   Добавлена живая статистика (время, соединения) в оверлей.
2.  **MainViewModel (Heuristics)**:
    -   Реализован метод `AnalyzeHeuristicSeverity` для фильтрации ложных срабатываний.
    -   Инфраструктурные домены (Microsoft, Azure, Analytics) теперь получают статус `Warn` вместо `Fail` при ошибках `TLS_DPI`.
    -   Добавлена проверка "родственных" сервисов (если основной домен работает, субдомены помечаются как `Warn`).

## План (оставшиеся задачи)

- [ ] **QA & Verification**
  - [ ] Проверить работу в режиме без Bypass (Flow Layer).
  - [ ] Проверить работу в режиме с Bypass (Watcher Mode).
  - [ ] Убедиться, что RST-блокер работает стабильно при активном Watcher.
  - [ ] Проверить Basic Test Mode:
    - [ ] YouTube должен определяться корректно.
    - [ ] IP-адреса не должны показывать "DNS: OK".



