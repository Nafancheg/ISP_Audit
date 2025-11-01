# [PURPLE] Task Owner: GUI Redesign — Light Theme с динамическими профилями

**Дата**: 2025-11-01
**Приоритет**: MEDIUM
**Статус**: TODO

---

## Проблема

**Краткое описание**:
Текущий GUI ISP Audit использует устаревший дизайн без системы токенов, не показывает пошаговое выполнение тестов и не поддерживает динамическое отображение профилей из JSON. Необходим современный UI в светлой теме с live-обновлением статусов и автоскроллом.

**Контекст**:
- Кто столкнётся: Игроки Star Citizen, использующие ISP Audit для диагностики
- Критичность: **MEDIUM** (текущий GUI работает, но UX можно улучшить)

---

## Желаемый результат (Definition of Done)

После выполнения:

1. **PNG-мокап** (1080-1280px, светлая тема) с 5 карточками из Default.json
2. **Дизайн-токены** в App.xaml или DesignTokens.xaml:
   - Типографика: H1 28/700, H2 18/600, Body 14/400, Caption 12/400
   - Отступы: xs=8, s=12, m=16, l=24, xl=32
   - Цвета: Bg #FAFAFB, Panel #FFFFFF, Primary #2563EB, Pass #10B981, Fail #EF4444, Warn #EAB308
   - Радиусы, тени, высоты контролов
3. **MainWindow.xaml** с компонентами:
   - Заголовок "ISP Audit"
   - Радио: "По хосту" / "По .exe" / "По профилю"
   - ComboBox профилей (показывает Name, TestMode, ExePath)
   - Кнопка "Тестировать" (Primary) → "Остановить" (Secondary) во время работы
   - Степпер прогресса (1/5, 2/5...)
   - ScrollViewer со списком карточек тестов:
     - Статус-круг (idle/running/pass/fail/warn)
     - Name (H2), Service (Body), Host (Caption)
     - Чип "Критичный" если Critical=true
     - Кнопка "Исправить" (если isFixable) или "Подробности"
   - Кнопка "Отчёт" (внизу, активна после завершения)
4. **MainWindow.xaml.cs** с логикой:
   - Загрузка Targets из выбранного профиля
   - Последовательное выполнение тестов (AuditRunner с IProgress)
   - Обновление статусов карточек в реальном времени
   - Автоскролл к активной карточке
   - Модалка "Исправить" с текстом и кнопками "Применить"/"Отмена"
   - Модалка "Подробности" с логами/метриками
   - CancellationToken для "Остановить"
   - Суммарный результат после завершения (OK/Fail/Warning count + время)
5. **Обновленный ServiceItemViewModel.cs** для карточек:
   - Свойства: Name, Service, Host, Critical, Status (enum), IsFixable, Timer
   - INotifyPropertyChanged для live-обновлений

Критерии приёмки:
- ✅ PNG-мокап соответствует описанию (все токены, 5 карточек из JSON)
- ✅ `dotnet build -c Debug` проходит без ошибок
- ✅ GUI показывает профиль Default с 5 targets при запуске
- ✅ При нажатии "Тестировать" карточки меняют статус поочередно (сверху вниз)
- ✅ Степпер обновляется (1/5 → 2/5 → ... → 5/5)
- ✅ Автоскролл к активной карточке
- ✅ Кнопка "Отчёт" активна после завершения, показывает суммарный результат
- ✅ Модалки "Исправить" и "Подробности" работают
- ✅ Кнопка "Остановить" прерывает выполнение
- ✅ Старые профили (StarCitizen.json) работают без изменений
- ✅ Нет регрессий — CLI режим работает как раньше

---

## Ограничения

**Технические**:
- .NET 9, WPF + MaterialDesignInXaml 5.1.0
- Светлая тема (Primary #2563EB, Secondary #2DD4BF)
- Async/await + CancellationToken
- ObservableCollection<ServiceItemViewModel> для карточек
- IProgress<TestProgress> для обновления UI из AuditRunner
- Обратная совместимость: **Да** (старые JSON-профили работают)

**Что НЕ делать**:
- ❌ НЕ трогать логику тестов (Tests/), AuditRunner.cs
- ❌ НЕ менять JSON-схему профилей
- ❌ НЕ использовать сторонние библиотеки кроме MaterialDesign
- ❌ НЕ делать темную тему
- ❌ НЕ реализовывать PDF-экспорт (это отдельная задача)

**Оценка**: **MEDIUM** (7-9 подзадач)

**Рекомендуемые модели**:
- Research/Planning: GPT-4o, Claude Sonnet
- Coding: GPT-4o-mini, Claude Haiku (быстрые модели для подзадач)
- QA: Claude Sonnet

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

**Статус**: [ ] TODO

**Промпт для нового чата**:
```
Ты [RED] Research Agent. Работаешь в изолированном контексте.

Прочитай файл agents/task_owner/current_task.md и исследуй проблему:
1. Найди все затронутые файлы и компоненты (GUI: MainWindow.xaml, MainWindow.xaml.cs, App.xaml, ServiceItemViewModel.cs)
2. Изучи текущую реализацию (как сейчас отображаются тесты, какие MaterialDesign компоненты используются)
3. Выяви риски и зависимости (ObservableCollection, IProgress, CancellationToken, профили JSON)
4. Пойми архитектуру релевантных частей (как AuditRunner работает с IProgress, как ServiceItemViewModel связан с UI)

Создай файл agents/research_agent/findings.md со структурой:

## Затронутые файлы
[список с описанием что делает каждый]

## Текущая реализация
[как работает сейчас: структура XAML, биндинги, статусы, прогресс]

## Риски и зависимости
[что может сломаться, от чего зависит: ObservableCollection thread safety, async/await в UI, MaterialDesign версия]

## Рекомендации для Planning Agent
[что важно учесть при планировании: порядок изменений, какие компоненты MaterialDesign использовать, как обеспечить обратную совместимость]
```

---

## [2] [BLUE] Planning Agent

**Статус**: [ ] TODO

**Промпт для нового чата**:
```
Ты [BLUE] Planning Agent. Работаешь в изолированном контексте.

Прочитай:
1. agents/task_owner/current_task.md (задача)
2. agents/research_agent/findings.md (результаты исследования)

Создай детальный план в agents/planning_agent/plan.md:

ВАЖНО: Оптимизируй для экономии API лимитов!
- Каждая подзадача = 1-2 файла максимум
- Группируй связанные изменения
- Минимизируй количество подзадач без потери качества

Формат каждой подзадачи:

## Подзадача N: [Название]
- Файлы: path/to/file.cs (строки X-Y если известно)
- Описание: [что именно изменить, какой код добавить/удалить/заменить]
- Зависимости: нет / после подзадачи M
- Риски: [если есть]
- Рекомендуемая модель: быстрая (GPT-4o-mini / Haiku / Flash)

В конце добавь секцию:

## Итого
- Количество подзадач: N
- Порядок выполнения: [последовательно / можно параллельно задачи X,Y,Z]
- Основные риски: [общие риски]
```

---

## [3] [GREEN] Coding Agent (повторить N раз)

**Статус по подзадачам**: (будет заполнено Planning Agent)

**Промпт для каждой подзадачи N**:
```
Ты [GREEN] Coding Agent #N. Работаешь в изолированном контексте.

1. Прочитай agents/planning_agent/plan.md
2. Найди в нём подзадачу N: [НАЗВАНИЕ ПОДЗАДАЧИ]
3. Прочитай указанные файлы
4. Внеси изменения согласно описанию в подзадаче
5. Убедись что синтаксис правильный

НЕ создавай промежуточные файлы!
Результат: изменённый код, готовый к тестированию.
```

---

## [4] [YELLOW] QA Agent

**Статус**: [ ] TODO

**Промпт для нового чата**:
```
Ты [YELLOW] QA Agent. Работаешь в изолированном контексте.

1. Прочитай agents/task_owner/current_task.md (секция "Желаемый результат")
2. Запусти `dotnet build -c Debug` для проверки компиляции
3. Запусти `dotnet run` и проверь GUI визуально:
   - Загружается Default.json с 5 targets
   - Радио-переключатель работает
   - ComboBox показывает профили
   - Кнопка "Тестировать" → карточки меняют статус поочередно
   - Степпер обновляется
   - Автоскролл к активной карточке
   - Кнопка "Остановить" прерывает выполнение
   - Модалки "Исправить" и "Подробности" открываются
   - Кнопка "Отчёт" активна после завершения
4. Проверь каждый критерий приёмки
5. Проверь на регрессии (StarCitizen.json работает, CLI режим работает)

Создай agents/qa_agent/test_report.md в формате:

## Результаты тестирования
[список проверенных критериев с PASS/FAIL]

## Найденные проблемы
[список проблем или 'Проблем не найдено']

## Рекомендации
[нужны ли фиксы, можно ли коммитить]
```

---

## [5] [CYAN] Delivery Agent

**Статус**: [ ] TODO

**Промпт для нового чата**:
```
Ты [CYAN] Delivery Agent. Работаешь в изолированном контексте.

1. Прочитай agents/task_owner/current_task.md и agents/planning_agent/plan.md
2. Создай краткий changelog (что изменилось, зачем)
3. Добавь запись в agents/delivery_agent/changelog.md
4. Создай git commit с сообщением:

GUI Redesign: Light Theme с динамическими профилями

Обновлен GUI ISP Audit в светлую тему с системой дизайн-токенов,
пошаговым отображением тестов и поддержкой динамических профилей из JSON.

Основные изменения:
- Дизайн-токены (типографика, цвета, отступы)
- Радио-переключатель режимов + ComboBox профилей
- Степпер прогресса с автоскроллом к активной карточке
- Карточки тестов со статусами (idle/running/pass/fail/warn)
- Модалки "Исправить" и "Подробности"
- Кнопка "Остановить" с CancellationToken
- Суммарный результат после завершения

Generated with AI Assistant

5. (Опционально) Обнови README.md если изменился функционал
```

---

## Заметки

**Входной JSON для мокапа** (Profiles/Default.json):
```json
{
  "Name": "Default",
  "TestMode": "general",
  "ExePath": "",
  "Targets": [
    {"Name":"YouTube","Host":"www.youtube.com","Service":"Video Streaming (TCP 80, 443)","Critical":true,"FallbackIp":null},
    {"Name":"Google DNS","Host":"dns.google","Service":"DNS over HTTPS (TCP 443)","Critical":true,"FallbackIp":"8.8.8.8"},
    {"Name":"Cloudflare","Host":"cloudflare.com","Service":"CDN/DNS (TCP 80, 443)","Critical":false,"FallbackIp":null},
    {"Name":"Amazon AWS","Host":"aws.amazon.com","Service":"Cloud Services (TCP 443)","Critical":false,"FallbackIp":null},
    {"Name":"Discord","Host":"discord.com","Service":"Gaming Chat (TCP 443, UDP 50000-65535)","Critical":false,"FallbackIp":null}
  ]
}
```

**Дизайн-токены**:
- Типографика: H1 28/700, H2 18/600, Body 14/400, Caption 12/400
- Отступы: xs=8, s=12, m=16, l=24, xl=32
- Скругления: radius=12
- Контролы: высота 40
- Икон/статус-кружок: 24
- Цвета Light:
  - Bg #FAFAFB, Panel #FFFFFF, Text #0B1220, Muted #667085, Border #E5E7EB
  - Primary #2563EB, PrimaryHover #1E55D7
  - Pass #10B981, Fail #EF4444, Warn #EAB308, Idle #9CA3AF, Running #2563EB
  - Тень: rgba(16,24,40,0.08)

**Состояния статуса**:
- idle — серый контур
- running — синий спиннер
- pass — зеленая ✓
- fail — красная ✕
- warn — жёлтый !

**Микро-копирайтинг** (карточка теста):
- Ожидание: "В очереди на проверку"
- Выполняется: "Проверяем: {Service}..."
- OK: "Проверка пройдена"
- Warning: "Замечания: {краткое описание}"
- Fail: "Ошибка: {краткое описание}"
- Skipped: "Пропущено из-за условий"

**Автоскролл**: `ScrollViewer.ScrollToVerticalOffset()` или `FrameworkElement.BringIntoView()`

**Модалки**: `materialDesign:DialogHost` или отдельные Window с `ShowDialog()`


