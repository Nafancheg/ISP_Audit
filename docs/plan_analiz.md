# Анализ плана ISP_Audit Roadmap (plan3.md)

**Дата:** 20.01.2026
**Версия:** С привязкой к реальному коду проекта

---

## 📊 Общая оценка

| Критерий | Оценка | Комментарий |
|----------|--------|-------------|
| **Полнота** | ⭐⭐⭐⭐⭐ (5/5) | Охватывает все аспекты: стабилизация, UX, observability, архитектура |
| **Реалистичность** | ⭐⭐⭐⭐ (4/5) | Сроки амбициозные, но достижимы при фокусе |
| **Структурированность** | ⭐⭐⭐⭐⭐ (5/5) | Чёткие фазы, критерии успеха, deliverables |
| **Приоритизация** | ⭐⭐⭐⭐⭐ (5/5) | Правильный P0→P3 порядок, сначала стабильность |
| **Риск-менеджмент** | ⭐⭐⭐⭐ (4/5) | Риски описаны, но buffer времени может быть недостаточен |

### Сильные стороны плана:
- ✅ Начинается с критических крашей (P0.1) — правильный подход
- ✅ Детальный debug-процесс с ежедневными задачами
- ✅ Инкрементальная миграция Policy-Driven (не Big Bang)
- ✅ Feature flags для безопасного отката
- ✅ Dual mode для параллельной работы старой и новой логики
- ✅ Метрики успеха (KPI) чётко определены

### Области для улучшения:
- ⚠️ 20-недельный timeline может растянуться (нужен buffer 30-40%)
- ⚠️ Некоторые задачи P1-P2 можно упростить или отложить
- ⚠️ Policy-Driven — высокий риск, нужен более детальный spike

### Текущее состояние проекта (важно!):
- ✅ **Policy-Driven базовая инфраструктура УЖЕ реализована** (см. `FlowPolicy`, `DecisionGraphSnapshot`, `PolicySetCompiler`)
- ✅ **BypassStateManager** — единый SSoT для bypass, уже есть guard-механизм
- ✅ **Транзакции Apply** — журнал `BypassApplyTransactionJournal` уже работает
- ✅ **Селективный UDP/443** — уже реализован (observed IPv4 targets)
- ⚠️ **TrafficEngine crash** — проблема актуальна, требует фикса

---

## �️ Карта файлов проекта (привязка к задачам)

### P0.1: TrafficEngine crash — ключевые файлы

| Файл | Роль | Проблема |
|------|------|----------|
| [Core/Traffic/TrafficEngine.cs](../Core/Traffic/TrafficEngine.cs#L268) | Главный loop пакетов | Место crash: `Loop crashed: {ex.Message}` (строка 268) |
| [Core/Traffic/TrafficEngine.cs](../Core/Traffic/TrafficEngine.cs#L13) | Коллекция фильтров | `_filters` (List) под `lock`, но итерация внутри lock (строка 203-218) |
| [Core/Traffic/Filters/BypassFilter.ProbeFlows.cs](../Core/Traffic/Filters/BypassFilter.ProbeFlows.cs#L47) | Probe flows cleanup | ⚠️ **ПОТЕНЦИАЛЬНАЯ ГОНКА**: `foreach` + `TryRemove` на `ConcurrentDictionary` (строки 47-52) |
| [Bypass/BypassStateManager.Udp443ActiveTargets.cs](../Bypass/BypassStateManager.Udp443ActiveTargets.cs#L58) | Active hosts TTL | `foreach` на `ConcurrentDictionary` под `lock` — безопасно |
| [Bypass/BypassStateManager.ObservedIpCache.cs](../Bypass/BypassStateManager.ObservedIpCache.cs#L143) | Observed IPs | `foreach` на `Dictionary.Keys` под `lock` — безопасно |

#### 🔴 Найденные потенциальные проблемы:

**1. BypassFilter.ProbeFlows.cs:47-52** — foreach + TryRemove:
```csharp
// Строки 47-52: ленивая чистка во время итерации
foreach (var kv in _probeFlowsUntilTick)  // ConcurrentDictionary
{
    if (now > kv.Value)
    {
        _probeFlowsUntilTick.TryRemove(kv.Key, out _);  // ⚠️ модификация во время итерации
    }
}
```
**Решение:** Собирать ключи на удаление в отдельный список, затем удалять.

**2. TrafficEngine.cs:203-218** — foreach под lock:
```csharp
lock (_filters)
{
    foreach (var filter in _filters)  // List<IPacketFilter>
    {
        // Process...
    }
}
```
**Статус:** Безопасно (lock защищает), но может быть contention при частой регистрации фильтров.

### P0.2: Apply timeout — ключевые файлы

| Файл | Роль | Что добавить |
|------|------|--------------|
| [Bypass/TlsBypassService.Engine.cs](../Bypass/TlsBypassService.Engine.cs#L27) | `ApplyAsync` entry point | Добавить фазовое логирование |
| [Bypass/TlsBypassService.Engine.cs](../Bypass/TlsBypassService.Engine.cs#L76) | `ApplyInternalAsync` | Фазы: RemoveFilter → Options → CreateFilter → RegisterFilter |
| [Bypass/BypassStateManager.cs](../Bypass/BypassStateManager.cs#L601) | Manager Apply | Обёртка Apply с gate и scope |
| [Core/Traffic/TrafficEngine.cs](../Core/Traffic/TrafficEngine.cs#L57) | `RegisterFilter` | Потенциальное место зависания |
| [Core/Traffic/TrafficEngine.cs](../Core/Traffic/TrafficEngine.cs#L113) | `StopAsync` | Потенциальное место зависания (ожидание loopTask) |

#### Текущий flow Apply:
```
BypassStateManager.ApplyTlsAsync()
  └─ _applyGate.WaitAsync()           // Сериализация
  └─ BypassStateManagerGuard.EnterScope()
  └─ _tlsService.SetUdp443DropTargetIpsForManager()
  └─ _tlsService.SetDecisionGraphSnapshotForManager()
  └─ _tlsService.ApplyAsync()
       └─ TlsBypassService.ApplyInternalAsync()
            └─ _trafficEngine.RemoveFilter("BypassFilter")  // ⚠️ Может зависать
            └─ new BypassFilter(...)
            └─ _trafficEngine.RegisterFilter(filter)
            └─ _trafficEngine.StartAsync()                  // ⚠️ Может зависать
```

### P1.2: Группировка доменов — ключевые файлы

| Файл | Роль | Текущее состояние |
|------|------|-------------------|
| [Core/Bypass/GroupBypassAttachmentStore.cs](../Core/Bypass/GroupBypassAttachmentStore.cs) | Хранилище групп | ✅ УЖЕ РЕАЛИЗОВАНО — persistence в `group_participation.json` |
| [ViewModels/TestResultsManager.cs](../ViewModels/TestResultsManager.cs) | Результаты тестов | GroupKey уже есть |
| [MainWindow.xaml](../MainWindow.xaml) | UI таблица | Колонка GroupKey уже есть |

### P1.3: Visibility UDP/443 — ключевые файлы

| Файл | Роль | Что показать в UI |
|------|------|-------------------|
| [Core/Traffic/Filters/BypassFilter.Udp443.cs](../Core/Traffic/Filters/BypassFilter.Udp443.cs) | Drop логика | `_udp443DropTargetDstIps` — список IP |
| [Core/Traffic/Filters/BypassFilter.Metrics.cs](../Core/Traffic/Filters/BypassFilter.Metrics.cs) | Метрики | `_udp443Dropped` — счётчик дропов |
| [Bypass/TlsBypassService.Udp443.cs](../Bypass/TlsBypassService.Udp443.cs#L47) | API для IP | `SetUdp443DropTargetIpsForManager()` |
| [Bypass/BypassStateManager.ObservedIpCache.cs](../Bypass/BypassStateManager.ObservedIpCache.cs) | Observed IPs | `GetObservedIpv4TargetsSnapshotForHost()` |

### Policy-Driven — уже реализованные компоненты

| Файл | Статус | Описание |
|------|--------|----------|
| [Core/Models/FlowPolicy.cs](../Core/Models/FlowPolicy.cs) | ✅ Готово | Структура политики |
| [Core/Models/DecisionGraphSnapshot.cs](../Core/Models/DecisionGraphSnapshot.cs) | ✅ Готово | Snapshot для lookup |
| [Core/Models/PolicySetCompiler.cs](../Core/Models/PolicySetCompiler.cs) | ✅ Готово | Компилятор политик |
| [Core/Traffic/Filters/BypassFilter.Udp443.cs](../Core/Traffic/Filters/BypassFilter.Udp443.cs#L81) | ✅ Готово | Policy-driven путь для UDP/443 |
| [Core/Traffic/Filters/BypassFilter.TlsStrategies.cs](../Core/Traffic/Filters/BypassFilter.TlsStrategies.cs#L75) | ✅ Готово | Policy-driven для TLS стратегий |
| [Bypass/BypassStateManager.cs](../Bypass/BypassStateManager.cs#L550) | ✅ Готово | Сборка DecisionGraph при Apply |

### 🔴 КРИТИЧЕСКИЙ (Блокирует работу, P0)

| ID | Задача | Ключевые файлы | Время | Статус |
|----|--------|----------------|-------|--------|
| **P0.1** | TrafficEngine crash | [TrafficEngine.cs#L268](../Core/Traffic/TrafficEngine.cs), [BypassFilter.ProbeFlows.cs#L47](../Core/Traffic/Filters/BypassFilter.ProbeFlows.cs) | 5 дней | ⬜ Не начато |
| **P0.2** | Apply timeout | [TlsBypassService.Engine.cs#L76](../Bypass/TlsBypassService.Engine.cs), [TrafficEngine.cs#L113](../Core/Traffic/TrafficEngine.cs) | 5-8 дней | ⬜ Не начато |
| **P0.3** | Stack trace | Все try-catch блоки, global handler | 2-3 дня | ⬜ Не начато |

**Итого КРИТИЧЕСКИЙ: ~12-16 дней (2 недели)**

---

### 🟠 ВЫСОКИЙ (Серьёзные проблемы UX, P1)

| ID | Задача | Ключевые файлы | Время | Статус |
|----|--------|----------------|-------|--------|
| **P1.1** | Deduplicate Apply | [BypassStateManager.cs](../Bypass/BypassStateManager.cs), [BypassApplyTransactionJournal.cs](../Bypass/BypassApplyTransactionJournal.cs) | 3-4 дня | ⬜ Не начато |
| **P1.2** | Группировка UI | [GroupBypassAttachmentStore.cs](../Core/Bypass/GroupBypassAttachmentStore.cs) — **УЖЕ ЕСТЬ** | 3-4 дня | 🟡 Частично |
| **P1.2+** | Авто-группировка | TestResultsManager + эвристики | 5-7 дней | ⬜ Не начато |
| **P1.3** | Visibility UDP/443 | [BypassFilter.Udp443.cs](../Core/Traffic/Filters/BypassFilter.Udp443.cs), [BypassFilter.Metrics.cs](../Core/Traffic/Filters/BypassFilter.Metrics.cs) | 4-5 дней | ⬜ Не начато |
| **P1.4** | Post-crash диагнозы | DiagnosticOrchestrator + UI | 2-3 дня | ⬜ Не начато |

**Итого ВЫСОКИЙ: ~17-23 дня (3-4 недели)**

---

### 🟡 СРЕДНИЙ (UX улучшения, P2)

| ID | Задача | Ключевые файлы | Время | Статус |
|----|--------|----------------|-------|--------|
| **P2.1** | AutoRetest debounce | [DiagnosticOrchestrator.cs](../ViewModels/DiagnosticOrchestrator.cs) | 2-3 дня | ⬜ Не начато |
| **P2.2** | Early noise filter | [NoiseHostFilter](../Utils/NoiseHostFilter.cs), pipeline | 1-2 дня | ⬜ Не начато |
| **P2.3** | Progress indicator | [BypassController.cs](../ViewModels/BypassController.cs), UI | 2-3 дня | ⬜ Не начато |
| **P2.4** | История транзакций | [BypassApplyTransactionJournal.cs](../Bypass/BypassApplyTransactionJournal.cs) — **ЕСТЬ** | 3-4 дня | 🟡 Частично |

**Итого СРЕДНИЙ: ~8-12 дней (2 недели)**

---

### 🟢 НИЗКИЙ (Observability, P3)

| ID | Задача | Ключевые файлы | Время | Статус |
|----|--------|----------------|-------|--------|
| **P3.1** | Метрики effectiveness | [TlsBypassService.Metrics.cs](../Bypass/TlsBypassService.Metrics.cs) | 5-7 дней | ⬜ Не начато |
| **P3.2** | Экспорт bug report | [BypassController.ApplyTransactions.cs](../ViewModels/BypassController.ApplyTransactions.cs) — **частично есть** | 4-5 дней | 🟡 Частично |
| **P3.3** | Dashboard системы | MainWindow + новая панель | 7-10 дней | ⬜ Не начато |

**Итого НИЗКИЙ: ~16-22 дня (3-4 недели)**

---

### 🔵 СТРАТЕГИЧЕСКИЙ (Policy-Driven, Фаза V) — ЧАСТИЧНО РЕАЛИЗОВАНО

| Этап | Задача | Статус | Что осталось |
|------|--------|--------|--------------|
| **Этап 0** | Контракты и каркас | ✅ **ГОТОВО** | `FlowPolicy`, `DecisionGraphSnapshot`, `PolicySetCompiler` уже есть |
| **Этап 1** | UDP/443 в политики | ✅ **ГОТОВО** | Policy-driven путь в [BypassFilter.Udp443.cs#L81](../Core/Traffic/Filters/BypassFilter.Udp443.cs) работает |
| **Этап 2** | TTL политики | ⬜ Не начато | Нужна поддержка TTL в FlowPolicy |
| **Этап 3** | TCP/80 Host tricks | 🟡 Частично | Базовая поддержка есть в [BypassFilter.HttpHostTricks.cs](../Core/Traffic/Filters/BypassFilter.HttpHostTricks.cs) |
| **Этап 4** | TCP/443 per-domain | 🟡 Частично | [BypassFilter.TlsStrategies.cs#L75](../Core/Traffic/Filters/BypassFilter.TlsStrategies.cs) — есть policy-driven выбор |
| **Этап 5** | Semantic Groups | 🟡 Частично | [GroupBypassAttachmentStore.cs](../Core/Bypass/GroupBypassAttachmentStore.cs) — backend есть |
| **Этап 6** | Observability UI | ⬜ Не начато | UI таблица политик не реализована |

**⚠️ ВАЖНО:** План plan3.md описывает Policy-Driven как будущую работу, но значительная часть УЖЕ РЕАЛИЗОВАНА в проекте!

---

## 📋 Актуализированный план работ

### 🏃 Спринт 1 (Неделя 1): КРИТИЧЕСКАЯ СТАБИЛИЗАЦИЯ

```
Фокус: Устранение crash TrafficEngine
```

#### День 1: Локализация

| Задача | Файл | Описание |
|--------|------|----------|
| Анализ логов | artifacts/*.log.txt | Найти ±100 строк вокруг crash |
| Stack trace | [TrafficEngine.cs#L268](../Core/Traffic/TrafficEngine.cs) | Добавить `ex.ToString()` вместо `ex.Message` |
| Карта коллекций | См. ниже | Составить список всех коллекций в hot path |

**Подозреваемые коллекции (из анализа кода):**

| Коллекция | Файл | Тип | Защита | Риск |
|-----------|------|-----|--------|------|
| `_filters` | [TrafficEngine.cs#L13](../Core/Traffic/TrafficEngine.cs) | `List<IPacketFilter>` | `lock(_filters)` | 🟢 Низкий |
| `_probeFlowsUntilTick` | [BypassFilter.ProbeFlows.cs#L11](../Core/Traffic/Filters/BypassFilter.ProbeFlows.cs) | `ConcurrentDictionary` | Нет | 🔴 **ВЫСОКИЙ** |
| `_connections` | [BypassFilter.TlsStrategies.cs#L15](../Core/Traffic/Filters/BypassFilter.TlsStrategies.cs) | `ConcurrentDictionary` | Нет | 🟢 Низкий (thread-safe API) |
| `_udp443ActiveHostsUntilTick` | [BypassStateManager.Udp443ActiveTargets.cs#L18](../Bypass/BypassStateManager.Udp443ActiveTargets.cs) | `ConcurrentDictionary` | `lock` | 🟢 Низкий |
| `entry.UntilTickByIp` | [BypassStateManager.ObservedIpCache.cs#L23](../Bypass/BypassStateManager.ObservedIpCache.cs) | `Dictionary` | `lock(entry.Sync)` | 🟢 Низкий |

#### 🔴 Главный подозреваемый: `_probeFlowsUntilTick`

**Проблемный код** ([BypassFilter.ProbeFlows.cs#L45-52](../Core/Traffic/Filters/BypassFilter.ProbeFlows.cs)):
```csharp
// Ленивая чистка: если словарь разросся (редко), удаляем просроченные записи.
if (_probeFlowsUntilTick.Count > 64)
{
    foreach (var kv in _probeFlowsUntilTick)  // ⚠️ Итерация
    {
        if (now > kv.Value)
        {
            _probeFlowsUntilTick.TryRemove(kv.Key, out _);  // ⚠️ Модификация
        }
    }
}
```

**Исправление:**
```csharp
if (_probeFlowsUntilTick.Count > 64)
{
    // Собираем ключи на удаление
    var toRemove = new List<ConnectionKey>();
    foreach (var kv in _probeFlowsUntilTick)
    {
        if (now > kv.Value)
        {
            toRemove.Add(kv.Key);
        }
    }
    // Удаляем после итерации
    foreach (var key in toRemove)
    {
        _probeFlowsUntilTick.TryRemove(key, out _);
    }
}
```

#### День 2-3: Воспроизведение + Hotfix

| Задача | Описание |
|--------|----------|
| Regression test | Создать тест: rapid apply/retest во время активной диагностики |
| Hotfix | Исправить foreach+TryRemove в ProbeFlows.cs |
| Аудит | Проверить все аналогичные паттерны в проекте |

#### День 4-5: Тестирование + Релиз

| Задача | Описание |
|--------|----------|
| Stress test | 1000 операций Apply/Rollback за минуту |
| Performance | Сравнить latency с baseline |
| Workaround | Debounce на быстрые Apply во время диагностики |

---

### 🏃 Спринт 2 (Неделя 2): APPLY TIMEOUT + STACK TRACE

```
Фокус: Полная observability для debug Apply
```

#### P0.2: Фазовое логирование Apply

**Текущий код** ([TlsBypassService.Engine.cs#L76](../Bypass/TlsBypassService.Engine.cs)):
```csharp
private async Task ApplyInternalAsync(CancellationToken cancellationToken)
{
    // Фазы не логируются!
    _trafficEngine.RemoveFilter("BypassFilter");
    // ...
    _trafficEngine.RegisterFilter(filter);
    await _trafficEngine.StartAsync(cancellationToken);
}
```

**Что добавить:**
```csharp
private async Task ApplyInternalAsync(CancellationToken cancellationToken)
{
    var sw = Stopwatch.StartNew();
    _log?.Invoke("[Apply] Phase 1: Preparing config...");
    
    _log?.Invoke($"[Apply] Phase 2: Removing old filter... ({sw.ElapsedMilliseconds}ms)");
    _trafficEngine.RemoveFilter("BypassFilter");
    
    _log?.Invoke($"[Apply] Phase 3: Creating new filter... ({sw.ElapsedMilliseconds}ms)");
    // ...
    
    _log?.Invoke($"[Apply] Phase 4: Registering filter... ({sw.ElapsedMilliseconds}ms)");
    _trafficEngine.RegisterFilter(filter);
    
    _log?.Invoke($"[Apply] Phase 5: Starting engine... ({sw.ElapsedMilliseconds}ms)");
    await _trafficEngine.StartAsync(cancellationToken);
    
    _log?.Invoke($"[Apply] Complete: {sw.ElapsedMilliseconds}ms total");
}
```

#### P0.3: Global Exception Handler

**Файлы для изменения:**
- [App.xaml.cs](../App.xaml.cs) — `AppDomain.CurrentDomain.UnhandledException`
- [Program.cs](../Program.cs) — `TaskScheduler.UnobservedTaskException`

---

### 🏃 Спринт 3 (Неделя 3): ВЫСОКОПРИОРИТЕТНЫЕ УЛУЧШЕНИЯ

```
Фокус: Deduplicate + UDP visibility (группировка УЖЕ есть)
```

#### P1.1: Deduplicate Apply

**Текущая проблема:** При обнаружении нового IP для googlevideo.com вызывается полный Apply.

**Решение в** [BypassStateManager.cs](../Bypass/BypassStateManager.cs):
```csharp
public async Task ApplyTlsAsync(...)
{
    // Проверка: не изменилась ли effective config?
    var currentEffective = GetCurrentEffectiveConfig();
    if (currentEffective.Equals(newEffective))
    {
        _log?.Invoke("[Bypass] Skip Apply: config unchanged");
        return;
    }
    // ...
}
```

#### P1.2: Группировка — УЖЕ РЕАЛИЗОВАНО

**Файлы:**
- [GroupBypassAttachmentStore.cs](../Core/Bypass/GroupBypassAttachmentStore.cs) — backend хранилище
- [MainWindow.xaml](../MainWindow.xaml) — колонка GroupKey уже есть
- `group_participation.json` — persistence

**Что осталось:** UI collapsible секции (визуальная группировка).

#### P1.3: Visibility UDP/443

**API уже есть:**
- `TlsBypassService.GetUdp443DropTargetIpsSnapshot()` — список IP
- `BypassFilter._udp443Dropped` — счётчик

**Что добавить в UI** ([MainWindow.xaml](../MainWindow.xaml)):
```xml
<Expander Header="Активные ограничения UDP/443">
    <ItemsControl ItemsSource="{Binding Udp443BlockedIps}">
        <ItemsControl.ItemTemplate>
            <DataTemplate>
                <TextBlock Text="{Binding}" />
            </DataTemplate>
        </ItemsControl.ItemTemplate>
    </ItemsControl>
    <TextBlock Text="{Binding Udp443DroppedCount, StringFormat='Заблокировано пакетов: {0}'}" />
</Expander>
```

---

### 🏃 Спринт 4-8: ОСТАВШИЕСЯ ЗАДАЧИ

| Неделя | Задачи | Файлы |
|--------|--------|-------|
| 4 | P1.4 Post-crash + P2.1 Debounce | DiagnosticOrchestrator.cs |
| 5 | P2.3 Progress + P2.4 История | BypassController.cs, UI |
| 6 | P3.1 Метрики effectiveness | TlsBypassService.Metrics.cs |
| 7 | P3.2 Экспорт | BypassController.ApplyTransactions.cs — **частично есть** |
| 8 | P3.3 Dashboard | Новая панель в MainWindow |

---

### 🏃 Policy-Driven: АКТУАЛЬНЫЙ СТАТУС

**⚠️ План plan3.md устарел в части Policy-Driven — большая часть уже реализована!**

| Компонент | Статус | Файл |
|-----------|--------|------|
| `FlowPolicy` | ✅ | [Core/Models/FlowPolicy.cs](../Core/Models/FlowPolicy.cs) |
| `DecisionGraphSnapshot` | ✅ | [Core/Models/DecisionGraphSnapshot.cs](../Core/Models/DecisionGraphSnapshot.cs) |
| `PolicySetCompiler` | ✅ | [Core/Models/PolicySetCompiler.cs](../Core/Models/PolicySetCompiler.cs) |
| UDP/443 policy-driven | ✅ | [BypassFilter.Udp443.cs#L81](../Core/Traffic/Filters/BypassFilter.Udp443.cs) |
| TLS strategy policy-driven | ✅ | [BypassFilter.TlsStrategies.cs#L75](../Core/Traffic/Filters/BypassFilter.TlsStrategies.cs) |
| Policy metrics | ✅ | [BypassFilter.PolicyMetrics.cs](../Core/Traffic/Filters/BypassFilter.PolicyMetrics.cs) |
| Feature gates | ✅ | `PolicyDrivenExecutionGates` |
| SemanticGroups backend | 🟡 | [GroupBypassAttachmentStore.cs](../Core/Bypass/GroupBypassAttachmentStore.cs) |
| TTL policies | ⬜ | Нужна доработка FlowPolicy |
| Observability UI | ⬜ | Нужна таблица политик в UI |

**Что реально осталось по Policy-Driven:**
1. TTL поддержка в FlowPolicy (1 неделя)
2. UI таблица активных политик (1 неделя)
3. Экспорт policy snapshot (уже частично есть в ApplyTransactions)

---

## ⚖️ Рекомендации по приоритизации (с учётом реального состояния)

### ✅ НЕМЕДЛЕННО (Неделя 1):

| Задача | Файл | Сложность |
|--------|------|-----------|
| **P0.1 Hotfix crash** | [BypassFilter.ProbeFlows.cs#L45-52](../Core/Traffic/Filters/BypassFilter.ProbeFlows.cs) | 🟢 Низкая |
| Stack trace в Loop | [TrafficEngine.cs#L268](../Core/Traffic/TrafficEngine.cs) | 🟢 Низкая |
| Аудит foreach+modify | Все ConcurrentDictionary | 🟡 Средняя |

### ✅ ПРИОРИТЕТ (Недели 2-3):

| Задача | Файл | Сложность |
|--------|------|-----------|
| **P0.2 Фазовое логирование** | [TlsBypassService.Engine.cs#L76](../Bypass/TlsBypassService.Engine.cs) | 🟢 Низкая |
| **P1.3 UDP visibility** | UI + `GetUdp443DropTargetIpsSnapshot()` | 🟡 Средняя |
| **P1.1 Deduplicate Apply** | [BypassStateManager.cs](../Bypass/BypassStateManager.cs) | 🟡 Средняя |

### ⏸️ УЖЕ РЕАЛИЗОВАНО (не требует работы):

| Задача из plan3.md | Файл | Статус |
|--------------------|------|--------|
| Policy-Driven Этап 0-1 | FlowPolicy, DecisionGraph | ✅ Готово |
| Группировка backend | GroupBypassAttachmentStore | ✅ Готово |
| История транзакций backend | BypassApplyTransactionJournal | ✅ Готово |
| Селективный UDP/443 | BypassFilter.Udp443.cs | ✅ Готово |

### 🚫 Устаревшие пункты plan3.md:

- **Этап 0 (Контракты)** — уже есть `FlowPolicy`, `DecisionGraphSnapshot`
- **Этап 1 (UDP/443)** — уже реализован policy-driven путь
- **Этап 4-6** — частично реализованы, нужна только UI часть

---

## 📈 Скорректированный Timeline

```
БЫЛО (plan3.md):    20 недель
АКТУАЛЬНО:          8-10 недель (с учётом уже сделанного)

Реальный scope:
- P0.1-P0.3 (crash + logging): 2 недели
- P1.1-P1.4 (UX):              2-3 недели
- P2.1-P2.4 (polish):          2 недели
- P3.1-P3.3 (observability):   2-3 недели
- Policy-Driven остаток:       1-2 недели (TTL + UI)
```

---

## 🎯 Немедленный следующий шаг

### Исправление crash `_probeFlowsUntilTick`

**Файл:** [Core/Traffic/Filters/BypassFilter.ProbeFlows.cs](../Core/Traffic/Filters/BypassFilter.ProbeFlows.cs)

**Текущий проблемный код (строки 45-52):**
```csharp
if (_probeFlowsUntilTick.Count > 64)
{
    foreach (var kv in _probeFlowsUntilTick)
    {
        if (now > kv.Value)
        {
            _probeFlowsUntilTick.TryRemove(kv.Key, out _);
        }
    }
}
```

**Исправление:**
```csharp
if (_probeFlowsUntilTick.Count > 64)
{
    var toRemove = new List<ConnectionKey>();
    foreach (var kv in _probeFlowsUntilTick)
    {
        if (now > kv.Value)
        {
            toRemove.Add(kv.Key);
        }
    }
    foreach (var key in toRemove)
    {
        _probeFlowsUntilTick.TryRemove(key, out _);
    }
}
```

**Готов применить исправление?**
