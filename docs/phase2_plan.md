# DPI Intelligence v2 — План внедрения

**Дата:** 16.12.2025  
**Статус:** Design Phase  
**Цель:** Заменить хаотичные эвристики на экспертную систему с объяснимыми решениями

---

## 🎯 Проблема

Сейчас байпас работает вслепую:
- `TlsBypassService` пробует техники и смотрит на метрики RST
- Legacy-диагностика (`StandardBlockageClassifier`) знает ЧТО сломано, но не влияет на выбор стратегии
- Два мира изолированы → неэффективный подбор стратегий

**Решение:** Создать intelligence layer между диагностикой и обходом.

---

## 📐 Архитектура (контракт)

### Слои системы

```
┌─────────────────────────────────────────────┐
│ Sensors (текущие сервисы)                   │
│ - RstInspectionService                      │
│ - TcpRetransmissionTracker                  │
│ - (опционально) StandardBlockageClassifier  │
│   *только legacy-вывод для UI, не source-of-truth для Signals*│
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ Signals Adapter (НОВОЕ)                     │
│ Собирает факты → BlockageSignalsV2          │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ Diagnosis Engine (НОВОЕ)                    │
│ Интерпретирует сигналы → DiagnosisResult    │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ Strategy Selector (НОВОЕ)                   │
│ Выбирает техники → BypassPlan               │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ Executor (существующий TlsBypassService)    │
│ Применяет план → Outcome                    │
└──────────────────┬──────────────────────────┘
                   ↓
┌─────────────────────────────────────────────┐
│ Feedback Store (НОВОЕ)                      │
│ Запоминает результаты, ранжирует стратегии  │
└─────────────────────────────────────────────┘
```

### Жёсткие границы (что запрещено)

❌ **Diagnosis Engine** не должен знать про:
- Фрагментацию, TTL, порядок чанков
- Конкретные параметры стратегий

❌ **Strategy Selector** не должен смотреть на:
- TTL, ретрансмиссии, тайминги пакетов
- Напрямую на Sensors

❌ **Feedback** не может:
- Менять диагноз напрямую
- Удалять правила (только ранжирование)

✅ **Разрешено:**
- `HostContext` (auto-hostlist) использовать для UI/логов
- Но НЕ для вычисления диагноза

---

## 📋 Модели данных (контракт)

### SignalEvent / SignalSequence (временные цепочки — первичный источник правды)

Ключевая поправка: блокировка — это **цепочка событий во времени**, а не один снимок.

В v2 `Signals Adapter` обязан собирать **последовательность событий** (stream), а уже затем (при необходимости) агрегировать её в производные признаки.

```csharp
public enum SignalType
{
    HostTested,             // факт завершения активной проверки (DNS/TCP/TLS)
    TcpRetransStats,        // обновление счётчиков ретрансмиссий/пакетов
    SuspiciousRstObserved,  // подозрительный RST (из инспектора)
    HttpRedirectObserved,   // DPI-подобный HTTP redirect
    UdpHandshakeUnanswered, // (если нужно) безответные UDP рукопожатия
}

public sealed class SignalEvent
{
    public string HostKey { get; init; }           // стабильный ключ (например: IP или IP:port:proto)
    public SignalType Type { get; init; }
    public object? Value { get; init; }
    public DateTime ObservedAtUtc { get; init; }
    public string Source { get; init; }            // "HostTester", "RstInspectionService", ...
}

public sealed class SignalSequence
{
    public string HostKey { get; init; }
    public List<SignalEvent> Events { get; } = new();
    public DateTime FirstSeenUtc { get; init; }
    public DateTime LastUpdatedUtc { get; set; }
}
```

Примечание:
- `SignalSequence` — это слой **фактов**. Никакой интерпретации и никаких стратегий внутри.
- Для диагностики удобно иметь производные признаки (см. ниже), но они должны вычисляться **из последовательности**, а не “снимком в момент T=0”.

### BlockageSignalsV2 (производные признаки из последовательности)

`BlockageSignalsV2` остаётся в контракте как **срез/агрегация** по окну времени (например 30–60 секунд, см. Step 0 / Implementation Details) поверх `SignalSequence`.
Это убирает проблему “T=0 vs T+2s vs T+5s”: адаптер дописывает события, а агрегатор пересчитывает признаки.

```csharp
public class BlockageSignalsV2 
{
    // TCP уровень
    public bool HasTcpReset { get; set; }
    public bool HasTcpTimeout { get; set; }
    public double RetransmissionRate { get; set; }  // 0.0-1.0
    
    // RST анализ
    public int? RstTtlDelta { get; set; }           // null если RST не было
    public TimeSpan? RstLatency { get; set; }       // null если RST не было
    
    // DNS уровень
    public bool HasDnsFailure { get; set; }
    public bool HasFakeIp { get; set; }             // 198.18.x.x
    
    // HTTP уровень
    public bool HasHttpRedirect { get; set; }
    
    // TLS уровень
    public bool HasTlsTimeout { get; set; }
    public bool HasTlsReset { get; set; }
    
    // Метаданные
    public int SampleSize { get; set; }
    public DateTime CapturedAt { get; set; }

    // Служебное качество данных
    public bool IsUnreliable { get; set; }         // если сигналы флапают/данных мало
}
```

### DiagnosisResult (интерпретация)

```csharp
public enum DiagnosisId 
{
    None,                   // не удалось диагностировать
    Unknown,                // недостаточно данных
    ActiveDpiEdge,          // быстрый RST с TTL аномалией
    StatefulDpi,            // медленный RST, stateful инспекция
    SilentDrop,             // timeout + высокие ретрансмиссии
    DnsHijack,              // DNS подмена
    HttpRedirect,           // HTTP заглушка
    MultiLayerBlock,        // DNS + DPI одновременно
    NoBlockage              // легитимная недоступность
}

public class DiagnosisResult 
{
    public DiagnosisId Diagnosis { get; set; }
    public int Confidence { get; set; }             // 0-100
    public string MatchedRuleName { get; set; }     // какое правило сработало
    public string ExplanationNotes { get; set; }    // "RST через 45ms, TTL +12"
    
    public BlockageSignalsV2 InputSignals { get; set; }
    public DateTime DiagnosedAt { get; set; }
}
```

### BypassPlan (рецепт)

```csharp
public enum StrategyId 
{
    None,
    TlsDisorder,
    TlsFragment,
    TlsFakeTtl,
    DropRst,
    UseDoh, // TODO: будущая стратегия; в MVP не использовать в маппинге (в репозитории может отсутствовать реализация)
    AggressiveFragment
}

// TODO (Step 0): добавить это в кодовую базу, сейчас в документе используется как контрактное поле.
public enum RiskLevel { Low, Medium, High }

public class BypassStrategy 
{
    public StrategyId Id { get; set; }
    public int BasePriority { get; set; }          // из таблицы маппинга
    public Dictionary<string, object> Parameters { get; set; }
    public RiskLevel Risk { get; set; }            // Low/Medium/High
}

public class BypassPlan 
{
    public List<BypassStrategy> Strategies { get; set; }
    public DiagnosisId ForDiagnosis { get; set; }
    public int PlanConfidence { get; set; }
    public string Reasoning { get; set; }
}
```

---

## 🚀 План внедрения (5 шагов)

### Шаг 0: Финализация контракта

**Что:** Зафиксировать модели данных и интерфейсы  
**Время:** 2-3 часа  
**Выход:** Этот документ + C# интерфейсы

**Критерий готовности:**
- ✅ Все модели определены (BlockageSignalsV2, DiagnosisResult, BypassPlan)
- ✅ Границы слоёв понятны и зафиксированы
- ✅ Нет двусмысленностей в контракте

### Implementation Details (уточнения контракта)

**SignalSequence storage:**
- Хранение: расширить существующий `InMemoryBlockageStateStore` (in-memory).
- Ключ: `HostKey` должен быть стабилен и непустой (например IP или IP:port:proto — зависит от доступных данных).

**Агрегация и окна:**
- Окно агрегации по умолчанию: **30 секунд**.
- Расширенное окно (для потенциально stateful/медленных сценариев): **60 секунд**.

**Очистка событий (защита от роста памяти):**
- TTL событий: **10 минут**.
- Очистка выполняется при `Append(...)` (удаляем события старше TTL).

**StandardBlockageClassifier:**
- В MVP продолжает работать параллельно (для legacy-UI/совместимости).
- В UI v2-диагноз приоритетнее, legacy явно маркируется как "legacy".
- После стабилизации v2: планируется полное отключение legacy-классификатора.

**Нереализованные стратегии:**
- `UseDoh` в MVP **не добавлять** в маппинг (в текущем репозитории может отсутствовать реализация DoH как стратегии).
- При попытке применить нереализованную стратегию: `log warning` + `skip` (без исключений).

**RiskLevel protection:**
- Стратегии с риском `High` запрещены при `confidence < 70`.
- Фильтрация реализуется в `StrategySelector.SelectStrategies()`.

---

### Шаг 1: Signals Adapter

**Что:** Собрать временные события из существующих сервисов, поддерживать `SignalSequence` и логировать  
**Время:** 1 день  
**Компонент:** `Core/Intelligence/SignalsAdapter.cs`

**Реализация:**

```csharp
public class SignalsAdapter 
{
    private static readonly TimeSpan DefaultAggregationWindow = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ExtendedAggregationWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan EventTtl = TimeSpan.FromMinutes(10);

    // Внимание: ниже псевдокод.
    // Идея: адаптер НЕ делает "один снимок".
    // Он дописывает события в последовательность и позволяет в любой момент построить агрегированный срез.

    public void AppendHostTested(HostTested tested)
    {
        Append(new SignalEvent {
            HostKey = tested.Host.RemoteIp.ToString(),
            Type = SignalType.HostTested,
            Value = tested,
            ObservedAtUtc = DateTime.UtcNow,
            Source = "HostTester"
        });
    }

    public void AppendSuspiciousRst(IPAddress ip, string details)
    {
        Append(new SignalEvent {
            HostKey = ip.ToString(),
            Type = SignalType.SuspiciousRstObserved,
            Value = details,
            ObservedAtUtc = DateTime.UtcNow,
            Source = "RstInspectionService"
        });
    }

    public BlockageSignalsV2 BuildSnapshot(string hostKey, TimeSpan window)
    {
        // Берём события за окно и строим производные признаки.
        // Реализация зависит от того, как вы храните/очищаете события.
        var seq = _stateStore.GetOrCreateSequence(hostKey);
        var events = seq.Events.Where(e => (DateTime.UtcNow - e.ObservedAtUtc) <= window).ToList();

        // В MVP допускается частичная агрегация: мы логируем события всегда,
        // а качество/полноту среза отражаем флагом IsUnreliable.
        var snapshot = new BlockageSignalsV2
        {
            CapturedAt = DateTime.UtcNow,
            SampleSize = events.Count,
            IsUnreliable = events.Count < 2
        };
        
        _logger.LogInformation($"SignalsWindow[{hostKey}]: {JsonSerializer.Serialize(snapshot)}");
        return snapshot;
    }

    private void Append(SignalEvent evt)
    {
        if (string.IsNullOrWhiteSpace(evt.HostKey))
        {
            _logger.LogWarning("SignalEvent ignored: empty HostKey");
            return;
        }

        var seq = _stateStore.GetOrCreateSequence(evt.HostKey);
        seq.Events.Add(evt);
        seq.LastUpdatedUtc = DateTime.UtcNow;

        // Очистка старых событий (TTL)
        var cutoff = DateTime.UtcNow - EventTtl;
        seq.Events.RemoveAll(e => e.ObservedAtUtc < cutoff);

        _logger.LogDebug($"SignalEvent[{evt.HostKey}] {evt.Type} from {evt.Source}");
    }
}
```

**Критерий готовности (Gate 1→2 — реалистичный и проверяемый):**

✅ **Успех:**
- События `SignalEvent` пишутся в лог/вывод без исключений (нет падений при отсутствии данных).
- Для 10 разных `HostKey`: минимум 2 события на хост.
- `HostKey` непустой в 100% событий.
- `Value != null` хотя бы в одном событии на хост.
- Человек может восстановить цепочку из логов: "HostTested → (потом) SuspiciousRst/Redirect/Retx".

❌ **Провал:** есть исключения/пустые ключи/невозможность восстановить цепочку → Step 2 запрещён.

---

### Шаг 2: Diagnosis Engine

**Что:** Реализовать правила для 2 диагнозов  
**Время:** 1-2 дня  
**Компонент:** `Core/Intelligence/DiagnosisEngine.cs`

**Диагнозы для MVP (поэтапно, без циклических зависимостей):**

Этап 1 (используем только то, что уже есть и стабильно собирается):
1. **DnsHijack** — по DNS-фейлам/подмене.
2. **SilentDrop / TcpTimeout** — по таймаутам + высокой доле ретрансмиссий.

Этап 2 (после расширения сенсоров RST и/или появления устойчивого маркера DPI-инжекции):
3. **ActiveDpiEdge** — добавляем правило только когда данные реально доступны.

**Реализация:**

```csharp
public class DiagnosticRule 
{
    public string Name { get; set; }
    public DiagnosisId Produces { get; set; }
    public int BaseConfidence { get; set; }        // 0-100
    public Func<BlockageSignalsV2, bool> Condition { get; set; }
    public Func<BlockageSignalsV2, string> ExplainFunc { get; set; }
}

public class DiagnosisEngine 
{
    private readonly List<DiagnosticRule> _rules = new() 
    {
        // Этап 1: DNS блокировка (данные доступны сразу)
        new() {
            Name = "DNS_Hijack_v1",
            Produces = DiagnosisId.DnsHijack,
            BaseConfidence = 95,
            Condition = s => 
                s.HasDnsFailure || s.HasFakeIp,
            ExplainFunc = s => 
                s.HasFakeIp ? "Fake IP 198.18.x.x" : "DNS resolution failed"
        },

        // Этап 1: таймаут/дроп (данные доступны сразу)
        new() {
            Name = "TCP_Timeout_Drop_v1",
            Produces = DiagnosisId.SilentDrop,
            BaseConfidence = 60,
            Condition = s => s.HasTcpTimeout && s.RetransmissionRate > 0.3,
            ExplainFunc = s => $"TCP timeout + retrans rate {s.RetransmissionRate:F2}"
        }
    };
    
    public DiagnosisResult Diagnose(BlockageSignalsV2 signals) 
    {
        // Найти все сработавшие правила
        var matched = _rules
            .Where(r => r.Condition(signals))
            .OrderByDescending(r => r.BaseConfidence)
            .ThenBy(r => r.Name)  // детерминизм при равенстве
            .ToList();
        
        if (!matched.Any()) {
            return new DiagnosisResult {
                Diagnosis = DiagnosisId.Unknown,
                Confidence = 0,
                MatchedRuleName = "None",
                ExplanationNotes = "Недостаточно данных",
                InputSignals = signals,
                DiagnosedAt = DateTime.UtcNow
            };
        }
        
        var best = matched.First();
        return new DiagnosisResult {
            Diagnosis = best.Produces,
            Confidence = best.BaseConfidence,
            MatchedRuleName = best.Name,
            ExplanationNotes = best.ExplainFunc(signals),
            InputSignals = signals,
            DiagnosedAt = DateTime.UtcNow
        };
    }
}
```

**Критерий готовности (Gate 2→3 — реалистичный):**

Нужны два набора "якорных" целей (конфигурируемо под регион/пользователя):
- 5 заведомо блокируемых/проблемных (для данного пользователя).
- 5 заведомо рабочих (например CDN/проверочные).

✅ **Успех:**
- Для проблемных: диагноз **не** `Unknown` и `Confidence > 30`.
- Для рабочих: диагноз `NoBlockage` либо `Unknown` с низкой уверенностью.
- `ExplanationNotes` читаем и ссылается на факты ("DNS fail", "timeout + retx", ...).

❌ **Провал:** диагностика часто `Unknown` на проблемных или даёт уверенные диагнозы на рабочих → дорабатываем правила.

---

### Шаг 3: Strategy Selector

**Что:** Таблица маппинга диагноз → стратегии  
**Время:** 4-6 часов  
**Компонент:** `Core/Intelligence/StrategySelector.cs`

**Реализация:**

```csharp
public class StrategySelector 
{
    // Таблица маппинга (hardcoded в MVP)
    private static readonly Dictionary<DiagnosisId, List<(StrategyId, int)>> _mapping = new() 
    {
        [DiagnosisId.ActiveDpiEdge] = new() {
            (StrategyId.TlsDisorder, 10),
            (StrategyId.TlsFragment, 8),
            (StrategyId.TlsFakeTtl, 5)
        },
        
        // DNS-блокировки в MVP: без авто-стратегий (только рекомендации/подсказки пользователю).
        // TODO: добавить UseDoh, когда появится реальная реализация стратегии.
        [DiagnosisId.DnsHijack] = new(),
        
        [DiagnosisId.None] = new(),
        [DiagnosisId.Unknown] = new()
    };
    
    public BypassPlan SelectStrategies(DiagnosisResult diagnosis) 
    {
        // Защита от слабых диагнозов
        if (diagnosis.Diagnosis == DiagnosisId.None || 
            diagnosis.Diagnosis == DiagnosisId.Unknown ||
            diagnosis.Confidence < 50) 
        {
            return new BypassPlan { 
                Strategies = new(),
                ForDiagnosis = diagnosis.Diagnosis,
                PlanConfidence = diagnosis.Confidence,
                Reasoning = "Диагноз неуверенный, обход не рекомендуется"
            };
        }
        
        // Получить стратегии из таблицы
        var strategies = _mapping[diagnosis.Diagnosis]
            .Select(x => new BypassStrategy {
                Id = x.Item1,
                BasePriority = x.Item2,
                Parameters = GetDefaultParameters(x.Item1),
                Risk = GetRiskLevel(x.Item1)
            })
            .OrderByDescending(s => s.BasePriority)
            .ToList();

        // Защита от агрессивных стратегий при недостаточной уверенности
        if (diagnosis.Confidence < 70)
        {
            strategies = strategies
                .Where(s => s.Risk != RiskLevel.High)
                .ToList();
        }
        
        return new BypassPlan {
            Strategies = strategies,
            ForDiagnosis = diagnosis.Diagnosis,
            PlanConfidence = diagnosis.Confidence,
            Reasoning = $"Диагноз '{diagnosis.Diagnosis}' (уверенность {diagnosis.Confidence}%) → {strategies.Count} стратегий"
        };
    }
    
    private Dictionary<string, object> GetDefaultParameters(StrategyId id) 
    {
        return id switch {
            StrategyId.TlsFragment => new() { ["split_position"] = 3, ["min_chunk"] = 8 },
            StrategyId.TlsFakeTtl => new() { ["ttl"] = 8 },
            _ => new()
        };
    }
    
    private RiskLevel GetRiskLevel(StrategyId id) 
    {
        return id switch {
            StrategyId.TlsDisorder => RiskLevel.Low,
            StrategyId.TlsFragment => RiskLevel.Low,
            StrategyId.TlsFakeTtl => RiskLevel.Medium,
            StrategyId.DropRst => RiskLevel.High,
            _ => RiskLevel.Low
        };
    }
}
```

**Критерий готовности (Gate 3→4):**

- ✅ Для `Diagnosis=None/Unknown` → пустой план
- ✅ Для слабых диагнозов (confidence <50) → пустой план
- ✅ Агрессивные стратегии (DROP_RST) не появляются при низкой уверенности
- ✅ Стратегии с `RiskLevel.High` фильтруются при confidence <70
- ✅ План детерминирован (одинаковый для одного диагноза)

---

### Шаг 4: Executor (MVP — только логирование)

**Что:** Компонент который ПОКА ТОЛЬКО логирует рекомендации  
**Время:** 2-3 часа  
**Компонент:** `Core/Intelligence/BypassExecutor.cs`

**ВАЖНО:** В MVP НЕ применяем стратегии автоматически.

Но MVP должен давать пользу: допускается **ручное применение** (по кнопке пользователя).
То есть "auto-apply" запрещён, а "one-click apply" (явное действие пользователя) разрешён.

**Реализация:**

```csharp
public class BypassExecutorMvp 
{
    private readonly ILogger _logger;
    
    public ExecutionOutcome LogRecommendations(BypassPlan plan) 
    {
        _logger.LogInformation($"[MVP] Diagnosis: {plan.ForDiagnosis}");
        _logger.LogInformation($"[MVP] Confidence: {plan.PlanConfidence}%");
        _logger.LogInformation($"[MVP] Reasoning: {plan.Reasoning}");
        
        if (!plan.Strategies.Any()) {
            _logger.LogInformation("[MVP] Стратегии не рекомендованы");
            return new ExecutionOutcome {
                WasExecuted = false,
                Note = "Диагноз слабый, обход не рекомендуется"
            };
        }
        
        foreach (var strategy in plan.Strategies) {
            _logger.LogInformation(
                $"[MVP] Рекомендуется: {strategy.Id} " +
                $"(приоритет: {strategy.BasePriority}, риск: {strategy.Risk})"
            );
        }
        
        return new ExecutionOutcome {
            WasExecuted = false,
            RecommendedStrategies = plan.Strategies,
            Note = "MVP mode: только рекомендации, авто-применение отключено"
        };
    }
}
```

**Критерий готовности (Gate 4→5):**

- ✅ Логи показывают понятный reasoning
- ✅ Никакого авто-применения bypass не происходит
- ✅ Рекомендации появляются только для уверенных диагнозов

---

### Шаг 5: Интеграция в UI

**Что:** Заменить старые рекомендации на v2  
**Время:** 4-6 часов  
**Компонент:** `ViewModels/DiagnosticOrchestrator.cs`

**Переходный период (чтобы не было двух “конкурирующих истин”):**
- Legacy-диагностика (`StandardBlockageClassifier`) остаётся, но в UI явно помечается как **legacy**.
- V2-диагноз показывается приоритетно (и именно он управляет рекомендациями v2).
- Технически это может быть реализовано через отдельные поля/строки для отображения (TODO в рамках Step 5).

**Реализация:**

```csharp
// В DiagnosticOrchestrator после завершения активной проверки хоста (DNS/TCP/TLS)
private void OnHostTested(HostTested tested)
{
    try
    {
        // 0) Дописать факт в последовательность событий (SignalSequence)
        var hostKey = tested.Host.RemoteIp.ToString();
        _signalsAdapter.AppendHostTested(tested);

        // 1) Построить агрегированный срез по окну (из последовательности, а не "снимком")
        var signals = _signalsAdapter.BuildSnapshot(hostKey, TimeSpan.FromSeconds(30));

        // 2) Диагностировать
        var diagnosis = _diagnosisEngine.Diagnose(signals);
        _logger.LogInformation(
            $"V2 диагноз: {diagnosis.Diagnosis} " +
            $"(уверенность: {diagnosis.Confidence}%, правило: {diagnosis.MatchedRuleName})"
        );

        // 3) Получить план
        var plan = _strategySelector.SelectStrategies(diagnosis);

        // 4) В MVP только логируем рекомендации (без авто-применения)
        _bypassExecutor.LogRecommendations(plan);

        // 5) UI: показываем v2 приоритетно, legacy — как пометку
        // Псевдокод отображения:
        // UpdateUi(hostKey, v2Diagnosis: diagnosis, plan: plan, legacy: tested.LegacyClassification);
    }
    catch (Exception ex)
    {
        _logger.LogError($"Intelligence failed: {ex.Message}");
    }
}
```

**Критерий готовности (финальный gate):**

- ✅ Старые рекомендации заменены на v2
- ✅ UI показывает `DiagnosisResult.ExplanationNotes`
- ✅ Нет регрессий в производительности
- ✅ Легитимные сайты не получают агрессивные рекомендации

---

## ⏱️ Общая оценка времени

| Шаг | Описание | Время |
|-----|----------|-------|
| 0 | Контракт (уточнения) | 2-3 часа |
| 1 | Signals Adapter | 1 день |
| 2 | Diagnosis Engine | 1-2 дня |
| 3 | Strategy Selector | 4-6 часов |
| 4 | Executor MVP | 2-3 часа |
| 5 | Интеграция UI | 4-6 часов |

**Итого: 3-5 дней** на полный MVP v2

---

## 🎯 Что дальше (после MVP)

### После стабилизации MVP:

1. **Добавить остальные диагнозы:**
   - StatefulDpi
   - SilentDrop
   - MultiLayerBlock

2. **Включить реальное выполнение:**
   - Заменить `LogRecommendations()` на `ExecuteAsync()`
   - Добавить feedback loop

3. **Feedback Store:**
   - Запоминать успешные стратегии
   - Автоматически ранжировать

4. **Расширить стратегии:**
   - HTTP Host tricks (2.1)
   - QUIC obfuscation (2.3)
   - Bad checksum (2.2, после снятия блокера)

---

## 📚 Существующие возможности (Phase 2, уже реализовано)

Эти компоненты уже работают и будут использоваться Executor'ом:

### ✅ TLS Fragment/Disorder (2.6)
- Реализовано в `TlsBypassService`
- Параметры сохраняются в `bypass_profile.json`
- Пресеты: стандарт/умеренный/агрессивный

### ✅ TTL Fake/AutoTTL (2.5)
- Применяется через `TlsBypassService`
- AutoTTL: перебор TTL 2-8 по метрикам
- Лучший TTL сохраняется в профиль

### 🟡 Auto-hostlist (2.4)
- Частично: сбор кандидатов работает
- НЕ участвует в Diagnosis Engine v2
- Используется только для UI/логов

### ⏸️ Отложено до MVP v2:
- HTTP Host tricks (2.1)
- Bad checksum (2.2) — блокер на уровне движка
- QUIC obfuscation (2.3)

---

## 🔒 Правила безопасности

### Защита от регрессий:

1. **Не переходить на следующий шаг без gate-проверки**
2. **Diagnosis=None/Unknown → пустой план**
3. **Confidence <50 → пустой план**
4. **Агрессивные стратегии (DROP_RST) → только при confidence >70**
5. **В MVP нет авто-применения bypass**

Дополнение:
- Допускается ручное применение стратегии (по кнопке/команде пользователя) только при достаточной уверенности.

### Откат при проблемах:

- Если Gate не пройден → дорабатываем текущий шаг
- Если интеграция сломала что-то → откат к старой версии
- Логи должны быть понятны для отладки

---

## 📖 Глоссарий

**Signals** — сырые факты из сенсоров (RST, timeout, retransmissions)  
**Diagnosis** — интерпретация сигналов (ActiveDpiEdge, DnsHijack и т.д.)  
**Strategy** — конкретная техника обхода (TlsFragment, UseDoh и т.д.)  
**Plan** — упорядоченный список стратегий для попытки  
**Executor** — компонент который применяет план  
**Feedback** — запись результатов для обучения системы  
**Gate** — контрольная точка между шагами (требования к качеству)

---

## ✍️ История изменений

**16.12.2025** — Первая версия (дизайн контракта + 5 шагов MVP)