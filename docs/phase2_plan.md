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

### BlockageSignalsV2 (факты)

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
    UseDoh, // TODO: пример будущей стратегии (в текущем репо DoH как стратегия может отсутствовать)
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

---

### Шаг 1: Signals Adapter

**Что:** Собрать сигналы из существующих сервисов и логировать  
**Время:** 1 день  
**Компонент:** `Core/Intelligence/SignalsAdapter.cs`

**Реализация:**

```csharp
public class SignalsAdapter 
{
    // Внимание: ниже псевдокод.
    // В текущем репозитории основная модель пайплайна — HostTested,
    // а агрегированные факты за окно даёт IBlockageStateStore.GetSignals(HostTested, window) → BlockageSignals.
    public BlockageSignalsV2 CollectSignals(HostTested tested, BlockageSignals windowSignals) 
    {
        var ip = tested.Host.RemoteIp;
        var (retrans, totalPackets) = _retransTracker.GetStatsForIp(ip);

        var signals = new BlockageSignalsV2 {
            // Из HostTested (факты тестера)
            HasTcpTimeout = !tested.TcpOk,
            HasDnsFailure = !tested.DnsOk || (tested.DnsStatus != null && tested.DnsStatus != "OK"),
            
            // Из BlockageSignals за окно
            HasHttpRedirect = windowSignals.HasHttpRedirectDpi,

            // Из RstInspectionService/BlockageSignals
            // Примечание: в текущем коде есть HasSuspiciousRst + SuspiciousRstDetails,
            // а поля RstTtlDelta/RstLatency можно добавить позже при расширении сенсоров.
            // (оставляем их в модели v2 как опциональные)
            
            // Из TcpRetransmissionTracker
            RetransmissionRate = totalPackets > 0 ? (double)retrans / totalPackets : 0,
            
            // Метаданные
            CapturedAt = DateTime.UtcNow,
            SampleSize = totalPackets
        };
        
        _logger.LogInformation($"Signals: {JsonSerializer.Serialize(signals)}");
        return signals;
    }
}
```

**Критерий готовности (Gate 1→2):**

Прогон: **10 хостов × 3 проверки = 30 измерений**

✅ **Успех:**
- Минимум 8 из 10 хостов показывают стабильные сигналы
- Для булевых: совпадение в 2 из 3 проверок
- Для численных: отклонение в пределах коридора (±50ms для latency, ±0.2 для retrans rate)
- Логи понятны и воспроизводимы

❌ **Провал:** Нестабильность >20% → не переходим на Шаг 2

---

### Шаг 2: Diagnosis Engine

**Что:** Реализовать правила для 2 диагнозов  
**Время:** 1-2 дня  
**Компонент:** `Core/Intelligence/DiagnosisEngine.cs`

**Диагнозы для MVP:**

1. **ActiveDpiEdge** — самый частый случай
2. **DnsHijack** — самый простой для детекта

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
        // Правило 1: Активный DPI на краю сети
        new() {
            Name = "Active_DPI_Edge_v1",
            Produces = DiagnosisId.ActiveDpiEdge,
            BaseConfidence = 85,
            Condition = s => 
                s.HasTcpReset &&
                s.RstTtlDelta.HasValue && s.RstTtlDelta.Value > 5 &&
                s.RstLatency.HasValue && s.RstLatency.Value.TotalMilliseconds < 100,
            ExplainFunc = s => 
                $"RST через {s.RstLatency?.TotalMilliseconds:F0}ms, TTL отклонение {s.RstTtlDelta}"
        },
        
        // Правило 2: DNS блокировка
        new() {
            Name = "DNS_Hijack_v1",
            Produces = DiagnosisId.DnsHijack,
            BaseConfidence = 95,
            Condition = s => 
                s.HasDnsFailure || s.HasFakeIp,
            ExplainFunc = s => 
                s.HasFakeIp ? "Fake IP 198.18.x.x" : "DNS resolution failed"
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

**Критерий готовности (Gate 2→3):**

Для каждого из 10 хостов:
- ✅ Диагноз совпадает с реальностью (ручная проверка)
- ✅ ExplanationNotes понятен человеку
- ✅ Confidence >50 для реальных блокировок
- ✅ Диагноз стабилен между запусками

❌ **Провал:** Ложные срабатывания >20% → доработать правила

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
        
        [DiagnosisId.DnsHijack] = new() {
            (StrategyId.UseDoh, 10)
        },
        
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
- ✅ План детерминирован (одинаковый для одного диагноза)

---

### Шаг 4: Executor (MVP — только логирование)

**Что:** Компонент который ПОКА ТОЛЬКО логирует рекомендации  
**Время:** 2-3 часа  
**Компонент:** `Core/Intelligence/BypassExecutor.cs`

**ВАЖНО:** В MVP НЕ применяем стратегии автоматически!

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

**Реализация:**

```csharp
// В DiagnosticOrchestrator после классификации хоста
private async Task OnHostClassified(TestResult result) 
{
    if (!result.HasIssues) return;
    
    try 
    {
        // 1. Собрать сигналы
        var signals = _signalsAdapter.CollectSignals(result, result.Ip);
        
        // 2. Диагностировать
        var diagnosis = _diagnosisEngine.Diagnose(signals);
        
        _logger.LogInformation(
            $"Диагноз: {diagnosis.Diagnosis} " +
            $"(уверенность: {diagnosis.Confidence}%, " +
            $"правило: {diagnosis.MatchedRuleName})"
        );
        
        // 3. Получить план
        var plan = _strategySelector.SelectStrategies(diagnosis);
        
        // 4. В MVP только логируем
        var outcome = _bypassExecutor.LogRecommendations(plan);
        
        // 5. Обновить UI
        result.DiagnosisInfo = diagnosis.ExplanationNotes;
        result.RecommendedStrategies = string.Join(", ", 
            plan.Strategies.Select(s => s.Id.ToString())
        );
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