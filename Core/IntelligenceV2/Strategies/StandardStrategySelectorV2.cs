using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.IntelligenceV2.Feedback;

namespace IspAudit.Core.IntelligenceV2.Strategies;

/// <summary>
/// Минимальный селектор стратегий v2 (MVP).
/// ВАЖНО: решение принимает строго по <see cref="DiagnosisResult"/> (id + confidence),
/// не читает сенсоры/метрики/тайминги.
/// </summary>
public sealed class StandardStrategySelectorV2
{
    private readonly IFeedbackStoreV2? _feedbackStore;
    private readonly FeedbackStoreOptions _feedbackOptions;

    public StandardStrategySelectorV2()
        : this(feedbackStore: null, feedbackOptions: null)
    {
    }

    public StandardStrategySelectorV2(IFeedbackStoreV2? feedbackStore, FeedbackStoreOptions? feedbackOptions = null)
    {
        _feedbackStore = feedbackStore;
        _feedbackOptions = feedbackOptions ?? new FeedbackStoreOptions();
    }

    private static readonly HashSet<StrategyId> ImplementedStrategies =
    [
        StrategyId.TlsDisorder,
        StrategyId.TlsFragment,
        StrategyId.DropRst,
        StrategyId.UseDoh,
    ];

    /// <summary>
    /// Построить план рекомендаций.
    /// Жёсткие защиты:
    /// - confidence &lt; 50 → пустой план
    /// - RiskLevel.High запрещён при confidence &lt; 70
    /// - нереализованные стратегии: warning + skip (без исключений)
    /// </summary>
    public BypassPlan Select(DiagnosisResult diagnosis, Action<string>? warningLog = null)
    {
        if (diagnosis is null) throw new ArgumentNullException(nameof(diagnosis));

        var confidence = Math.Clamp(diagnosis.Confidence, 0, 100);

        if (confidence < 50)
        {
            return CreateEmptyPlan(diagnosis.DiagnosisId, confidence, "confidence < 50");
        }

        var candidates = BuildCandidates(diagnosis.DiagnosisId);
        if (candidates.Count == 0)
        {
            return CreateEmptyPlan(diagnosis.DiagnosisId, confidence, "нет маппинга для диагноза");
        }

        var filtered = new List<BypassStrategy>(capacity: candidates.Count);

        foreach (var candidate in candidates)
        {
            if (candidate.Risk == RiskLevel.High && confidence < StrategyContractConstraints.MinConfidenceForHighRiskStrategies)
            {
                continue;
            }

            if (!ImplementedStrategies.Contains(candidate.Id))
            {
                EmitWarning(warningLog, $"[IntelligenceV2][Selector] Стратегия {candidate.Id} не реализована — пропуск.");
                continue;
            }

            filtered.Add(new BypassStrategy
            {
                Id = candidate.Id,
                BasePriority = candidate.BasePriority,
                Risk = candidate.Risk,
                Parameters = candidate.Parameters
            });
        }

        if (filtered.Count == 0)
        {
            return CreateEmptyPlan(diagnosis.DiagnosisId, confidence, "все стратегии отфильтрованы по риску/реализации");
        }

        var forDiagnosisId = diagnosis.DiagnosisId;

        // Стабильная сортировка:
        // 1) effective priority (base + feedback) ↓
        // 2) base priority ↓
        // 3) risk ↑
        // 4) id ↑
        var ranked = filtered
            .Select(s =>
            {
                var boost = TryGetFeedbackBoost(forDiagnosisId, s.Id);
                return new RankedStrategy(s, boost);
            })
            .ToList();

        var ordered = ranked
            .OrderByDescending(s => s.EffectivePriority)
            .ThenByDescending(s => s.BasePriority)
            .ThenBy(s => s.Risk)
            .ThenBy(s => s.Id)
            .Select(s => s.Strategy)
            .ToList();

        // Важное правило UX/исполнения: одновременно должен применяться только один режим TLS-обхода.
        // Иначе селектор может выдать противоречивые рекомендации (например, Disorder + Fragment),
        // а исполнитель всё равно вынужден выбрать одну (см. профиль TLS strategy).
        ordered = KeepOnlyOneTlsModeStrategy(ordered);

        var anyFeedbackApplied = ranked.Any(r => r.FeedbackBoost != 0);

        return new BypassPlan
        {
            ForDiagnosis = forDiagnosisId,
            PlanConfidence = confidence,
            PlannedAtUtc = DateTimeOffset.UtcNow,
            Reasoning = anyFeedbackApplied
                ? "план сформирован по диагнозу v2 (feedback)"
                : "план сформирован по диагноза v2 (MVP)",
            Strategies = ordered
        };
    }

    private static List<BypassStrategy> KeepOnlyOneTlsModeStrategy(List<BypassStrategy> strategies)
    {
        // Группа взаимоисключающих стратегий. Оставляем первую по ранжированию.
        var tlsModeGroup = new HashSet<StrategyId>
        {
            StrategyId.TlsDisorder,
            StrategyId.TlsFragment,
            StrategyId.AggressiveFragment,
        };

        var result = new List<BypassStrategy>(strategies.Count);
        var tlsModeAlreadyAdded = false;

        foreach (var strategy in strategies)
        {
            if (!tlsModeGroup.Contains(strategy.Id))
            {
                result.Add(strategy);
                continue;
            }

            if (tlsModeAlreadyAdded)
            {
                continue;
            }

            result.Add(strategy);
            tlsModeAlreadyAdded = true;
        }

        return result;
    }

    private int TryGetFeedbackBoost(DiagnosisId diagnosisId, StrategyId strategyId)
    {
        if (_feedbackStore == null)
        {
            return 0;
        }

        if (!_feedbackStore.TryGetStats(new FeedbackKey(diagnosisId, strategyId), out var stats))
        {
            return 0;
        }

        if (stats.TotalCount < _feedbackOptions.MinSamplesToAffectRanking)
        {
            return 0;
        }

        // Нормируем success-rate в диапазон [-0.5; +0.5] относительно 50%.
        // Затем переводим в бонус к basePriority.
        // Важно: формула должна быть детерминированной.
        var centered = stats.SuccessRate - 0.5;
        var raw = (int)Math.Round(centered * (_feedbackOptions.MaxPriorityBoostAbs * 2.0), MidpointRounding.AwayFromZero);
        return Math.Clamp(raw, -_feedbackOptions.MaxPriorityBoostAbs, _feedbackOptions.MaxPriorityBoostAbs);
    }

    private static BypassPlan CreateEmptyPlan(DiagnosisId diagnosisId, int confidence, string reason)
    {
        return new BypassPlan
        {
            ForDiagnosis = diagnosisId,
            PlanConfidence = confidence,
            PlannedAtUtc = DateTimeOffset.UtcNow,
            Reasoning = reason,
            Strategies = new List<BypassStrategy>()
        };
    }

    private static void EmitWarning(Action<string>? warningLog, string message)
    {
        if (warningLog != null)
        {
            warningLog(message);
            return;
        }

        Trace.WriteLine(message);
    }

    private static List<StrategyTemplate> BuildCandidates(DiagnosisId diagnosisId)
    {
        // MVP: маппинг небольшой и консервативный.
        // ВАЖНО: не читаем diagnosis.InputSignals / метрики — только DiagnosisId.
        return diagnosisId switch
        {
            // Вариант C: DoH не рекомендуем при "чисто DNS" диагнозе,
            // чтобы не повышать риск ложных рекомендаций и не путать UX.
            DiagnosisId.DnsHijack =>
                new List<StrategyTemplate>(),

            DiagnosisId.SilentDrop =>
            [
                new StrategyTemplate(
                    StrategyId.TlsFragment,
                    BasePriority: 90,
                    Risk: RiskLevel.Medium,
                    Parameters: new Dictionary<string, object?>
                    {
                        // Явно задаём параметры, чтобы план был детерминированным.
                        // Иначе executor оставит текущий пресет пользователя, и результат будет зависеть от UI-состояния.
                        ["TlsFragmentSizes"] = new[] { 64 },
                        ["AutoAdjustAggressive"] = false
                    }),
                new StrategyTemplate(StrategyId.DropRst, BasePriority: 50, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
            ],

            DiagnosisId.MultiLayerBlock =>
            [
                new StrategyTemplate(StrategyId.UseDoh, BasePriority: 100, Risk: RiskLevel.Low, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(StrategyId.TlsDisorder, BasePriority: 90, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(StrategyId.DropRst, BasePriority: 50, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
            ],

            // Будущие диагнозы (может появиться в следующих итерациях diagnosis engine)
            DiagnosisId.ActiveDpiEdge or DiagnosisId.StatefulDpi =>
            [
                new StrategyTemplate(StrategyId.TlsDisorder, BasePriority: 90, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(
                    StrategyId.TlsFragment,
                    BasePriority: 80,
                    Risk: RiskLevel.Medium,
                    Parameters: new Dictionary<string, object?>
                    {
                        ["TlsFragmentSizes"] = new[] { 64 },
                        ["AutoAdjustAggressive"] = false
                    }),
                new StrategyTemplate(StrategyId.DropRst, BasePriority: 50, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),

                // High-risk стратегия: разрешена только при confidence >= 70.
                new StrategyTemplate(StrategyId.AggressiveFragment, BasePriority: 20, Risk: RiskLevel.High, Parameters: new Dictionary<string, object?>())
            ],

            _ => new List<StrategyTemplate>()
        };
    }

    private sealed record StrategyTemplate(
        StrategyId Id,
        int BasePriority,
        RiskLevel Risk,
        Dictionary<string, object?> Parameters)
    {
    }

    private readonly record struct RankedStrategy(BypassStrategy Strategy, int FeedbackBoost)
    {
        public StrategyId Id => Strategy.Id;
        public int BasePriority => Strategy.BasePriority;
        public RiskLevel Risk => Strategy.Risk;
        public int EffectivePriority => BasePriority + FeedbackBoost;
    }
}
