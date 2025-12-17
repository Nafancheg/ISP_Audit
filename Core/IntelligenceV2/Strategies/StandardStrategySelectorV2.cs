using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using IspAudit.Core.IntelligenceV2.Contracts;

namespace IspAudit.Core.IntelligenceV2.Strategies;

/// <summary>
/// Минимальный селектор стратегий v2 (MVP).
/// ВАЖНО: решение принимает строго по <see cref="DiagnosisResult"/> (id + confidence),
/// не читает сенсоры/метрики/тайминги.
/// </summary>
public sealed class StandardStrategySelectorV2
{
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

        // Стабильная сортировка: приоритет ↓, затем риск ↑, затем id.
        var ordered = filtered
            .OrderByDescending(s => s.BasePriority)
            .ThenBy(s => s.Risk)
            .ThenBy(s => s.Id)
            .ToList();

        return new BypassPlan
        {
            ForDiagnosis = diagnosis.DiagnosisId,
            PlanConfidence = confidence,
            PlannedAtUtc = DateTimeOffset.UtcNow,
            Reasoning = "план сформирован по диагноза v2 (MVP)",
            Strategies = ordered
        };
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
            DiagnosisId.DnsHijack =>
            [
                new StrategyTemplate(StrategyId.UseDoh, basePriority: 100, risk: RiskLevel.Low)
            ],

            DiagnosisId.SilentDrop =>
            [
                new StrategyTemplate(StrategyId.TlsFragment, basePriority: 90, risk: RiskLevel.Medium),
                new StrategyTemplate(StrategyId.DropRst, basePriority: 50, risk: RiskLevel.Medium),
            ],

            DiagnosisId.MultiLayerBlock =>
            [
                new StrategyTemplate(StrategyId.UseDoh, basePriority: 100, risk: RiskLevel.Low),
                new StrategyTemplate(StrategyId.TlsDisorder, basePriority: 90, risk: RiskLevel.Medium),
                new StrategyTemplate(StrategyId.DropRst, basePriority: 50, risk: RiskLevel.Medium),
            ],

            // Будущие диагнозы (может появиться в следующих итерациях diagnosis engine)
            DiagnosisId.ActiveDpiEdge or DiagnosisId.StatefulDpi =>
            [
                new StrategyTemplate(StrategyId.TlsDisorder, basePriority: 90, risk: RiskLevel.Medium),
                new StrategyTemplate(StrategyId.TlsFragment, basePriority: 80, risk: RiskLevel.Medium),
                new StrategyTemplate(StrategyId.DropRst, basePriority: 50, risk: RiskLevel.Medium),

                // High-risk стратегия: разрешена только при confidence >= 70.
                new StrategyTemplate(StrategyId.AggressiveFragment, basePriority: 20, risk: RiskLevel.High)
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
        public StrategyTemplate(StrategyId id, int basePriority, RiskLevel risk)
            : this(id, basePriority, risk, new Dictionary<string, object?>())
        {
        }
    }
}
