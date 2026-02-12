using System;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Core.Intelligence.Contracts;

namespace IspAudit.Core.Intelligence.Execution;

/// <summary>
/// Утилиты выбора/дедупликации INTEL-планов.
/// Задача: не применять повторно «слабый» (доминируемый) план,
/// если уже активен/применён более сильный план для той же цели.
/// </summary>
public static class IntelPlanSelector
{
    /// <summary>
    /// Проверка: новый план доминируется активным (новый ⊂ активного).
    /// Смысл: если все действия нового плана уже входят в активный план,
    /// то повторное применение не даёт эффекта и только шумит лог/UX.
    /// </summary>
    public static bool IsDominated(BypassPlan newPlan, BypassPlan activePlan)
    {
        if (newPlan == null) throw new ArgumentNullException(nameof(newPlan));
        if (activePlan == null) throw new ArgumentNullException(nameof(activePlan));

        var newActions = BuildActionSet(newPlan);
        var activeActions = BuildActionSet(activePlan);

        return IsSubset(newActions, activeActions);
    }

    /// <summary>
    /// Проверка доминирования по сигнатурам (формат соответствует DiagnosticOrchestrator.BuildPlanSignature).
    /// </summary>
    public static bool IsDominated(string? newPlanSignature, string? activePlanSignature)
    {
        var newSig = (newPlanSignature ?? string.Empty).Trim();
        var activeSig = (activePlanSignature ?? string.Empty).Trim();

        if (newSig.Length == 0 || activeSig.Length == 0)
        {
            return false;
        }

        var newActions = ParseSignatureToActionSet(newSig);
        var activeActions = ParseSignatureToActionSet(activeSig);

        if (newActions.Count == 0 || activeActions.Count == 0)
        {
            return false;
        }

        return IsSubset(newActions, activeActions);
    }

    private static HashSet<string> BuildActionSet(BypassPlan plan)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var s in plan.Strategies)
        {
            if (s == null) continue;
            if (s.Id == StrategyId.None) continue;
            set.Add("S:" + s.Id);
        }

        if (plan.DropUdp443) set.Add("F:DropUdp443");
        if (plan.AllowNoSni) set.Add("F:AllowNoSni");

        return set;
    }

    private static HashSet<string> ParseSignatureToActionSet(string signature)
    {
        // Формат: "StrategyA,StrategyB|U1|N0".
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var parts = signature.Split('|', StringSplitOptions.TrimEntries);
        if (parts.Length >= 1)
        {
            var listPart = parts[0].Trim();
            if (!string.IsNullOrWhiteSpace(listPart))
            {
                foreach (var item in listPart.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (string.IsNullOrWhiteSpace(item)) continue;
                    set.Add("S:" + item);
                }
            }
        }

        // Флаги U/N.
        foreach (var p in parts.Skip(1))
        {
            if (p.Length < 2) continue;
            if (p.StartsWith("U", StringComparison.OrdinalIgnoreCase) && p.EndsWith("1", StringComparison.Ordinal))
            {
                set.Add("F:DropUdp443");
            }
            else if (p.StartsWith("N", StringComparison.OrdinalIgnoreCase) && p.EndsWith("1", StringComparison.Ordinal))
            {
                set.Add("F:AllowNoSni");
            }
        }

        return set;
    }

    private static bool IsSubset(HashSet<string> candidate, HashSet<string> active)
    {
        if (candidate.Count == 0) return false;
        if (active.Count == 0) return false;

        foreach (var a in candidate)
        {
            if (!active.Contains(a)) return false;
        }

        return true;
    }
}
