using System;

namespace IspAudit.ViewModels.Orchestrator;

internal sealed class CardActionHandler
{
    public string ResolveBestHostKey(string? preferredHostKey, string? lastIntelPlanHostKey, string? lastIntelDiagnosisHostKey)
    {
        if (!string.IsNullOrWhiteSpace(preferredHostKey)) return preferredHostKey.Trim();
        if (!string.IsNullOrWhiteSpace(lastIntelPlanHostKey)) return lastIntelPlanHostKey.Trim();
        if (!string.IsNullOrWhiteSpace(lastIntelDiagnosisHostKey)) return lastIntelDiagnosisHostKey.Trim();
        return string.Empty;
    }
}
