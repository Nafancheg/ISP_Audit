namespace IspAudit.Core.Diagnostics;

/// <summary>
/// Строковые маркеры/контрактные значения, которые используются как "сигнальные" значения
/// между слоями пайплайна (например, отсутствие стратегии обхода).
///
/// Цель: убрать магические строки из логики UI/pipeline.
/// </summary>
public static class PipelineContract
{
    public const string BypassNone = "NONE";
    public const string BypassUnknown = "UNKNOWN";
}
