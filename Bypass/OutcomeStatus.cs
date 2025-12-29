using System;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Outcome (результат) для HTTPS: SUCCESS/FAILED/UNKNOWN.
    /// Важно: без MITM нельзя делать выводы из пассивного анализа HTTPS,
    /// поэтому результат должен опираться на активный probe или оставаться UNKNOWN.
    /// </summary>
    public enum OutcomeStatus
    {
        Unknown = 0,
        Success = 1,
        Failed = 2
    }

    public sealed record OutcomeStatusSnapshot(OutcomeStatus Status, string Text, string Details);
}
