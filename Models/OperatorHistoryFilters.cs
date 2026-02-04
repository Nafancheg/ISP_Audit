namespace IspAudit.Models
{
    /// <summary>
    /// Фильтр времени для «Истории активности» в Operator UI.
    /// </summary>
    public enum OperatorHistoryTimeRange
    {
        Today = 0,
        Last7Days = 1,
        All = 2
    }

    /// <summary>
    /// Фильтр типа события для «Истории активности».
    /// </summary>
    public enum OperatorHistoryTypeFilter
    {
        All = 0,
        Checks = 1,
        Fixes = 2,
        Errors = 3
    }
}
