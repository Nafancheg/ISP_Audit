namespace IspAudit.Core.Models
{
    public enum FilterAction
    {
        Process,    // Пропускаем дальше (тестировать или показывать)
        Drop,       // Игнорировать полностью (шум, дубликат)
        LogOnly     // Не показывать в UI, но записать в лог (успешные тесты)
    }

    public record FilterDecision(FilterAction Action, string Reason);
}
