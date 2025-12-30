using System;
using IspAudit.Bypass;

namespace TestNetworkApp.Smoke
{
    /// <summary>
    /// Адаптер для smoke-тестов: позволяет обращаться к BypassFilter без using на namespace фильтров.
    /// Нужен, чтобы smoke-набор компилировался детерминированно даже при больших partial-файлах.
    /// </summary>
    internal sealed class BypassFilter : IspAudit.Core.Traffic.Filters.BypassFilter
    {
        public BypassFilter(BypassProfile profile, Action<string>? logAction = null, string presetName = "")
            : base(profile, logAction, presetName)
        {
        }
    }
}
