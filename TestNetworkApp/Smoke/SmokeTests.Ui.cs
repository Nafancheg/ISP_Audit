using System;
using System.Threading;
using System.Threading.Tasks;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> Ui_UiReducerSmoke(CancellationToken ct)
            => RunAsync("UI-011", "UI-Reducer smoke (--ui-reducer-smoke)", () =>
            {
                Program.RunUiReducerSmoke_ForSmokeRunner();
                return new SmokeTestResult("UI-011", "UI-Reducer smoke (--ui-reducer-smoke)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "Выполнено без исключений");
            }, ct);
    }
}
