using System.Threading;

namespace IspAudit.ViewModels.OrchestratorState
{
    /// <summary>
    /// Состояние пост-Apply ретеста (UX): короткий прогон после применения обхода,
    /// чтобы пользователь сразу видел эффект.
    /// </summary>
    internal sealed class PostApplyRetestState
    {
        public bool IsRunning { get; set; }

        public string Status { get; set; } = "";

        public CancellationTokenSource? Cancellation { get; set; }
    }
}
