using System;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Wpf;

namespace IspAudit.ViewModels
{
    public sealed partial class OperatorViewModel
    {
        public ICommand RollbackCommand { get; }

        private async Task RollbackAsync()
        {
            EnsureDraftExistsBestEffort(reason: "rollback");
            _activeSession?.Actions.Add("Откат: запуск");

            try
            {
                await Main.Bypass.RollbackAutopilotOnlyAsync().ConfigureAwait(false);
                _activeSession?.Actions.Add("Откат: выполнено (только Autopilot)");

                // Rollback часто является «закрывающим» действием. Если сессия без проверки — закрываем сразу.
                if (_activeSession != null && !_activeSession.CheckCompleted)
                {
                    TryFinalizeActiveSessionBestEffort(preferPostApply: false);
                }
            }
            catch (Exception ex)
            {
                _activeSession?.Actions.Add($"Откат: ошибка ({ex.Message})");
                TryFinalizeActiveSessionBestEffort(preferPostApply: false);
            }
        }
    }
}
