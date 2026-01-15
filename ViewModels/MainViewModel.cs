using System.ComponentModel;
using IspAudit.Bypass;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Главная ViewModel.
    /// Тонкий координатор между BypassController,
    /// DiagnosticOrchestrator и TestResultsManager.
    /// </summary>
    public partial class MainViewModel : INotifyPropertyChanged
    {
        #region Controllers (Composition)

        /// <summary>
        /// Контроллер bypass-стратегий
        /// </summary>
        public BypassController Bypass { get; }

        /// <summary>
        /// Оркестратор диагностики
        /// </summary>
        public DiagnosticOrchestrator Orchestrator { get; }

        /// <summary>
        /// Менеджер результатов тестирования
        /// </summary>
        public TestResultsManager Results { get; }

        #endregion
    }
}
