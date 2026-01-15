using System.Linq;
using IspAudit.Core.Diagnostics;
using IspAudit.Models;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        #region Счётчики

        public int TotalTargets => TestResults.Count;
        public int ProgressBarMax => TotalTargets == 0 ? 1 : TotalTargets;
        public int CurrentTest => TestResults.Count(t =>
            t.Status == TestStatus.Running ||
            t.Status == TestStatus.Pass ||
            t.Status == TestStatus.Fail ||
            t.Status == TestStatus.Warn);
        public int CompletedTests => TestResults.Count(t =>
            t.Status == TestStatus.Pass ||
            t.Status == TestStatus.Fail ||
            t.Status == TestStatus.Warn);
        public int PassCount => TestResults.Count(t => t.Status == TestStatus.Pass);
        public int FailCount => TestResults.Count(t => t.Status == TestStatus.Fail);
        public int WarnCount => TestResults.Count(t => t.Status == TestStatus.Warn);

        #endregion

        private void NotifyCountersChanged()
        {
            OnPropertyChanged(nameof(TotalTargets));
            OnPropertyChanged(nameof(ProgressBarMax));
            OnPropertyChanged(nameof(CurrentTest));
            OnPropertyChanged(nameof(CompletedTests));
            OnPropertyChanged(nameof(PassCount));
            OnPropertyChanged(nameof(FailCount));
            OnPropertyChanged(nameof(WarnCount));
        }
    }
}
