using IspAudit.Core.Diagnostics;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        #region Initialization

        public void Initialize()
        {
            TestResults.Clear();
            _testResultMap.Clear();
            _resolvedIpMap.Clear();
            _pendingResolutions.Clear();
            _lastUpdatedHost = null;
            _lastUserFacingHost = null;

            _domainCatalog = DomainFamilyCatalog.LoadOrDefault(Log);
            _domainFamilies = new DomainFamilyAnalyzer(_domainCatalog, Log);
            OnPropertyChanged(nameof(SuggestedDomainSuffix));
            OnPropertyChanged(nameof(SuggestedDomainSubhostCount));
            OnPropertyChanged(nameof(CanSuggestDomainAggregation));
        }

        /// <summary>
        /// Сброс статусов существующих записей в Idle (для повторного запуска)
        /// </summary>
        public void ResetStatuses()
        {
            foreach (var test in TestResults)
            {
                test.Status = TestStatus.Idle;
                test.Details = string.Empty;
                test.Error = null!; // сбрасываем в null намеренно
            }
            NotifyCountersChanged();
        }

        /// <summary>
        /// Полная очистка результатов (для нового запуска диагностики)
        /// </summary>
        public void Clear()
        {
            Initialize();
            NotifyCountersChanged();
        }

        #endregion
    }
}
