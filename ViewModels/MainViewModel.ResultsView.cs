using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        private ICollectionView? _resultsView;
        private DispatcherTimer? _resultsViewRefreshTimer;
        private NotifyCollectionChangedEventHandler? _resultsViewCollectionChangedHandler;
        private NotifyCollectionChangedEventHandler? _resultsViewApplyTransactionsChangedHandler;
        private EventHandler? _resultsViewRefreshTimerTickHandler;

        private bool _isResultsFocusMode = true;
        public bool IsResultsFocusMode
        {
            get => _isResultsFocusMode;
            set
            {
                if (_isResultsFocusMode == value) return;
                _isResultsFocusMode = value;
                OnPropertyChanged(nameof(IsResultsFocusMode));
                RefreshResultsViewNow();
            }
        }

        private bool _showNoiseResults;
        public bool ShowNoiseResults
        {
            get => _showNoiseResults;
            set
            {
                if (_showNoiseResults == value) return;
                _showNoiseResults = value;
                OnPropertyChanged(nameof(ShowNoiseResults));
                RefreshResultsViewNow();
            }
        }

        public ICollectionView ResultsView => _resultsView ??= CreateResultsView();

        private ICollectionView CreateResultsView()
        {
            var view = CollectionViewSource.GetDefaultView(Results.TestResults);
            view.Filter = FilterTestResult;
            return view;
        }

        private bool FilterTestResult(object obj)
        {
            if (obj is not TestResult tr) return false;

            try
            {
                // В режиме "Все" ничего не фильтруем.
                if (!IsResultsFocusMode) return true;

                var hostKey = GetPreferredHostKey(tr);

                // По умолчанию скрываем шумовые хосты, чтобы UI не превращался в поток телеметрии.
                if (!ShowNoiseResults && IsNoiseHostKey(hostKey ?? string.Empty))
                {
                    // Но если пользователь явно применял к строке bypass — показываем, чтобы было видно, что сделали.
                    if (!tr.IsAppliedBypassTarget)
                    {
                        return false;
                    }
                }

                // Всегда показываем важные статусы.
                if (tr.Status == TestStatus.Fail || tr.Status == TestStatus.Warn || tr.Status == TestStatus.Running)
                {
                    return true;
                }

                // Всегда показываем то, что уже применяли.
                if (tr.IsAppliedBypassTarget)
                {
                    return true;
                }

                // Показываем строки из активной (текущей) группы, чтобы было видно "что сейчас применено".
                var activeGroupKey = ActiveApplyGroupKey;
                if (!string.IsNullOrWhiteSpace(activeGroupKey))
                {
                    var rowGroupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                    if (string.Equals(rowGroupKey, activeGroupKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                // Остальное скрываем в фокусе (обычно это PASS и вспомогательные домены).
                return false;
            }
            catch
            {
                // Фильтр не должен ронять UI.
                return true;
            }
        }

        private void InitResultsViewAndFiltering()
        {
            _resultsView = CreateResultsView();

            _resultsViewCollectionChangedHandler = OnTestResultsCollectionChanged;
            Results.TestResults.CollectionChanged += _resultsViewCollectionChangedHandler;

            foreach (var tr in Results.TestResults)
            {
                HookTestResult(tr);
            }

            // Обновляем summary при изменениях apply-журнала (видимость "что применено").
            try
            {
                _resultsViewApplyTransactionsChangedHandler = (_, __) => RaiseActiveApplySummaryChanged();
                Bypass.ApplyTransactions.CollectionChanged += _resultsViewApplyTransactionsChangedHandler;
            }
            catch
            {
                // ignore
            }
        }

        private void OnTestResultsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            try
            {
                if (e.OldItems != null)
                {
                    foreach (var item in e.OldItems)
                    {
                        if (item is TestResult tr) UnhookTestResult(tr);
                    }
                }

                if (e.NewItems != null)
                {
                    foreach (var item in e.NewItems)
                    {
                        if (item is TestResult tr) HookTestResult(tr);
                    }
                }
            }
            catch
            {
                // ignore
            }

            ScheduleResultsViewRefresh();
        }

        private void HookTestResult(TestResult tr)
        {
            tr.PropertyChanged += OnTestResultPropertyChanged;
        }

        private void UnhookTestResult(TestResult tr)
        {
            tr.PropertyChanged -= OnTestResultPropertyChanged;
        }

        private void OnTestResultPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            // Не перерисовываем каждую миллисекунду: группируем апдейты.
            if (e.PropertyName == nameof(TestResult.Status)
                || e.PropertyName == nameof(TestResult.IsAppliedBypassTarget)
                || e.PropertyName == nameof(TestResult.IsManuallyExcludedFromApplyGroup))
            {
                ScheduleResultsViewRefresh();
            }
        }

        private void ScheduleResultsViewRefresh()
        {
            if (_resultsView == null) return;

            if (_resultsViewRefreshTimer == null)
            {
                _resultsViewRefreshTimer = new DispatcherTimer(DispatcherPriority.Background)
                {
                    Interval = TimeSpan.FromMilliseconds(150)
                };
                _resultsViewRefreshTimerTickHandler = (_, __) =>
                {
                    try
                    {
                        _resultsViewRefreshTimer?.Stop();
                        _resultsView?.Refresh();
                    }
                    catch
                    {
                        // ignore
                    }
                };
                _resultsViewRefreshTimer.Tick += _resultsViewRefreshTimerTickHandler;
            }

            try
            {
                _resultsViewRefreshTimer.Stop();
                _resultsViewRefreshTimer.Start();
            }
            catch
            {
                // ignore
            }
        }

        private void RefreshResultsViewNow()
        {
            try
            {
                _resultsView?.Refresh();
            }
            catch
            {
                // ignore
            }

            RaiseActiveApplySummaryChanged();
        }

        public string ActiveApplySummaryText
        {
            get
            {
                try
                {
                    if (!Bypass.IsBypassActive)
                    {
                        return "Bypass: выключен";
                    }

                    var groupKey = ActiveApplyGroupKey;
                    var tx = Bypass.TryGetLatestApplyTransactionForGroupKey(groupKey);

                    if (tx == null)
                    {
                        var host = Bypass.GetOutcomeTargetHost();
                        var target = string.IsNullOrWhiteSpace(host) ? "цель не задана" : host;
                        return $"Bypass: активен; цель: {target}";
                    }

                    var plan = string.IsNullOrWhiteSpace(tx.AppliedStrategyText) ? (tx.PlanText ?? string.Empty) : tx.AppliedStrategyText;
                    var act = string.IsNullOrWhiteSpace(tx.ActivationStatusText) ? "ACT: ?" : $"ACT: {tx.ActivationStatusText}";
                    var outcomeTarget = tx.Result?.OutcomeTargetHost;
                    var targetText = string.IsNullOrWhiteSpace(outcomeTarget) ? "" : $"; цель: {outcomeTarget}";
                    return $"Bypass: {plan}; {act}{targetText}";
                }
                catch
                {
                    return "Bypass: (ошибка формирования статуса)";
                }
            }
        }

        private void RaiseActiveApplySummaryChanged()
        {
            OnPropertyChanged(nameof(ActiveApplySummaryText));
        }

        private void UnsubscribeResultsViewEventsBestEffort()
        {
            try
            {
                if (_resultsViewCollectionChangedHandler != null)
                {
                    Results.TestResults.CollectionChanged -= _resultsViewCollectionChangedHandler;
                    _resultsViewCollectionChangedHandler = null;
                }
            }
            catch
            {
                // ignore
            }

            try
            {
                if (_resultsViewApplyTransactionsChangedHandler != null)
                {
                    Bypass.ApplyTransactions.CollectionChanged -= _resultsViewApplyTransactionsChangedHandler;
                    _resultsViewApplyTransactionsChangedHandler = null;
                }
            }
            catch
            {
                // ignore
            }

            try
            {
                foreach (var tr in Results.TestResults)
                {
                    UnhookTestResult(tr);
                }
            }
            catch
            {
                // ignore
            }

            try
            {
                if (_resultsViewRefreshTimer != null)
                {
                    if (_resultsViewRefreshTimerTickHandler != null)
                    {
                        _resultsViewRefreshTimer.Tick -= _resultsViewRefreshTimerTickHandler;
                        _resultsViewRefreshTimerTickHandler = null;
                    }

                    _resultsViewRefreshTimer.Stop();
                    _resultsViewRefreshTimer = null;
                }
            }
            catch
            {
                // ignore
            }
        }
    }
}
