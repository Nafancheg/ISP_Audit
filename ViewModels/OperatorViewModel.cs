using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Models;
using IspAudit.Wpf;
using MaterialDesignThemes.Wpf;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Лёгкая ViewModel для «Операторского» UI.
    /// Оборачивает MainViewModel и предоставляет упрощённые computed-свойства.
    /// </summary>
    public sealed partial class OperatorViewModel : INotifyPropertyChanged
    {
        public enum OperatorStatus
        {
            Idle,
            Checking,
            Ok,
            Warn,
            Blocked,
            Fixing
        }

        private sealed record OperatorStatusPresentation(
            string Headline,
            string UserDetailsStatus,
            PackIconKind HeroIconKind,
            System.Windows.Media.Brush HeroAccentBrush,
            string DefaultPrimaryButtonText);

        private static OperatorStatusPresentation GetPresentation(OperatorStatus status)
        {
            return status switch
            {
                OperatorStatus.Checking => new OperatorStatusPresentation(
                    Headline: "Анализ сети…",
                    UserDetailsStatus: "Проверка",
                    HeroIconKind: PackIconKind.Radar,
                    HeroAccentBrush: System.Windows.Media.Brushes.DodgerBlue,
                    DefaultPrimaryButtonText: "Остановить"),

                OperatorStatus.Fixing => new OperatorStatusPresentation(
                    Headline: "Исправляю…",
                    UserDetailsStatus: "Идёт исправление",
                    HeroIconKind: PackIconKind.Wrench,
                    HeroAccentBrush: System.Windows.Media.Brushes.DodgerBlue,
                    DefaultPrimaryButtonText: "Исправляю…"),

                OperatorStatus.Blocked => new OperatorStatusPresentation(
                    Headline: "Доступ заблокирован",
                    UserDetailsStatus: "Блокировка",
                    HeroIconKind: PackIconKind.ShieldAlert,
                    HeroAccentBrush: System.Windows.Media.Brushes.IndianRed,
                    DefaultPrimaryButtonText: "Исправить"),

                OperatorStatus.Warn => new OperatorStatusPresentation(
                    Headline: "Некоторые сервисы нестабильны",
                    UserDetailsStatus: "Ограничения",
                    HeroIconKind: PackIconKind.ShieldOutline,
                    HeroAccentBrush: System.Windows.Media.Brushes.DarkOrange,
                    DefaultPrimaryButtonText: "Исправить"),

                OperatorStatus.Ok => new OperatorStatusPresentation(
                    Headline: "Сеть работает нормально",
                    UserDetailsStatus: "Норма",
                    HeroIconKind: PackIconKind.ShieldCheck,
                    HeroAccentBrush: System.Windows.Media.Brushes.SeaGreen,
                    DefaultPrimaryButtonText: "Проверить снова"),

                _ => new OperatorStatusPresentation(
                    Headline: "Нажмите для проверки",
                    UserDetailsStatus: "Ожидание",
                    HeroIconKind: PackIconKind.Shield,
                    HeroAccentBrush: System.Windows.Media.Brushes.Gray,
                    DefaultPrimaryButtonText: "Проверить сеть")
            };
        }

        public MainViewModel Main { get; }

        private bool _isSourceSectionExpanded = true;
        private bool _didAutoCollapseSourceSection;
        private bool _isDetailsExpanded;

        private readonly ObservableCollection<string> _summaryProblemCards = new();

        public ICommand ClearHistoryCommand { get; }
        public ICommand ClearSessionsCommand { get; }
        public ICommand ToggleDetailsCommand { get; }

        public ObservableCollection<string> SummaryProblemCards => _summaryProblemCards;
        public bool HasSummaryProblems => _summaryProblemCards.Count > 0;

        public OperatorViewModel(MainViewModel main)
        {
            Main = main ?? throw new ArgumentNullException(nameof(main));

            InitializeSessionsBestEffort();
            InitializeHistoryBestEffort();
            InitializeWizardTrackingStateBestEffort();

            // При первом прогоне сворачиваем секцию выбора источника, чтобы она не съедала экран.
            // Далее состояние контролируется пользователем.
            _isSourceSectionExpanded = Status == OperatorStatus.Idle;
            _didAutoCollapseSourceSection = Status != OperatorStatus.Idle;

            RollbackCommand = new RelayCommand(async _ => await RollbackAsync().ConfigureAwait(false));
            ClearHistoryCommand = new RelayCommand(_ => ClearHistoryBestEffort());
            ClearSessionsCommand = new RelayCommand(_ => ClearSessionsBestEffort());
            ToggleDetailsCommand = new RelayCommand(_ => IsDetailsExpanded = !IsDetailsExpanded);

            Main.PropertyChanged += MainOnPropertyChanged;

            try
            {
                Main.TestResults.CollectionChanged += TestResultsOnCollectionChanged;
            }
            catch
            {
                // ignore
            }

            RefreshSummaryProblemsBestEffort();

            // Семантика итогов post-apply ретеста (OK/FAIL/PARTIAL/UNKNOWN).
            try
            {
                Main.Orchestrator.OnPostApplyCheckVerdict += OrchestratorOnPostApplyCheckVerdict;
            }
            catch
            {
                // ignore
            }
        }

        private void TestResultsOnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            try
            {
                RefreshSummaryProblemsBestEffort();
                OnPropertyChanged(nameof(CheckedProblemsLine));
            }
            catch
            {
                // ignore
            }
        }

        public bool IsSourceSectionExpanded
        {
            get => _isSourceSectionExpanded;
            set
            {
                if (_isSourceSectionExpanded == value) return;
                _isSourceSectionExpanded = value;
                OnPropertyChanged(nameof(IsSourceSectionExpanded));
            }
        }

        public bool IsDetailsExpanded
        {
            get => _isDetailsExpanded;
            set
            {
                if (_isDetailsExpanded == value) return;
                _isDetailsExpanded = value;
                OnPropertyChanged(nameof(IsDetailsExpanded));
            }
        }
        public event PropertyChangedEventHandler? PropertyChanged;

        private void MainOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            try
            {
                RaiseDerivedProperties();

                if (string.Equals(e.PropertyName, nameof(MainViewModel.ScreenState), StringComparison.Ordinal))
                {
                    TrackScreenStateTransition();
                    AutoCollapseSourceSectionBestEffort();
                }
                else if (string.Equals(e.PropertyName, nameof(MainViewModel.IsApplyRunning), StringComparison.Ordinal))
                {
                    TrackApplyTransition();
                    AutoCollapseSourceSectionBestEffort();
                }
                else if (string.Equals(e.PropertyName, nameof(MainViewModel.IsPostApplyRetestRunning), StringComparison.Ordinal)
                      || string.Equals(e.PropertyName, nameof(MainViewModel.PostApplyRetestStatus), StringComparison.Ordinal))
                {
                    TrackPostApplyRetestBestEffort();
                    AutoCollapseSourceSectionBestEffort();
                }
                else if (string.Equals(e.PropertyName, nameof(MainViewModel.FailCount), StringComparison.Ordinal)
                      || string.Equals(e.PropertyName, nameof(MainViewModel.WarnCount), StringComparison.Ordinal)
                      || string.Equals(e.PropertyName, nameof(MainViewModel.PassCount), StringComparison.Ordinal))
                {
                    // На завершении диагностики могут прилетать счётчики отдельно.
                    // Обновим фильтры/derived без логирования.
                    RefreshSummaryProblemsBestEffort();
                }
            }
            catch
            {
                // ignore
            }
        }

        private void RaiseDerivedProperties()
        {
            OnPropertyChanged(nameof(Status));
            OnPropertyChanged(nameof(HeroIconKind));
            OnPropertyChanged(nameof(HeroAccentBrush));
            OnPropertyChanged(nameof(IsSourceStepVisible));
            OnPropertyChanged(nameof(IsProgressStepVisible));
            OnPropertyChanged(nameof(IsSummaryStepVisible));
            OnPropertyChanged(nameof(IsFixingStepVisible));
            OnPropertyChanged(nameof(IsSourceSelectionEnabled));
            OnPropertyChanged(nameof(IsPrimaryActionEnabled));
            OnPropertyChanged(nameof(IsFixStepCardVisible));
            OnPropertyChanged(nameof(FixStepTitle));
            OnPropertyChanged(nameof(FixStepStatusText));
            OnPropertyChanged(nameof(HasFixStepOutcome));
            OnPropertyChanged(nameof(FixStepOutcomeText));
            OnPropertyChanged(nameof(Headline));
            OnPropertyChanged(nameof(SummaryLine));
            OnPropertyChanged(nameof(CheckedProblemsLine));
            OnPropertyChanged(nameof(HasSummaryProblems));
            OnPropertyChanged(nameof(UserDetails_Source));
            OnPropertyChanged(nameof(UserDetails_Anchor));
            OnPropertyChanged(nameof(UserDetails_Status));
            OnPropertyChanged(nameof(UserDetails_Result));
            OnPropertyChanged(nameof(UserDetails_AutoFix));
            OnPropertyChanged(nameof(UserDetails_Bypass));
            OnPropertyChanged(nameof(UserDetails_LastAction));
            OnPropertyChanged(nameof(HasUserDetails_SubHosts));
            OnPropertyChanged(nameof(UserDetails_SubHosts));
            OnPropertyChanged(nameof(RawDetailsText));
            OnPropertyChanged(nameof(ShowFixButton));
            OnPropertyChanged(nameof(ShowPrimaryButton));
            OnPropertyChanged(nameof(PrimaryButtonText));
            OnPropertyChanged(nameof(FixButtonText));
            OnPropertyChanged(nameof(HasHistory));
            OnPropertyChanged(nameof(HasSessions));
        }

        private void RefreshSummaryProblemsBestEffort()
        {
            try
            {
                var lines = BuildProblemsSnapshotLines(maxItems: 10).ToList();

                _summaryProblemCards.Clear();
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    _summaryProblemCards.Add(line);
                }

                OnPropertyChanged(nameof(HasSummaryProblems));
            }
            catch
            {
                // ignore
            }
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
