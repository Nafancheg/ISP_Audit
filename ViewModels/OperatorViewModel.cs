using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Media;
using IspAudit;
using System.Threading;
using IspAudit.Models;
using IspAudit.Utils;
using IspAudit.Wpf;
using MaterialDesignThemes.Wpf;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Лёгкая ViewModel для «Операторского» UI.
    /// Оборачивает MainViewModel и предоставляет упрощённые computed-свойства.
    /// </summary>
    public sealed class OperatorViewModel : INotifyPropertyChanged
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

        private const int MaxHistoryEntries = 256;
        private const int MaxSessionsEntries = 128;
        private const string AllHistoryGroupsKey = "__all__";
        private readonly ObservableCollection<OperatorEventEntry> _historyAll = new();

        private sealed class SessionDraft
        {
            public string Id { get; } = Guid.NewGuid().ToString("N");
            public DateTimeOffset StartedAtUtc { get; set; } = DateTimeOffset.UtcNow;
            public string TrafficSource { get; set; } = string.Empty;
            public bool AutoFixEnabledAtStart { get; set; }

            public bool CheckCompleted { get; set; }
            public int PassCount { get; set; }
            public int WarnCount { get; set; }
            public int FailCount { get; set; }
            public string CountsText { get; set; } = string.Empty;
            public List<string> Problems { get; } = new();

            public bool HadApply { get; set; }
            public string PostApplyVerdict { get; set; } = string.Empty;
            public string PostApplyStatusText { get; set; } = string.Empty;
            public List<string> Actions { get; } = new();

            public bool Ended { get; set; }
        }

        private SessionDraft? _activeSession;
        private bool _pendingFixTriggeredByUser;

        public sealed record HistoryGroupOption(string Key, string Title);

        public ObservableCollection<OperatorEventEntry> HistoryEvents { get; } = new();
        public ObservableCollection<HistoryGroupOption> HistoryGroupOptions { get; } = new();

        public ObservableCollection<OperatorSessionEntry> Sessions { get; } = new();

        private OperatorHistoryTimeRange _historyTimeRange = OperatorHistoryTimeRange.Last7Days;
        private OperatorHistoryTypeFilter _historyTypeFilter = OperatorHistoryTypeFilter.All;
        private string _historyGroupKey = AllHistoryGroupsKey;

        private string _lastScreenState = string.Empty;
        private bool _lastIsApplyRunning;

        private bool _fixStepLatched;
        private string _lastPostApplyVerdict = string.Empty;
        private string _lastPostApplyDetails = string.Empty;
        private DateTimeOffset _lastPostApplyVerdictAtUtc = DateTimeOffset.MinValue;

        private bool _isSourceSectionExpanded = true;
        private bool _didAutoCollapseSourceSection;

        public ICommand RollbackCommand { get; }
        public ICommand ClearHistoryCommand { get; }
        public ICommand ClearSessionsCommand { get; }

        public OperatorViewModel(MainViewModel main)
        {
            Main = main ?? throw new ArgumentNullException(nameof(main));

            // История сессий (best-effort).
            try
            {
                var loadedSessions = OperatorSessionStore.LoadBestEffort(log: null);
                foreach (var s in loadedSessions)
                {
                    Sessions.Add(s);
                }
                SortSessionsBestEffort();
            }
            catch
            {
                // ignore
            }

            // История активности (best-effort).
            try
            {
                var loaded = OperatorEventStore.LoadBestEffort(log: null);
                foreach (var e in loaded)
                {
                    _historyAll.Add(e);
                }
            }
            catch
            {
                // ignore
            }

            RebuildHistoryGroupOptionsBestEffort();
            ApplyHistoryFilters();

            _lastScreenState = (Main.ScreenState ?? string.Empty).Trim();
            _lastIsApplyRunning = Main.IsApplyRunning;

            // При первом прогоне сворачиваем секцию выбора источника, чтобы она не съедала экран.
            // Далее состояние контролируется пользователем.
            _isSourceSectionExpanded = Status == OperatorStatus.Idle;
            _didAutoCollapseSourceSection = Status != OperatorStatus.Idle;

            RollbackCommand = new RelayCommand(async _ => await RollbackAsync().ConfigureAwait(false));
            ClearHistoryCommand = new RelayCommand(_ => ClearHistoryBestEffort());
            ClearSessionsCommand = new RelayCommand(_ => ClearSessionsBestEffort());

            Main.PropertyChanged += MainOnPropertyChanged;

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

        public OperatorHistoryTimeRange HistoryTimeRange
        {
            get => _historyTimeRange;
            set
            {
                if (_historyTimeRange == value) return;
                _historyTimeRange = value;
                OnPropertyChanged(nameof(HistoryTimeRange));
                ApplyHistoryFilters();
            }
        }

        public OperatorHistoryTypeFilter HistoryTypeFilter
        {
            get => _historyTypeFilter;
            set
            {
                if (_historyTypeFilter == value) return;
                _historyTypeFilter = value;
                OnPropertyChanged(nameof(HistoryTypeFilter));
                ApplyHistoryFilters();
            }
        }

        public string HistoryGroupKey
        {
            get => _historyGroupKey;
            set
            {
                if (string.Equals(_historyGroupKey, value, StringComparison.Ordinal)) return;
                _historyGroupKey = string.IsNullOrWhiteSpace(value) ? AllHistoryGroupsKey : value;
                OnPropertyChanged(nameof(HistoryGroupKey));
                ApplyHistoryFilters();
            }
        }

        public bool HasHistory => _historyAll.Count > 0;

        public bool HasSessions => Sessions.Count > 0;

        public string Headline
        {
            get
            {
                return GetPresentation(Status).Headline;
            }
        }

        public string SummaryLine
        {
            get
            {
                if (Status == OperatorStatus.Checking)
                {
                    return Main.RunningStatusText;
                }

                if (Status == OperatorStatus.Fixing)
                {
                    var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                    if (Main.IsPostApplyRetestRunning && !string.IsNullOrWhiteSpace(post)) return post;

                    var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(apply)
                        ? "Применяю безопасные действия и перепроверяю…"
                        : apply;
                }

                if (Main.IsDone)
                {
                    return $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";
                }

                // Idle
                if (Main.IsBasicTestMode)
                {
                    return "Тестовый режим: быстрая проверка интернета (включено в настройках). Нажмите «Проверить».";
                }

                var exePath = (Main.ExePath ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(exePath))
                {
                    try
                    {
                        return $"Источник: {Path.GetFileName(exePath)}. Нажмите «Проверить».";
                    }
                    catch
                    {
                        return "Источник: выбранное приложение (.exe). Нажмите «Проверить».";
                    }
                }

                return "Выберите приложение (.exe) и нажмите «Проверить».";
            }
        }

        public string UserDetails_Anchor
        {
            get
            {
                try
                {
                    var host = (Main.Bypass.OutcomeTargetHost ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(host) ? "—" : host;
                }
                catch
                {
                    return "—";
                }
            }
        }

        public string UserDetails_Source
        {
            get
            {
                var t = BuildTrafficSourceText();
                return string.IsNullOrWhiteSpace(t) ? "—" : t;
            }
        }

        public string UserDetails_Status
        {
            get
            {
                return GetPresentation(Status).UserDetailsStatus;
            }
        }

        public string UserDetails_Result
        {
            get
            {
                if (!Main.IsDone)
                {
                    // В процессе/idle показывать счётчики бессмысленно.
                    return "—";
                }

                return $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";
            }
        }

        public string UserDetails_AutoFix
            => Main.EnableAutoBypass ? "Включено" : "Выключено";

        public string UserDetails_Bypass
            => Main.IsBypassActive ? "Активен" : "Не активен";

        public string UserDetails_LastAction
        {
            get
            {
                var fix = (Main.ActiveApplySummaryText ?? string.Empty).Trim();
                var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();

                // Выводим самое «человеческое» из доступного.
                if (!string.IsNullOrWhiteSpace(fix)) return fix;

                if (!string.IsNullOrWhiteSpace(apply) && !string.IsNullOrWhiteSpace(post))
                {
                    return $"{apply}; {post}";
                }

                if (!string.IsNullOrWhiteSpace(apply)) return apply;
                if (!string.IsNullOrWhiteSpace(post)) return post;

                return Main.HasAnyRecommendations ? "Доступны рекомендации по исправлению" : "—";
            }
        }

        public string RawDetailsText
        {
            get
            {
                try
                {
                    var parts = new List<string>(capacity: 6);

                    var diag = (Main.DiagnosticStatus ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(diag)) parts.Add(diag);

                    var abs = (Main.AutoBypassStatus ?? string.Empty).Trim();
                    var abv = (Main.AutoBypassVerdict ?? string.Empty).Trim();
                    var abm = (Main.AutoBypassMetrics ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(abs)) parts.Add(abs);
                    if (!string.IsNullOrWhiteSpace(abv)) parts.Add(abv);
                    if (!string.IsNullOrWhiteSpace(abm)) parts.Add(abm);

                    return parts.Count == 0 ? "—" : string.Join(Environment.NewLine, parts);
                }
                catch
                {
                    return "—";
                }
            }
        }

        public OperatorStatus Status
        {
            get
            {
                if (Main.IsApplyRunning || Main.IsPostApplyRetestRunning) return OperatorStatus.Fixing;
                if (Main.IsRunning) return OperatorStatus.Checking;

                // P1.11: операторский статус должен отражать "первичную семантику" (P1.8),
                // т.е. учитывать пост‑проверку после Apply как главный итог.
                try
                {
                    var results = Main.TestResults;
                    if (results == null || results.Count == 0) return OperatorStatus.Idle;

                    var hasAnyNonIdle = false;
                    var hasFail = false;
                    var hasWarn = false;
                    var hasPass = false;

                    foreach (var tr in results)
                    {
                        if (tr == null) continue;

                        // Если по какой-то карточке идёт post-apply ретест (queued/running),
                        // показываем "Исправляем…" даже если глобальный флаг IsPostApplyRetestRunning не поднят.
                        if (tr.PostApplyCheckStatus == PostApplyCheckStatus.Queued
                            || tr.PostApplyCheckStatus == PostApplyCheckStatus.Running)
                        {
                            return OperatorStatus.Fixing;
                        }

                        var s = tr.PrimaryStatus;
                        if (s == TestStatus.Running) return OperatorStatus.Checking;
                        if (s == TestStatus.Idle) continue;

                        hasAnyNonIdle = true;
                        if (s == TestStatus.Fail)
                        {
                            hasFail = true;
                            break;
                        }
                        if (s == TestStatus.Warn) hasWarn = true;
                        if (s == TestStatus.Pass) hasPass = true;
                    }

                    if (!hasAnyNonIdle) return OperatorStatus.Idle;
                    if (hasFail) return OperatorStatus.Blocked;
                    if (hasWarn) return OperatorStatus.Warn;
                    if (hasPass) return OperatorStatus.Ok;

                    return OperatorStatus.Idle;
                }
                catch
                {
                    // Best-effort fallback на старую семантику (счётчики от пайплайна), если коллекция меняется во время перечисления.
                    if (Main.IsDone)
                    {
                        if (Main.FailCount > 0) return OperatorStatus.Blocked;
                        if (Main.WarnCount > 0) return OperatorStatus.Warn;
                        return OperatorStatus.Ok;
                    }

                    return OperatorStatus.Idle;
                }
            }
        }

        public PackIconKind HeroIconKind
        {
            get
            {
                return GetPresentation(Status).HeroIconKind;
            }
        }

        public System.Windows.Media.Brush HeroAccentBrush
        {
            get
            {
                return GetPresentation(Status).HeroAccentBrush;
            }
        }

        public bool IsSourceStepVisible =>
            Status == OperatorStatus.Idle
            || Status == OperatorStatus.Ok
            || Status == OperatorStatus.Warn
            || Status == OperatorStatus.Blocked;

        public bool IsProgressStepVisible => Status == OperatorStatus.Checking;

        public bool IsSummaryStepVisible =>
            Status == OperatorStatus.Ok
            || Status == OperatorStatus.Warn
            || Status == OperatorStatus.Blocked;

        public bool IsFixingStepVisible => Status == OperatorStatus.Fixing;

        public bool IsSourceSelectionEnabled => IsSourceStepVisible && !Main.IsRunning && !Main.IsApplyRunning && !Main.IsPostApplyRetestRunning;

        public bool IsPrimaryActionEnabled => Status != OperatorStatus.Fixing;

        public bool IsFixStepCardVisible
            => Status == OperatorStatus.Fixing
            || _fixStepLatched
            || !string.IsNullOrWhiteSpace(Main.PostApplyRetestStatus)
            || !string.IsNullOrWhiteSpace(_lastPostApplyVerdict);

        public string FixStepTitle
        {
            get
            {
                if (Main.IsApplyRunning) return "Исправление…";
                if (Main.IsPostApplyRetestRunning) return "Перепроверка…";
                return "Итог после исправления";
            }
        }

        public string FixStepStatusText
        {
            get
            {
                if (Main.IsApplyRunning)
                {
                    var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(apply) ? "Применяю рекомендации…" : apply;
                }

                if (Main.IsPostApplyRetestRunning)
                {
                    var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                    return string.IsNullOrWhiteSpace(post) ? "Ретест после исправления: выполняется…" : post;
                }

                var done = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(done)) return done;

                if (_fixStepLatched)
                {
                    return "Ретест после исправления: завершён";
                }

                return "—";
            }
        }

        public bool HasFixStepOutcome => !string.IsNullOrWhiteSpace(_lastPostApplyVerdict);

        private bool IsEscalationAvailableNow
        {
            get
            {
                // «Усилить» показываем только после неуспешного пост-apply ретеста.
                var v = (_lastPostApplyVerdict ?? string.Empty).Trim().ToUpperInvariant();
                if (v != "FAIL" && v != "PARTIAL") return false;

                // В non-admin режиме применить байпас нельзя.
                if (!Main.ShowBypassPanel) return false;

                // Если идёт apply/ретест — не эскалируем.
                if (Main.IsApplyRunning || Main.IsPostApplyRetestRunning) return false;

                // Детерминированная лестница должна совпадать с Orchestrator.TryBuildEscalationPlan:
                // 1) Fragment -> Disorder
                // 2) DropRst
                // 3) QUIC fallback
                // 4) AllowNoSNI
                if (Main.IsFragmentEnabled && !Main.IsDisorderEnabled) return true;
                if (!Main.IsDropRstEnabled) return true;
                if (!Main.IsQuicFallbackEnabled) return true;
                if (!Main.IsAllowNoSniEnabled) return true;

                return false;
            }
        }

        public string FixStepOutcomeText
        {
            get
            {
                var v = (_lastPostApplyVerdict ?? string.Empty).Trim().ToUpperInvariant();
                if (string.IsNullOrWhiteSpace(v)) return string.Empty;

                var headline = v switch
                {
                    "OK" => "Итог: стало лучше",
                    "PARTIAL" => "Итог: частично",
                    "FAIL" => "Итог: не помогло",
                    "UNKNOWN" => "Итог: не удалось проверить",
                    _ => $"Итог: {v}"
                };

                var d = (_lastPostApplyDetails ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(d)) return headline;
                return $"{headline} ({d})";
            }
        }

        public bool ShowFixButton =>
            (Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
            && (Main.HasAnyRecommendations || IsEscalationAvailableNow)
            && !Main.IsApplyRunning;

        public bool ShowPrimaryButton => !ShowFixButton;

        public string PrimaryButtonText
        {
            get
            {
                var p = GetPresentation(Status);

                // Единственное исключение из таблицы: если "Исправить" недоступно, предлагаем повторную проверку.
                if ((Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
                    && !Main.HasAnyRecommendations)
                {
                    return "Проверить снова";
                }

                return p.DefaultPrimaryButtonText;
            }
        }

        public ICommand PrimaryCommand
        {
            get
            {
                // Всегда возвращаем одну команду, чтобы можно было логировать события.
                return new RelayCommand(_ => ExecutePrimary());
            }
        }

        public string FixButtonText
            => Main.IsApplyRunning
                ? "Исправляю…"
                : IsEscalationAvailableNow
                    ? "Усилить"
                    : "Исправить";
        public ICommand FixCommand => new RelayCommand(_ => ExecuteFix());

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
            OnPropertyChanged(nameof(UserDetails_Source));
            OnPropertyChanged(nameof(UserDetails_Anchor));
            OnPropertyChanged(nameof(UserDetails_Status));
            OnPropertyChanged(nameof(UserDetails_Result));
            OnPropertyChanged(nameof(UserDetails_AutoFix));
            OnPropertyChanged(nameof(UserDetails_Bypass));
            OnPropertyChanged(nameof(UserDetails_LastAction));
            OnPropertyChanged(nameof(RawDetailsText));
            OnPropertyChanged(nameof(ShowFixButton));
            OnPropertyChanged(nameof(ShowPrimaryButton));
            OnPropertyChanged(nameof(PrimaryButtonText));
            OnPropertyChanged(nameof(FixButtonText));
            OnPropertyChanged(nameof(HasHistory));
            OnPropertyChanged(nameof(HasSessions));
        }

        private void AutoCollapseSourceSectionBestEffort()
        {
            try
            {
                if (_didAutoCollapseSourceSection) return;

                // Как только начинается проверка/исправление или появился итог — сворачиваем.
                if (Status != OperatorStatus.Idle)
                {
                    _didAutoCollapseSourceSection = true;
                    IsSourceSectionExpanded = false;
                }
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

        private void ExecutePrimary()
        {
            if ((Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
                && (Main.HasAnyRecommendations || IsEscalationAvailableNow))
            {
                ExecuteFix();
                return;
            }

            ExecuteStartOrStop();
        }

        private void ExecuteStartOrStop()
        {
            try
            {
                Main.StartLiveTestingCommand.Execute(null);
            }
            catch (Exception ex)
            {
                // Best-effort: фиксируем как «сессию-ошибку», чтобы оператор видел попытку.
                FinalizeSessionAsErrorBestEffort("Ошибка запуска проверки", ex.Message);
                throw;
            }
        }

        private void ExecuteFix()
        {
            try
            {
                _pendingFixTriggeredByUser = true;

                if (IsEscalationAvailableNow)
                {
                    Main.ApplyEscalationCommand.Execute(null);
                }
                else
                {
                    Main.ApplyRecommendationsCommand.Execute(null);
                }
            }
            catch (Exception ex)
            {
                FinalizeSessionAsErrorBestEffort("Ошибка запуска исправления", ex.Message);
                throw;
            }
        }

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

        private void TrackScreenStateTransition()
        {
            var now = (Main.ScreenState ?? string.Empty).Trim();
            var prev = _lastScreenState;
            if (string.Equals(now, prev, StringComparison.Ordinal)) return;

            _lastScreenState = now;

            if (string.Equals(now, "running", StringComparison.OrdinalIgnoreCase))
            {
                ClearFixWizardStateBestEffort();
                StartNewDraftForCheckBestEffort();
                return;
            }

            if (string.Equals(now, "done", StringComparison.OrdinalIgnoreCase))
            {
                CompleteCheckInDraftBestEffort();
                TryFinalizeActiveSessionBestEffort(preferPostApply: true);
            }
        }

        private void TrackApplyTransition()
        {
            var now = Main.IsApplyRunning;
            var prev = _lastIsApplyRunning;
            if (now == prev) return;

            _lastIsApplyRunning = now;

            if (now)
            {
                _fixStepLatched = true;
                EnsureDraftExistsBestEffort(reason: "apply_start");
                if (_activeSession != null)
                {
                    _activeSession.HadApply = true;
                    var mode = _pendingFixTriggeredByUser ? "ручное" : "авто";
                    _pendingFixTriggeredByUser = false;

                    var detail = (Main.ApplyStatusText ?? string.Empty).Trim();
                    _activeSession.Actions.Add(string.IsNullOrWhiteSpace(detail)
                        ? $"Исправление: запуск ({mode})"
                        : $"Исправление: запуск ({mode}) — {detail}");
                }
                return;
            }

            // Apply закончился.
            _fixStepLatched = true;
            EnsureDraftExistsBestEffort(reason: "apply_end");
            if (_activeSession != null)
            {
                var apply = (Main.ApplyStatusText ?? string.Empty).Trim();
                var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                _activeSession.PostApplyStatusText = post;

                if (!string.IsNullOrWhiteSpace(apply) && !string.IsNullOrWhiteSpace(post))
                {
                    _activeSession.Actions.Add($"Исправление: завершено — {apply}; {post}");
                }
                else if (!string.IsNullOrWhiteSpace(apply))
                {
                    _activeSession.Actions.Add($"Исправление: завершено — {apply}");
                }
                else if (!string.IsNullOrWhiteSpace(post))
                {
                    _activeSession.Actions.Add($"Исправление: завершено — {post}");
                }
                else
                {
                    _activeSession.Actions.Add("Исправление: завершено");
                }
            }

            TryFinalizeActiveSessionBestEffort(preferPostApply: true);
        }

        private void OrchestratorOnPostApplyCheckVerdict(string hostKey, string verdict, string mode, string? details)
        {
            try
            {
                EnsureDraftExistsBestEffort(reason: "post_apply_verdict");
                if (_activeSession == null) return;

                _fixStepLatched = true;
                _lastPostApplyVerdict = (verdict ?? string.Empty).Trim();
                _lastPostApplyDetails = (details ?? string.Empty).Trim();
                _lastPostApplyVerdictAtUtc = DateTimeOffset.UtcNow;

                _activeSession.HadApply = true;
                _activeSession.PostApplyVerdict = (verdict ?? string.Empty).Trim();

                var d = (details ?? string.Empty).Trim();
                var hk = (hostKey ?? string.Empty).Trim();
                var m = (mode ?? string.Empty).Trim();

                var line = string.IsNullOrWhiteSpace(d)
                    ? $"Ретест после исправления: {verdict} ({m})"
                    : $"Ретест после исправления: {verdict} ({m}) — {hk}; {d}";

                _activeSession.Actions.Add(line);

                TryFinalizeActiveSessionBestEffort(preferPostApply: true);

                // Событие приходит не через Main.PropertyChanged — обновим UI явно.
                RaiseDerivedProperties();
            }
            catch
            {
                // ignore
            }
        }

        private void TrackPostApplyRetestBestEffort()
        {
            try
            {
                if (Main.IsPostApplyRetestRunning)
                {
                    _fixStepLatched = true;
                    return;
                }

                var post = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(post))
                {
                    _fixStepLatched = true;
                }
            }
            catch
            {
                // ignore
            }
        }

        private void ClearFixWizardStateBestEffort()
        {
            try
            {
                _fixStepLatched = false;
                _lastPostApplyVerdict = string.Empty;
                _lastPostApplyDetails = string.Empty;
                _lastPostApplyVerdictAtUtc = DateTimeOffset.MinValue;
            }
            catch
            {
                // ignore
            }
        }

        private void StartNewDraftForCheckBestEffort()
        {
            try
            {
                // Если предыдущая сессия не была закрыта (например ожидали ретест, но пользователь начал новую проверку)
                // — закрываем best-effort как UNKNOWN.
                if (_activeSession != null && !_activeSession.Ended)
                {
                    _activeSession.Actions.Add("Новая проверка запущена: предыдущая сессия закрыта без итогового ретеста");
                    FinalizeDraftBestEffort(_activeSession, outcomeOverride: "UNKNOWN");
                }

                _activeSession = new SessionDraft
                {
                    StartedAtUtc = DateTimeOffset.UtcNow,
                    TrafficSource = BuildSessionTrafficDescriptorTextBestEffort(),
                    AutoFixEnabledAtStart = Main.EnableAutoBypass
                };
                _activeSession.Actions.Add("Проверка: началась");
            }
            catch
            {
                // ignore
            }
        }

        private void CompleteCheckInDraftBestEffort()
        {
            try
            {
                EnsureDraftExistsBestEffort(reason: "check_done");
                if (_activeSession == null) return;

                _activeSession.CheckCompleted = true;
                _activeSession.PassCount = Main.PassCount;
                _activeSession.WarnCount = Main.WarnCount;
                _activeSession.FailCount = Main.FailCount;
                _activeSession.CountsText = $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";

                _activeSession.Problems.Clear();
                foreach (var line in BuildProblemsSnapshotLines(maxItems: 10))
                {
                    _activeSession.Problems.Add(line);
                }

                var cancelled = Main.Orchestrator.LastRunWasUserCancelled;
                var outcome = cancelled
                    ? "CANCELLED"
                    : (_activeSession.FailCount > 0 ? "FAIL" : (_activeSession.WarnCount > 0 ? "WARN" : "OK"));

                var title = outcome == "OK" ? "Проверка: завершена (норма)"
                    : outcome == "WARN" ? "Проверка: завершена (есть ограничения)"
                    : outcome == "FAIL" ? "Проверка: завершена (есть блокировки)"
                    : "Проверка: завершена";

                _activeSession.Actions.Add($"{title} — {_activeSession.CountsText}");
            }
            catch
            {
                // ignore
            }
        }

        private void EnsureDraftExistsBestEffort(string reason)
        {
            try
            {
                if (_activeSession != null && !_activeSession.Ended) return;

                _activeSession = new SessionDraft
                {
                    StartedAtUtc = DateTimeOffset.UtcNow,
                    TrafficSource = BuildSessionTrafficDescriptorTextBestEffort(),
                    AutoFixEnabledAtStart = Main.EnableAutoBypass
                };

                if (!string.IsNullOrWhiteSpace(reason))
                {
                    _activeSession.Actions.Add($"Сессия: создана ({reason})");
                }
            }
            catch
            {
                // ignore
            }
        }

        private string BuildSessionTrafficDescriptorTextBestEffort()
        {
            try
            {
                var source = BuildTrafficSourceText();

                return source;
            }
            catch
            {
                return BuildTrafficSourceText();
            }
        }

        private IEnumerable<string> BuildProblemsSnapshotLines(int maxItems)
        {
            try
            {
                var list = Main.TestResults
                    .Where(r => r != null)
                    .Where(r => r.Status == TestStatus.Fail || r.Status == TestStatus.Warn)
                    .OrderBy(r => r.Status == TestStatus.Fail ? 0 : 1)
                    .ThenBy(r => (r.DisplayHost ?? string.Empty), StringComparer.OrdinalIgnoreCase)
                    .Take(Math.Max(1, maxItems))
                    .Select(BuildProblemLine)
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .ToList();

                return list;
            }
            catch
            {
                return Array.Empty<string>();
            }
        }

        private static string BuildProblemLine(TestResult r)
        {
            try
            {
                var host = (r.DisplayHost ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(host)) host = (r.DisplayIp ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(host)) host = "(неизвестная цель)";

                var status = r.Status == TestStatus.Fail ? "FAIL" : "WARN";
                var tags = new List<string>(capacity: 4);
                if (r.IsRstInjection) tags.Add("RST");
                if (r.IsHttpRedirect) tags.Add("Redirect");
                if (r.IsRetransmissionHeavy) tags.Add("Retransmit");
                if (r.IsUdpBlockage) tags.Add("UDP/QUIC");

                var tagText = tags.Count > 0 ? $" ({string.Join(", ", tags)})" : string.Empty;
                var err = (r.Error ?? string.Empty).Trim();

                if (!string.IsNullOrWhiteSpace(err))
                {
                    return $"{host} — {status}{tagText}: {err}";
                }

                return $"{host} — {status}{tagText}";
            }
            catch
            {
                return string.Empty;
            }
        }

        private void TryFinalizeActiveSessionBestEffort(bool preferPostApply)
        {
            try
            {
                if (_activeSession == null || _activeSession.Ended) return;

                // Если был Apply — стараемся закрывать по verdict (семантика P1.8).
                if (preferPostApply && _activeSession.HadApply)
                {
                    if (!string.IsNullOrWhiteSpace(_activeSession.PostApplyVerdict))
                    {
                        FinalizeDraftBestEffort(_activeSession, outcomeOverride: MapVerdictToOutcome(_activeSession.PostApplyVerdict));
                        _activeSession = null;
                        return;
                    }

                    // Fallback: если ретест уже не бежит и статус заполнен — тоже закрываем.
                    if (!Main.IsPostApplyRetestRunning && !string.IsNullOrWhiteSpace(Main.PostApplyRetestStatus))
                    {
                        _activeSession.PostApplyStatusText = (Main.PostApplyRetestStatus ?? string.Empty).Trim();
                        FinalizeDraftBestEffort(_activeSession, outcomeOverride: string.Empty);
                        _activeSession = null;
                        return;
                    }

                    // Ждём.
                    return;
                }

                // Без Apply: закрываем по завершению проверки.
                if (_activeSession.CheckCompleted)
                {
                    FinalizeDraftBestEffort(_activeSession, outcomeOverride: string.Empty);
                    _activeSession = null;
                }
            }
            catch
            {
                // ignore
            }
        }

        private void FinalizeSessionAsErrorBestEffort(string title, string details)
        {
            try
            {
                EnsureDraftExistsBestEffort(reason: "error");
                if (_activeSession == null) return;

                _activeSession.Actions.Add($"Ошибка: {title} — {details}");
                FinalizeDraftBestEffort(_activeSession, outcomeOverride: "FAIL");
                _activeSession = null;
            }
            catch
            {
                // ignore
            }
        }

        private static string MapVerdictToOutcome(string verdict)
        {
            var v = (verdict ?? string.Empty).Trim().ToUpperInvariant();
            return v switch
            {
                "OK" => "OK",
                "FAIL" => "FAIL",
                "PARTIAL" => "WARN",
                "UNKNOWN" => "UNKNOWN",
                _ => string.IsNullOrWhiteSpace(v) ? string.Empty : v
            };
        }

        private void FinalizeDraftBestEffort(SessionDraft draft, string outcomeOverride)
        {
            try
            {
                if (draft.Ended) return;
                draft.Ended = true;

                var endUtc = DateTimeOffset.UtcNow;

                var cancelled = Main.Orchestrator.LastRunWasUserCancelled;
                var baseOutcome = cancelled
                    ? "CANCELLED"
                    : (draft.FailCount > 0 ? "FAIL" : (draft.WarnCount > 0 ? "WARN" : "OK"));

                var outcome = string.IsNullOrWhiteSpace(outcomeOverride) ? baseOutcome : outcomeOverride.Trim();

                var problemsText = string.Join("\n", draft.Problems.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => "• " + s));
                var actionsText = string.Join("\n", draft.Actions.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => "• " + s));

                var entry = new OperatorSessionEntry
                {
                    Id = draft.Id,
                    StartedAtUtc = draft.StartedAtUtc.ToString("u").TrimEnd(),
                    EndedAtUtc = endUtc.ToString("u").TrimEnd(),
                    TrafficSource = draft.TrafficSource,
                    AutoFixEnabledAtStart = draft.AutoFixEnabledAtStart,
                    Outcome = outcome,
                    CountsText = draft.CountsText,
                    ProblemsText = problemsText,
                    ActionsText = actionsText,
                    PostApplyVerdict = draft.PostApplyVerdict,
                    PostApplyStatusText = string.IsNullOrWhiteSpace(draft.PostApplyStatusText) ? (Main.PostApplyRetestStatus ?? string.Empty).Trim() : draft.PostApplyStatusText
                };

                // Новые сверху.
                Sessions.Insert(0, entry);
                SortSessionsBestEffort();
                while (Sessions.Count > MaxSessionsEntries)
                {
                    Sessions.RemoveAt(Sessions.Count - 1);
                }
                OnPropertyChanged(nameof(HasSessions));

                var snapshot = Sessions.ToList();
                _ = Task.Run(() =>
                {
                    try
                    {
                        OperatorSessionStore.PersistBestEffort(snapshot, log: null);
                    }
                    catch
                    {
                        // ignore
                    }
                });
            }
            catch
            {
                // ignore
            }
        }

        private void ClearSessionsBestEffort()
        {
            try
            {
                Sessions.Clear();
                OperatorSessionStore.TryDeletePersistedFileBestEffort(log: null);
                OnPropertyChanged(nameof(HasSessions));
            }
            catch
            {
                // ignore
            }
        }

        private void AddHistoryEvent(OperatorEventEntry entry)
        {
            try
            {
                if (entry == null) return;

                // Новые сверху.
                _historyAll.Insert(0, entry);

                while (_historyAll.Count > MaxHistoryEntries)
                {
                    _historyAll.RemoveAt(_historyAll.Count - 1);
                }

                RebuildHistoryGroupOptionsBestEffort();
                ApplyHistoryFilters();
                OnPropertyChanged(nameof(HasHistory));

                // Persist best-effort в фоне.
                var snapshot = _historyAll.ToList();
                _ = Task.Run(() =>
                {
                    try
                    {
                        OperatorEventStore.PersistBestEffort(snapshot, log: null);
                    }
                    catch
                    {
                        // ignore
                    }
                });
            }
            catch
            {
                // ignore
            }
        }

        private void ClearHistoryBestEffort()
        {
            try
            {
                _historyAll.Clear();
                HistoryEvents.Clear();
                OperatorEventStore.TryDeletePersistedFileBestEffort(log: null);
                RebuildHistoryGroupOptionsBestEffort();
                OnPropertyChanged(nameof(HasHistory));
            }
            catch
            {
                // ignore
            }
        }

        private void RebuildHistoryGroupOptionsBestEffort()
        {
            try
            {
                var keys = _historyAll
                    .Where(e => e != null)
        private void SortSessionsBestEffort()
        {
                    .Select(e => (e.GroupKey ?? string.Empty).Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(k => string.IsNullOrWhiteSpace(k) ? "" : k, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var options = new List<HistoryGroupOption>(capacity: 1 + keys.Count)
                {
                    new HistoryGroupOption(AllHistoryGroupsKey, "Все")
                };

                foreach (var k in keys)
                {
                    var title = string.IsNullOrWhiteSpace(k) ? "Без группы" : k;
                    options.Add(new HistoryGroupOption(string.IsNullOrWhiteSpace(k) ? string.Empty : k, title));
                }

                var selected = _historyGroupKey;
                HistoryGroupOptions.Clear();
                foreach (var opt in options)
                {
                    HistoryGroupOptions.Add(opt);
                }

                // Если выбранная группа исчезла — откатываемся на "Все".
                var exists = HistoryGroupOptions.Any(o => string.Equals(o.Key, selected, StringComparison.Ordinal));
                if (!exists)
        private static int GetOutcomeRank(string? outcome)
        {
                {
                    _historyGroupKey = AllHistoryGroupsKey;
                    OnPropertyChanged(nameof(HistoryGroupKey));
                }
            }
            catch
            {
                // ignore
            }
        }

        private void ApplyHistoryFilters()
        {
            try
            {
        private static DateTimeOffset GetSessionTimeUtc(OperatorSessionEntry? entry)
        {
                var nowLocal = DateTimeOffset.Now;
                DateTimeOffset? cutoff = null;

                if (HistoryTimeRange == OperatorHistoryTimeRange.Today)
                {
                    cutoff = new DateTimeOffset(nowLocal.Date, nowLocal.Offset);
                }
                else if (HistoryTimeRange == OperatorHistoryTimeRange.Last7Days)
                {
                    cutoff = nowLocal.AddDays(-7);
                }

                bool IsTypeMatch(OperatorEventEntry e)
                {
                    var cat = (e.Category ?? string.Empty).Trim();
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.All) return true;
        private static bool TryParseUtc(string? text, out DateTimeOffset value)
        {
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.Checks) return cat.Equals("check", StringComparison.OrdinalIgnoreCase);
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.Fixes) return cat.Equals("fix", StringComparison.OrdinalIgnoreCase) || cat.Equals("rollback", StringComparison.OrdinalIgnoreCase);
                    if (HistoryTypeFilter == OperatorHistoryTypeFilter.Errors) return cat.Equals("error", StringComparison.OrdinalIgnoreCase);
                    return true;
                }

                bool IsTimeMatch(OperatorEventEntry e)
                {
                    if (cutoff == null) return true;
                    try
                    {
                        var local = e.OccurredAt.ToLocalTime();
                        return local >= cutoff.Value;
                    }
                    catch
                    {
                        return true;
                    }
                }

                bool IsGroupMatch(OperatorEventEntry e)
                {
                    if (string.Equals(HistoryGroupKey, AllHistoryGroupsKey, StringComparison.Ordinal))
                    {
                        return true;
                    }

                    var g = (e.GroupKey ?? string.Empty).Trim();
                    return string.Equals(g, HistoryGroupKey, StringComparison.OrdinalIgnoreCase);
                }

                var filtered = _historyAll
                    .Where(e => e != null)
                    .Where(IsTypeMatch)
                    .Where(IsTimeMatch)
                    .Where(IsGroupMatch)
                    .OrderByDescending(e => e.OccurredAt)
                    .Take(MaxHistoryEntries)
                    .ToList();

                HistoryEvents.Clear();
                foreach (var e in filtered)
                {
                    HistoryEvents.Add(e);
                }
            }
            catch
            {
                // ignore
            }
        }

        private string BuildTrafficSourceText()
        {
            try
            {
                if (Main.IsBasicTestMode)
                {
                    return "Источник: быстрая проверка интернета (тестовый режим)";
                }

                var exePath = (Main.ExePath ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(exePath))
                {
                    return "Источник: приложение (.exe) не выбрано";
                }

                try
                {
                    return $"Источник: {Path.GetFileName(exePath)}";
                }
                catch
                {
                    return "Источник: выбранное приложение (.exe)";
                }
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
