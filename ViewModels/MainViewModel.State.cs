using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region UI State

        private string _screenState = "start";
        private string _exePath = "";
        private string _currentAction = "";
        private string _userMessage = "Готов к диагностике. Выберите приложение и нажмите 'Начать'.";
        private bool _enableLiveTesting = true;
        private bool _enableAutoBypass = true;
        private bool _isBasicTestMode = false;
        private bool _isDarkTheme = false;

        // P1.x: явное согласие оператора на системные изменения DNS/DoH.
        // По умолчанию: запрещено. Разрешение хранится в state/operator_consent.json.
        private bool _allowDnsDohSystemChanges;

        public bool IsDarkTheme
        {
            get => _isDarkTheme;
            set
            {
                if (_isDarkTheme != value)
                {
                    _isDarkTheme = value;
                    OnPropertyChanged(nameof(IsDarkTheme));
                    ApplyTheme(value);
                }
            }
        }

        public bool AllowDnsDohSystemChanges
        {
            get => _allowDnsDohSystemChanges;
            set
            {
                if (_allowDnsDohSystemChanges == value) return;
                _allowDnsDohSystemChanges = value;
                OnPropertyChanged(nameof(AllowDnsDohSystemChanges));
                OperatorConsentStore.SaveBestEffort(value);

                try
                {
                    _bypassState.AllowDnsDohSystemChanges = value;
                }
                catch
                {
                    // ignore
                }
            }
        }

        public string ScreenState
        {
            get => _screenState;
            set
            {
                var oldState = _screenState;
                _screenState = value;
                OnPropertyChanged(nameof(ScreenState));
                OnPropertyChanged(nameof(IsStart));
                OnPropertyChanged(nameof(IsRunning));
                OnPropertyChanged(nameof(IsDone));
                OnPropertyChanged(nameof(ShowSummary));
                OnPropertyChanged(nameof(ShowReport));
                OnPropertyChanged(nameof(RunningStatusText));
                OnPropertyChanged(nameof(StartButtonText));

                Log($"✓ ScreenState: '{oldState}' → '{value}'");

                if (value == "start")
                {
                    Results.ResetStatuses();
                }
            }
        }

        public bool IsStart => ScreenState == "start";
        public bool IsRunning => ScreenState == "running" || Orchestrator.IsDiagnosticRunning;
        public bool IsDone => ScreenState == "done";
        public bool ShowSummary => IsDone;
        public bool ShowReport => IsDone;

        private bool _isLeftPanelPinned;
        public bool IsLeftPanelPinned
        {
            get => _isLeftPanelPinned;
            set
            {
                if (_isLeftPanelPinned == value) return;
                _isLeftPanelPinned = value;
                OnPropertyChanged(nameof(IsLeftPanelPinned));

                // Если пользователь закрепил панель — сразу показываем.
                if (_isLeftPanelPinned)
                {
                    IsLeftPanelOpen = true;
                }
            }
        }

        private bool _isLeftPanelOpen = true;
        public bool IsLeftPanelOpen
        {
            get => _isLeftPanelOpen;
            set
            {
                if (_isLeftPanelOpen == value) return;
                _isLeftPanelOpen = value;
                OnPropertyChanged(nameof(IsLeftPanelOpen));
            }
        }

        public string ExePath
        {
            get => _exePath;
            set { _exePath = value; OnPropertyChanged(nameof(ExePath)); }
        }

        private bool _isUnlimitedTime;
        public bool IsUnlimitedTime
        {
            get => _isUnlimitedTime;
            set { _isUnlimitedTime = value; OnPropertyChanged(nameof(IsUnlimitedTime)); }
        }

        private bool _isNetworkChangePromptVisible;
        private string _networkChangePromptText = string.Empty;
        private bool _isNetworkRevalidating;
        private System.Threading.CancellationTokenSource? _networkRevalidateCts;

        private bool _isCrashReportsPromptVisible;
        private string _crashReportsPromptText = string.Empty;

        public bool IsNetworkChangePromptVisible
        {
            get => _isNetworkChangePromptVisible;
            private set
            {
                if (_isNetworkChangePromptVisible == value) return;
                _isNetworkChangePromptVisible = value;
                OnPropertyChanged(nameof(IsNetworkChangePromptVisible));
            }
        }

        public string NetworkChangePromptText
        {
            get => _networkChangePromptText;
            private set
            {
                if (string.Equals(_networkChangePromptText, value, StringComparison.Ordinal)) return;
                _networkChangePromptText = value;
                OnPropertyChanged(nameof(NetworkChangePromptText));
            }
        }

        public bool IsCrashReportsPromptVisible
        {
            get => _isCrashReportsPromptVisible;
            private set
            {
                if (_isCrashReportsPromptVisible == value) return;
                _isCrashReportsPromptVisible = value;
                OnPropertyChanged(nameof(IsCrashReportsPromptVisible));
            }
        }

        public string CrashReportsPromptText
        {
            get => _crashReportsPromptText;
            private set
            {
                if (string.Equals(_crashReportsPromptText, value, StringComparison.Ordinal)) return;
                _crashReportsPromptText = value;
                OnPropertyChanged(nameof(CrashReportsPromptText));
            }
        }

        private bool _isSteamMode;
        public bool IsSteamMode
        {
            get => _isSteamMode;
            set { _isSteamMode = value; OnPropertyChanged(nameof(IsSteamMode)); }
        }

        public string CurrentAction
        {
            get => _currentAction;
            set
            {
                if (string.Equals(_currentAction, value, StringComparison.Ordinal)) return;
                _currentAction = value;
                OnPropertyChanged(nameof(CurrentAction));
            }
        }

        public string UserMessage
        {
            get => _userMessage;
            set
            {
                if (string.Equals(_userMessage, value, StringComparison.Ordinal)) return;
                _userMessage = value;
                OnPropertyChanged(nameof(UserMessage));
            }
        }

        public bool EnableLiveTesting
        {
            get => _enableLiveTesting;
            set { _enableLiveTesting = value; OnPropertyChanged(nameof(EnableLiveTesting)); }
        }

        public bool EnableAutoBypass
        {
            get => _enableAutoBypass;
            set { _enableAutoBypass = value; OnPropertyChanged(nameof(EnableAutoBypass)); }
        }

        public bool IsBasicTestMode
        {
            get => _isBasicTestMode;
            set { _isBasicTestMode = value; OnPropertyChanged(nameof(IsBasicTestMode)); }
        }

        public string RunningStatusText => $"Диагностика: {Results.CurrentTest} из {Results.TotalTargets}";
        public string StartButtonText => IsRunning ? "Остановить диагностику" : "Начать диагностику";

        public ICommand ToggleLeftPanelCommand { get; }

        // Прокси-свойства для счётчиков (для совместимости с существующим XAML)
        public ObservableCollection<TestResult> TestResults => Results.TestResults;
        public int TotalTargets => Results.TotalTargets;
        public int ProgressBarMax => Results.ProgressBarMax;
        public int CurrentTest => Results.CurrentTest;
        public int CompletedTests => Results.CompletedTests;
        public int PassCount => Results.PassCount;
        public int FailCount => Results.FailCount;
        public int WarnCount => Results.WarnCount;

        // Прокси-свойства для Orchestrator
        public int FlowEventsCount => Orchestrator.FlowEventsCount;
        public int ConnectionsDiscovered => Orchestrator.ConnectionsDiscovered;
        public string FlowModeText => Orchestrator.FlowModeText;
        public string DiagnosticStatus => Orchestrator.DiagnosticStatus;
        public bool IsDiagnosticRunning => Orchestrator.IsDiagnosticRunning;
        public string AutoBypassStatus => Orchestrator.AutoBypassStatus;
        public string AutoBypassVerdict => Orchestrator.AutoBypassVerdict;
        public string AutoBypassMetrics => Orchestrator.AutoBypassMetrics;
        public System.Windows.Media.Brush AutoBypassStatusBrush => Orchestrator.AutoBypassStatusBrush;
        public bool HasRecommendations => Orchestrator.HasRecommendations;
        public bool HasAnyRecommendations => Orchestrator.HasAnyRecommendations;
        public string RecommendedStrategiesText => Orchestrator.RecommendedStrategiesText;
        public string ManualRecommendationsText => Orchestrator.ManualRecommendationsText;
        public string RecommendationHintText => Orchestrator.RecommendationHintText;

        public bool IsPostApplyRetestRunning => Orchestrator.IsPostApplyRetestRunning;
        public string PostApplyRetestStatus => Orchestrator.PostApplyRetestStatus;
        public string EndpointBlockStatus => Orchestrator.EndpointBlockStatus;

        public bool IsApplyRunning => Orchestrator.IsApplyRunning;
        public string ApplyStatusText => Orchestrator.ApplyStatusText;

        public bool HasDomainSuggestion
        {
            get
            {
                try
                {
                    if (SelectedTestResult?.Target == null) return false;

                    if (!Results.CanSuggestDomainAggregation) return false;

                    var suffix = Results.SuggestedDomainSuffix;
                    if (string.IsNullOrWhiteSpace(suffix)) return false;

                    // Показываем кнопку только если выбранная цель действительно относится к этому домену.
                    var hostKey = GetPreferredHostKey(SelectedTestResult);
                    if (string.IsNullOrWhiteSpace(hostKey)) return false;

                    return hostKey.Equals(suffix, StringComparison.OrdinalIgnoreCase) ||
                           hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase);
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool HasDomainGroupSuggestion
        {
            get
            {
                try
                {
                    if (SelectedTestResult?.Target == null) return false;
                    if (!Results.CanSuggestDomainGroup) return false;

                    var hostKey = GetPreferredHostKey(SelectedTestResult);
                    if (string.IsNullOrWhiteSpace(hostKey)) return false;

                    return Results.IsHostInSuggestedDomainGroup(hostKey);
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool HasLearnedDomainGroupSuggestion
        {
            get
            {
                try
                {
                    if (!HasDomainGroupSuggestion) return false;
                    return Results.IsSuggestedDomainGroupLearned;
                }
                catch
                {
                    return false;
                }
            }
        }

        public string ApplyDomainGroupButtonText
        {
            get
            {
                if (IsApplyingRecommendations) return "Применяю…";
                var name = Results.SuggestedDomainGroupDisplayName;
                if (string.IsNullOrWhiteSpace(name)) name = Results.SuggestedDomainGroupKey;
                var display = string.IsNullOrWhiteSpace(name) ? "…" : name;
                return $"Подключить (группа: {display})";
            }
        }

        public string DomainGroupSuggestionHintText
        {
            get
            {
                var key = Results.SuggestedDomainGroupKey;
                if (string.IsNullOrWhiteSpace(key)) return "";

                var name = Results.SuggestedDomainGroupDisplayName;
                if (string.IsNullOrWhiteSpace(name)) name = key;

                var domains = Results.SuggestedDomainGroupDomains;
                var list = domains == null || domains.Count == 0 ? "(пусто)" : string.Join(", ", domains);

                return $"Кросс-доменная группа: {name} ({key}).\n" +
                       $"Домены: {list}.\n" +
                       "Кнопка применяет план рекомендаций к группе (GroupKey=ключ группы, OutcomeTargetHost=anchor-домен).\n" +
                       $"Справочник/кэш: {IspAudit.Utils.DomainGroupCatalog.CatalogFilePath}";
            }
        }

        public string PromoteDomainGroupSuggestionButtonText
        {
            get
            {
                if (IsApplyingRecommendations) return "Применяю…";
                return "Закрепить группу (learned → pinned)";
            }
        }

        public string IgnoreDomainGroupSuggestionButtonText
        {
            get
            {
                return "Скрыть подсказку (learned)";
            }
        }

        public string PromoteDomainGroupSuggestionHintText
        {
            get
            {
                var key = Results.SuggestedDomainGroupKey;
                if (string.IsNullOrWhiteSpace(key)) return "";

                return "Переносит текущую learned-группу в pinned (ручные группы).\n" +
                       "После этого подсказка станет стабильной и не зависит от обучения.\n" +
                       $"Файл: {IspAudit.Utils.DomainGroupCatalog.CatalogFilePath}";
            }
        }

        public string IgnoreDomainGroupSuggestionHintText
        {
            get
            {
                var key = Results.SuggestedDomainGroupKey;
                if (string.IsNullOrWhiteSpace(key)) return "";

                return "Скрывает текущую learned-группу из подсказок (ignore).\n" +
                       "Это влияет только на UX, фильтрацию пакетов не меняет.\n" +
                       $"Файл: {IspAudit.Utils.DomainGroupCatalog.CatalogFilePath}";
            }
        }

        public string ApplyDomainButtonText => IsApplyingRecommendations
            ? "Применяю…"
            : $"Подключить (домен: {Results.SuggestedDomainSuffix ?? "…"})";

        public bool IsSuggestedDomainPinned
        {
            get
            {
                try
                {
                    var suffix = Results.SuggestedDomainSuffix;
                    if (string.IsNullOrWhiteSpace(suffix)) return false;
                    return Results.IsDomainPinned(suffix);
                }
                catch
                {
                    return false;
                }
            }
        }

        public string ToggleDomainPinButtonText
        {
            get
            {
                var suffix = Results.SuggestedDomainSuffix;
                if (string.IsNullOrWhiteSpace(suffix)) return "Закрепить домен";
                return IsSuggestedDomainPinned
                    ? $"Открепить домен: {suffix}"
                    : $"Закрепить домен: {suffix}";
            }
        }

        public string DomainSuggestionHintText
        {
            get
            {
                var suffix = Results.SuggestedDomainSuffix;
                if (string.IsNullOrWhiteSpace(suffix)) return "";

                var n = Results.SuggestedDomainSubhostCount;
                return $"Авто-обнаружение CDN/шардов: замечено {n} подхостов для *.{suffix}.\n" +
                      "Кнопка применяет план рекомендаций к домену (OutcomeTargetHost=домен).\n" +
                      (IsSuggestedDomainPinned
                          ? "Домен закреплён: подсказка может включаться быстрее.\n"
                          : "Можно закрепить домен, чтобы подсказка включалась быстрее.\n") +
                       $"Справочник/кэш: {IspAudit.Utils.DomainFamilyCatalog.CatalogFilePath}";
            }
        }

        /// <summary>
        /// Текущая «активная группа» применения обхода (для подсветки строк в таблице).
        /// Вычисляется из OutcomeTargetHost и SuggestedDomainSuffix.
        /// </summary>
        public string ActiveApplyGroupKey
        {
            get
            {
                try
                {
                    var host = Bypass.GetOutcomeTargetHost();
                    return GetStableApplyGroupKeyForHostKey(host);
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        private TestResult? _selectedTestResult;
        public TestResult? SelectedTestResult
        {
            get => _selectedTestResult;
            set
            {
                if (ReferenceEquals(_selectedTestResult, value)) return;
                _selectedTestResult = value;
                OnPropertyChanged(nameof(SelectedTestResult));
                OnPropertyChanged(nameof(HasDomainSuggestion));
                OnPropertyChanged(nameof(HasVerifiedWinForSelectedTarget));

                // Важно для QUIC→TCP (селективный режим): если цель не задана, UDP/443 по IPv4 не глушится.
                // Самый понятный UX: цель берём из выбранной строки результатов (если это не шумовой хост).
                TryUpdateOutcomeTargetFromSelection(_selectedTestResult);

                // Step 9: панель деталей по выбранной карточке
                UpdateSelectedResultApplyTransactionDetails();

                // UX: в режиме "Фокус" при смене выбора хотим быстро показать строки активной группы
                // и актуальную сводку "что сейчас применено".
                RefreshResultsViewNow();
            }
        }

        public bool HasVerifiedWinForSelectedTarget
        {
            get
            {
                try
                {
                    if (!ShowBypassPanel) return false;
                    var hk = GetPreferredHostKey(SelectedTestResult);
                    return TryGetVerifiedWinForHostKey(hk, out _);
                }
                catch
                {
                    return false;
                }
            }
        }

        private string _selectedResultApplyTransactionTitle = "Детали применения обхода";
        public string SelectedResultApplyTransactionTitle
        {
            get => _selectedResultApplyTransactionTitle;
            private set
            {
                if (string.Equals(_selectedResultApplyTransactionTitle, value, StringComparison.Ordinal)) return;
                _selectedResultApplyTransactionTitle = value;
                OnPropertyChanged(nameof(SelectedResultApplyTransactionTitle));
            }
        }

        private string _selectedResultApplyTransactionJson = string.Empty;
        public string SelectedResultApplyTransactionJson
        {
            get => _selectedResultApplyTransactionJson;
            private set
            {
                if (string.Equals(_selectedResultApplyTransactionJson, value, StringComparison.Ordinal)) return;
                _selectedResultApplyTransactionJson = value ?? string.Empty;
                OnPropertyChanged(nameof(SelectedResultApplyTransactionJson));
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            }
        }

        private void TryUpdateOutcomeTargetFromSelection(TestResult? selected)
        {
            try
            {
                if (selected == null) return;

                var hostKey = GetPreferredHostKey(selected);
                if (string.IsNullOrWhiteSpace(hostKey)) return;

                if (NoiseHostFilter.Instance.IsNoiseHost(hostKey)) return;

                Bypass.SetOutcomeTargetHost(hostKey);
            }
            catch
            {
                // Наблюдаемость/UX не должны ломать UI
            }
        }

        private bool _isApplyingRecommendations;
        public bool IsApplyingRecommendations
        {
            get => _isApplyingRecommendations;
            private set
            {
                if (_isApplyingRecommendations == value) return;
                _isApplyingRecommendations = value;
                OnPropertyChanged(nameof(IsApplyingRecommendations));
                OnPropertyChanged(nameof(ApplyRecommendationsButtonText));
                OnPropertyChanged(nameof(ApplyDomainButtonText));
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            }
        }

        public string ApplyRecommendationsButtonText => IsApplyingRecommendations
            ? "Применяю…"
            : BuildApplyRecommendationsButtonText();

        public string ApplyRecommendationsHintText
        {
            get
            {
                try
                {
                    if (IsApplyingRecommendations) return "Идёт применение рекомендаций…";

                    var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                    if (!string.IsNullOrWhiteSpace(preferredHostKey))
                    {
                        var groupKey = ComputeApplyGroupKey(preferredHostKey, Results.SuggestedDomainSuffix);
                        return $"Применяет план рекомендаций для выбранной строки.\nЦель: {preferredHostKey}\nГруппа: {groupKey}";
                    }

                    // Если ничего не выбрано — orchestrator выберет сохранённую/последнюю цель.
                    var activeGroup = ActiveApplyGroupKey;
                    if (!string.IsNullOrWhiteSpace(activeGroup))
                    {
                        return $"Применяет план рекомендаций для последней известной цели (без выбора строки).\nТекущая активная группа: {activeGroup}";
                    }

                    return "Применяет план рекомендаций.\nСовет: выберите строку результата, чтобы явно задать цель.";
                }
                catch
                {
                    return "Применяет план рекомендаций.";
                }
            }
        }

        private string BuildApplyRecommendationsButtonText()
        {
            try
            {
                var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                if (!string.IsNullOrWhiteSpace(preferredHostKey))
                {
                    var groupKey = ComputeApplyGroupKey(preferredHostKey, Results.SuggestedDomainSuffix);
                    if (!string.IsNullOrWhiteSpace(groupKey))
                    {
                        return $"Применить рекомендации (группа: {groupKey})";
                    }

                    return $"Применить рекомендации (цель: {preferredHostKey})";
                }

                var activeGroup = ActiveApplyGroupKey;
                if (!string.IsNullOrWhiteSpace(activeGroup))
                {
                    return $"Применить рекомендации (активная группа: {activeGroup})";
                }

                return "Применить рекомендации (цель: авто)";
            }
            catch
            {
                return "Применить рекомендации";
            }
        }

        // Прокси-свойства для BypassController
        public bool ShowBypassPanel => Bypass.ShowBypassPanel;
        public bool IsBypassActive => Bypass.IsBypassActive;
        public bool IsFragmentEnabled { get => Bypass.IsFragmentEnabled; set => Bypass.IsFragmentEnabled = value; }
        public bool IsDisorderEnabled { get => Bypass.IsDisorderEnabled; set => Bypass.IsDisorderEnabled = value; }
        public bool IsFakeEnabled { get => Bypass.IsFakeEnabled; set => Bypass.IsFakeEnabled = value; }
        public bool IsDropRstEnabled { get => Bypass.IsDropRstEnabled; set => Bypass.IsDropRstEnabled = value; }
        public bool IsQuicFallbackEnabled { get => Bypass.IsQuicFallbackEnabled; set => Bypass.IsQuicFallbackEnabled = value; }
        public bool IsQuicFallbackGlobal { get => Bypass.IsQuicFallbackGlobal; set => Bypass.IsQuicFallbackGlobal = value; }
        public bool IsAllowNoSniEnabled { get => Bypass.IsAllowNoSniEnabled; set => Bypass.IsAllowNoSniEnabled = value; }
        public bool IsDoHEnabled { get => Bypass.IsDoHEnabled; set => Bypass.IsDoHEnabled = value; }
        public bool IsVpnDetected => Bypass.IsVpnDetected;
        public string VpnWarningText => Bypass.VpnWarningText;
        public string CompatibilityWarning => Bypass.CompatibilityWarning;
        public bool HasCompatibilityWarning => Bypass.HasCompatibilityWarning;
        public string BypassWarningText => Bypass.BypassWarningText;
        public string CurrentBypassStrategy => Bypass.CurrentBypassStrategy;
        public bool IsTlsFragmentActive => Bypass.IsTlsFragmentActive;
        public bool IsTlsDisorderActive => Bypass.IsTlsDisorderActive;
        public bool IsTlsFakeActive => Bypass.IsTlsFakeActive;
        public bool IsDropRstActive => Bypass.IsDropRstActive;
        public bool IsDoHActive => Bypass.IsDoHActive;
        public System.Collections.Generic.List<IspAudit.Bypass.TlsFragmentPreset> FragmentPresets => Bypass.FragmentPresets;
        public IspAudit.Bypass.TlsFragmentPreset? SelectedFragmentPreset { get => Bypass.SelectedFragmentPreset; set => Bypass.SelectedFragmentPreset = value; }
        public string SelectedFragmentPresetLabel => Bypass.SelectedFragmentPresetLabel;
        public string BypassMetricsText => Bypass.BypassMetricsText;
        public string BypassSemanticGroupsText => Bypass.BypassSemanticGroupsText;
        public string BypassSemanticGroupsSummaryText => Bypass.BypassSemanticGroupsSummaryText;
        public System.Windows.Media.Brush BypassVerdictBrush => Bypass.BypassVerdictBrush;
        public string BypassVerdictText => Bypass.BypassVerdictText;

        // Traffic Engine Performance
        private double _trafficEngineLatency;
        public double TrafficEngineLatency
        {
            get => _trafficEngineLatency;
            set
            {
                _trafficEngineLatency = value;
                OnPropertyChanged(nameof(TrafficEngineLatency));
                OnPropertyChanged(nameof(TrafficEngineLatencyText));
                OnPropertyChanged(nameof(TrafficEngineLatencyColor));
            }
        }

        public string TrafficEngineLatencyText => $"{TrafficEngineLatency:F3} ms";

        public System.Windows.Media.Brush TrafficEngineLatencyColor
        {
            get
            {
                if (TrafficEngineLatency < 0.5) return System.Windows.Media.Brushes.Green;
                if (TrafficEngineLatency < 2.0) return System.Windows.Media.Brushes.Orange;
                return System.Windows.Media.Brushes.Red;
            }
        }

        #endregion
    }
}
