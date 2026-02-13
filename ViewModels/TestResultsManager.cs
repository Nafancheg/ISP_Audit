using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using System.Threading;
using IspAudit.Core.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Models;
using IspAudit;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Менеджер результатов тестирования.
    /// Управляет ObservableCollection<TestResult>, парсит сообщения pipeline,
    /// применяет эвристики для классификации блокировок.
    /// </summary>
    public partial class TestResultsManager : INotifyPropertyChanged
    {
        private readonly SynchronizationContext? _uiContext;
        private readonly NoiseHostFilter _noiseHostFilter;

        private readonly ConcurrentDictionary<string, TestResult> _testResultMap = new();
        private readonly ConcurrentDictionary<string, Target> _resolvedIpMap = new();
        private readonly ConcurrentDictionary<string, bool> _pendingResolutions = new();
        private string? _lastUpdatedHost;
        private string? _lastUserFacingHost;

        private readonly Queue<(DateTime Time, bool IsSuccess)> _healthHistory = new();

        // UI должен быть детерминированным: одинаковые условия → одинаковая карточка.
        // Для пользователя ключом важнее сервис/hostname (SNI), а не IP.
        // Также важен режим «Нестабильно», когда в окне есть и успехи, и ошибки.

        private readonly ConcurrentDictionary<string, string> _ipToUiKey = new();

        // P1.9: агрегация CDN/подхостов в одну строку по groupKey.
        // Храним множество «членов» (домены/подхосты) для отображения счётчика ×N.
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _aggregatedMembersByUiKey = new(StringComparer.OrdinalIgnoreCase);

        // Кэш: groupKey -> якорный домен (человекочитаемое имя строки)
        private readonly ConcurrentDictionary<string, string> _groupKeyToAnchorDomain = new(StringComparer.OrdinalIgnoreCase);

        // Источник истины для pinning hostKey -> groupKey (state/group_participation.json)
        public GroupBypassAttachmentStore? GroupBypassAttachmentStore { get; set; }

        // Доменная агрегация (общая): автоматически ищем «семейства» доменов, где появляется много вариативных подхостов.
        // Список семейств хранится во внешнем JSON рядом с приложением (state/domain_families.json).
        private DomainFamilyCatalogState _domainCatalog = new();
        private DomainFamilyAnalyzer _domainFamilies = new(new DomainFamilyCatalogState());

        // P1.2: кросс-доменные группы (YouTube: youtube.com + googlevideo.com + ...)
        // Каталог групп: state/domain_groups.json
        private DomainGroupCatalogState _domainGroupCatalog = new();
        private DomainGroupAnalyzer _domainGroups = new(new DomainGroupCatalogState());
        private DomainGroupLearner _domainGroupLearner = null!;

        public string? SuggestedDomainSuffix => _domainFamilies.CurrentSuggestion?.DomainSuffix;
        public int SuggestedDomainSubhostCount => _domainFamilies.CurrentSuggestion?.UniqueSubhosts ?? 0;
        public bool CanSuggestDomainAggregation => _domainFamilies.CurrentSuggestion != null;

        public string? SuggestedDomainGroupKey => _domainGroups.CurrentSuggestion?.GroupKey;
        public string? SuggestedDomainGroupDisplayName => _domainGroups.CurrentSuggestion?.DisplayName;
        public string? SuggestedDomainGroupAnchorDomain => _domainGroups.CurrentSuggestion?.AnchorDomain;
        public System.Collections.Generic.IReadOnlyList<string> SuggestedDomainGroupDomains => _domainGroups.CurrentSuggestion?.Domains ?? Array.Empty<string>();
        public bool CanSuggestDomainGroup => _domainGroups.CurrentSuggestion != null;

        public bool IsSuggestedDomainGroupLearned
        {
            get
            {
                try
                {
                    var key = (SuggestedDomainGroupKey ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(key)) return false;
                    return _domainGroupCatalog?.LearnedGroups?.ContainsKey(key) == true;
                }
                catch
                {
                    return false;
                }
            }
        }

        private readonly record struct OutcomeHistory(DateTime LastPassUtc, DateTime LastProblemUtc);
        private readonly ConcurrentDictionary<string, OutcomeHistory> _outcomeHistoryByKey = new();

        private static readonly TimeSpan UnstableWindow = TimeSpan.FromSeconds(60);

        private double _healthScore = 100;
        public double HealthScore
        {
            get => _healthScore;
            set
            {
                if (Math.Abs(_healthScore - value) > 0.1)
                {
                    _healthScore = value;
                    OnPropertyChanged(nameof(HealthScore));
                    OnPropertyChanged(nameof(HealthColor));
                }
            }
        }

        public string HealthColor => HealthScore > 80 ? "#10B981" : (HealthScore > 50 ? "#EAB308" : "#EF4444");

        public event PropertyChangedEventHandler? PropertyChanged;
        public event Action<string>? OnLog;

        public TestResultsManager(NoiseHostFilter noiseHostFilter)
        {
            _noiseHostFilter = noiseHostFilter ?? throw new ArgumentNullException(nameof(noiseHostFilter));

            // P1.2: learner требует NoiseHostFilter для отсечения шумовых доменов.
            _domainGroupLearner = new DomainGroupLearner(_domainGroupCatalog, _noiseHostFilter);

            // В идеале этот объект создаётся в UI потоке (MainViewModel), тогда здесь будет WPF SynchronizationContext.
            // В smoke/тестах UI может отсутствовать — тогда _uiContext будет null и мы выполняем действия напрямую.
            _uiContext = SynchronizationContext.Current;
        }

        private void UiPost(Action action)
        {
            try
            {
                if (action == null) return;

                if (_uiContext == null || ReferenceEquals(SynchronizationContext.Current, _uiContext))
                {
                    action();
                    return;
                }

                _uiContext.Post(_ =>
                {
                    try
                    {
                        action();
                    }
                    catch
                    {
                        // Best-effort: UI обновления не должны валить рантайм.
                    }
                }, null);
            }
            catch
            {
                // ignore
            }
        }

        /// <summary>
        /// Коллекция результатов тестирования (для UI binding)
        /// </summary>
        public ObservableCollection<TestResult> TestResults { get; } = new();

    }
}
