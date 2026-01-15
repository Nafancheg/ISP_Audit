using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
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

        // Доменная агрегация (общая): автоматически ищем «семейства» доменов, где появляется много вариативных подхостов.
        // Список семейств хранится во внешнем JSON (LocalAppData\ISP_Audit\domain_families.json).
        private DomainFamilyCatalogState _domainCatalog = new();
        private DomainFamilyAnalyzer _domainFamilies = new(new DomainFamilyCatalogState());

        public string? SuggestedDomainSuffix => _domainFamilies.CurrentSuggestion?.DomainSuffix;
        public int SuggestedDomainSubhostCount => _domainFamilies.CurrentSuggestion?.UniqueSubhosts ?? 0;
        public bool CanSuggestDomainAggregation => _domainFamilies.CurrentSuggestion != null;

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

        /// <summary>
        /// Коллекция результатов тестирования (для UI binding)
        /// </summary>
        public ObservableCollection<TestResult> TestResults { get; } = new();

    }
}
