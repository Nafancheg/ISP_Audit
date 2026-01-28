using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Intelligence.Diagnosis;
using IspAudit.Core.Intelligence.Execution;
using IspAudit.Core.Intelligence.Signals;
using IspAudit.Core.Intelligence.Strategies;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;

namespace IspAudit.Utils
{
    /// <summary>
    /// Live Testing Pipeline - модульная обработка обнаруженных хостов
    /// Sniffer → Tester → Classifier → Bypass → UI
    /// </summary>
    public partial class LiveTestingPipeline : IDisposable
    {
        private readonly PipelineConfig _config;
        private readonly IProgress<string>? _progress;
        private readonly TrafficEngine? _trafficEngine;
        private readonly DnsParserService? _dnsParser;

        private readonly Channel<HostDiscovered> _snifferQueue;
        private readonly Channel<HostTested> _testerQueue;
        private readonly Channel<HostBlocked> _bypassQueue;

        private readonly CancellationTokenSource _cts = new();
        private readonly Task[] _workers;

        // Health/observability: счётчики для понимания, где теряются данные.
        private long _statHostsEnqueued;
        private long _statSnifferDropped;
        private long _statTesterDequeued;
        private long _statTesterDropped;
        private long _statTesterCompleted;
        private long _statTesterErrors;
        private long _statClassifierDequeued;
        private long _statUiIssuesEnqueued;
        private long _statUiLogOnly;
        private long _statUiDropped;
        private Task? _healthTask;

        // Единый фильтр трафика (дедупликация + шум + UI правила)
        private readonly ITrafficFilter _filter;

        // Счётчики для отслеживания очереди
        private int _pendingInSniffer;
        private int _pendingInTester;
        private int _pendingInClassifier;

        /// <summary>
        /// Количество хостов, ожидающих обработки во всех очередях
        /// </summary>
        public int PendingCount => _pendingInSniffer + _pendingInTester + _pendingInClassifier;

        // Modules
        private readonly IHostTester _tester;
        private readonly IBlockageStateStore _stateStore;

        // DPI Intelligence (Step 1): сбор событий в TTL-store
        private readonly SignalsAdapter _signalsAdapter;

        // DPI Intelligence (Step 2): постановка диагноза по агрегированным сигналам
        private readonly StandardDiagnosisEngine _diagnosisEngine;

        // DPI Intelligence (Step 3): выбор плана стратегий строго по DiagnosisResult
        private readonly StandardStrategySelector _strategySelector;

        // DPI Intelligence (Step 4): исполнитель MVP (только логирование рекомендаций)
        private readonly BypassExecutorMvp _executor;

        /// <summary>
        /// Событие: план рекомендаций построен для хоста.
        /// ВАЖНО: это только доставка данных в UI/оркестратор; auto-apply запрещён.
        /// </summary>
        public event Action<string, BypassPlan>? OnPlanBuilt;

        // Автоматический сбор hostlist (опционально)
        private readonly AutoHostlistService? _autoHostlist;

        public LiveTestingPipeline(
            PipelineConfig config,
            IProgress<string>? progress = null,
            TrafficEngine? trafficEngine = null,
            DnsParserService? dnsParser = null,
            ITrafficFilter? filter = null,
            IBlockageStateStore? stateStore = null,
            AutoHostlistService? autoHostlist = null,
            IHostTester? tester = null)
        {
            _config = config;
            _progress = progress;
            _dnsParser = dnsParser;

            // Используем переданный фильтр или создаем новый
            _filter = filter ?? new UnifiedTrafficFilter();

            // Используем переданный движок
            if (trafficEngine != null)
            {
                _trafficEngine = trafficEngine;
            }

            // Инициализация модулей
            _stateStore = stateStore ?? new InMemoryBlockageStateStore();

            _autoHostlist = autoHostlist;

            _tester = tester ?? new StandardHostTester(progress, dnsParser?.DnsCache, config.TestTimeout);

            // INTEL: store/adapter (без диагнозов/стратегий на этом шаге)
            _signalsAdapter = new SignalsAdapter(new InMemorySignalSequenceStore());

            // INTEL: diagnosis (стратегий/параметров обхода тут нет)
            _diagnosisEngine = new StandardDiagnosisEngine();

            // INTEL: selector (план стратегий по диагнозу)
            var feedbackStore = FeedbackStoreProvider.TryGetStore(msg => _progress?.Report(msg));
            _strategySelector = new StandardStrategySelector(feedbackStore);

            // INTEL: executor (только форматирование/логирование)
            _executor = new BypassExecutorMvp();

            // Создаем bounded каналы для передачи данных между воркерами (защита от OOM)
            var channelOptions = new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.DropOldest };
            _snifferQueue = Channel.CreateBounded<HostDiscovered>(channelOptions);
            _testerQueue = Channel.CreateBounded<HostTested>(channelOptions);
            _bypassQueue = Channel.CreateBounded<HostBlocked>(channelOptions);

            // Запускаем воркеры
            _workers = new[]
            {
                Task.Run(() => TesterWorker(_cts.Token)),
                Task.Run(() => ClassifierWorker(_cts.Token)),
                Task.Run(() => UiWorker(_cts.Token))
            };

            // Периодический health-лог (не спамит: пишет только если есть активность или очередь растёт).
            _healthTask = Task.Run(() => HealthLoop(_cts.Token));
        }
    }
}
