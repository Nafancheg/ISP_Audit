using System;
using System.Collections.Concurrent;
using System.Diagnostics;
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

        private readonly Channel<QueuedHost> _snifferHighQueue;
        private readonly Channel<QueuedHost> _snifferLowQueue;
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
        private int _pendingInSnifferHigh;
        private int _pendingInSnifferLow;
        private int _pendingInTester;
        private int _pendingInClassifier;

        /// <summary>
        /// Количество хостов, ожидающих обработки во всех очередях
        /// </summary>
        public int PendingCount => _pendingInSnifferHigh + _pendingInSnifferLow + _pendingInTester + _pendingInClassifier;

        // P1.5: метрики и деградация очередей
        private volatile bool _isDegradeMode;
        private int _degradePendingTicks;
        private long _statQueueAgeSamples;
        private long _statQueueAgeP95ms;

        private readonly QueueAgeWindow _queueAgeWindow = new(size: 256);

        // P1.5: «повторные фейлы» — если по IP уже видели проблему, новые события поднимаем в high.
        private readonly ConcurrentDictionary<string, byte> _recentProblemIps = new(StringComparer.Ordinal);

        // P1.5: «быстрый» тестер для деградации очереди low (timeout/2).
        private readonly IHostTester? _degradedTester;

        private readonly record struct QueuedHost(HostDiscovered Host, long EnqueuedTimestamp, bool IsHighPriority);

        private sealed class QueueAgeWindow
        {
            private readonly int[] _buffer;
            private int _idx;
            private int _count;
            private readonly object _lock = new();

            public QueueAgeWindow(int size)
            {
                if (size < 16) size = 16;
                _buffer = new int[size];
            }

            public void Add(int ageMs)
            {
                if (ageMs < 0) ageMs = 0;
                lock (_lock)
                {
                    _buffer[_idx] = ageMs;
                    _idx = (_idx + 1) % _buffer.Length;
                    if (_count < _buffer.Length) _count++;
                }
            }

            public bool TryGetP95(out int p95Ms)
            {
                lock (_lock)
                {
                    if (_count <= 0)
                    {
                        p95Ms = 0;
                        return false;
                    }

                    var arr = new int[_count];
                    for (int i = 0; i < _count; i++)
                    {
                        arr[i] = _buffer[i];
                    }

                    Array.Sort(arr);
                    var idx = (int)Math.Ceiling(arr.Length * 0.95) - 1;
                    if (idx < 0) idx = 0;
                    if (idx >= arr.Length) idx = arr.Length - 1;
                    p95Ms = arr[idx];
                    return true;
                }
            }
        }

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
            ITrafficFilter filter,
            IProgress<string>? progress = null,
            TrafficEngine? trafficEngine = null,
            DnsParserService? dnsParser = null,
            IBlockageStateStore stateStore = null!,
            AutoHostlistService? autoHostlist = null,
            IHostTester tester = null!,
            IHostTester? degradedTester = null)
        {
            _config = config;
            _progress = progress;
            _dnsParser = dnsParser;

            _filter = filter ?? throw new ArgumentNullException(nameof(filter));

            // Используем переданный движок
            if (trafficEngine != null)
            {
                _trafficEngine = trafficEngine;
            }

            // Инициализация модулей
            _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));

            _autoHostlist = autoHostlist;

            _tester = tester ?? throw new ArgumentNullException(nameof(tester));
            _degradedTester = degradedTester;

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
            // P1.5: low-очередь компактная (50) с DropOldest; high — шире.
            var highOptions = new BoundedChannelOptions(200) { FullMode = BoundedChannelFullMode.DropOldest };
            var lowOptions = new BoundedChannelOptions(50) { FullMode = BoundedChannelFullMode.DropOldest };
            var stageOptions = new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.DropOldest };

            _snifferHighQueue = Channel.CreateBounded<QueuedHost>(highOptions);
            _snifferLowQueue = Channel.CreateBounded<QueuedHost>(lowOptions);
            _testerQueue = Channel.CreateBounded<HostTested>(stageOptions);
            _bypassQueue = Channel.CreateBounded<HostBlocked>(stageOptions);

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
