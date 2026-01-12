using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;
using IspAudit.Core.IntelligenceV2.Diagnosis;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.IntelligenceV2.Execution;
using IspAudit.Core.IntelligenceV2.Signals;
using IspAudit.Core.IntelligenceV2.Strategies;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;

namespace IspAudit.Utils
{
    /// <summary>
    /// Live Testing Pipeline - модульная обработка обнаруженных хостов
    /// Sniffer → Tester → Classifier → Bypass → UI
    /// </summary>
    public class LiveTestingPipeline : IDisposable
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

        // DPI Intelligence v2 (Step 1): сбор событий в TTL-store
        private readonly SignalsAdapterV2 _signalsAdapterV2;

        // DPI Intelligence v2 (Step 2): постановка диагноза по агрегированным сигналам
        private readonly StandardDiagnosisEngineV2 _diagnosisEngineV2;

        // DPI Intelligence v2 (Step 3): выбор плана стратегий строго по DiagnosisResult
        private readonly StandardStrategySelectorV2 _strategySelectorV2;

        // DPI Intelligence v2 (Step 4): исполнитель MVP (только логирование рекомендаций)
        private readonly BypassExecutorMvp _executorV2;

        /// <summary>
        /// Событие: v2 план рекомендаций построен для хоста.
        /// ВАЖНО: это только доставка данных в UI/оркестратор; auto-apply запрещён.
        /// </summary>
        public event Action<string, BypassPlan>? OnV2PlanBuilt;

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

            _tester = tester ?? new StandardHostTester(progress, dnsParser?.DnsCache);

            // v2 store/adapter (без диагнозов/стратегий на этом шаге)
            _signalsAdapterV2 = new SignalsAdapterV2(new InMemorySignalSequenceStore());

            // v2 diagnosis (стратегий/параметров обхода тут нет)
            _diagnosisEngineV2 = new StandardDiagnosisEngineV2();

            // v2 selector (план стратегий по диагнозу)
            _strategySelectorV2 = new StandardStrategySelectorV2();

            // v2 executor (только форматирование/логирование)
            _executorV2 = new BypassExecutorMvp();
            
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

        /// <summary>
        /// Добавляет обнаруженный хост в очередь на тестирование
        /// </summary>
        public async ValueTask EnqueueHostAsync(HostDiscovered host)
        {
            Interlocked.Increment(ref _statHostsEnqueued);
            Interlocked.Increment(ref _pendingInSniffer);
            await _snifferQueue.Writer.WriteAsync(host).ConfigureAwait(false);
        }

        private async Task HealthLoop(CancellationToken ct)
        {
            // Держим локальные снапшоты, чтобы писать только дельты.
            long prevEnq = 0;
            long prevTesterDeq = 0;
            long prevTesterDrop = 0;
            long prevTesterOk = 0;
            long prevTesterErr = 0;
            long prevClassifierDeq = 0;
            long prevUiIssues = 0;
            long prevUiLogOnly = 0;
            long prevUiDropped = 0;

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);

                    var enq = Interlocked.Read(ref _statHostsEnqueued);
                    var testerDeq = Interlocked.Read(ref _statTesterDequeued);
                    var testerDrop = Interlocked.Read(ref _statTesterDropped);
                    var testerOk = Interlocked.Read(ref _statTesterCompleted);
                    var testerErr = Interlocked.Read(ref _statTesterErrors);
                    var classifierDeq = Interlocked.Read(ref _statClassifierDequeued);
                    var uiIssues = Interlocked.Read(ref _statUiIssuesEnqueued);
                    var uiLogOnly = Interlocked.Read(ref _statUiLogOnly);
                    var uiDropped = Interlocked.Read(ref _statUiDropped);

                    var delta = (enq - prevEnq) + (testerDeq - prevTesterDeq) + (classifierDeq - prevClassifierDeq) + (uiIssues - prevUiIssues);
                    var pending = PendingCount;

                    // Не спамим: если конвейер стоит и очереди пусты — молчим.
                    if (delta == 0 && pending == 0)
                    {
                        continue;
                    }

                    // Если очередь раздувается — это сигнал потерь/узких мест.
                    if (pending >= 200 || delta > 0)
                    {
                        _progress?.Report(
                            $"[PipelineHealth] pending={pending} | enq={enq}(+{enq - prevEnq}) " +
                            $"tester=deq:{testerDeq}(+{testerDeq - prevTesterDeq}) drop:{testerDrop}(+{testerDrop - prevTesterDrop}) ok:{testerOk}(+{testerOk - prevTesterOk}) err:{testerErr}(+{testerErr - prevTesterErr}) " +
                            $"classifier=deq:{classifierDeq}(+{classifierDeq - prevClassifierDeq}) " +
                            $"ui=issues:{uiIssues}(+{uiIssues - prevUiIssues}) logOnly:{uiLogOnly}(+{uiLogOnly - prevUiLogOnly}) drop:{uiDropped}(+{uiDropped - prevUiDropped})");
                    }

                    prevEnq = enq;
                    prevTesterDeq = testerDeq;
                    prevTesterDrop = testerDrop;
                    prevTesterOk = testerOk;
                    prevTesterErr = testerErr;
                    prevClassifierDeq = classifierDeq;
                    prevUiIssues = uiIssues;
                    prevUiLogOnly = uiLogOnly;
                    prevUiDropped = uiDropped;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
            }
            catch
            {
                // Health-лог не должен валить pipeline
            }
        }
        
        /// <summary>
        /// Завершает приём новых хостов и ожидает обработки всех в очереди
        /// </summary>
        /// <param name="timeout">Максимальное время ожидания</param>
        /// <returns>true если все хосты обработаны, false если таймаут</returns>
        public async Task<bool> DrainAndCompleteAsync(TimeSpan timeout)
        {
            // Закрываем входную очередь - больше хостов не будет.
            // ВАЖНО: завершение делаем по цепочке (tester→classifier→ui), иначе возможна гонка:
            // PendingCount не учитывает элементы, уже лежащие в Channel, и ранний TryComplete может
            // закрыть _bypassQueue до того, как ClassifierWorker успеет написать туда элемент.
            _snifferQueue.Writer.TryComplete();

            _progress?.Report($"[Pipeline] Ожидание завершения тестов... (pending: {PendingCount})");

            var deadline = DateTime.UtcNow + timeout;

            async Task<bool> WaitTaskWithDeadlineAsync(Task task)
            {
                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero) return false;
                var completedTask = await Task.WhenAny(task, Task.Delay(remaining)).ConfigureAwait(false);
                return completedTask == task;
            }

            // 1) Ждём, пока тестер дочитает sniffer-очередь и допишет всё в tester-очередь.
            if (_workers.Length >= 1)
            {
                if (!await WaitTaskWithDeadlineAsync(_workers[0]).ConfigureAwait(false))
                {
                    _progress?.Report("[Pipeline] ⚠ Таймаут на завершении TesterWorker");
                    return false;
                }
            }
            _testerQueue.Writer.TryComplete();

            // 2) Ждём, пока классификатор дочитает tester-очередь и допишет всё в bypass-очередь.
            if (_workers.Length >= 2)
            {
                if (!await WaitTaskWithDeadlineAsync(_workers[1]).ConfigureAwait(false))
                {
                    _progress?.Report("[Pipeline] ⚠ Таймаут на завершении ClassifierWorker");
                    return false;
                }
            }
            _bypassQueue.Writer.TryComplete();

            // 3) Ждём, пока UI воркер дочитает bypass-очередь и выплюнет все строки.
            if (_workers.Length >= 3)
            {
                if (!await WaitTaskWithDeadlineAsync(_workers[2]).ConfigureAwait(false))
                {
                    _progress?.Report("[Pipeline] ⚠ Таймаут на завершении UiWorker");
                    return false;
                }
            }

            _progress?.Report("[Pipeline] ✓ Все тесты завершены");
            return true;
        }

        /// <summary>
        /// Worker 1: Тестирование хостов
        /// </summary>
        private async Task TesterWorker(CancellationToken ct)
        {
            await foreach (var host in _snifferQueue.Reader.ReadAllAsync(ct))
            {
                Interlocked.Decrement(ref _pendingInSniffer);
                Interlocked.Increment(ref _statTesterDequeued);
                
                // Получаем hostname из объекта или кеша (если есть) для более умной дедупликации
                var hostname = host.SniHostname ?? host.Hostname;
                if (string.IsNullOrEmpty(hostname))
                {
                    hostname = _dnsParser?.DnsCache.TryGetValue(host.RemoteIp.ToString(), out var name) == true 
                        ? name : null;
                }
                if (string.IsNullOrEmpty(hostname))
                {
                    hostname = _dnsParser?.SniCache.TryGetValue(host.RemoteIp.ToString(), out var sniName) == true
                        ? sniName : null;
                }

                // Проверяем через единый фильтр (дедупликация + шум)
                var decision = _filter.ShouldTest(host, hostname);
                if (decision.Action == FilterAction.Drop)
                {
                    Interlocked.Increment(ref _statTesterDropped);
                    continue;
                }

                // Дедупликация на уровне "сессии тестирования":
                // если цель уже была поставлена на тест — повторные события не должны доходить до тестера.
                if (!_stateStore.TryBeginHostTest(host, hostname))
                {
                    Interlocked.Increment(ref _statTesterDropped);
                    continue;
                }
                
                Interlocked.Increment(ref _pendingInTester);
                try
                {
                    // Тестируем хост (DNS, TCP, TLS)
                    var result = await _tester.TestHostAsync(host, ct).ConfigureAwait(false);
                    await _testerQueue.Writer.WriteAsync(result, ct).ConfigureAwait(false);
                    Interlocked.Increment(ref _statTesterCompleted);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    // Не логируем при отмене
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _statTesterErrors);
                    _progress?.Report($"[TESTER] Ошибка тестирования {host.RemoteIp}: {ex.Message}");
                }
                finally
                {
                    Interlocked.Decrement(ref _pendingInTester);
                }
            }
        }

        /// <summary>
        /// Worker 2: Классификация блокировок и выбор bypass стратегии
        /// </summary>
        private async Task ClassifierWorker(CancellationToken ct)
        {
            await foreach (var tested in _testerQueue.Reader.ReadAllAsync(ct))
            {
                Interlocked.Increment(ref _pendingInClassifier);
                Interlocked.Increment(ref _statClassifierDequeued);
                try
                {
                    // Регистрируем результат в сторе, чтобы поддерживать fail counter + time window
                    _stateStore.RegisterResult(tested);

                    // v2: снимаем «сенсорные» факты без зависимости от legacy BlockageSignals.
                    // Пока legacy-сигналы остаются для UI/AutoHostlist, но v2 контур может быть переведён отдельно.
                    var inspection = (_stateStore as IInspectionSignalsProvider)?.GetInspectionSignalsSnapshot(tested)
                        ?? InspectionSignalsSnapshot.Empty;

                    // v2: записываем факты в последовательность событий + минимальный Gate-лог.
                    // Окно Gate-логов использует дефолт контракта (30 сек), но сами legacy signals сняты за 60 сек.
                    _signalsAdapterV2.Observe(tested, inspection, _progress);

                    // v2: строим агрегированный срез и ставим диагноз (без стратегий/обхода)
                    var snapshot = _signalsAdapterV2.BuildSnapshot(tested, inspection, IntelligenceV2ContractDefaults.DefaultAggregationWindow);
                    var diagnosis = _diagnosisEngineV2.Diagnose(snapshot);

                    // v2: формируем план рекомендаций строго по диагнозу.
                    // Важно: не применять автоматически (только показать в UI/логах).
                    var plan = _strategySelectorV2.Select(diagnosis, msg => _progress?.Report(msg));

                    // Доставляем план наружу (UI/оркестратор). Не применяется автоматически.
                    try
                    {
                        // Для UX важно привязывать план к «человеческому» ключу (SNI/hostname),
                        // иначе кнопка применения/сопоставление с диагнозом может расходиться.
                        var planHostKey =
                            tested.SniHostname ??
                            tested.Hostname ??
                            tested.ReverseDnsHostname ??
                            tested.Host.RemoteIp?.ToString() ??
                            tested.Host.Key;
                        OnV2PlanBuilt?.Invoke(planHostKey, plan);
                    }
                    catch
                    {
                        // Игнорируем ошибки подписчиков: пайплайн должен быть устойчив.
                    }

                    // Формируем результат для UI/фильтра: стратегия всегда NONE, а в RecommendedAction кладём факты/уверенность.
                    var blocked = BuildHostBlockedForUi(tested, inspection, diagnosis, plan);

                    // Принимаем решение о показе через единый фильтр
                    var decision = _filter.ShouldDisplay(blocked);

                    var remoteIp = tested.Host.RemoteIp;
                    var remoteIpString = remoteIp?.ToString();

                    // Пытаемся обновить hostname из кеша (мог появиться за время теста)
                    var hostname = tested.SniHostname ?? tested.Hostname;
                    if (string.IsNullOrEmpty(hostname) && _dnsParser != null)
                    {
                        if (!string.IsNullOrEmpty(remoteIpString))
                        {
                            _dnsParser.DnsCache.TryGetValue(remoteIpString, out hostname);
                        }
                    }
                    if (string.IsNullOrEmpty(hostname) && _dnsParser != null)
                    {
                        if (!string.IsNullOrEmpty(remoteIpString))
                        {
                            _dnsParser.SniCache.TryGetValue(remoteIpString, out hostname);
                        }
                    }

                    // Auto-hostlist: добавляем кандидатов только по не-шумовым хостам.
                    if (_autoHostlist != null)
                    {
                        _autoHostlist.Observe(tested, inspection, hostname);

                        // v2: добавляем auto-hostlist как источник контекста (evidence/notes).
                        // Важно: это не меняет диагноз напрямую, только делает хвост более информативным.
                        if (_autoHostlist.TryGetCandidateFor(tested, hostname, out var candidate))
                        {
                            diagnosis = EnrichDiagnosisWithAutoHostlist(diagnosis, candidate);
                        }
                    }

                    // В сообщениях пайплайна используем IP как технический якорь.
                    // UI-слой может отображать карточки по человеко‑понятному ключу (SNI/hostname),
                    // сохраняя IP как FallbackIp для корреляции.
                    var displayHost = remoteIpString ?? tested.Host.Key;

                    var sni = tested.SniHostname;
                    if (string.IsNullOrWhiteSpace(sni) && _dnsParser != null)
                    {
                        _dnsParser.SniCache.TryGetValue(displayHost, out sni);
                    }
                    var rdns = tested.ReverseDnsHostname;
                    var namesSuffix = $" SNI={(string.IsNullOrWhiteSpace(sni) ? "-" : sni)} RDNS={(string.IsNullOrWhiteSpace(rdns) ? "-" : rdns)}";
                    
                    // Перепроверяем шум с обновлённым hostname.
                    // Важно: НЕ отбрасываем реальные проблемы/блокировки только из-за шумового rDNS.
                    if (decision.Action != FilterAction.Process && !string.IsNullOrEmpty(hostname) && NoiseHostFilter.Instance.IsNoiseHost(hostname))
                    {
                        _progress?.Report($"[NOISE] Отфильтрован (late): {displayHost}");
                        continue; // Пропускаем только «непроблемные» шумовые хосты
                    }

                    if (decision.Action == FilterAction.Process)
                    {
                        // Это блокировка или проблема - отправляем в UI
                        await _bypassQueue.Writer.WriteAsync(blocked, ct).ConfigureAwait(false);
                        Interlocked.Increment(ref _statUiIssuesEnqueued);
                    }
                    else if (decision.Action == FilterAction.LogOnly)
                    {
                        // Хост работает - просто логируем (не отправляем в UI)
                        var port = tested.Host.RemotePort;
                        var latency = tested.TcpLatencyMs > 0 ? $" ({tested.TcpLatencyMs}ms)" : "";
                        _progress?.Report($"✓ {displayHost}:{port}{latency}{namesSuffix}");
                        Interlocked.Increment(ref _statUiLogOnly);
                    }
                    else if (decision.Action == FilterAction.Drop)
                    {
                        // Шумовой хост - отправляем специальное сообщение для UI (удаления карточки)
                        _progress?.Report($"[NOISE] Отфильтрован: {displayHost}");
                        Interlocked.Increment(ref _statUiDropped);
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[CLASSIFIER] Ошибка классификации: {ex.Message}");
                }
                finally
                {
                    Interlocked.Decrement(ref _pendingInClassifier);
                }
            }
        }

        private static HostBlocked BuildHostBlockedForUi(HostTested tested, InspectionSignalsSnapshot inspectionSignals, DiagnosisResult diagnosis, BypassPlan plan)
        {
            // Для успешных результатов оставляем прежний контракт (фильтр ожидает NONE + OK)
            if (tested.DnsOk && tested.TcpOk && tested.TlsOk)
            {
                // UDP blockage не считаем «ошибкой» для UI (браузер часто откатывается на TCP)
                if (inspectionSignals.UdpUnansweredHandshakes > 2)
                {
                    var udpTested = tested with { BlockageType = BlockageCode.UdpBlockage };
                    return new HostBlocked(udpTested, PipelineContract.BypassNone, BlockageCode.StatusOk);
                }

                if (diagnosis.DiagnosisId == DiagnosisId.NoBlockage)
                {
                    return new HostBlocked(tested, PipelineContract.BypassNone, BlockageCode.StatusOk);
                }

                // Если v2 увидел флаги, но тесты формально OK — не делаем уверенных выводов.
                return new HostBlocked(tested, PipelineContract.BypassNone, BuildEvidenceTail(diagnosis));
            }

            // Проблема/блокировка: показываем «хвост» из фактов для QA/лога.
            // Если селектор дал план — отображаем краткую рекомендацию.
            var bypassStrategy = plan.Strategies.Count == 0 ? PipelineContract.BypassNone : BuildBypassStrategyText(plan);
            return new HostBlocked(tested, bypassStrategy, BuildEvidenceTail(diagnosis));
        }

        private static string BuildBypassStrategyText(BypassPlan plan)
        {
            // Короткая строка для UI/логов. Не привязана к авто-применению.
            var tokens = new List<string>(capacity: plan.Strategies.Count + 2);
            tokens.AddRange(plan.Strategies.Select(s => s.Id.ToString()));
            if (plan.DropUdp443) tokens.Add("DropUdp443");
            if (plan.AllowNoSni) tokens.Add("AllowNoSni");

            var ids = tokens.Count == 0 ? PipelineContract.BypassNone : string.Join(" + ", tokens);
            return $"v2:{ids} (conf={plan.PlanConfidence})";
        }

        private static DiagnosisResult EnrichDiagnosisWithAutoHostlist(DiagnosisResult diagnosis, AutoHostCandidate candidate)
        {
            var evidence = diagnosis.Evidence.Count == 0
                ? new Dictionary<string, string>(StringComparer.Ordinal)
                : new Dictionary<string, string>(diagnosis.Evidence, StringComparer.Ordinal);

            // Ключи фиксируем с префиксом, чтобы не конфликтовать с другими evidence.
            evidence.TryAdd("autoHL.key", candidate.Host);
            evidence.TryAdd("autoHL.hits", candidate.Hits.ToString());
            evidence.TryAdd("autoHL.score", candidate.Score.ToString());
            evidence.TryAdd("autoHL.lastSeenUtc", candidate.LastSeenUtc.ToString("O"));

            // Важно: UI форматтер берёт только первую ноту из хвоста.
            // Поэтому auto-hostlist добавляем первой строкой.
            var notes = diagnosis.ExplanationNotes.Count == 0
                ? new List<string>(capacity: 1)
                : diagnosis.ExplanationNotes.ToList();

            notes.Insert(0, $"autoHL hits={candidate.Hits} score={candidate.Score}");

            return new DiagnosisResult
            {
                DiagnosisId = diagnosis.DiagnosisId,
                Confidence = diagnosis.Confidence,
                MatchedRuleName = diagnosis.MatchedRuleName,
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = diagnosis.InputSignals,
                DiagnosedAtUtc = diagnosis.DiagnosedAtUtc,
            };
        }

        private static string BuildEvidenceTail(DiagnosisResult diagnosis)
        {
            // Формат специально в круглых скобках — UiWorker вытаскивает хвост и добавляет в строку.
            var header = $"v2:{diagnosis.DiagnosisId} conf={diagnosis.Confidence}";
            if (diagnosis.ExplanationNotes.Count == 0)
            {
                return $"({header})";
            }

            return $"({header}; {string.Join("; ", diagnosis.ExplanationNotes)})";
        }

        /// <summary>
        /// Worker 3: Обновление UI (bypass применяется отдельно, не во время диагностики)
        /// </summary>
        private async Task UiWorker(CancellationToken ct)
        {
            await foreach (var blocked in _bypassQueue.Reader.ReadAllAsync(ct))
            {
                try
                {
                    var host = blocked.TestResult.Host.RemoteIp.ToString();
                    var port = blocked.TestResult.Host.RemotePort;

                    var sni = blocked.TestResult.SniHostname;
                    if (string.IsNullOrWhiteSpace(sni) && _dnsParser != null)
                    {
                        _dnsParser.SniCache.TryGetValue(host, out sni);
                    }
                    var rdns = blocked.TestResult.ReverseDnsHostname;
                    var namesSuffix = $" SNI={(string.IsNullOrWhiteSpace(sni) ? "-" : sni)} RDNS={(string.IsNullOrWhiteSpace(rdns) ? "-" : rdns)}";
                    
                    // Формируем детальное сообщение
                    var details = $"{host}:{port}{namesSuffix}";
                    if (blocked.TestResult.TcpLatencyMs > 0)
                    {
                        details += $" ({blocked.TestResult.TcpLatencyMs}ms)";
                    }
                    
                    // Статус проверок
                    var checks = $"DNS:{(blocked.TestResult.DnsOk ? "✓" : "✗")} TCP:{(blocked.TestResult.TcpOk ? "✓" : "✗")} TLS:{(blocked.TestResult.TlsOk ? "✓" : "✗")}";

                    var blockage = string.IsNullOrEmpty(blocked.TestResult.BlockageType)
                        ? PipelineContract.BypassUnknown
                        : blocked.TestResult.BlockageType;

                    // Краткий хвост из текста рекомендации (там уже зашиты счётчики фейлов и ретрансмиссий)
                    string? suffix = null;
                    if (!string.IsNullOrWhiteSpace(blocked.RecommendedAction))
                    {
                        // Ищем первую открывающую скобку – именно там StandardBlockageClassifier
                        // дописывает агрегированные сигналы: "(фейлов за Ns: N, ретрансмиссий: M, ...)".
                        var idx = blocked.RecommendedAction.IndexOf('(');
                        if (idx >= 0 && blocked.RecommendedAction.EndsWith(")", StringComparison.Ordinal))
                        {
                            var tail = blocked.RecommendedAction.Substring(idx).Trim();
                            if (!string.IsNullOrEmpty(tail))
                            {
                                if (_executorV2.TryFormatDiagnosisSuffix(tail, out var formattedTail))
                                {
                                    suffix = formattedTail;
                                }
                                else
                                {
                                    suffix = tail;
                                }
                            }
                        }
                    }

                    var uiLine = suffix is null
                        ? $"❌ {details} | {checks} | {blockage}"
                        : $"❌ {details} | {checks} | {blockage} {suffix}";

                    _progress?.Report(uiLine);
                    
                    // Показываем рекомендацию, но НЕ применяем bypass автоматически
                    // Bypass должен применяться отдельной командой после завершения диагностики
                    if (blocked.BypassStrategy != PipelineContract.BypassNone && blocked.BypassStrategy != PipelineContract.BypassUnknown)
                    {
                        if (_executorV2.TryBuildRecommendationLine(host, blocked.BypassStrategy, out var recommendationLine))
                        {
                            _progress?.Report(recommendationLine);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[UI] Ошибка обработки: {ex.Message}");
                }
            }
        }

        private bool _disposed;
        
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            
            try { _cts.Cancel(); } catch { }
            
            _snifferQueue.Writer.TryComplete();
            _testerQueue.Writer.TryComplete();
            _bypassQueue.Writer.TryComplete();
            
            // Ждём завершения воркеров максимум 3 секунды
            try
            {
                if (_healthTask != null)
                {
                    Task.WhenAll(_workers.Append(_healthTask)).Wait(3000);
                }
                else
                {
                    Task.WhenAll(_workers).Wait(3000);
                }
            }
            catch { }
            
            try { _cts.Dispose(); } catch { }
        }

        /// <summary>
        /// Принудительно запускает повторное тестирование указанного IP.
        /// Используется, когда пассивные анализаторы (UDP/RST) обнаруживают проблему постфактум.
        /// </summary>
        public void ForceRetest(IPAddress ip)
        {
            if (_disposed) return;

            // 1. Сбрасываем фильтр для этого IP, чтобы он не был отброшен как дубликат
            _filter.Invalidate(ip.ToString());

            // 2. Создаем искусственное событие обнаружения хоста
            // Предполагаем порт 443, так как это наиболее вероятно для QUIC/Web
            var key = $"{ip}:443:UDP";
            var host = new HostDiscovered(
                key, 
                ip, 
                443, 
                IspAudit.Bypass.TransportProtocol.Udp, 
                DateTime.UtcNow);
            
            // 3. Отправляем в очередь на обработку
            _snifferQueue.Writer.TryWrite(host);
        }
    }
}
