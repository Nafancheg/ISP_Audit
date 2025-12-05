using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;

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
        private readonly IspAudit.Bypass.WinDivertBypassManager? _bypassManager;
        private readonly DnsParserService? _dnsParser;
        
        private readonly Channel<HostDiscovered> _snifferQueue;
        private readonly Channel<HostTested> _testerQueue;
        private readonly Channel<HostBlocked> _bypassQueue;
        
        private readonly CancellationTokenSource _cts = new();
        private readonly Task[] _workers;
        
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
        private readonly IBlockageClassifier _classifier;
        private readonly IBlockageStateStore _stateStore;
        private readonly BypassCoordinator? _coordinator; // Главный координатор bypass-стратегий
        
        public LiveTestingPipeline(
            PipelineConfig config, 
            IProgress<string>? progress = null, 
            IspAudit.Bypass.WinDivertBypassManager? bypassManager = null, 
            DnsParserService? dnsParser = null,
            ITrafficFilter? filter = null,
            IBlockageStateStore? stateStore = null,
            System.Collections.Generic.IEnumerable<string>? activeStrategies = null)
        {
            _config = config;
            _progress = progress;
            _dnsParser = dnsParser;
            
            // Используем переданный фильтр или создаем новый
            _filter = filter ?? new UnifiedTrafficFilter();
            
            // Используем переданный менеджер или создаем новый если auto-bypass включен
            if (bypassManager != null)
            {
                _bypassManager = bypassManager;
            }
            // Если менеджер не передан, но нужен auto-bypass - создаем локальный (но это плохой сценарий для персистентности)
            else if (_config.EnableAutoBypass && IspAudit.Bypass.WinDivertBypassManager.HasAdministratorRights)
            {
                _bypassManager = new IspAudit.Bypass.WinDivertBypassManager();
            }

            // Инициализация модулей
            _stateStore = stateStore ?? new InMemoryBlockageStateStore();

            _tester = new StandardHostTester(progress, dnsParser?.DnsCache);
            
            var stdClassifier = new StandardBlockageClassifier(_stateStore);
            if (activeStrategies != null)
            {
                foreach (var s in activeStrategies)
                {
                    stdClassifier.ActiveStrategies.Add(s);
                }
            }
            _classifier = stdClassifier;
            
            // BypassCoordinator — главный "мозг" управления bypass-стратегиями
            // Содержит логику: кеширование работающих стратегий, перебор, ретест
            if (_bypassManager != null)
            {
                _coordinator = new BypassCoordinator(_bypassManager);
            }
            
            // Создаем unbounded каналы для передачи данных между воркерами
            _snifferQueue = Channel.CreateUnbounded<HostDiscovered>();
            _testerQueue = Channel.CreateUnbounded<HostTested>();
            _bypassQueue = Channel.CreateUnbounded<HostBlocked>();
            
            // Запускаем воркеры
            _workers = new[]
            {
                Task.Run(() => TesterWorker(_cts.Token)),
                Task.Run(() => ClassifierWorker(_cts.Token)),
                Task.Run(() => UiWorker(_cts.Token))
            };
        }

        /// <summary>
        /// Добавляет обнаруженный хост в очередь на тестирование
        /// </summary>
        public async ValueTask EnqueueHostAsync(HostDiscovered host)
        {
            Interlocked.Increment(ref _pendingInSniffer);
            await _snifferQueue.Writer.WriteAsync(host).ConfigureAwait(false);
        }
        
        /// <summary>
        /// Завершает приём новых хостов и ожидает обработки всех в очереди
        /// </summary>
        /// <param name="timeout">Максимальное время ожидания</param>
        /// <returns>true если все хосты обработаны, false если таймаут</returns>
        public async Task<bool> DrainAndCompleteAsync(TimeSpan timeout)
        {
            // Закрываем входную очередь - больше хостов не будет
            _snifferQueue.Writer.TryComplete();
            
            _progress?.Report($"[Pipeline] Ожидание завершения тестов... (в очереди: {PendingCount})");
            
            var deadline = DateTime.UtcNow + timeout;
            
            // Ждём пока все очереди опустеют
            while (PendingCount > 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(200).ConfigureAwait(false);
                
                // Логируем прогресс каждые 2 секунды
                if ((int)(deadline - DateTime.UtcNow).TotalSeconds % 2 == 0)
                {
                    _progress?.Report($"[Pipeline] Осталось в очереди: {PendingCount}");
                }
            }
            
            var completed = PendingCount == 0;
            if (completed)
            {
                _progress?.Report("[Pipeline] ✓ Все тесты завершены");
            }
            else
            {
                _progress?.Report($"[Pipeline] ⚠ Таймаут, не завершено: {PendingCount}");
            }
            
            // Закрываем остальные очереди
            _testerQueue.Writer.TryComplete();
            _bypassQueue.Writer.TryComplete();
            
            return completed;
        }

        /// <summary>
        /// Worker 1: Тестирование хостов
        /// </summary>
        private async Task TesterWorker(CancellationToken ct)
        {
            await foreach (var host in _snifferQueue.Reader.ReadAllAsync(ct))
            {
                Interlocked.Decrement(ref _pendingInSniffer);
                
                // Получаем hostname из объекта или кеша (если есть) для более умной дедупликации
                var hostname = host.Hostname;
                if (string.IsNullOrEmpty(hostname))
                {
                    hostname = _dnsParser?.DnsCache.TryGetValue(host.RemoteIp.ToString(), out var name) == true 
                        ? name : null;
                }

                // Проверяем через единый фильтр (дедупликация + шум)
                var decision = _filter.ShouldTest(host, hostname);
                if (decision.Action == FilterAction.Drop)
                {
                    continue;
                }
                
                Interlocked.Increment(ref _pendingInTester);
                try
                {
                    // Тестируем хост (DNS, TCP, TLS)
                    var result = await _tester.TestHostAsync(host, ct).ConfigureAwait(false);
                    await _testerQueue.Writer.WriteAsync(result, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    // Не логируем при отмене
                }
                catch (Exception ex)
                {
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
                try
                {
                    // Регистрируем результат в сторе, чтобы поддерживать fail counter + time window
                    _stateStore.RegisterResult(tested);

                    // Классифицируем блокировку
                    var blocked = _classifier.ClassifyBlockage(tested);

                    // Принимаем решение о показе через единый фильтр
                    var decision = _filter.ShouldDisplay(blocked);

                    // Пытаемся обновить hostname из кеша (мог появиться за время теста)
                    var hostname = tested.Hostname;
                    if (string.IsNullOrEmpty(hostname) && _dnsParser != null)
                    {
                        _dnsParser.DnsCache.TryGetValue(tested.Host.RemoteIp.ToString(), out hostname);
                    }
                    
                    // Используем hostname или IP
                    var displayHost = hostname ?? tested.Host.RemoteIp.ToString();
                    
                    // Перепроверяем шум с обновлённым hostname
                    if (!string.IsNullOrEmpty(hostname) && NoiseHostFilter.Instance.IsNoiseHost(hostname))
                    {
                        _progress?.Report($"[NOISE] Отфильтрован (late): {displayHost}");
                        continue; // Пропускаем шумовой хост
                    }

                    if (decision.Action == FilterAction.Process)
                    {
                        // Это блокировка или проблема - отправляем в UI
                        await _bypassQueue.Writer.WriteAsync(blocked, ct).ConfigureAwait(false);
                    }
                    else if (decision.Action == FilterAction.LogOnly)
                    {
                        // Хост работает - просто логируем (не отправляем в UI)
                        var port = tested.Host.RemotePort;
                        var latency = tested.TcpLatencyMs > 0 ? $" ({tested.TcpLatencyMs}ms)" : "";
                        _progress?.Report($"✓ {displayHost}:{port}{latency}");
                    }
                    else if (decision.Action == FilterAction.Drop)
                    {
                        // Шумовой хост - отправляем специальное сообщение для UI (удаления карточки)
                        _progress?.Report($"[NOISE] Отфильтрован: {displayHost}");
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

        /// <summary>
        /// Worker 3: Обновление UI (bypass применяется отдельно, не во время диагностики)
        /// </summary>
        private async Task UiWorker(CancellationToken ct)
        {
            await foreach (var blocked in _bypassQueue.Reader.ReadAllAsync(ct))
            {
                try
                {
                    var host = blocked.TestResult.Hostname ?? blocked.TestResult.Host.RemoteIp.ToString();
                    var port = blocked.TestResult.Host.RemotePort;
                    
                    // Формируем детальное сообщение
                    var details = $"{host}:{port}";
                    if (blocked.TestResult.TcpLatencyMs > 0)
                    {
                        details += $" ({blocked.TestResult.TcpLatencyMs}ms)";
                    }
                    
                    // Статус проверок
                    var checks = $"DNS:{(blocked.TestResult.DnsOk ? "✓" : "✗")} TCP:{(blocked.TestResult.TcpOk ? "✓" : "✗")} TLS:{(blocked.TestResult.TlsOk ? "✓" : "✗")}";

                    var blockage = string.IsNullOrEmpty(blocked.TestResult.BlockageType)
                        ? "UNKNOWN"
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
                                suffix = tail;
                            }
                        }
                    }

                    var uiLine = suffix is null
                        ? $"❌ {details} | {checks} | {blockage}"
                        : $"❌ {details} | {checks} | {blockage} {suffix}";

                    _progress?.Report(uiLine);
                    
                    // Показываем рекомендацию, но НЕ применяем bypass автоматически
                    // Bypass должен применяться отдельной командой после завершения диагностики
                    if (blocked.BypassStrategy != "NONE" && blocked.BypassStrategy != "UNKNOWN")
                    {
                        _progress?.Report($"   💡 Рекомендация: {blocked.BypassStrategy}");
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
                Task.WhenAll(_workers).Wait(3000);
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
