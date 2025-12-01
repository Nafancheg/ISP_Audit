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
        
        private readonly Channel<HostDiscovered> _snifferQueue;
        private readonly Channel<HostTested> _testerQueue;
        private readonly Channel<HostBlocked> _bypassQueue;
        
        private readonly CancellationTokenSource _cts = new();
        private readonly Task[] _workers;

        // Modules
        private readonly IHostTester _tester;
        private readonly IBlockageClassifier _classifier;
        private readonly BypassCoordinator? _coordinator; // Главный координатор bypass-стратегий
        
        public LiveTestingPipeline(PipelineConfig config, IProgress<string>? progress = null, IspAudit.Bypass.WinDivertBypassManager? bypassManager = null, DnsParserService? dnsParser = null)
        {
            _config = config;
            _progress = progress;
            
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
            _tester = new StandardHostTester(progress, dnsParser?.DnsCache);
            _classifier = new StandardBlockageClassifier();
            
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
            await _snifferQueue.Writer.WriteAsync(host).ConfigureAwait(false);
        }

        /// <summary>
        /// Worker 1: Тестирование хостов
        /// </summary>
        private async Task TesterWorker(CancellationToken ct)
        {
            await foreach (var host in _snifferQueue.Reader.ReadAllAsync(ct))
            {
                try
                {
                    // Тестируем хост (DNS, TCP, TLS)
                    var result = await _tester.TestHostAsync(host, ct).ConfigureAwait(false);
                    await _testerQueue.Writer.WriteAsync(result, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[TESTER] Ошибка тестирования {host.RemoteIp}: {ex.Message}");
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
                try
                {
                    // Классифицируем блокировку
                    var blocked = _classifier.ClassifyBlockage(tested);

                    // Если стратегия OK (NONE + OK), то это успех
                    if (blocked.BypassStrategy == "NONE" && blocked.RecommendedAction == "OK")
                    {
                        // Хост работает - просто логируем
                        var host = tested.Hostname ?? tested.Host.RemoteIp.ToString();
                        var port = tested.Host.RemotePort;
                        var latency = tested.TcpLatencyMs > 0 ? $" ({tested.TcpLatencyMs}ms)" : "";
                        _progress?.Report($"✓ {host}:{port}{latency}");
                    }
                    else
                    {
                        // Это блокировка или проблема (включая PORT_CLOSED, FAKE_IP и т.д.)
                        await _bypassQueue.Writer.WriteAsync(blocked, ct).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[CLASSIFIER] Ошибка классификации: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Worker 3: Обновление UI и применение bypass стратегий через BypassCoordinator
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
                    
                    _progress?.Report($"❌ {details} | {checks} | {blocked.TestResult.BlockageType}");
                    _progress?.Report($"   → Рекомендуемая стратегия: {blocked.BypassStrategy}");
                    
                    // Применяем bypass динамически через BypassCoordinator если:
                    // 1. Стратегия не NONE (есть что применять)
                    // 2. Auto-bypass включен в конфигурации
                    // 3. Координатор доступен
                    // 4. Bypass manager не в состоянии Faulted
                    if (blocked.BypassStrategy != "NONE" && 
                        _config.EnableAutoBypass && 
                        _coordinator != null &&
                        _bypassManager != null &&
                        _bypassManager.State != BypassState.Faulted)
                    {
                        _progress?.Report($"[BYPASS] Координатор применяет стратегию для {host}...");
                        
                        // BypassCoordinator.AutoFixLiveAsync — главный метод:
                        // - Проверяет кеш работающих стратегий
                        // - Перебирает стратегии по приоритету
                        // - Выполняет ретест после каждой
                        // - Кеширует успешную стратегию
                        var fixResult = await _coordinator.AutoFixLiveAsync(
                            blocked.TestResult,
                            async (testedHost) => await _tester.TestHostAsync(testedHost.Host, ct).ConfigureAwait(false),
                            ct
                        ).ConfigureAwait(false);
                        
                        if (fixResult.Success)
                        {
                            _progress?.Report($"✓✓ BYPASS УСПЕХ: {fixResult.Strategy} работает для {host}");
                        }
                        else
                        {
                            _progress?.Report($"✗ BYPASS НЕ ПОМОГ: {fixResult.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[UI] Ошибка обработки: {ex.Message}");
                }
            }
        }







        public void Dispose()
        {
            _cts.Cancel();
            _snifferQueue.Writer.Complete();
            _testerQueue.Writer.Complete();
            _bypassQueue.Writer.Complete();
            
            Task.WhenAll(_workers).GetAwaiter().GetResult();
            _cts.Dispose();
            
            // НЕ отключаем bypass manager здесь, если он был передан извне (MainViewModel)
            // MainViewModel сам управляет его жизненным циклом
            if (_bypassManager != null && _config.EnableAutoBypass && IspAudit.Bypass.WinDivertBypassManager.HasAdministratorRights)
            {
                 // Если мы создали его сами (в конструкторе), то мы его и чистим
                 // Но в текущей архитектуре MainViewModel передает его нам
                 // Поэтому здесь мы ничего не делаем с _bypassManager, если он пришел извне
            }
        }
    }
}
