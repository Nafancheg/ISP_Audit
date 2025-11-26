using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
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
        private readonly IBypassEnforcer _bypassEnforcer;
        
        public LiveTestingPipeline(PipelineConfig config, IProgress<string>? progress = null, IspAudit.Bypass.WinDivertBypassManager? bypassManager = null, DnsParserService? dnsParser = null)
        {
            _config = config;
            _progress = progress;
            
            // Используем переданный менеджер или создаем новый если auto-bypass включен
            if (bypassManager != null)
            {
                _bypassManager = bypassManager;
            }
            else if (_config.EnableAutoBypass && IspAudit.Bypass.WinDivertBypassManager.HasAdministratorRights)
            {
                _bypassManager = new IspAudit.Bypass.WinDivertBypassManager();
            }

            // Инициализация модулей
            _tester = new StandardHostTester(progress, dnsParser?.DnsCache);
            _classifier = new StandardBlockageClassifier();
            _bypassEnforcer = new WinDivertBypassEnforcer(_bypassManager, _tester, progress);
            
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
        /// Worker 3: Обновление UI с результатами
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
                    _progress?.Report($"   → Стратегия: {blocked.BypassStrategy}");
                    
                    // Если включен auto-bypass - применяем стратегию
                    if (_config.EnableAutoBypass && blocked.BypassStrategy != "NONE" && blocked.BypassStrategy != "UNKNOWN")
                    {
                        _progress?.Report($"   → Применяю bypass для {host}...");
                        // Fire and forget - Enforcer handles serialization internally
                        _ = Task.Run(() => _bypassEnforcer.ApplyBypassAsync(blocked, ct), ct);
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
            
            // Отключаем bypass manager если был создан
            _bypassManager?.DisableAsync().GetAwaiter().GetResult();
            _bypassManager?.Dispose();
        }
    }
}
