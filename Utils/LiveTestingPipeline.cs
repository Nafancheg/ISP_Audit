using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    /// <summary>
    /// Модели данных для pipeline обработки
    /// </summary>
    /// 
    /// <summary>
    /// Хост обнаружен снифером
    /// </summary>
    public record HostDiscovered(
        string Key,                    // IP:Port:Protocol
        IPAddress RemoteIp,
        int RemotePort,
        TransportProtocol Protocol,
        DateTime DiscoveredAt
    );

    /// <summary>
    /// Результат тестирования хоста
    /// </summary>
    public record HostTested(
        HostDiscovered Host,
        bool DnsOk,
        bool TcpOk,
        bool TlsOk,
        string? DnsStatus,             // OK, DNS_FILTERED, DNS_BOGUS, DNS_BYPASS
        string? Hostname,              // Резолвленное имя
        int? TcpLatencyMs,
        string? BlockageType,          // null, TCP_RST, TLS_DPI, UDP_DROP
        DateTime TestedAt
    );

    /// <summary>
    /// Хост с блокировкой, требуется bypass
    /// </summary>
    public record HostBlocked(
        HostTested TestResult,
        string BypassStrategy,         // TLS_FRAGMENT, TCP_TTL, UDP_FAKE
        string RecommendedAction       // "Применить TLS fragmentation", "Заблокировать RST пакеты"
    );

    /// <summary>
    /// Конфигурация pipeline
    /// </summary>
    public class PipelineConfig
    {
        public bool EnableLiveTesting { get; set; } = true;
        public bool EnableAutoBypass { get; set; } = true; // Автоматическое применение bypass включено по умолчанию
        public int MaxConcurrentTests { get; set; } = 5;
        public TimeSpan TestTimeout { get; set; } = TimeSpan.FromSeconds(3);
    }

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
        
        public LiveTestingPipeline(PipelineConfig config, IProgress<string>? progress = null)
        {
            _config = config;
            _progress = progress;
            
            // Инициализируем bypass manager если auto-bypass включен
            if (_config.EnableAutoBypass && IspAudit.Bypass.WinDivertBypassManager.HasAdministratorRights)
            {
                _bypassManager = new IspAudit.Bypass.WinDivertBypassManager();
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
                    var result = await TestHostAsync(host, ct).ConfigureAwait(false);
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
                    // Если хост заблокирован - классифицируем и выбираем стратегию
                    if (!tested.TlsOk || !tested.TcpOk || tested.DnsStatus == "DNS_FILTERED")
                    {
                        var blocked = ClassifyBlockage(tested);
                        await _bypassQueue.Writer.WriteAsync(blocked, ct).ConfigureAwait(false);
                    }
                    else
                    {
                        // Хост работает - просто логируем
                        var host = tested.Hostname ?? tested.Host.RemoteIp.ToString();
                        var port = tested.Host.RemotePort;
                        var latency = tested.TcpLatencyMs > 0 ? $" ({tested.TcpLatencyMs}ms)" : "";
                        _progress?.Report($"✓ {host}:{port}{latency}");
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
                        await ApplyBypassAsync(blocked, ct).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[UI] Ошибка обработки: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Тестирует хост (DNS, TCP, TLS)
        /// </summary>
        private async Task<HostTested> TestHostAsync(HostDiscovered host, CancellationToken ct)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            bool dnsOk = true;
            bool tcpOk = false;
            bool tlsOk = false;
            string dnsStatus = "OK";
            string? hostname = null;
            string? blockageType = null;
            int tcpLatencyMs = 0;

            try
            {
                // 1. Reverse DNS (быстро)
                try
                {
                    var hostEntry = await System.Net.Dns.GetHostEntryAsync(host.RemoteIp.ToString()).ConfigureAwait(false);
                    hostname = hostEntry.HostName;
                }
                catch
                {
                    // Не критично, продолжаем
                }

                // 2. TCP connect (таймаут 3с)
                try
                {
                    using var tcpClient = new System.Net.Sockets.TcpClient();
                    var connectTask = tcpClient.ConnectAsync(host.RemoteIp, host.RemotePort);
                    
                    var timeoutTask = Task.Delay(3000, ct);
                    var completedTask = await Task.WhenAny(connectTask, timeoutTask).ConfigureAwait(false);
                    
                    if (completedTask == connectTask)
                    {
                        await connectTask.ConfigureAwait(false); // Проверяем исключения
                        tcpOk = true;
                        tcpLatencyMs = (int)sw.ElapsedMilliseconds;
                    }
                    else
                    {
                        blockageType = "TCP_TIMEOUT";
                    }
                }
                catch (System.Net.Sockets.SocketException ex)
                {
                    if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionRefused)
                    {
                        // Порт закрыт, но хост доступен
                        tcpOk = false;
                        blockageType = "PORT_CLOSED";
                    }
                    else if (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
                    {
                        tcpOk = false;
                        blockageType = "TCP_RST";
                    }
                    else
                    {
                        tcpOk = false;
                        blockageType = "TCP_ERROR";
                    }
                }

                // 3. TLS handshake (только для порта 443 и если TCP прошел)
                if (tcpOk && host.RemotePort == 443 && !string.IsNullOrEmpty(hostname))
                {
                    try
                    {
                        using var tcpClient = new System.Net.Sockets.TcpClient();
                        await tcpClient.ConnectAsync(host.RemoteIp, 443, ct).ConfigureAwait(false);
                        
                        using var sslStream = new System.Net.Security.SslStream(tcpClient.GetStream(), false);
                        var tlsTask = sslStream.AuthenticateAsClientAsync(hostname, null, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
                        
                        var timeoutTask = Task.Delay(3000, ct);
                        var completedTask = await Task.WhenAny(tlsTask, timeoutTask).ConfigureAwait(false);
                        
                        if (completedTask == tlsTask)
                        {
                            await tlsTask.ConfigureAwait(false);
                            tlsOk = true;
                        }
                        else
                        {
                            blockageType = "TLS_TIMEOUT";
                        }
                    }
                    catch (System.Security.Authentication.AuthenticationException)
                    {
                        tlsOk = false;
                        blockageType = "TLS_DPI";
                    }
                    catch
                    {
                        tlsOk = false;
                        blockageType = blockageType ?? "TLS_ERROR";
                    }
                }
                else if (host.RemotePort == 443)
                {
                    // Не можем проверить TLS без hostname
                    tlsOk = tcpOk;
                }
                else
                {
                    // Не HTTPS - считаем OK если TCP прошел
                    tlsOk = tcpOk;
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[TESTER] Ошибка {host.RemoteIp}:{host.RemotePort}: {ex.Message}");
            }

            return new HostTested(
                host,
                dnsOk,
                tcpOk,
                tlsOk,
                dnsStatus,
                hostname,
                tcpLatencyMs,
                blockageType,
                DateTime.UtcNow
            );
        }

        /// <summary>
        /// Классифицирует тип блокировки и выбирает bypass стратегию
        /// </summary>
        private HostBlocked ClassifyBlockage(HostTested tested)
        {
            string strategy;
            string action;
            
            // Приоритет: DNS -> TCP -> TLS
            if (tested.DnsStatus == "DNS_FILTERED" || tested.DnsStatus == "DNS_BOGUS")
            {
                strategy = "DOH";
                action = $"DNS блокировка: использовать DoH для {tested.Hostname ?? tested.Host.RemoteIp.ToString()}";
            }
            else if (tested.BlockageType == "TCP_RST")
            {
                strategy = "DROP_RST";
                action = $"TCP RST injection: блокировать RST пакеты для {tested.Host.RemoteIp}:{tested.Host.RemotePort}";
            }
            else if (tested.BlockageType == "TLS_DPI")
            {
                strategy = "TLS_FRAGMENT";
                action = $"DPI блокировка TLS: фрагментация ClientHello для {tested.Hostname ?? tested.Host.RemoteIp.ToString()}";
            }
            else if (tested.BlockageType == "TLS_TIMEOUT" && tested.TcpOk)
            {
                // TCP работает, но TLS таймаут - вероятно DPI
                strategy = "TLS_FRAGMENT";
                action = $"TLS таймаут (возможно DPI): фрагментация для {tested.Hostname ?? tested.Host.RemoteIp.ToString()}";
            }
            else if (tested.BlockageType == "TCP_TIMEOUT")
            {
                // TCP таймаут - может быть firewall или route block
                strategy = "PROXY";
                action = $"TCP таймаут: возможна блокировка на уровне маршрутизации для {tested.Host.RemoteIp}:{tested.Host.RemotePort}";
            }
            else if (tested.BlockageType == "PORT_CLOSED")
            {
                // Порт закрыт - не блокировка, просто сервис недоступен
                strategy = "NONE";
                action = $"Порт {tested.Host.RemotePort} закрыт на {tested.Host.RemoteIp} (не блокировка)";
            }
            else
            {
                // Неопределенная проблема
                strategy = "UNKNOWN";
                action = $"Неизвестная проблема с {tested.Host.RemoteIp}:{tested.Host.RemotePort}";
            }
            
            return new HostBlocked(tested, strategy, action);
        }

        /// <summary>
        /// Применяет bypass стратегию через WinDivert
        /// </summary>
        private async Task ApplyBypassAsync(HostBlocked blocked, CancellationToken ct)
        {
            try
            {
                var host = blocked.TestResult.Hostname ?? blocked.TestResult.Host.RemoteIp.ToString();
                var ip = blocked.TestResult.Host.RemoteIp;
                var port = blocked.TestResult.Host.RemotePort;

                switch (blocked.BypassStrategy)
                {
                    case "DROP_RST":
                        _progress?.Report($"[BYPASS] Применяю DROP_RST для {ip}:{port}...");
                        
                        if (_bypassManager != null)
                        {
                            await _bypassManager.ApplyBypassStrategyAsync("DROP_RST", ip, port).ConfigureAwait(false);
                            _progress?.Report($"✓ DROP_RST bypass активен для {ip}:{port}");
                        }
                        else
                        {
                            _progress?.Report($"⚠ DROP_RST bypass требует прав администратора (WinDivert)");
                        }
                        break;

                    case "TLS_FRAGMENT":
                        _progress?.Report($"[BYPASS] Применяю TLS_FRAGMENT для {host}...");
                        
                        if (_bypassManager != null)
                        {
                            await _bypassManager.ApplyBypassStrategyAsync("TLS_FRAGMENT", ip, port).ConfigureAwait(false);
                            _progress?.Report($"✓ TLS_FRAGMENT bypass активен для {host} (фрагментация ClientHello)");
                        }
                        else
                        {
                            _progress?.Report($"⚠ TLS_FRAGMENT bypass требует прав администратора (WinDivert)");
                        }
                        break;

                    case "DOH":
                        _progress?.Report($"[BYPASS] DNS блокировка для {host} - используйте DoH (1.1.1.1, 8.8.8.8)");
                        _progress?.Report($"ℹ Для {host}: рекомендуется настроить DoH в системе или использовать hosts файл");
                        break;

                    case "PROXY":
                        _progress?.Report($"[BYPASS] TCP timeout для {ip}:{port} - возможна блокировка маршрутизации");
                        _progress?.Report($"ℹ Для {ip}:{port}: рекомендуется использовать VPN или прокси");
                        break;

                    case "NONE":
                        // Порт закрыт - не применяем bypass
                        break;

                    case "UNKNOWN":
                        _progress?.Report($"⚠ Неизвестный тип блокировки для {host}:{port}");
                        break;
                }

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _progress?.Report($"[BYPASS] Ошибка применения bypass: {ex.Message}");
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
