using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;

namespace IspAudit.Utils
{
    /// <summary>
    /// Чистый сборщик сетевого трафика.
    /// Single Responsibility: только сбор соединений через WinDivert Socket Layer.
    /// НЕ содержит логику тестирования, bypass, или UI.
    /// </summary>
    public sealed class TrafficCollector : IDisposable
    {
        private readonly ConnectionMonitorService _connectionMonitor;
        private readonly PidTrackerService _pidTracker;
        private readonly DnsParserService _dnsParser;
        private readonly IProgress<string>? _progress;
        private readonly ITrafficFilter _filter;

        // Флаг подробного логирования событий соединений (для диагностики проблем сбора)
        private const bool VerboseConnectionLogging = false;
        // Ограничение на количество подробных логов для снижения шума
        private const int VerboseConnectionLogLimit = 200;
        
        private readonly ConcurrentDictionary<string, ConnectionInfo> _connections = new();
        private int _rawEventsLogged;
        private DateTime _lastNewConnectionTime = DateTime.UtcNow;
        private bool _disposed;
        private bool _collecting = true; // Флаг активности сбора
        
        // Канал для передачи хостов — хранится здесь для возможности завершить при Dispose
        private System.Threading.Channels.ChannelWriter<HostDiscovered>? _activeWriter;
        
        /// <summary>
        /// Событие обнаружения нового хоста (для live pipeline)
        /// </summary>
        public event Action<HostDiscovered>? OnHostDiscovered;
        
        /// <summary>
        /// Событие обновления hostname (DNS резолв)
        /// </summary>
        public event Action<string, string>? OnHostnameResolved;
        
        /// <summary>
        /// Количество обнаруженных уникальных соединений
        /// </summary>
        public int ConnectionsCount => _connections.Count;
        
        /// <summary>
        /// Время последнего нового соединения
        /// </summary>
        public DateTime LastNewConnectionTime => _lastNewConnectionTime;
        
        /// <summary>
        /// Сбрасывает таймер тишины (для продления диагностики пользователем)
        /// </summary>
        public void ResetSilenceTimer()
        {
            _lastNewConnectionTime = DateTime.UtcNow;
        }
        
        /// <summary>
        /// Останавливает сбор новых соединений (закрывает канал).
        /// Pipeline продолжит обрабатывать уже собранные данные.
        /// </summary>
        public void StopCollecting()
        {
            if (!_collecting) return;
            _collecting = false;
            
            _progress?.Report("[Collector] Остановка сбора (ожидание завершения тестов)");
            _activeWriter?.TryComplete();
        }

        public TrafficCollector(
            ConnectionMonitorService connectionMonitor,
            PidTrackerService pidTracker,
            DnsParserService dnsParser,
            IProgress<string>? progress = null,
            ITrafficFilter? filter = null)
        {
            _connectionMonitor = connectionMonitor ?? throw new ArgumentNullException(nameof(connectionMonitor));
            _pidTracker = pidTracker ?? throw new ArgumentNullException(nameof(pidTracker));
            _dnsParser = dnsParser ?? throw new ArgumentNullException(nameof(dnsParser));
            _progress = progress;
            _filter = filter ?? new UnifiedTrafficFilter();
        }

        /// <summary>
        /// Вспомогательный метод для smoke-тестов: прогоняет ту же логику фильтрации PID/loopback/дедуп,
        /// но без необходимости реально поднимать ConnectionMonitor/WinDivert.
        /// </summary>
        public bool TryBuildHostFromConnectionEventForSmoke(
            int pid,
            byte protocol,
            IPAddress remoteIp,
            ushort remotePort,
            out HostDiscovered host)
        {
            host = default!;

            // Фильтруем по отслеживаемым PID
            if (!_pidTracker.IsPidTracked(pid))
            {
                return false;
            }

            // Loopback не должен попадать в pipeline
            if (IPAddress.IsLoopback(remoteIp))
            {
                return false;
            }

            // Игнорируем 0.0.0.0 (часто бывает при биндинге или ошибках)
            if (remoteIp.Equals(IPAddress.Any) || remoteIp.Equals(IPAddress.IPv6Any))
            {
                return false;
            }

            var key = $"{remoteIp}:{remotePort}:{protocol}";

            // Дедуп по цели
            if (!_connections.TryAdd(key, new ConnectionInfo
                {
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    Protocol = protocol == 6 ? TransportProtocol.TCP : TransportProtocol.UDP,
                    FirstSeen = DateTime.UtcNow
                }))
            {
                return false;
            }

            // Обогащаем hostname из DNS кеша (если есть)
            string? hostname = null;
            _dnsParser.DnsCache.TryGetValue(remoteIp.ToString(), out hostname);

            var candidate = new HostDiscovered(
                Key: key,
                RemoteIp: remoteIp,
                RemotePort: remotePort,
                Protocol: protocol == 6 ? IspAudit.Bypass.TransportProtocol.Tcp : IspAudit.Bypass.TransportProtocol.Udp,
                DiscoveredAt: DateTime.UtcNow)
            {
                Hostname = hostname
            };

            var decision = _filter.ShouldTest(candidate, hostname);
            if (decision.Action == FilterAction.Drop)
            {
                // Откатываем дедуп-метку, иначе тестовое событие навсегда "заблокирует" ключ.
                _connections.TryRemove(key, out _);
                return false;
            }

            host = candidate;
            return true;
        }

        /// <summary>
        /// Запуск сбора трафика.
        /// Возвращает IAsyncEnumerable обнаруженных хостов для pipeline обработки.
        /// </summary>
        public async IAsyncEnumerable<HostDiscovered> CollectAsync(
            TimeSpan? captureTimeout = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var timeoutText = captureTimeout.HasValue 
                ? $"на {captureTimeout.Value.TotalSeconds}с" 
                : "(до ручной остановки)";
            _progress?.Report($"Старт захвата трафика {timeoutText}");

            // Канал для передачи обнаруженных хостов (ограничен 1000, старые отбрасываются при переполнении)
            var hostChannel = System.Threading.Channels.Channel.CreateBounded<HostDiscovered>(
                new System.Threading.Channels.BoundedChannelOptions(1000) 
                { 
                    FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest 
                });
            var writer = hostChannel.Writer;
            _activeWriter = writer;
            
            // Настройка таймаута
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (captureTimeout.HasValue)
            {
                cts.CancelAfter(captureTimeout.Value);
            }

            // Подписка на события соединений
            void OnConnectionEvent(int eventNum, int pid, byte protocol, IPAddress remoteIp, ushort remotePort, ushort localPort)
            {
                // Подробный лог входящего события
                if (VerboseConnectionLogging && _rawEventsLogged < VerboseConnectionLogLimit)
                {
                    // Копируем PID-ы под локальный снапшот для безопасного логирования
                    int[] trackedSnapshot;
                    try
                    {
                        trackedSnapshot = _pidTracker.GetTrackedPidsSnapshot();
                    }
                    catch
                    {
                        trackedSnapshot = Array.Empty<int>();
                    }

                    bool isTracked = trackedSnapshot.Contains(pid);
                    _progress?.Report($"[Collector][Raw] evt={eventNum} pid={pid} proto={(protocol == 6 ? "TCP" : "UDP")} {remoteIp}:{remotePort} -> local:{localPort} tracked={isTracked} trackedPids=[{string.Join(",", trackedSnapshot)}]");
                    Interlocked.Increment(ref _rawEventsLogged);
                }

                // Фильтруем по отслеживаемым PID
                if (!_pidTracker.IsPidTracked(pid))
                {
                    return;
                }

                // Loopback (127.0.0.0/8, ::1) не должен попадать в карточки
                if (IPAddress.IsLoopback(remoteIp))
                {
                    return;
                }

                // Игнорируем 0.0.0.0 (часто бывает при биндинге или ошибках)
                if (remoteIp.Equals(IPAddress.Any) || remoteIp.Equals(IPAddress.IPv6Any))
                {
                    return;
                }

                var key = $"{remoteIp}:{remotePort}:{protocol}";
                
                if (_connections.TryAdd(key, new ConnectionInfo
                {
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    Protocol = protocol == 6 ? TransportProtocol.TCP : TransportProtocol.UDP,
                    FirstSeen = DateTime.UtcNow
                }))
                {
                    _lastNewConnectionTime = DateTime.UtcNow;
                    
                    // Обогащаем hostname из DNS кеша (если есть)
                    string? hostname = null;
                    _dnsParser.DnsCache.TryGetValue(remoteIp.ToString(), out hostname);
                    
                    if (!string.IsNullOrEmpty(hostname))
                    {
                        _connections[key].Hostname = hostname;
                    }

                    // До создания карточки/логирования применяем единый фильтр (loopback/шум/дубликаты)
                    var candidate = new HostDiscovered(
                        Key: key,
                        RemoteIp: remoteIp,
                        RemotePort: remotePort,
                        Protocol: protocol == 6 ? IspAudit.Bypass.TransportProtocol.Tcp : IspAudit.Bypass.TransportProtocol.Udp,
                        DiscoveredAt: DateTime.UtcNow)
                    {
                        Hostname = hostname
                    };

                    var decision = _filter.ShouldTest(candidate, hostname);
                    if (decision.Action == FilterAction.Drop)
                    {
                        return;
                    }
                    
                    // В логах/сообщениях пайплайна используем IP как технический якорь,
                    // а hostname (DNS/SNI) передаём как доп.метаданные. UI может
                    // отображать карточку по человеко‑понятному ключу (SNI/hostname),
                    // сохраняя IP как FallbackIp.
                    var displayIp = remoteIp.ToString();
                    var dnsSuffix = string.IsNullOrWhiteSpace(hostname) ? "" : $" DNS={hostname}";
                    _progress?.Report($"[Collector] Новое соединение #{_connections.Count}: {displayIp}:{remotePort}{dnsSuffix} (proto={protocol}, pid={pid})");

                    // Передаём дальше — Pipeline продолжит обработку
                    writer.TryWrite(candidate);
                    OnHostDiscovered?.Invoke(candidate);
                }
            }
            
            // Подписка на DNS обновления — только обновляем внутренний кеш
            void OnHostnameUpdated(string ip, string hostname)
            {
                foreach (var kvp in _connections)
                {
                    if (kvp.Value.RemoteIp.ToString() == ip && kvp.Value.Hostname != hostname)
                    {
                        kvp.Value.Hostname = hostname;
                        _progress?.Report($"[Collector] Hostname обновлен: {ip} → {hostname}");
                        OnHostnameResolved?.Invoke(ip, hostname);
                        // НЕ отправляем хост повторно — UI обновит по сообщению
                    }
                }
            }

            _connectionMonitor.OnConnectionEvent += OnConnectionEvent;
            _dnsParser.OnHostnameUpdated += OnHostnameUpdated;

            try
            {
                // Читаем из канала и возвращаем хосты
                await foreach (var host in hostChannel.Reader.ReadAllAsync(cts.Token).ConfigureAwait(false))
                {
                    yield return host;
                }
            }
            finally
            {
                _connectionMonitor.OnConnectionEvent -= OnConnectionEvent;
                _dnsParser.OnHostnameUpdated -= OnHostnameUpdated;
                _activeWriter = null;
                writer.TryComplete();
                
                _progress?.Report($"[Collector] Завершено. Всего соединений: {_connections.Count}");
            }
        }

        /// <summary>
        /// Получить собранные соединения с обогащением hostname
        /// </summary>
        public async Task<DiagnosticProfile> BuildProfileAsync(
            string? processName = null,
            CancellationToken cancellationToken = default)
        {
            _progress?.Report($"Генерация профиля для {_connections.Count} соединений...");

            // Обогащение hostname из DNS кеша и reverse DNS
            await EnrichHostnamesAsync(cancellationToken).ConfigureAwait(false);

            // Группируем по hostname (или IP), исключаем шумные хосты
            var targetGroups = _connections.Values
                .Where(c => !_filter.IsNoise(c.Hostname)) // Фильтруем шумные хосты через единый фильтр
                .GroupBy(c => c.Hostname ?? c.RemoteIp.ToString())
                .OrderByDescending(g => g.Count())
                .ToList();

            var targets = new List<TargetDefinition>();

            foreach (var group in targetGroups)
            {
                var hostname = group.Key;
                var portsUsed = group.Select(c => c.RemotePort).Distinct().OrderBy(p => p).ToList();
                var protocols = group.Select(c => c.Protocol).Distinct().ToList();
                var firstConnection = group.First();

                var target = new TargetDefinition
                {
                    Name = hostname,
                    Host = hostname,
                    Service = DetermineService(hostname, portsUsed, protocols),
                    Critical = false,
                    FallbackIp = firstConnection.RemoteIp.ToString(),
                    Ports = portsUsed.Select(p => (int)p).ToList(),
                    Protocols = protocols.Select(p => p.ToString()).ToList()
                };
                
                targets.Add(target);
                _progress?.Report($"  • {hostname}: порты {string.Join(", ", portsUsed)} ({string.Join(", ", protocols)})");
            }

            // Добавляем неудачные DNS запросы
            foreach (var fail in _dnsParser.FailedRequests.Values)
            {
                if (targets.Any(t => t.Host.Equals(fail.Hostname, StringComparison.OrdinalIgnoreCase)))
                    continue;

                targets.Add(new TargetDefinition
                {
                    Name = fail.Hostname,
                    Host = fail.Hostname,
                    Service = "dns-failed",
                    Critical = false,
                    FallbackIp = "",
                    Ports = new List<int>(),
                    Protocols = new List<string>()
                });
                
                _progress?.Report($"  • {fail.Hostname} (DNS FAIL: {fail.Error})");
            }

            return new DiagnosticProfile
            {
                Name = $"Captured_{processName ?? "Unknown"}",
                TestMode = "host",
                ExePath = "",
                Targets = targets
            };
        }

        private async Task EnrichHostnamesAsync(CancellationToken cancellationToken)
        {
            int fromCache = 0;
            int fromReverseDns = 0;

            // Из DNS кеша
            foreach (var conn in _connections.Values)
            {
                string ipStr = conn.RemoteIp.ToString();
                if (_dnsParser.DnsCache.TryGetValue(ipStr, out string? hostname))
                {
                    conn.Hostname = hostname;
                    fromCache++;
                }
            }

            // Reverse DNS для оставшихся
            var remaining = _connections.Values.Where(c => c.Hostname == null).ToList();
            var tasks = remaining.Select(async conn =>
            {
                try
                {
                    var entry = await System.Net.Dns.GetHostEntryAsync(
                        conn.RemoteIp.ToString(), 
                        System.Net.Sockets.AddressFamily.InterNetwork, 
                        cancellationToken).ConfigureAwait(false);
                    if (entry.HostName != null)
                    {
                        conn.Hostname = entry.HostName.ToLowerInvariant();
                        Interlocked.Increment(ref fromReverseDns);
                    }
                }
                catch { }
            });

            await Task.WhenAll(tasks).ConfigureAwait(false);
            _progress?.Report($"✓ Hostname resolved: {fromCache + fromReverseDns}/{_connections.Count} (кеш: {fromCache}, reverse: {fromReverseDns})");
        }

        private static string DetermineService(string hostname, List<ushort> ports, List<TransportProtocol> protocols)
        {
            bool hasUdp = protocols.Contains(TransportProtocol.UDP);
            bool hasTcp = protocols.Contains(TransportProtocol.TCP);
            
            if (ports.Contains(53) && hasUdp) return "dns";
            if ((ports.Contains(443) || ports.Contains(80)) && hasTcp) return "web";
            if (ports.Any(p => p >= 27000 && p <= 28000)) return hasUdp ? "game-udp" : "game-tcp";
            if (ports.Any(p => p >= 64000 && p <= 65000)) return hasUdp ? "voice-udp" : "voice-tcp";
            if (hasUdp && !hasTcp) return "unknown-udp";
            if (hasTcp && !hasUdp) return "unknown-tcp";
            
            return "unknown";
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            
            // Завершаем канал — это разблокирует ReadAllAsync
            _activeWriter?.TryComplete();
            _activeWriter = null;
            
            _connections.Clear();
        }

        /// <summary>
        /// Внутренняя структура для хранения информации о соединении
        /// </summary>
        private class ConnectionInfo
        {
            public IPAddress RemoteIp { get; set; } = IPAddress.None;
            public ushort RemotePort { get; set; }
            public TransportProtocol Protocol { get; set; }
            public DateTime FirstSeen { get; set; }
            public string? Hostname { get; set; }
        }
    }
}
