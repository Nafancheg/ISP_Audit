using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
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
        
        private readonly ConcurrentDictionary<string, ConnectionInfo> _connections = new();
        private DateTime _lastNewConnectionTime = DateTime.UtcNow;
        private bool _disposed;
        
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

        public TrafficCollector(
            ConnectionMonitorService connectionMonitor,
            PidTrackerService pidTracker,
            DnsParserService dnsParser,
            IProgress<string>? progress = null)
        {
            _connectionMonitor = connectionMonitor ?? throw new ArgumentNullException(nameof(connectionMonitor));
            _pidTracker = pidTracker ?? throw new ArgumentNullException(nameof(pidTracker));
            _dnsParser = dnsParser ?? throw new ArgumentNullException(nameof(dnsParser));
            _progress = progress;
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

            // Канал для передачи обнаруженных хостов
            var hostChannel = System.Threading.Channels.Channel.CreateUnbounded<HostDiscovered>();
            var writer = hostChannel.Writer;
            
            // Настройка таймаута
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (captureTimeout.HasValue)
            {
                cts.CancelAfter(captureTimeout.Value);
            }

            // Подписка на события соединений
            void OnConnectionEvent(int eventNum, int pid, byte protocol, IPAddress remoteIp, ushort remotePort, ushort localPort)
            {
                // Фильтруем по отслеживаемым PID
                if (!_pidTracker.TrackedPids.Contains(pid))
                    return;

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
                    _progress?.Report($"[Collector] Новое соединение #{_connections.Count}: {remoteIp}:{remotePort} (proto={protocol}, pid={pid})");
                    
                    var host = new HostDiscovered(
                        Key: key,
                        RemoteIp: remoteIp,
                        RemotePort: remotePort,
                        Protocol: protocol == 6 ? IspAudit.Bypass.TransportProtocol.Tcp : IspAudit.Bypass.TransportProtocol.Udp,
                        DiscoveredAt: DateTime.UtcNow
                    );
                    
                    // Пишем в канал для yield return
                    writer.TryWrite(host);
                    
                    // Вызываем событие (для обратной совместимости)
                    OnHostDiscovered?.Invoke(host);
                }
            }
            
            // Подписка на DNS обновления
            void OnHostnameUpdated(string ip, string hostname)
            {
                foreach (var kvp in _connections)
                {
                    if (kvp.Value.RemoteIp.ToString() == ip && kvp.Value.Hostname != hostname)
                    {
                        kvp.Value.Hostname = hostname;
                        _progress?.Report($"[Collector] Hostname обновлен: {ip} → {hostname}");
                        OnHostnameResolved?.Invoke(ip, hostname);
                        
                        // Отправляем хост повторно для переоценки
                        var host = new HostDiscovered(
                            Key: kvp.Key,
                            RemoteIp: kvp.Value.RemoteIp,
                            RemotePort: kvp.Value.RemotePort,
                            Protocol: kvp.Value.Protocol == TransportProtocol.TCP 
                                ? IspAudit.Bypass.TransportProtocol.Tcp 
                                : IspAudit.Bypass.TransportProtocol.Udp,
                            DiscoveredAt: DateTime.UtcNow
                        );
                        writer.TryWrite(host);
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
                writer.Complete();
                
                _progress?.Report($"[Collector] Завершено. Всего соединений: {_connections.Count}");
            }
        }

        /// <summary>
        /// Получить собранные соединения с обогащением hostname
        /// </summary>
        public async Task<GameProfile> BuildProfileAsync(
            string? processName = null,
            CancellationToken cancellationToken = default)
        {
            _progress?.Report($"Генерация профиля для {_connections.Count} соединений...");

            // Обогащение hostname из DNS кеша и reverse DNS
            await EnrichHostnamesAsync(cancellationToken).ConfigureAwait(false);

            // Группируем по hostname (или IP)
            var targetGroups = _connections.Values
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

            return new GameProfile
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
