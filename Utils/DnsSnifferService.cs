using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    /// <summary>
    /// Сервис для парсинга DNS-ответов из пакетов NetworkMonitorService.
    /// </summary>
    public class DnsParserService : IDisposable
    {
        private readonly NetworkMonitorService _networkMonitor;
        private readonly IProgress<string>? _progress;
        private readonly ConcurrentDictionary<string, string> _dnsCache;
        
        // Хранение активных запросов: TransactionID -> (Hostname, Timestamp)
        private readonly ConcurrentDictionary<ushort, (string Hostname, DateTime Timestamp)> _pendingRequests = new();
        
        // Хранение обнаруженных сбоев: Hostname -> Info
        private readonly ConcurrentDictionary<string, DnsFailureInfo> _failedRequests = new();

        public int ParsedCount { get; private set; }
        
        /// <summary>
        /// Кеш DNS: IP → hostname
        /// </summary>
        public IReadOnlyDictionary<string, string> DnsCache => _dnsCache;

        /// <summary>
        /// Список доменов, для которых DNS-запрос завершился ошибкой или таймаутом
        /// </summary>
        public IReadOnlyDictionary<string, DnsFailureInfo> FailedRequests => _failedRequests;

        public DnsParserService(NetworkMonitorService networkMonitor, IProgress<string>? progress = null)
        {
            _networkMonitor = networkMonitor ?? throw new ArgumentNullException(nameof(networkMonitor));
            _progress = progress;
            _dnsCache = new ConcurrentDictionary<string, string>();
            
            // Запускаем очистку старых pending запросов (таймауты)
            _ = CleanupPendingRequestsLoop();
        }

        public Task StartAsync()
        {
            _networkMonitor.OnPacketReceived += OnPacketReceived;
            _progress?.Report("[DnsParser] ✓ Подписка на NetworkMonitor активна");
            return Task.CompletedTask;
        }

        private void OnPacketReceived(PacketData packet)
        {
            if (packet.IsOutbound)
            {
                // Парсим исходящий запрос
                TryParseDnsRequest(packet.Buffer, packet.Length);
            }
            else
            {
                // Парсим входящий ответ
                if (TryParseDnsResponse(packet.Buffer, packet.Length))
                {
                    ParsedCount++;
                }
            }
        }

        private void TryParseDnsRequest(byte[] buffer, int length)
        {
            try
            {
                if (length < 20) return;
                
                int ipHeaderLen = (buffer[0] & 0x0F) * 4;
                int udpHeaderLen = 8;
                int dnsOffset = ipHeaderLen + udpHeaderLen;
                
                if (dnsOffset + 12 > length) return;

                // Transaction ID
                ushort txId = (ushort)((buffer[dnsOffset] << 8) | buffer[dnsOffset + 1]);
                
                // Flags
                int flags = (buffer[dnsOffset + 2] << 8) | buffer[dnsOffset + 3];
                bool isResponse = (flags & 0x8000) != 0;
                if (isResponse) return; // Это не запрос

                // Парсим имя вопроса
                int pos = dnsOffset + 12;
                string? qname = ReadDnsName(buffer, pos, dnsOffset);
                
                if (!string.IsNullOrEmpty(qname))
                {
                    _pendingRequests[txId] = (qname.ToLowerInvariant(), DateTime.UtcNow);
                }
            }
            catch { }
        }

        private bool TryParseDnsResponse(byte[] buffer, int length)
        {
            try
            {
                if (length < 20) return false;
                
                int ipHeaderLen = (buffer[0] & 0x0F) * 4;
                int udpHeaderLen = 8;
                int dnsOffset = ipHeaderLen + udpHeaderLen;
                
                if (dnsOffset + 12 > length) return false;
                
                // Transaction ID
                ushort txId = (ushort)((buffer[dnsOffset] << 8) | buffer[dnsOffset + 1]);

                // DNS header
                int flags = (buffer[dnsOffset + 2] << 8) | buffer[dnsOffset + 3];
                bool isResponse = (flags & 0x8000) != 0;
                if (!isResponse) return false;
                
                // RCODE (нижние 4 бита флагов)
                int rcode = flags & 0x0F;
                
                // Проверяем, был ли такой запрос
                if (_pendingRequests.TryRemove(txId, out var requestInfo))
                {
                    if (rcode != 0) // Ошибка (NXDOMAIN, SERVFAIL и т.д.)
                    {
                        _failedRequests[requestInfo.Hostname] = new DnsFailureInfo
                        {
                            Hostname = requestInfo.Hostname,
                            Timestamp = DateTime.UtcNow,
                            Error = $"DNS Error RCODE={rcode}"
                        };
                        OnDnsLookupFailed?.Invoke(requestInfo.Hostname, $"DNS Error RCODE={rcode}");
                    }
                }

                int answerCount = (buffer[dnsOffset + 6] << 8) | buffer[dnsOffset + 7];
                if (answerCount == 0) return false;
                
                int pos = dnsOffset + 12;
                
                // Пропускаем секцию вопросов
                int questionCount = (buffer[dnsOffset + 4] << 8) | buffer[dnsOffset + 5];
                for (int q = 0; q < questionCount; q++)
                {
                    while (pos < length && buffer[pos] != 0)
                    {
                        if ((buffer[pos] & 0xC0) == 0xC0)
                        {
                            pos += 2;
                            break;
                        }
                        pos += buffer[pos] + 1;
                    }
                    pos += 5; // null terminator + type + class
                    if (pos >= length) return false;
                }
                
                // Парсим секцию ответов (A-записи)
                for (int a = 0; a < answerCount && pos + 12 < length; a++)
                {
                    string? name = null;
                    
                    // Читаем имя (с обработкой сжатия)
                    // ВАЖНО: В DNS ответе имя в секции Answer часто является указателем на имя в секции Question.
                    // Но иногда это CNAME. Нам нужно имя, к которому был запрос (Question Name), 
                    // но здесь мы парсим Answer.
                    // Если это A-запись, то 'name' - это имя хоста.
                    
                    if ((buffer[pos] & 0xC0) == 0xC0)
                    {
                        int pointer = ((buffer[pos] & 0x3F) << 8) | buffer[pos + 1];
                        name = ReadDnsName(buffer, dnsOffset + pointer, dnsOffset);
                        pos += 2;
                    }
                    else
                    {
                        name = ReadDnsName(buffer, pos, dnsOffset);
                        while (pos < length && buffer[pos] != 0)
                        {
                            pos += buffer[pos] + 1;
                        }
                        pos++;
                    }
                    
                    if (pos + 10 > length) break;
                    
                    int type = (buffer[pos] << 8) | buffer[pos + 1];
                    int dataLen = (buffer[pos + 8] << 8) | buffer[pos + 9];
                    pos += 10;
                    
                    // Тип A (IPv4)
                    if (type == 1 && dataLen == 4 && pos + 4 <= length)
                    {
                        var ip = $"{buffer[pos]}.{buffer[pos + 1]}.{buffer[pos + 2]}.{buffer[pos + 3]}";
                        if (!string.IsNullOrEmpty(name))
                        {
                            // Сохраняем имя в нижнем регистре для консистентности
                            _dnsCache[ip] = name.ToLowerInvariant();
                        }
                    }
                    // Тип CNAME (5) - можно было бы отслеживать цепочки, но пока просто пропускаем
                    
                    pos += dataLen;
                }
                
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task CleanupPendingRequestsLoop()
        {
            while (true)
            {
                await Task.Delay(5000); // Проверка каждые 5 секунд
                var now = DateTime.UtcNow;
                var timeout = TimeSpan.FromSeconds(5); // Таймаут DNS запроса

                foreach (var kvp in _pendingRequests)
                {
                    if (now - kvp.Value.Timestamp > timeout)
                    {
                        if (_pendingRequests.TryRemove(kvp.Key, out var info))
                        {
                            // Запрос протух - считаем таймаутом
                            _failedRequests[info.Hostname] = new DnsFailureInfo
                            {
                                Hostname = info.Hostname,
                                Timestamp = now,
                                Error = "Timeout"
                            };
                            OnDnsLookupFailed?.Invoke(info.Hostname, "Timeout");
                        }
                    }
                }
            }
        }

        private static string? ReadDnsName(byte[] buffer, int pos, int dnsOffset)
        {
            var parts = new System.Collections.Generic.List<string>();
            int maxIterations = 50;
            
            while (pos < buffer.Length && buffer[pos] != 0 && maxIterations-- > 0)
            {
                if ((buffer[pos] & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= buffer.Length) break;
                    int pointer = ((buffer[pos] & 0x3F) << 8) | buffer[pos + 1];
                    pos = dnsOffset + pointer;
                    continue;
                }
                
                int len = buffer[pos];
                if (len == 0 || pos + len + 1 > buffer.Length) break;
                
                var label = System.Text.Encoding.ASCII.GetString(buffer, pos + 1, len);
                parts.Add(label);
                pos += len + 1;
            }
            
            return parts.Count > 0 ? string.Join(".", parts) : null;
        }

        public Task StopAsync()
        {
            _networkMonitor.OnPacketReceived -= OnPacketReceived;
            _progress?.Report($"[DnsParser] Завершение. Распарсено ответов: {ParsedCount}, кеш: {_dnsCache.Count} записей");
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            StopAsync().GetAwaiter().GetResult();
        }

        public event Action<string, string>? OnDnsLookupFailed;
    }

    public class DnsFailureInfo
    {
        public string Hostname { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Error { get; set; } = "";
    }
}
