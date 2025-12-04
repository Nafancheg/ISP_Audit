using System;
using System.Collections.Concurrent;
using System.Net;
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
        private const bool VerboseDnsLogging = false;
        
        // Хранение активных запросов: TransactionID -> (Hostname, Timestamp)
        private readonly ConcurrentDictionary<ushort, (string Hostname, DateTime Timestamp)> _pendingRequests = new();
        
        // Хранение обнаруженных сбоев: Hostname -> Info
        private readonly ConcurrentDictionary<string, DnsFailureInfo> _failedRequests = new();

        public int ParsedCount { get; private set; }

        private readonly CancellationTokenSource _cts = new();
        
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
            _ = CleanupPendingRequestsLoop(_cts.Token);
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
                // Парсим исходящий запрос DNS
                TryParseDnsRequest(packet.Buffer, packet.Length);
                
                // Парсим TLS SNI (для определения хоста без DNS)
                TryParseTlsSni(packet.Buffer, packet.Length);
            }
            else
            {
                // Парсим входящий ответ DNS
                if (TryParseDnsResponse(packet.Buffer, packet.Length))
                {
                    ParsedCount++;
                }
            }
        }

        private void TryParseTlsSni(byte[] buffer, int length)
        {
            try
            {
                // 1. Parse IP Header to find Protocol and DestIP
                int ipVersion = (buffer[0] >> 4);
                int ipHeaderLen;
                int protocol;
                string destIp;

                if (ipVersion == 4)
                {
                    ipHeaderLen = (buffer[0] & 0x0F) * 4;
                    protocol = buffer[9];
                    destIp = new IPAddress(new byte[] { buffer[16], buffer[17], buffer[18], buffer[19] }).ToString();
                }
                else if (ipVersion == 6)
                {
                    ipHeaderLen = 40;
                    protocol = buffer[6]; // Next Header (simplified, doesn't handle extension headers)
                    var ipBytes = new byte[16];
                    Array.Copy(buffer, 24, ipBytes, 0, 16);
                    destIp = new IPAddress(ipBytes).ToString();
                }
                else return;

                if (protocol != 6) return; // Not TCP

                // 2. Parse TCP Header to find Payload
                int tcpOffset = ipHeaderLen;
                if (tcpOffset + 20 > length) return;
                
                int tcpHeaderLen = ((buffer[tcpOffset + 12] >> 4) & 0x0F) * 4;
                int payloadOffset = tcpOffset + tcpHeaderLen;
                
                if (payloadOffset >= length) return; // No payload

                // 3. Parse TLS Record
                // Content Type (1) + Version (2) + Length (2)
                if (payloadOffset + 5 > length) return;
                
                byte contentType = buffer[payloadOffset];
                if (contentType != 22) return; // Not Handshake

                // 4. Parse Handshake Protocol
                // Handshake Type (1) + Length (3)
                int handshakeOffset = payloadOffset + 5;
                if (handshakeOffset + 4 > length) return;
                
                byte handshakeType = buffer[handshakeOffset];
                if (handshakeType != 1) return; // Not Client Hello

                // 5. Parse Client Hello
                int pos = handshakeOffset + 4;
                
                // Version (2) + Random (32)
                pos += 34;
                if (pos >= length) return;

                // Session ID
                if (pos + 1 > length) return;
                int sessionIdLen = buffer[pos];
                pos += 1 + sessionIdLen;
                if (pos >= length) return;

                // Cipher Suites
                if (pos + 2 > length) return;
                int cipherSuitesLen = (buffer[pos] << 8) | buffer[pos + 1];
                pos += 2 + cipherSuitesLen;
                if (pos >= length) return;

                // Compression Methods
                if (pos + 1 > length) return;
                int compMethodsLen = buffer[pos];
                pos += 1 + compMethodsLen;
                if (pos >= length) return;

                // Extensions
                if (pos + 2 > length) return;
                int extensionsLen = (buffer[pos] << 8) | buffer[pos + 1];
                pos += 2;
                
                int extensionsEnd = pos + extensionsLen;
                if (extensionsEnd > length) extensionsEnd = length;

                while (pos + 4 <= extensionsEnd)
                {
                    int extType = (buffer[pos] << 8) | buffer[pos + 1];
                    int extLen = (buffer[pos + 2] << 8) | buffer[pos + 3];
                    pos += 4;

                    if (extType == 0) // Server Name (SNI)
                    {
                        if (pos + 2 <= extensionsEnd)
                        {
                            int listLen = (buffer[pos] << 8) | buffer[pos + 1];
                            int sniPos = pos + 2;
                            
                            if (sniPos + 3 <= extensionsEnd)
                            {
                                byte nameType = buffer[sniPos]; // 0 = host_name
                                int nameLen = (buffer[sniPos + 1] << 8) | buffer[sniPos + 2];
                                
                                if (nameType == 0 && sniPos + 3 + nameLen <= extensionsEnd)
                                {
                                    var hostname = System.Text.Encoding.ASCII.GetString(buffer, sniPos + 3, nameLen);
                                    if (!string.IsNullOrEmpty(hostname))
                                    {
                                        // Found SNI!
                                        var lowerName = hostname.ToLowerInvariant();
                                        
                                        // Update cache
                                        var isNew = true;
                                        if (_dnsCache.TryGetValue(destIp, out var existingName))
                                        {
                                            if (existingName == lowerName) isNew = false;
                                        }
                                        
                                        if (isNew)
                                        {
                                            _dnsCache[destIp] = lowerName;
                                            OnHostnameUpdated?.Invoke(destIp, lowerName);
                                            _progress?.Report($"[SNI] Detected: {destIp} -> {lowerName}");
                                        }
                                    }
                                }
                            }
                        }
                        break; // Found SNI, stop parsing extensions
                    }

                    pos += extLen;
                }
            }
            catch { }
        }

        private void TryParseDnsRequest(byte[] buffer, int length)
        {
            try
            {
                if (length < 28) return; // Минимум: IP (20) + UDP (8)
                
                // Проверяем протокол — должен быть UDP (17)
                int protocol = buffer[9];
                if (protocol != 17) return; // Не UDP — не DNS
                
                int ipHeaderLen = (buffer[0] & 0x0F) * 4;
                
                // Проверяем порт назначения — должен быть 53 (DNS)
                int destPort = (buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1];
                if (destPort != 53) return; // Не DNS порт
                
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
                    var lower = qname.ToLowerInvariant();
                    _pendingRequests[txId] = (lower, DateTime.UtcNow);

                    if (VerboseDnsLogging)
                    {
                        _progress?.Report($"[DNS][Req] txid={txId} qname={lower}");
                    }
                }
            }
            catch { }
        }

        private bool TryParseDnsResponse(byte[] buffer, int length)
        {
            try
            {
                if (length < 28) return false; // Минимум: IP (20) + UDP (8)
                
                // Проверяем протокол — должен быть UDP (17)
                int protocol = buffer[9];
                if (protocol != 17) return false; // Не UDP — не DNS
                
                int ipHeaderLen = (buffer[0] & 0x0F) * 4;
                
                // Проверяем порт источника — должен быть 53 (DNS ответ)
                int srcPort = (buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1];
                if (srcPort != 53) return false; // Не DNS порт
                
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
                        if (VerboseDnsLogging)
                        {
                            _progress?.Report($"[DNS][Resp][ERR] txid={txId} host={requestInfo.Hostname} rcode={rcode}");
                        }
                    }
                    else if (VerboseDnsLogging)
                    {
                        _progress?.Report($"[DNS][Resp] txid={txId} host={requestInfo.Hostname} rcode=0");
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
                        var ip = new IPAddress(new byte[] { buffer[pos], buffer[pos + 1], buffer[pos + 2], buffer[pos + 3] }).ToString();
                        if (!string.IsNullOrEmpty(name))
                        {
                            var lowerName = name.ToLowerInvariant();
                            var isNew = true;
                            if (_dnsCache.TryGetValue(ip, out var existingName))
                            {
                                if (existingName == lowerName) isNew = false;
                            }
                            
                            if (isNew)
                            {
                                _dnsCache[ip] = lowerName;
                                OnHostnameUpdated?.Invoke(ip, lowerName);
                                if (VerboseDnsLogging)
                                {
                                    _progress?.Report($"[DNS][A] {lowerName} -> {ip}");
                                }
                            }
                        }
                    }
                    // Тип AAAA (IPv6)
                    else if (type == 28 && dataLen == 16 && pos + 16 <= length)
                    {
                        var ipBytes = new byte[16];
                        Array.Copy(buffer, pos, ipBytes, 0, 16);
                        var ip = new IPAddress(ipBytes).ToString();
                        if (!string.IsNullOrEmpty(name))
                        {
                            var lowerName = name.ToLowerInvariant();
                            var isNew = true;
                            if (_dnsCache.TryGetValue(ip, out var existingName))
                            {
                                if (existingName == lowerName) isNew = false;
                            }
                            
                            if (isNew)
                            {
                                _dnsCache[ip] = lowerName;
                                OnHostnameUpdated?.Invoke(ip, lowerName);
                                if (VerboseDnsLogging)
                                {
                                    _progress?.Report($"[DNS][AAAA] {lowerName} -> {ip}");
                                }
                            }
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

        private async Task CleanupPendingRequestsLoop(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, cancellationToken).ConfigureAwait(false); // Проверка каждые 5 секунд
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                var now = DateTime.UtcNow;
                var timeout = TimeSpan.FromSeconds(5); // Таймаут DNS запроса

                foreach (var kvp in _pendingRequests)
                {
                    if (now - kvp.Value.Timestamp > timeout &&
                        _pendingRequests.TryRemove(kvp.Key, out var info))
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
            try
            {
                _cts.Cancel();
            }
            catch
            {
            }

            StopAsync().GetAwaiter().GetResult();
            _cts.Dispose();
        }

        public event Action<string, string>? OnDnsLookupFailed;
        
        /// <summary>
        /// Событие при обновлении/добавлении hostname для IP (IP, Hostname)
        /// </summary>
        public event Action<string, string>? OnHostnameUpdated;
    }

    public class DnsFailureInfo
    {
        public string Hostname { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Error { get; set; } = "";
    }
}
