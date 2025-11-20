using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;

namespace IspAudit.Utils
{
    /// <summary>
    /// Анализатор сетевого трафика процесса через WinDivert NETWORK layer + GetExtendedTcpTable
    /// </summary>
    internal static class TrafficAnalyzer
    {
        /// <summary>
        /// Анализирует сетевой трафик указанного процесса и генерирует GameProfile
        /// </summary>
        public static async Task<GameProfile> AnalyzeProcessTrafficAsync(
            int targetPid,
            TimeSpan captureTimeout,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            progress?.Report($"Старт захвата трафика процесса PID={targetPid} на {captureTimeout.TotalSeconds}с");

            var connections = new ConcurrentDictionary<string, NetworkConnection>();
            var dnsCache = new ConcurrentDictionary<string, string>(); // IP → hostname from DNS responses

            // WinDivert filter: захватываем TCP/UDP (включая DNS порт 53)
            // Фильтрация по PID делается через сопоставление локальных портов с GetExtendedTcpTable
            var filter = "outbound and (tcp or udp)";

            WinDivertNative.SafeHandle? handle = null;
            try
            {
                // Открыть NETWORK layer (захват IP пакетов)
                // Sniff флаг - пассивный мониторинг без изменения пакетов
                handle = WinDivertNative.Open(filter, WinDivertNative.Layer.Network, 0, WinDivertNative.OpenFlags.Sniff);
                progress?.Report("WinDivert NETWORK layer активирован");

                // Захват трафика с таймаутом
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(captureTimeout);

                await Task.Run(() => CaptureLoop(handle, targetPid, connections, dnsCache, progress, cts.Token), cts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                progress?.Report($"Захват завершен: timeout {captureTimeout.TotalSeconds}с");
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 87)
            {
                progress?.Report("Ошибка 87 (ERROR_INVALID_PARAMETER): Невалидный фильтр или несовместимая конфигурация WinDivert");
                throw new InvalidOperationException($"WinDivert NETWORK layer ошибка. Filter: {filter}. Убедитесь что WinDivert 2.2+ установлен.", ex);
            }
            catch (Exception ex)
            {
                progress?.Report($"Ошибка захвата: {ex.Message}");
                throw;
            }
            finally
            {
                handle?.Dispose();
            }

            // Reverse DNS для hostname (используем DNS cache в первую очередь)
            await EnrichWithHostnamesAsync(connections, dnsCache, progress, cancellationToken).ConfigureAwait(false);

            // Генерация GameProfile
            var profile = BuildGameProfile(connections, progress);
            progress?.Report($"Профиль создан: {profile.Targets.Count} целей, {connections.Count} соединений");

            return profile;
        }

        /// <summary>
        /// Цикл захвата пакетов из WinDivert
        /// </summary>
        private static void CaptureLoop(
            WinDivertNative.SafeHandle handle,
            int targetPid,
            ConcurrentDictionary<string, NetworkConnection> connections,
            ConcurrentDictionary<string, string> dnsCache,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[WinDivertNative.MaxPacketSize];
            var addr = new WinDivertNative.Address();
            uint readLen;

            int packetCount = 0;
            int matchedPackets = 0;

            // Кэш: localPort → PID (обновляется каждые 2 секунды)
            var portToPidCache = new ConcurrentDictionary<ushort, int>();
            var lastCacheUpdate = DateTime.UtcNow.AddSeconds(-10); // Force initial update

            while (!cancellationToken.IsCancellationRequested)
            {
                // Recv блокирующий, прерывается через CancellationToken -> WinDivertShutdown
                if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref addr, out readLen))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted)
                        break; // Handle закрыт или отменено

                    // Логируем неожиданные ошибки
                    if (error != 0)
                        progress?.Report($"WinDivert Recv ошибка: {error}");
                    
                    continue;
                }

                // Игнорируем loopback
                if (addr.IsLoopback)
                    continue;

                packetCount++;

                // Обновляем кэш портов каждые 2 секунды (и сразу при первом пакете)
                if ((DateTime.UtcNow - lastCacheUpdate).TotalSeconds >= 2)
                {
                    int portsBefore = portToPidCache.Count;
                    UpdatePortToPidCache(portToPidCache, targetPid, progress);
                    lastCacheUpdate = DateTime.UtcNow;
                    
                    if (portToPidCache.Count == 0)
                    {
                        progress?.Report($"⚠️ Кэш пуст после обновления: процесс PID={targetPid} не имеет активных TCP/UDP соединений (было: {portsBefore})");
                    }
                    else if (portsBefore != portToPidCache.Count)
                    {
                        progress?.Report($"Кэш портов обновлен: {portsBefore} → {portToPidCache.Count} портов");
                    }
                }

                // Обрабатываем IP пакет
                // 1. Парсим DNS ответы (UDP port 53) для hostname mapping
                // 2. Парсим TCP/UDP для connection tracking
                ProcessPacket(buffer, (int)readLen, addr, targetPid, portToPidCache, connections, dnsCache, ref matchedPackets, progress);

                // Периодический отчет
                if (packetCount % 500 == 0)
                    progress?.Report($"Пакетов: {packetCount}, совпало PID: {matchedPackets}, соединений: {connections.Count}");
            }

            progress?.Report($"Захват завершен: {packetCount} пакетов захвачено, {matchedPackets} от PID={targetPid}, {connections.Count} уникальных соединений");
            
            if (connections.Count == 0)
            {
                progress?.Report("⚠️ ДИАГНОСТИКА: Соединения не обнаружены.");
                progress?.Report($"   • Всего пакетов обработано: {packetCount}");
                progress?.Report($"   • Пакетов от целевого PID: {matchedPackets}");
                progress?.Report($"   • Портов в финальном кэше: {portToPidCache.Count}");
                if (portToPidCache.Count > 0)
                {
                    var ports = string.Join(", ", portToPidCache.Keys.Take(10));
                    progress?.Report($"   • Порты процесса: {ports}{(portToPidCache.Count > 10 ? "..." : "")}");
                }
                progress?.Report("");
                progress?.Report("Возможные причины:");
                progress?.Report("   1. Процесс не устанавливал новые соединения за 30 сек");
                progress?.Report("   2. Соединения установлены ДО захвата (WinDivert запустился поздно)");
                progress?.Report("   3. Процесс использует существующие keep-alive соединения");
                progress?.Report("   4. Файрволл блокирует процесс");
            }
        }

        /// <summary>
        /// Обновляет кэш localPort → PID для всех портов целевого процесса
        /// </summary>
        private static void UpdatePortToPidCache(
            ConcurrentDictionary<ushort, int> cache,
            int targetPid,
            IProgress<string>? progress)
        {
            try
            {
                cache.Clear();
                int tcpCount = 0;
                int udpCount = 0;

                // TCP порты
                int bufferSize = 0;
                int result = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 2, 5, 0);
                
                if (bufferSize > 0)
                {
                    var buffer = Marshal.AllocHGlobal(bufferSize);
                    try
                    {
                        result = NativeMethods.GetExtendedTcpTable(buffer, ref bufferSize, false, 2, 5, 0);
                        if (result == 0)
                        {
                            int entryCount = Marshal.ReadInt32(buffer);
                            IntPtr rowPtr = buffer + 4;

                            for (int i = 0; i < entryCount; i++)
                            {
                                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
                                
                                if (row.OwningPid == targetPid)
                                {
                                    ushort port = (ushort)IPAddress.NetworkToHostOrder((short)row.LocalPort);
                                    cache[port] = targetPid;
                                    tcpCount++;
                                }

                                rowPtr += Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();
                            }
                        }
                        else
                        {
                            progress?.Report($"⚠️ GetExtendedTcpTable failed with error {result}");
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }

                // UDP порты
                bufferSize = 0;
                result = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, false, 2, 1, 0);
                
                if (bufferSize > 0)
                {
                    var udpBuffer = Marshal.AllocHGlobal(bufferSize);
                    try
                    {
                        result = NativeMethods.GetExtendedUdpTable(udpBuffer, ref bufferSize, false, 2, 1, 0);
                        if (result == 0)
                        {
                            int entryCount = Marshal.ReadInt32(udpBuffer);
                            IntPtr rowPtr = udpBuffer + 4;

                            for (int i = 0; i < entryCount; i++)
                            {
                                var row = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(rowPtr);
                                
                                if (row.OwningPid == targetPid)
                                {
                                    ushort port = (ushort)IPAddress.NetworkToHostOrder((short)row.LocalPort);
                                    cache[port] = targetPid;
                                    udpCount++;
                                }

                                rowPtr += Marshal.SizeOf<NativeMethods.MIB_UDPROW_OWNER_PID>();
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(udpBuffer);
                    }
                }

                if (cache.Count > 0)
                {
                    progress?.Report($"✓ Кэш обновлен: {tcpCount} TCP + {udpCount} UDP = {cache.Count} портов процесса PID={targetPid}");
                }
                else
                {
                    progress?.Report($"⚠️ Процесс PID={targetPid} не имеет активных TCP/UDP портов (возможно, еще не установил соединения)");
                }
            }
            catch (Exception ex)
            {
                progress?.Report($"❌ Ошибка обновления кэша портов: {ex.Message}");
            }
        }

        /// <summary>
        /// Обрабатывает IP пакет: парсит DNS ответы и TCP/UDP соединения
        /// </summary>
        private static void ProcessPacket(
            byte[] buffer,
            int length,
            WinDivertNative.Address addr,
            int targetPid,
            ConcurrentDictionary<ushort, int> portToPidCache,
            ConcurrentDictionary<string, NetworkConnection> connections,
            ConcurrentDictionary<string, string> dnsCache,
            ref int matchedPackets,
            IProgress<string>? progress)
        {
            if (addr.IsIPv6 || length < 20)
                return; // IPv4 only, минимум IP header

            // Парсинг IPv4 заголовка
            int ipHeaderLen = (buffer[0] & 0x0F) * 4;
            if (length < ipHeaderLen + 8) // IP + минимум TCP/UDP header
                return;

            byte protocol = buffer[9]; // Protocol field в IP header
            
            // Destination IP (bytes 16-19 в IP header)
            var remoteIp = new IPAddress(new byte[] { buffer[16], buffer[17], buffer[18], buffer[19] });
            
            if (IsLocalAddress(remoteIp))
                return;

            ushort localPort = 0;
            ushort remotePort = 0;
            TransportProtocol transportProto;

            if (protocol == 6) // TCP
            {
                if (length < ipHeaderLen + 20) // Минимум TCP header
                    return;
                    
                localPort = (ushort)((buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1]);
                remotePort = (ushort)((buffer[ipHeaderLen + 2] << 8) | buffer[ipHeaderLen + 3]);
                transportProto = TransportProtocol.TCP;
                
                // Попытка извлечь SNI из TLS ClientHello (port 443)
                if (remotePort == 443 && length > ipHeaderLen + 40)
                {
                    TryExtractSniFromTls(buffer, ipHeaderLen, length, remoteIp, dnsCache);
                }
            }
            else if (protocol == 17) // UDP
            {
                if (length < ipHeaderLen + 8) // UDP header = 8 bytes
                    return;
                    
                localPort = (ushort)((buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1]);
                remotePort = (ushort)((buffer[ipHeaderLen + 2] << 8) | buffer[ipHeaderLen + 3]);
                transportProto = TransportProtocol.UDP;
                
                // Парсинг DNS ответов (port 53)
                if (remotePort == 53 && length > ipHeaderLen + 20)
                {
                    TryParseDnsResponse(buffer, ipHeaderLen + 8, length, dnsCache);
                }
            }
            else
            {
                return; // Не TCP/UDP
            }

            // Проверяем PID через кэш портов (быстрая проверка без API вызовов)
            if (!portToPidCache.TryGetValue(localPort, out int cachedPid) || cachedPid != targetPid)
                return; // Не наш процесс

            matchedPackets++;
            
            // Логируем первые 5 совпадений для диагностики
            if (matchedPackets <= 5)
            {
                progress?.Report($"✓ Пакет #{matchedPackets}: {transportProto} localPort={localPort} → {remoteIp}:{remotePort}");
            }

            // Добавляем соединение
            var key = $"{remoteIp}:{remotePort}:{transportProto}";

            connections.AddOrUpdate(
                key,
                _ => new NetworkConnection
                {
                    RemoteIp = remoteIp,
                    RemotePort = remotePort,
                    Protocol = transportProto,
                    PacketCount = 1,
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow
                },
                (_, existing) =>
                {
                    existing.PacketCount++;
                    existing.LastSeen = DateTime.UtcNow;
                    return existing;
                });
        }

        /// <summary>
        /// Пытается извлечь SNI (Server Name Indication) из TLS ClientHello
        /// </summary>
        private static void TryExtractSniFromTls(
            byte[] buffer,
            int ipHeaderLen,
            int totalLength,
            IPAddress remoteIp,
            ConcurrentDictionary<string, string> dnsCache)
        {
            try
            {
                // TCP header length
                int tcpHeaderLen = ((buffer[ipHeaderLen + 12] >> 4) & 0x0F) * 4;
                int tlsOffset = ipHeaderLen + tcpHeaderLen;

                if (totalLength < tlsOffset + 43) // Минимум TLS handshake
                    return;

                // TLS record: Content Type (0x16 = Handshake), Version, Length
                if (buffer[tlsOffset] != 0x16) // Not Handshake
                    return;

                // Handshake Type (0x01 = ClientHello)
                if (buffer[tlsOffset + 5] != 0x01)
                    return;

                // Ищем SNI extension (type 0x0000)
                int pos = tlsOffset + 43; // Skip fixed ClientHello fields
                
                // Session ID length
                if (totalLength < pos + 1)
                    return;
                int sessionIdLen = buffer[pos];
                pos += 1 + sessionIdLen;

                // Cipher Suites length
                if (totalLength < pos + 2)
                    return;
                int cipherSuitesLen = (buffer[pos] << 8) | buffer[pos + 1];
                pos += 2 + cipherSuitesLen;

                // Compression Methods length
                if (totalLength < pos + 1)
                    return;
                int compressionLen = buffer[pos];
                pos += 1 + compressionLen;

                // Extensions length
                if (totalLength < pos + 2)
                    return;
                int extensionsLen = (buffer[pos] << 8) | buffer[pos + 1];
                pos += 2;

                int extensionsEnd = pos + extensionsLen;
                
                while (pos + 4 < extensionsEnd && pos + 4 < totalLength)
                {
                    int extType = (buffer[pos] << 8) | buffer[pos + 1];
                    int extLen = (buffer[pos + 2] << 8) | buffer[pos + 3];
                    pos += 4;

                    if (extType == 0) // SNI extension
                    {
                        if (pos + extLen > totalLength)
                            return;

                        // SNI list length (2 bytes)
                        if (extLen < 5)
                            return;
                        
                        int sniListLen = (buffer[pos] << 8) | buffer[pos + 1];
                        pos += 2;

                        // SNI entry: type (1 byte), length (2 bytes), name
                        if (buffer[pos] == 0) // Type 0 = hostname
                        {
                            int nameLen = (buffer[pos + 1] << 8) | buffer[pos + 2];
                            pos += 3;

                            if (pos + nameLen <= totalLength)
                            {
                                string hostname = System.Text.Encoding.ASCII.GetString(buffer, pos, nameLen);
                                dnsCache[remoteIp.ToString()] = hostname;
                                return;
                            }
                        }
                        return;
                    }

                    pos += extLen;
                }
            }
            catch
            {
                // Парсинг TLS ненадежен - игнорируем ошибки
            }
        }

        /// <summary>
        /// Пытается распарсить DNS ответ и извлечь A records
        /// </summary>
        private static void TryParseDnsResponse(
            byte[] buffer,
            int dnsOffset,
            int totalLength,
            ConcurrentDictionary<string, string> dnsCache)
        {
            try
            {
                if (totalLength < dnsOffset + 12) // DNS header = 12 bytes
                    return;

                // DNS header: [0-1] Transaction ID, [2-3] Flags, [4-5] Questions, [6-7] Answers, [8-9] Authority, [10-11] Additional
                byte flags = buffer[dnsOffset + 2];
                
                // Проверяем: это Response (QR=1) и без ошибок (RCODE=0)
                if ((flags & 0x80) == 0 || (buffer[dnsOffset + 3] & 0x0F) != 0)
                    return;

                int questionsCount = (buffer[dnsOffset + 4] << 8) | buffer[dnsOffset + 5];
                int answersCount = (buffer[dnsOffset + 6] << 8) | buffer[dnsOffset + 7];

                if (answersCount == 0)
                    return;

                int pos = dnsOffset + 12;

                // Skip questions section
                for (int i = 0; i < questionsCount; i++)
                {
                    // Read QNAME (labels до 0x00)
                    string? qname = ReadDnsName(buffer, ref pos, totalLength, dnsOffset);
                    if (qname == null || pos + 4 > totalLength)
                        return;
                    
                    pos += 4; // Skip QTYPE (2) + QCLASS (2)
                }

                // Parse answers section (A records only)
                for (int i = 0; i < answersCount && pos < totalLength; i++)
                {
                    string? name = ReadDnsName(buffer, ref pos, totalLength, dnsOffset);
                    if (name == null || pos + 10 > totalLength)
                        return;

                    int rrType = (buffer[pos] << 8) | buffer[pos + 1]; // TYPE
                    pos += 8; // Skip TYPE (2) + CLASS (2) + TTL (4)
                    
                    int rdLength = (buffer[pos] << 8) | buffer[pos + 1];
                    pos += 2;

                    if (pos + rdLength > totalLength)
                        return;

                    // A record (TYPE = 1, IPv4)
                    if (rrType == 1 && rdLength == 4)
                    {
                        var ip = new IPAddress(new byte[] { buffer[pos], buffer[pos + 1], buffer[pos + 2], buffer[pos + 3] });
                        dnsCache[ip.ToString()] = name;
                    }

                    pos += rdLength;
                }
            }
            catch
            {
                // DNS парсинг ненадежен - игнорируем ошибки
            }
        }

        /// <summary>
        /// Читает DNS name (с поддержкой compression)
        /// </summary>
        private static string? ReadDnsName(byte[] buffer, ref int pos, int totalLength, int dnsOffset)
        {
            var labels = new List<string>();
            int jumps = 0;
            int originalPos = -1;

            while (pos < totalLength && jumps < 10)
            {
                int len = buffer[pos];

                if (len == 0) // End of name
                {
                    pos++;
                    break;
                }

                // Compression pointer (2 bytes: 11xxxxxx xxxxxxxx)
                if ((len & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= totalLength)
                        return null;

                    if (originalPos == -1)
                        originalPos = pos + 2; // Save position after pointer

                    int offset = ((len & 0x3F) << 8) | buffer[pos + 1];
                    pos = dnsOffset + offset;
                    jumps++;
                    continue;
                }

                // Regular label
                if (pos + 1 + len > totalLength)
                    return null;

                string label = System.Text.Encoding.ASCII.GetString(buffer, pos + 1, len);
                labels.Add(label);
                pos += 1 + len;
            }

            if (originalPos != -1)
                pos = originalPos;

            return labels.Count > 0 ? string.Join(".", labels) : null;
        }

        /// <summary>
        /// P/Invoke для Windows IP Helper API
        /// </summary>
        private static class NativeMethods
        {
            [DllImport("iphlpapi.dll", SetLastError = true)]
            internal static extern int GetExtendedTcpTable(
                IntPtr pTcpTable,
                ref int pdwSize,
                bool bOrder,
                int ulAf,
                int tableClass,
                int reserved);

            [DllImport("iphlpapi.dll", SetLastError = true)]
            internal static extern int GetExtendedUdpTable(
                IntPtr pUdpTable,
                ref int pdwSize,
                bool bOrder,
                int ulAf,
                int tableClass,
                int reserved);

            [StructLayout(LayoutKind.Sequential)]
            internal struct MIB_TCPROW_OWNER_PID
            {
                public uint State;
                public uint LocalAddr;
                public int LocalPort; // Big-endian
                public uint RemoteAddr;
                public int RemotePort; // Big-endian
                public int OwningPid;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct MIB_UDPROW_OWNER_PID
            {
                public uint LocalAddr;
                public int LocalPort; // Big-endian
                public int OwningPid;
            }
        }

        /// <summary>
        /// Обогащение соединений hostname из DNS cache + Reverse DNS fallback
        /// </summary>
        private static async Task EnrichWithHostnamesAsync(
            ConcurrentDictionary<string, NetworkConnection> connections,
            ConcurrentDictionary<string, string> dnsCache,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            progress?.Report($"Обогащение hostname для {connections.Count} соединений...");

            int fromCache = 0;
            int fromReverseDns = 0;

            // Сначала используем DNS cache (из DNS responses + SNI)
            foreach (var conn in connections.Values)
            {
                string ipStr = conn.RemoteIp.ToString();
                if (dnsCache.TryGetValue(ipStr, out string? hostname))
                {
                    conn.Hostname = hostname.ToLowerInvariant();
                    fromCache++;
                }
            }

            // Для оставшихся - Reverse DNS
            var remainingConnections = connections.Values.Where(c => c.Hostname == null).ToList();
            
            if (remainingConnections.Any())
            {
                var tasks = remainingConnections.Select(async conn =>
                {
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(conn.RemoteIp.ToString(), AddressFamily.InterNetwork, cancellationToken).ConfigureAwait(false);
                        if (entry.HostName != null)
                        {
                            conn.Hostname = entry.HostName.ToLowerInvariant();
                            System.Threading.Interlocked.Increment(ref fromReverseDns);
                        }
                    }
                    catch
                    {
                        // Reverse DNS failed
                    }
                });

                await Task.WhenAll(tasks).ConfigureAwait(false);
            }

            var totalResolved = connections.Values.Count(c => c.Hostname != null);
            progress?.Report($"✓ Hostname resolved: {totalResolved}/{connections.Count} ({fromCache} from DNS cache, {fromReverseDns} from reverse DNS)");
        }

        /// <summary>
        /// Генерация GameProfile из захваченных соединений
        /// </summary>
        private static GameProfile BuildGameProfile(
            ConcurrentDictionary<string, NetworkConnection> connections,
            IProgress<string>? progress)
        {
            // Группируем по hostname (если есть) или IP
            var targetGroups = connections.Values
                .GroupBy(c => c.Hostname ?? c.RemoteIp.ToString())
                .OrderByDescending(g => g.Sum(c => c.PacketCount)) // Сортировка по активности
                .ToList();

            var targets = new List<TargetDefinition>();

            foreach (var group in targetGroups)
            {
                var hostname = group.Key;
                var portsUsed = group.Select(c => c.RemotePort).Distinct().OrderBy(p => p).ToList();
                var protocols = group.Select(c => c.Protocol).Distinct().ToList();

                var target = new TargetDefinition
                {
                    Name = hostname,
                    Host = hostname,
                    Service = DetermineService(hostname, portsUsed),
                    Critical = false, // Пользователь может пометить вручную
                };

                targets.Add(target);

                progress?.Report($"  - {hostname}: {string.Join(",", portsUsed)} ({string.Join(",", protocols)})");
            }

            return new GameProfile
            {
                Name = "CapturedProfile",
                TestMode = "host",
                ExePath = "",
                Targets = targets
            };
        }

        /// <summary>
        /// Определяет тип сервиса по hostname/портам
        /// </summary>
        private static string DetermineService(string hostname, List<ushort> ports)
        {
            // Эвристика на основе портов
            if (ports.Contains(443) || ports.Contains(80))
                return "web";
            if (ports.Any(p => p >= 27000 && p <= 28000))
                return "game";
            if (ports.Any(p => p >= 64000 && p <= 65000))
                return "voice";
            return "unknown";
        }

        /// <summary>
        /// Проверяет, является ли IP локальным/приватным
        /// </summary>
        private static bool IsLocalAddress(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork)
                return false;

            var bytes = ip.GetAddressBytes();

            // 10.0.0.0/8
            if (bytes[0] == 10)
                return true;

            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                return true;

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
                return true;

            // 127.0.0.0/8
            if (bytes[0] == 127)
                return true;

            return false;
        }
    }
}
