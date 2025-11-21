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
    /// Анализатор сетевого трафика процесса через WinDivert Dual Layer (Network + Flow).
    /// Использует Layer.Flow для точного определения PID и Layer.Network для захвата пакетов.
    /// </summary>
    internal static class TrafficAnalyzer
    {
        // Структура для хранения заголовков пакетов (без payload для экономии памяти)
        private struct PacketHeader
        {
            public DateTime Timestamp;
            public ushort LocalPort;
            public IPAddress RemoteIp;
            public ushort RemotePort;
            public TransportProtocol Protocol;
            public int TotalSize;
            // Можно добавить TCP flags если нужно
        }

        // Ключ для маппинга потоков: (LocalPort, Protocol)
        private record struct FlowKey(ushort LocalPort, byte Protocol);

        /// <summary>
        /// Анализирует сетевой трафик указанного процесса и генерирует GameProfile
        /// </summary>
        public static async Task<GameProfile> AnalyzeProcessTrafficAsync(
            int targetPid,
            TimeSpan captureTimeout,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            // Выполняем всё в фоновом потоке, чтобы не блокировать UI при инициализации
            return await Task.Run(async () =>
            {
                progress?.Report($"Старт Dual Layer захвата трафика PID={targetPid} на {captureTimeout.TotalSeconds}с");

                // 1. Коллекции данных
                var flowMap = new ConcurrentDictionary<FlowKey, int>(); // (Port, Proto) -> PID
                var packetBuffer = new ConcurrentBag<PacketHeader>();
                var dnsCache = new ConcurrentDictionary<string, string>(); // IP -> Hostname

                // 2. WinDivert фильтр
                // Исключаем loopback, но оставляем частные сети (VPN/NAT)
                var networkFilter = "outbound and !loopback and (tcp or udp)";
                // Flow layer filter: используем "true", так как макросы tcp/udp могут быть недоступны для Flow layer
                // Фильтрация по протоколу будет выполнена в коде
                var flowFilter = "true";

                // 3. Запуск задач мониторинга
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(captureTimeout);

                // 3.1 Снапшот существующих соединений (для тех, что открыты ДО запуска)
                try 
                {
                    progress?.Report("Снятие снапшота активных соединений...");
                    PopulateExistingFlows(flowMap, progress);
                    progress?.Report($"Снапшот соединений: найдено {flowMap.Count} активных сокетов. TargetPID={targetPid}");
                    
                    // Debug: check if we have any ports for targetPid
                    var targetPorts = flowMap.Where(kv => kv.Value == targetPid).Select(kv => kv.Key.LocalPort).ToList();
                    if (targetPorts.Any())
                    {
                        progress?.Report($"Порты для PID {targetPid}: {string.Join(", ", targetPorts.Take(10))}{(targetPorts.Count > 10 ? "..." : "")}");
                    }
                    else
                    {
                        progress?.Report($"ВНИМАНИЕ: Для PID {targetPid} не найдено активных портов в снапшоте.");
                    }
                }
                catch (Exception ex)
                {
                    progress?.Report($"Ошибка получения таблицы соединений: {ex.Message}");
                }

                Task? flowTask = null;
                Task? netTask = null;

                try
                {
                    // Запускаем Flow Monitor (Layer.Flow)
                    progress?.Report($"Запуск Flow Monitor с фильтром: '{flowFilter}'");
                    flowTask = Task.Run(() => RunFlowMonitor(flowFilter, flowMap, targetPid, progress, cts.Token), cts.Token);
                    
                    // Запускаем Packet Capture (Layer.Network)
                    progress?.Report($"Запуск Packet Capture с фильтром: '{networkFilter}'");
                    netTask = Task.Run(() => RunPacketCapture(networkFilter, packetBuffer, dnsCache, progress, cts.Token), cts.Token);

                    progress?.Report("WinDivert мониторинг активен (Flow + Network layers)");

                    // Ждем завершения (по таймауту или отмене)
                    await Task.WhenAll(flowTask, netTask).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    progress?.Report($"Захват завершен (таймаут {captureTimeout.TotalSeconds}с)");
                }
                catch (Exception ex)
                {
                    progress?.Report($"Ошибка во время захвата: {ex.Message}");
                    // Не прерываем выполнение, пробуем собрать то, что успели
                }

                // 4. Корреляция и анализ
                progress?.Report($"Анализ данных: {packetBuffer.Count} пакетов, {flowMap.Count} потоков...");
                
                if (packetBuffer.Count == 0)
                {
                    progress?.Report("WARNING: packetBuffer пуст — WinDivert не захватил ни одного пакета. Возможные причины: процесс не создал соединения, фильтр слишком строгий, или нет прав админа.");
                }

                // Фильтруем пакеты, принадлежащие целевому процессу
                var targetPackets = packetBuffer
                    .Where(p => 
                    {
                        // Проверяем маппинг порта на PID
                        byte protoByte = p.Protocol == TransportProtocol.TCP ? (byte)6 : (byte)17;
                        
                        // Для outbound пакетов LocalPort (Source) должен совпадать с портом процесса
                        bool matchLocal = flowMap.TryGetValue(new FlowKey(p.LocalPort, protoByte), out int pid) && pid == targetPid;
                        
                        return matchLocal;
                    })
                    .ToList();

                if (targetPackets.Count == 0 && packetBuffer.Count > 0)
                {
                    progress?.Report($"WARNING: 0 packets matched PID {targetPid}. Dumping first 5 packets for debug:");
                    foreach(var p in packetBuffer.Take(5))
                    {
                        byte protoByte = p.Protocol == TransportProtocol.TCP ? (byte)6 : (byte)17;
                        flowMap.TryGetValue(new FlowKey(p.LocalPort, protoByte), out int pidLocal);
                        flowMap.TryGetValue(new FlowKey(p.RemotePort, protoByte), out int pidRemote);
                        progress?.Report($"  [{p.Protocol}] {p.LocalPort} -> {p.RemoteIp}:{p.RemotePort} (LocalPID={pidLocal}, RemotePID={pidRemote})");
                    }
                }

                progress?.Report($"Найдено {targetPackets.Count} пакетов от PID={targetPid}");

                // 5. Сборка соединений
                var connections = new ConcurrentDictionary<string, NetworkConnection>();
                
                foreach (var p in targetPackets)
                {
                    // Для outbound пакетов RemoteIp/RemotePort уже корректны
                    var remoteIp = p.RemoteIp;
                    var remotePort = p.RemotePort;

                    var key = $"{remoteIp}:{remotePort}:{p.Protocol}";
                    connections.AddOrUpdate(
                        key,
                        _ => new NetworkConnection
                        {
                            RemoteIp = remoteIp,
                            RemotePort = remotePort,
                            Protocol = p.Protocol,
                            PacketCount = 1,
                            FirstSeen = p.Timestamp,
                            LastSeen = p.Timestamp
                        },
                        (_, existing) =>
                        {
                            existing.PacketCount++;
                            existing.TotalBytes += p.TotalSize;
                            if (p.Timestamp > existing.LastSeen) existing.LastSeen = p.Timestamp;
                            return existing;
                        });
                }

                // 6. Обогащение Hostnames
                await EnrichWithHostnamesAsync(connections, dnsCache, progress, default).ConfigureAwait(false);

                // 7. Генерация профиля
                var profile = BuildGameProfile(connections, progress);
                return profile;
            });
        }

        private static void RunFlowMonitor(
            string filter,
            ConcurrentDictionary<FlowKey, int> flowMap,
            int targetPid,
            IProgress<string>? progress,
            CancellationToken token)
        {
            WinDivertNative.SafeHandle? handle = null;
            try
            {
                // Use Sniff | RecvOnly as per flowtrack.c example
                handle = WinDivertNative.Open(filter, WinDivertNative.Layer.Flow, 0, WinDivertNative.OpenFlags.Sniff | WinDivertNative.OpenFlags.RecvOnly);
                
                // Flow layer does not use packet buffer, pass NULL/0
                var addr = new WinDivertNative.Address();
                int flowCount = 0;

                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(handle, IntPtr.Zero, 0, ref addr, IntPtr.Zero))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted) break;
                        
                        progress?.Report($"FlowMonitor Recv Error: {error}");
                        // Avoid tight loop on error
                        Thread.Sleep(100); 
                        continue;
                    }
                    
                    flowCount++;
                    if (flowCount % 50 == 0)
                    {
                        // progress?.Report($"Flow events: {flowCount}, Map size: {flowMap.Count}");
                    }

                    if (addr.Event == WinDivertNative.WINDIVERT_EVENT_FLOW_ESTABLISHED)
                    {
                        // Manual filtering for Flow layer
                        if (!addr.Outbound || addr.Loopback)
                            continue;

                        // WinDivert сообщает PID процесса!
                        var pid = (int)addr.Flow.ProcessId;
                        var localPort = addr.Flow.LocalPort;
                        var protocol = addr.Flow.Protocol;

                        flowMap.TryAdd(new FlowKey(localPort, protocol), pid);
                        
                        if (pid == targetPid)
                        {
                            progress?.Report($"✓ FLOW MATCH: PID={pid} LocalPort={localPort} Proto={protocol}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                progress?.Report($"FlowMonitor Critical Error: {ex.Message}");
            }
            finally
            {
                handle?.Dispose();
            }
        }

        private static void RunPacketCapture(
            string filter,
            ConcurrentBag<PacketHeader> packetBuffer,
            ConcurrentDictionary<string, string> dnsCache,
            IProgress<string>? progress,
            CancellationToken token)
        {
            WinDivertNative.SafeHandle? handle = null;
            try
            {
                handle = WinDivertNative.Open(filter, WinDivertNative.Layer.Network, 0, WinDivertNative.OpenFlags.Sniff);
                var buffer = new byte[WinDivertNative.MaxPacketSize];
                var addr = new WinDivertNative.Address();
                uint readLen;
                int capturedCount = 0;
                const int MaxPackets = 100000; // Limit memory usage

                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref addr, out readLen))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted) break;
                        continue;
                    }

                    if (capturedCount >= MaxPackets) continue;

                    // Parse IP/TCP/UDP headers
                    if (TryParsePacket(buffer, (int)readLen, addr, out var header))
                    {
                        packetBuffer.Add(header);
                        capturedCount++;

                        // Периодический отчёт о захвате
                        if (capturedCount % 500 == 0)
                        {
                            progress?.Report($"PacketCapture: захвачено {capturedCount} пакетов");
                        }

                        // Opportunistic DNS parsing
                        if (header.Protocol == TransportProtocol.UDP && header.RemotePort == 53)
                        {
                            TryParseDns(buffer, (int)readLen, dnsCache);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                progress?.Report($"PacketCapture Error: {ex.Message}");
            }
            finally
            {
                handle?.Dispose();
            }
        }

        private static bool TryParsePacket(byte[] buffer, int length, WinDivertNative.Address addr, out PacketHeader header)
        {
            header = default;
            if (addr.IPv6 || length < 20) return false;

            int ipHeaderLen = (buffer[0] & 0x0F) * 4;
            if (length < ipHeaderLen + 8) return false;

            byte protocol = buffer[9];
            var remoteIp = new IPAddress(new byte[] { buffer[16], buffer[17], buffer[18], buffer[19] });
            
            ushort localPort = 0;
            ushort remotePort = 0;
            TransportProtocol transportProto;

            if (protocol == 6) // TCP
            {
                if (length < ipHeaderLen + 20) return false;
                
                // Прямое чтение портов из network order (big-endian)
                // (buffer << 8) | buffer уже даёт правильное значение для сравнения с Flow layer
                localPort = (ushort)((buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1]);
                remotePort = (ushort)((buffer[ipHeaderLen + 2] << 8) | buffer[ipHeaderLen + 3]);
                transportProto = TransportProtocol.TCP;
            }
            else if (protocol == 17) // UDP
            {
                localPort = (ushort)((buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1]);
                remotePort = (ushort)((buffer[ipHeaderLen + 2] << 8) | buffer[ipHeaderLen + 3]);
                transportProto = TransportProtocol.UDP;
            }
            else
            {
                return false;
            }

            header = new PacketHeader
            {
                Timestamp = DateTime.UtcNow,
                LocalPort = localPort,
                RemoteIp = remoteIp,
                RemotePort = remotePort,
                Protocol = transportProto,
                TotalSize = length
            };
            return true;
        }

        private static void TryParseDns(byte[] buffer, int length, ConcurrentDictionary<string, string> dnsCache)
        {
             // Simplified DNS parsing logic reused from previous version
             // Need to calculate offsets again
             int ipHeaderLen = (buffer[0] & 0x0F) * 4;
             int udpHeaderLen = 8;
             int dnsOffset = ipHeaderLen + udpHeaderLen;
             
             if (length < dnsOffset + 12) return;
             
             // Reuse the existing TryParseDnsResponse logic
             // We need to copy that method back or make it static
             TrafficAnalyzer.TryParseDnsResponse(buffer, dnsOffset, length, dnsCache);
        }

        // ... Existing helper methods (TryParseDnsResponse, ReadDnsName, EnrichWithHostnamesAsync, BuildGameProfile, DetermineService) ...
        // I will include them below to ensure the file is complete.

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
                if (totalLength < dnsOffset + 12) return;

                byte flags = buffer[dnsOffset + 2];
                if ((flags & 0x80) == 0 || (buffer[dnsOffset + 3] & 0x0F) != 0) return; // Not response or error

                int questionsCount = (buffer[dnsOffset + 4] << 8) | buffer[dnsOffset + 5];
                int answersCount = (buffer[dnsOffset + 6] << 8) | buffer[dnsOffset + 7];

                if (answersCount == 0) return;

                int pos = dnsOffset + 12;

                for (int i = 0; i < questionsCount; i++)
                {
                    string? qname = ReadDnsName(buffer, ref pos, totalLength, dnsOffset);
                    if (qname == null || pos + 4 > totalLength) return;
                    pos += 4;
                }

                for (int i = 0; i < answersCount && pos < totalLength; i++)
                {
                    string? name = ReadDnsName(buffer, ref pos, totalLength, dnsOffset);
                    if (name == null || pos + 10 > totalLength) return;

                    int rrType = (buffer[pos] << 8) | buffer[pos + 1];
                    pos += 8; 
                    
                    int rdLength = (buffer[pos] << 8) | buffer[pos + 1];
                    pos += 2;

                    if (pos + rdLength > totalLength) return;

                    if (rrType == 1 && rdLength == 4)
                    {
                        var ip = new IPAddress(new byte[] { buffer[pos], buffer[pos + 1], buffer[pos + 2], buffer[pos + 3] });
                        dnsCache[ip.ToString()] = name;
                    }

                    pos += rdLength;
                }
            }
            catch { }
        }

        private static string? ReadDnsName(byte[] buffer, ref int pos, int totalLength, int dnsOffset)
        {
            var labels = new List<string>();
            int jumps = 0;
            int originalPos = -1;

            while (pos < totalLength && jumps < 10)
            {
                int len = buffer[pos];
                if (len == 0) { pos++; break; }

                if ((len & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= totalLength) return null;
                    if (originalPos == -1) originalPos = pos + 2;
                    int offset = ((len & 0x3F) << 8) | buffer[pos + 1];
                    pos = dnsOffset + offset;
                    jumps++;
                    continue;
                }

                if (pos + 1 + len > totalLength) return null;
                string label = System.Text.Encoding.ASCII.GetString(buffer, pos + 1, len);
                labels.Add(label);
                pos += 1 + len;
            }

            if (originalPos != -1) pos = originalPos;
            return labels.Count > 0 ? string.Join(".", labels) : null;
        }

        private static async Task EnrichWithHostnamesAsync(
            ConcurrentDictionary<string, NetworkConnection> connections,
            ConcurrentDictionary<string, string> dnsCache,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            progress?.Report($"Обогащение hostname для {connections.Count} соединений...");
            int fromCache = 0;
            int fromReverseDns = 0;

            foreach (var conn in connections.Values)
            {
                string ipStr = conn.RemoteIp.ToString();
                if (dnsCache.TryGetValue(ipStr, out string? hostname))
                {
                    conn.Hostname = hostname.ToLowerInvariant();
                    fromCache++;
                }
            }

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
                    catch { }
                });
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            progress?.Report($"✓ Hostname resolved: {fromCache + fromReverseDns}/{connections.Count}");
        }

        private static GameProfile BuildGameProfile(
            ConcurrentDictionary<string, NetworkConnection> connections,
            IProgress<string>? progress)
        {
            var targetGroups = connections.Values
                .GroupBy(c => c.Hostname ?? c.RemoteIp.ToString())
                .OrderByDescending(g => g.Sum(c => c.PacketCount))
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
                    Critical = false,
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

        private static string DetermineService(string hostname, List<ushort> ports)
        {
            if (ports.Contains(443) || ports.Contains(80)) return "web";
            if (ports.Any(p => p >= 27000 && p <= 28000)) return "game";
            if (ports.Any(p => p >= 64000 && p <= 65000)) return "voice";
            return "unknown";
        }

        private static void PopulateExistingFlows(ConcurrentDictionary<FlowKey, int> flowMap, IProgress<string>? progress)
        {
            // TCP
            var tcpRows = GetAllTcpConnections();
            int tcpCount = 0;
            foreach (var row in tcpRows)
            {
                // LocalPort in MIB_TCPROW_OWNER_PID is in network byte order? 
                // Actually GetExtendedTcpTable returns ports in network byte order usually.
                // Let's check implementation of GetAllTcpConnections.
                // If it returns host order, we are good.
                flowMap.TryAdd(new FlowKey((ushort)row.LocalPort, 6), row.ProcessId);
                if (row.ProcessId > 0) tcpCount++;
            }
            progress?.Report($"PopulateExistingFlows: Loaded {tcpCount} TCP connections");

            // UDP
            var udpRows = GetAllUdpConnections();
            int udpCount = 0;
            foreach (var row in udpRows)
            {
                flowMap.TryAdd(new FlowKey((ushort)row.LocalPort, 17), row.ProcessId);
                if (row.ProcessId > 0) udpCount++;
            }
            progress?.Report($"PopulateExistingFlows: Loaded {udpCount} UDP connections");
        }

        // --- IP Helper API P/Invoke ---

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TcpTableClass tblClass, uint reserved = 0);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UdpTableClass tblClass, uint reserved = 0);

        private enum TcpTableClass
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UdpTableClass
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public int owningPid;

            public ushort LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)localPort);
            public int ProcessId => owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public uint localPort;
            public int owningPid;

            public ushort LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)localPort);
            public int ProcessId => owningPid;
        }

        private static List<MIB_TCPROW_OWNER_PID> GetAllTcpConnections()
        {
            var table = new List<MIB_TCPROW_OWNER_PID>();
            int bufferSize = 0;
            
            // Loop to handle buffer resizing
            for (int i = 0; i < 5; i++)
            {
                uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2 /* AF_INET */, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
                if (ret != 0 && ret != 122) // 122 = ERROR_INSUFFICIENT_BUFFER
                    return table;

                IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
                    if (ret == 122) 
                    {
                        // Buffer too small (changed between calls), retry
                        continue;
                    }
                    if (ret != 0) return table;

                    int numEntries = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
                    
                    for (int j = 0; j < numEntries; j++)
                    {
                        MIB_TCPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                        table.Add(row);
                        rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_TCPROW_OWNER_PID>());
                    }
                    return table; // Success
                }
                finally
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                }
            }
            return table;
        }

        private static List<MIB_UDPROW_OWNER_PID> GetAllUdpConnections()
        {
            var table = new List<MIB_UDPROW_OWNER_PID>();
            int bufferSize = 0;
            
            for (int i = 0; i < 5; i++)
            {
                uint ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, 2 /* AF_INET */, UdpTableClass.UDP_TABLE_OWNER_PID);
                if (ret != 0 && ret != 122) return table;

                IntPtr udpTablePtr = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    ret = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, 2, UdpTableClass.UDP_TABLE_OWNER_PID);
                    if (ret == 122) continue;
                    if (ret != 0) return table;

                    int numEntries = Marshal.ReadInt32(udpTablePtr);
                    IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);

                    for (int j = 0; j < numEntries; j++)
                    {
                        MIB_UDPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                        table.Add(row);
                        rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_UDPROW_OWNER_PID>());
                    }
                    return table;
                }
                finally
                {
                    Marshal.FreeHGlobal(udpTablePtr);
                }
            }
            return table;
        }
    }
}
