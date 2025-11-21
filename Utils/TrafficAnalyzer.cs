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
    /// Легковесный анализатор сетевого трафика процесса через WinDivert Flow Layer.
    /// ИСПОЛЬЗУЕТСЯ ДЛЯ STAGE1: быстрый сбор уникальных IP-адресов без захвата пакетов.
    /// Для детального анализа (Stage2) используйте TrafficAnalyzerDualLayer.
    /// </summary>
    internal static class TrafficAnalyzer
    {
        /// <summary>
        /// Собирает список уникальных IP-адресов из сетевых соединений процесса.
        /// Использует только Flow Layer (без захвата пакетов) для минимального overhead.
        /// </summary>
        public static async Task<GameProfile> AnalyzeProcessTrafficAsync(
            int targetPid,
            TimeSpan? captureTimeout,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            return await Task.Run(async () =>
            {
                var secondsText = captureTimeout.HasValue ? $"на {captureTimeout.Value.TotalSeconds}с" : "(до ручной остановки)";
                progress?.Report($"Старт Flow-only захвата трафика PID={targetPid} {secondsText}");
                
                // Получаем имя процесса для фильтрации всех связанных процессов (включая дочерние)
                string? processName = null;
                HashSet<int> targetPids;
                try
                {
                    using var proc = System.Diagnostics.Process.GetProcessById(targetPid);
                    processName = proc.ProcessName;
                    
                    // Сразу собираем все PID процессов с таким же именем
                    var allProcesses = System.Diagnostics.Process.GetProcessesByName(processName);
                    targetPids = new HashSet<int>(allProcesses.Select(p => p.Id));
                    progress?.Report($"Процесс: '{processName}', найдено {targetPids.Count} экземпляров (PIDs: {string.Join(", ", targetPids.Take(10))})");
                }
                catch (Exception ex)
                {
                    progress?.Report($"Ошибка получения информации о процессе PID {targetPid}: {ex.Message}");
                    targetPids = new HashSet<int> { targetPid };
                }

                // Коллекция для хранения уникальных соединений: RemoteIP:RemotePort:Protocol
                var connections = new ConcurrentDictionary<string, ConnectionInfo>();
                var dnsCache = new ConcurrentDictionary<string, string>(); // IP -> Hostname (из DNS-запросов)

                // Настройка таймаута
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (captureTimeout.HasValue)
                {
                    cts.CancelAfter(captureTimeout.Value);
                }

                // Запуск Flow Monitor
                Task? flowTask = null;
                try
                {
                    progress?.Report("Запуск Flow Monitor (только события соединений)");
                    flowTask = Task.Run(() => RunFlowMonitor(targetPids, connections, progress, cts.Token), cts.Token);
                    
                    await flowTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    if (captureTimeout.HasValue)
                    {
                        progress?.Report($"Захват завершен (таймаут {captureTimeout.Value.TotalSeconds}с)");
                    }
                    else
                    {
                        progress?.Report("Захват остановлен пользователем");
                    }
                }
                catch (Exception ex)
                {
                    progress?.Report($"Ошибка во время захвата: {ex.Message}");
                }

                progress?.Report($"Обнаружено {connections.Count} уникальных соединений");

                // Обогащение hostname через reverse DNS
                await EnrichWithHostnamesAsync(connections, progress, cancellationToken).ConfigureAwait(false);

                // Генерация профиля
                var profile = BuildGameProfile(connections, processName, progress);
                return profile;
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Мониторит Flow Layer для сбора событий создания соединений
        /// </summary>
        private static void RunFlowMonitor(
            HashSet<int> targetPids,
            ConcurrentDictionary<string, ConnectionInfo> connections,
            IProgress<string>? progress,
            CancellationToken token)
        {
            WinDivertNative.SafeHandle? handle = null;
            int flowCount = 0;
            int matchCount = 0;
            const int MaxConnections = 50; // Лимит уникальных соединений

            try
            {
                progress?.Report("[FLOW] Открытие WinDivert Flow layer...");
                
                try
                {
                    handle = WinDivertNative.Open("true", WinDivertNative.Layer.Flow, 0, 
                        WinDivertNative.OpenFlags.Sniff | WinDivertNative.OpenFlags.RecvOnly);
                    progress?.Report("[FLOW] ✓ WinDivert Flow layer открыт успешно");
                }
                catch (System.ComponentModel.Win32Exception wx)
                {
                    if (wx.NativeErrorCode == 1058)
                    {
                        progress?.Report("[FLOW] Ошибка: служба драйвера отключена (код 1058). Запустите ISP_Audit от имени администратора.");
                    }
                    else
                    {
                        progress?.Report($"[FLOW] Ошибка WinDivertOpen: {wx.NativeErrorCode} - {wx.Message}");
                    }
                    return;
                }

                var addr = new WinDivertNative.Address();

                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(handle, IntPtr.Zero, 0, out var _, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted) 
                            break;
                        
                        progress?.Report($"[FLOW] Recv Error: {error}");
                        Thread.Sleep(100);
                        continue;
                    }

                    flowCount++;

                    // Обрабатываем только события FLOW_ESTABLISHED
                    if (addr.Event != WinDivertNative.WINDIVERT_EVENT_FLOW_ESTABLISHED)
                        continue;

                    // Пропускаем loopback
                    if (addr.Loopback)
                        continue;

                    var pid = (int)addr.Data.Flow.ProcessId;
                    
                    // Фильтруем по целевым PID
                    if (!targetPids.Contains(pid))
                        continue;

                    matchCount++;

                    // Извлекаем информацию о соединении
                    // RemoteAddr1 содержит IPv4 адрес в host byte order
                    var remoteIp = new IPAddress(addr.Data.Flow.RemoteAddr1);
                    var remotePort = addr.Data.Flow.RemotePort;
                    var protocol = addr.Data.Flow.Protocol; // 6=TCP, 17=UDP

                    // Формируем ключ: IP:Port:Protocol
                    var key = $"{remoteIp}:{remotePort}:{protocol}";

                    // Добавляем в коллекцию (если ещё нет)
                    if (connections.TryAdd(key, new ConnectionInfo
                    {
                        RemoteIp = remoteIp,
                        RemotePort = remotePort,
                        Protocol = protocol == 6 ? TransportProtocol.TCP : TransportProtocol.UDP,
                        FirstSeen = DateTime.UtcNow
                    }))
                    {
                        // Живое обновление
                        if (connections.Count % 5 == 0 || connections.Count <= 10)
                        {
                            progress?.Report($"Обнаружено соединений: {connections.Count}");
                        }

                        // Достигли лимита — завершаем
                        if (connections.Count >= MaxConnections)
                        {
                            progress?.Report($"Достигнут лимит соединений ({MaxConnections}), завершение захвата");
                            break;
                        }
                    }
                }

                progress?.Report($"[FLOW] Обработано событий: {flowCount}, совпадений с целевыми PID: {matchCount}");
            }
            catch (Exception ex)
            {
                progress?.Report($"[FLOW] КРИТИЧЕСКАЯ ОШИБКА: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                progress?.Report("[FLOW] Закрытие Flow layer");
                handle?.Dispose();
            }
        }

        /// <summary>
        /// Обогащение соединений hostname через reverse DNS
        /// </summary>
        private static async Task EnrichWithHostnamesAsync(
            ConcurrentDictionary<string, ConnectionInfo> connections,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            progress?.Report($"Разрешение hostname для {connections.Count} соединений...");
            int resolvedCount = 0;

            var tasks = connections.Values.Select(async conn =>
            {
                try
                {
                    var entry = await Dns.GetHostEntryAsync(conn.RemoteIp.ToString(), AddressFamily.InterNetwork, cancellationToken)
                        .ConfigureAwait(false);
                    if (entry.HostName != null)
                    {
                        conn.Hostname = entry.HostName.ToLowerInvariant();
                        Interlocked.Increment(ref resolvedCount);
                    }
                }
                catch
                {
                    // Игнорируем ошибки reverse DNS
                }
            });

            await Task.WhenAll(tasks).ConfigureAwait(false);
            progress?.Report($"✓ Hostname resolved: {resolvedCount}/{connections.Count}");
        }

        /// <summary>
        /// Генерация GameProfile из собранных соединений
        /// </summary>
        private static GameProfile BuildGameProfile(
            ConcurrentDictionary<string, ConnectionInfo> connections,
            string? processName,
            IProgress<string>? progress)
        {
            progress?.Report("Генерация профиля целей...");

            // Группируем по hostname (или IP, если hostname не разрешён)
            var targetGroups = connections.Values
                .GroupBy(c => c.Hostname ?? c.RemoteIp.ToString())
                .OrderByDescending(g => g.Count()) // Сортируем по количеству соединений
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
                    Critical = false
                };
                
                targets.Add(target);
                progress?.Report($"  • {hostname}: порты {string.Join(", ", portsUsed)} ({string.Join(", ", protocols)})");
            }

            return new GameProfile
            {
                Name = $"Captured_{processName ?? "Unknown"}",
                TestMode = "host",
                ExePath = "",
                Targets = targets
            };
        }

        /// <summary>
        /// Определяет тип сервиса по hostname и портам
        /// </summary>
        private static string DetermineService(string hostname, List<ushort> ports)
        {
            if (ports.Contains(443) || ports.Contains(80)) return "web";
            if (ports.Any(p => p >= 27000 && p <= 28000)) return "game";
            if (ports.Any(p => p >= 64000 && p <= 65000)) return "voice";
            if (ports.Contains(53)) return "dns";
            return "unknown";
        }

        /// <summary>
        /// Информация о сетевом соединении (легковесная структура)
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
