using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Models;

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
        /// НОВАЯ ВЕРСИЯ: Использует внешние FlowMonitorService и DnsParserService (D1).
        /// </summary>
        public static async Task<GameProfile> AnalyzeProcessTrafficAsync(
            int targetPid,
            TimeSpan? captureTimeout,
            FlowMonitorService flowMonitor,
            PidTrackerService pidTracker,
            DnsParserService dnsParser,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default,
            bool enableLiveTesting = false,
            bool enableAutoBypass = false,
            IspAudit.Bypass.WinDivertBypassManager? bypassManager = null)
        {
            return await Task.Run(async () =>
            {
                var secondsText = captureTimeout.HasValue ? $"на {captureTimeout.Value.TotalSeconds}с" : "(до ручной остановки)";
                progress?.Report($"Старт захвата трафика PID={targetPid} {secondsText} (используя внешние сервисы)");
                
                // Коллекция для хранения уникальных соединений
                var connections = new ConcurrentDictionary<string, ConnectionInfo>();
                
                // Инициализация live-testing pipeline (если включен)
                LiveTestingPipeline? pipeline = null;
                if (enableLiveTesting)
                {
                    var pipelineConfig = new PipelineConfig
                    {
                        EnableLiveTesting = true,
                        EnableAutoBypass = enableAutoBypass,
                        MaxConcurrentTests = 5,
                        TestTimeout = TimeSpan.FromSeconds(3)
                    };
                    pipeline = new LiveTestingPipeline(pipelineConfig, progress, bypassManager);
                    progress?.Report("✓ Live-testing pipeline активен");
                }

                // Настройка таймаута
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (captureTimeout.HasValue)
                {
                    cts.CancelAfter(captureTimeout.Value);
                }

                // Подписываемся на уведомления о новых PIDs от PidTracker
                pidTracker.OnNewPidsDiscovered += (newPids) =>
                {
                    progress?.Report($"[TrafficAnalyzer] PidTracker обнаружил новые PIDs: {string.Join(", ", newPids)} — теперь отслеживаем {pidTracker.TrackedPids.Count} процессов");
                };

                // Подписываемся на события FlowMonitor
                int connectionCount = 0;
                int totalFlowEvents = 0;
                int targetPidMatches = 0;
                void OnFlowEvent(int eventNum, int pid, byte protocol, uint remoteIp, ushort remotePort, ushort localPort)
                {
                    totalFlowEvents++;
                    
                    // Используем актуальный список PIDs из PidTracker (обновляется динамически)
                    if (!pidTracker.TrackedPids.Contains(pid))
                        return;
                    
                    targetPidMatches++;
                    
                    // ИСПРАВЛЕНИЕ: WinDivert возвращает IP в host byte order, конвертируем правильно
                    var ipBytes = BitConverter.GetBytes(remoteIp);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(ipBytes);
                    var ip = new IPAddress(ipBytes);
                    var key = $"{ip}:{remotePort}:{protocol}";
                    
                    if (connections.TryAdd(key, new ConnectionInfo
                    {
                        RemoteIp = ip,
                        RemotePort = remotePort,
                        Protocol = protocol == 6 ? TransportProtocol.TCP : TransportProtocol.UDP,
                        FirstSeen = DateTime.UtcNow
                    }))
                    {
                        connectionCount++;
                        progress?.Report($"[TrafficAnalyzer] Новое соединение #{connectionCount}: {ip}:{remotePort} (proto={protocol}, pid={pid})");
                        
                        // Live testing для нового соединения
                        if (pipeline != null)
                        {
                            var host = new IspAudit.Core.Models.HostDiscovered(
                                Key: $"{ip}:{remotePort}:{protocol}",
                                RemoteIp: ip,
                                RemotePort: remotePort,
                                Protocol: protocol == 6 ? IspAudit.Bypass.TransportProtocol.Tcp : IspAudit.Bypass.TransportProtocol.Udp,
                                DiscoveredAt: DateTime.UtcNow
                            );
                            _ = Task.Run(() => pipeline.EnqueueHostAsync(host), cts.Token);
                        }
                    }
                }
                
                flowMonitor.OnFlowEvent += OnFlowEvent;
                
                try
                {
                    // Status Reporter: периодические обновления
                    var statusTask = Task.Run(async () =>
                    {
                        int lastCount = 0;
                        while (!cts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(10000, cts.Token).ConfigureAwait(false);
                            if (connections.Count > lastCount)
                            {
                                progress?.Report($"Захват активен ({(DateTime.UtcNow - flowMonitor.FlowOpenedUtc!.Value).TotalSeconds:F0}с), соединений: {connections.Count}. Выполните действия в приложении.");
                                lastCount = connections.Count;
                            }
                        }
                    }, cts.Token);
                    
                    await statusTask.ConfigureAwait(false);
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
                finally
                {
                    flowMonitor.OnFlowEvent -= OnFlowEvent;
                    progress?.Report($"[TrafficAnalyzer] Статистика: получено Flow событий={totalFlowEvents}, совпадений PID={targetPidMatches}, уникальных соединений={connections.Count}");
                }

                progress?.Report($"Обнаружено {connections.Count} уникальных соединений");

                // Обогащение hostname из DnsParserService (передаем кеш напрямую как ConcurrentDictionary)
                var dnsCache = new ConcurrentDictionary<string, string>(dnsParser.DnsCache);
                await EnrichWithHostnamesAsync(connections, dnsCache, progress, cancellationToken).ConfigureAwait(false);

                // Генерация профиля
                return BuildGameProfile(connections, null, progress);
            }, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// СТАРАЯ ВЕРСИЯ: Использует внутренний Flow/DNS (deprecated, для обратной совместимости).
        /// </summary>
        public static async Task<GameProfile> AnalyzeProcessTrafficAsync(
            int targetPid,
            TimeSpan? captureTimeout,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default,
            bool enableLiveTesting = false,
            bool enableAutoBypass = false,
            IspAudit.Bypass.WinDivertBypassManager? bypassManager = null)
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
                    
                    // ДОБАВЛЯЕМ: поиск дочерних процессов (для WebView2/CEF и т.д.)
                    if (OperatingSystem.IsWindows())
                    {
                        var childPids = GetChildProcesses(targetPid);
                        foreach (var childPid in childPids)
                        {
                            targetPids.Add(childPid);
                        }
                        
                        if (childPids.Count > 0)
                        {
                            progress?.Report($"  Найдено дочерних процессов: {childPids.Count}");
                        }
                    }
                    
                    progress?.Report($"Процесс: '{processName}' (PID={targetPid}), найдено экземпляров: {allProcesses.Length}, всего PIDs: {targetPids.Count}");
                    if (targetPids.Count > 1)
                    {
                        progress?.Report($"  Отслеживаемые PIDs: {string.Join(", ", targetPids.Take(20))}");
                    }
                }
                catch (Exception ex)
                {
                    progress?.Report($"Ошибка получения информации о процессе PID {targetPid}: {ex.Message}");
                    targetPids = new HashSet<int> { targetPid };
                }

                // Коллекция для хранения уникальных соединений: RemoteIP:RemotePort:Protocol
                var connections = new ConcurrentDictionary<string, ConnectionInfo>();
                var dnsCache = new ConcurrentDictionary<string, string>(); // IP -> Hostname (из DNS-запросов процесса)

                // Инициализация live-testing pipeline (если включен)
                LiveTestingPipeline? pipeline = null;
                if (enableLiveTesting)
                {
                    var pipelineConfig = new PipelineConfig
                    {
                        EnableLiveTesting = true,
                        EnableAutoBypass = enableAutoBypass,
                        MaxConcurrentTests = 5,
                        TestTimeout = TimeSpan.FromSeconds(3)
                    };
                    pipeline = new LiveTestingPipeline(pipelineConfig, progress, bypassManager);
                    progress?.Report("✓ Live-testing pipeline активен");
                }

                // Настройка таймаута
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                if (captureTimeout.HasValue)
                {
                    cts.CancelAfter(captureTimeout.Value);
                }

                // Запуск мониторинга
                Task? flowTask = null;
                Task? dnsTask = null;
                Task? pidUpdaterTask = null;
                try
                {
                    bool isContinuous = !captureTimeout.HasValue;
                    progress?.Report($"Запуск Flow Monitor (события соединений) + DNS Sniffer (парсинг DNS-ответов), режим: {(isContinuous ? "непрерывный" : "30с")}");
                    
                    // PID Updater: динамическое отслеживание новых процессов с тем же именем (для launcher-паттерна)
                    pidUpdaterTask = Task.Run(() => UpdateTargetPidsAsync(processName, targetPids, progress, cts.Token), cts.Token);
                    
                    // Flow Monitor: сбор соединений по PID
                    flowTask = Task.Run(() => RunFlowMonitor(targetPids, connections, isContinuous, pipeline, progress, cts.Token), cts.Token);
                    
                    // DNS Sniffer: парсинг DNS-ответов для получения hostname
                    dnsTask = Task.Run(() => RunDnsSniffer(dnsCache, progress, cts.Token), cts.Token);
                    
                    // Status Reporter: периодические обновления статуса
                    var statusTask = Task.Run(() => ReportCaptureStatus(targetPid, connections, progress, cts.Token), cts.Token);
                    
                    await Task.WhenAll(flowTask, dnsTask, pidUpdaterTask, statusTask).ConfigureAwait(false);
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

                // Обогащение hostname: сначала из DNS-кеша, потом reverse DNS
                await EnrichWithHostnamesAsync(connections, dnsCache, progress, cancellationToken).ConfigureAwait(false);

                // Генерация профиля
                var profile = BuildGameProfile(connections, processName, progress);
                return profile;
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Периодически выводит статус захвата для диагностики "пустого" снифа
        /// </summary>
        private static async Task ReportCaptureStatus(
            int targetPid,
            ConcurrentDictionary<string, ConnectionInfo> connections,
            IProgress<string>? progress,
            CancellationToken token)
        {
            try
            {
                var startTime = DateTime.Now;
                int lastCount = 0;
                
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(10000, token).ConfigureAwait(false); // Каждые 10 секунд
                    
                    var elapsed = DateTime.Now - startTime;
                    var currentCount = connections.Count;
                    
                    if (currentCount == 0)
                    {
                        // Проверяем жив ли процесс
                        try
                        {
                            using var proc = System.Diagnostics.Process.GetProcessById(targetPid);
                            if (proc.HasExited)
                            {
                                progress?.Report($"⚠️ Процесс завершился (захват: {elapsed.TotalSeconds:F0}с, соединений: 0)");
                                break;
                            }
                            else
                            {
                                progress?.Report($"Захват активен ({elapsed.TotalSeconds:F0}с), соединений: 0. Выполните действия в приложении.");
                            }
                        }
                        catch (ArgumentException)
                        {
                            progress?.Report($"⚠️ Процесс не найден (PID={targetPid})");
                            break;
                        }
                    }
                    else if (currentCount != lastCount)
                    {
                        progress?.Report($"Захвачено соединений: {currentCount}");
                        lastCount = currentCount;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
            catch (Exception ex)
            {
                progress?.Report($"[STATUS] Ошибка: {ex.Message}");
            }
        }

        /// <summary>
        /// Динамически обновляет список целевых PID для поддержки launcher-паттерна и дочерних процессов.
        /// Каждые 2 секунды проверяет наличие новых процессов с таким же именем + дочерние процессы всех известных PID.
        /// </summary>
        private static async Task UpdateTargetPidsAsync(
            string? processName,
            HashSet<int> targetPids,
            IProgress<string>? progress,
            CancellationToken token)
        {
            if (string.IsNullOrEmpty(processName))
                return;

            try
            {
                int newPidCount = 0;
                int iterationCount = 0;
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(2000, token).ConfigureAwait(false);
                    iterationCount++;

                    var newPidsFound = new List<int>();

                    // 1. Получаем текущий список процессов по имени
                    var currentProcesses = System.Diagnostics.Process.GetProcessesByName(processName);
                    var currentPids = new HashSet<int>(currentProcesses.Select(p => p.Id));

                    // Проверяем новые PID по имени процесса
                    var newPidsByName = currentPids.Except(targetPids).ToList();
                    if (newPidsByName.Any())
                    {
                        newPidsFound.AddRange(newPidsByName);
                        foreach (var pid in newPidsByName)
                        {
                            targetPids.Add(pid);
                        }
                    }

                    // 2. Ищем дочерние процессы у всех известных PID (для WebView2/CEF)
                    if (OperatingSystem.IsWindows())
                    {
                        var knownPids = targetPids.ToList(); // Snapshot для безопасной итерации
                        foreach (var parentPid in knownPids)
                        {
                            try
                            {
                                var childPids = GetChildProcesses(parentPid);
                                var newChildPids = childPids.Except(targetPids).ToList();
                                if (newChildPids.Any())
                                {
                                    newPidsFound.AddRange(newChildPids);
                                    foreach (var childPid in newChildPids)
                                    {
                                        targetPids.Add(childPid);
                                    }
                                }
                            }
                            catch
                            {
                                // Процесс мог завершиться - игнорируем
                            }
                        }
                    }

                    // Репорт о новых PID
                    if (newPidsFound.Any())
                    {
                        newPidCount++;
                        progress?.Report($"  Добавлено новых PIDs: {string.Join(", ", newPidsFound)} (всего отслеживается: {targetPids.Count})");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
            catch (Exception ex)
            {
                progress?.Report($"[PID] Ошибка обновления списка PID: {ex.Message}");
            }
        }

        /// <summary>
        /// Мониторит Flow Layer для сбора событий создания соединений
        /// </summary>
        private static void RunFlowMonitor(
            HashSet<int> targetPids,
            ConcurrentDictionary<string, ConnectionInfo> connections,
            bool isContinuous,
            LiveTestingPipeline? pipeline,
            IProgress<string>? progress,
            CancellationToken token)
        {
            WinDivertNative.SafeHandle? handle = null;
            int flowCount = 0;
            int matchCount = 0;
            DateTime? flowHandleOpenedUtc = null;
            DateTime? firstTargetFlowUtc = null;
            const int MaxConnections = 50; // Лимит уникальных соединений (только для фиксированного режима)

            try
            {
                progress?.Report("[FLOW] Открытие WinDivert Flow layer...");
                
                try
                {
                    const string flowFilter = "true"; // TODO(D1): сделать конфигурируемым через профиль/настройки
                    handle = WinDivertNative.Open(flowFilter, WinDivertNative.Layer.Flow, 0, 
                        WinDivertNative.OpenFlags.Sniff | WinDivertNative.OpenFlags.RecvOnly);
                    flowHandleOpenedUtc = DateTime.UtcNow;
                    progress?.Report($"[FLOW] ✓ WinDivert Flow layer открыт успешно (Filter='{flowFilter}', Utc={flowHandleOpenedUtc:O})");
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

                    // Фиксируем момент первого события для целевого PID
                    if (!firstTargetFlowUtc.HasValue)
                    {
                        firstTargetFlowUtc = DateTime.UtcNow;
                        var deltaMs = (flowHandleOpenedUtc.HasValue)
                            ? (firstTargetFlowUtc.Value - flowHandleOpenedUtc.Value).TotalMilliseconds
                            : (double?)null;

                        if (deltaMs.HasValue)
                        {
                            progress?.Report($"[FLOW] Первое целевое событие: Utc={firstTargetFlowUtc:O}, Δ={deltaMs.Value:F0} мс с момента открытия handle");
                        }
                        else
                        {
                            progress?.Report($"[FLOW] Первое целевое событие: Utc={firstTargetFlowUtc:O}");
                        }
                    }

                    // Извлекаем информацию о соединении
                    // RemoteAddr1 в WinDivert хранится в network byte order (big-endian)
                    // Преобразуем в byte[] для IPAddress (тоже big-endian)
                    uint remoteAddrRaw = addr.Data.Flow.RemoteAddr1;
                    var remoteIpBytes = new byte[4]
                    {
                        (byte)((remoteAddrRaw >> 24) & 0xFF),
                        (byte)((remoteAddrRaw >> 16) & 0xFF),
                        (byte)((remoteAddrRaw >> 8) & 0xFF),
                        (byte)(remoteAddrRaw & 0xFF)
                    };
                    var remoteIp = new IPAddress(remoteIpBytes);
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

                        // LIVE TESTING: отправляем хост в pipeline на тестирование
                        if (pipeline != null)
                        {
                            var discovered = new HostDiscovered(
                                key,
                                remoteIp,
                                remotePort,
                                protocol == 6 ? IspAudit.Bypass.TransportProtocol.Tcp : IspAudit.Bypass.TransportProtocol.Udp,
                                DateTime.UtcNow
                            );
                            _ = pipeline.EnqueueHostAsync(discovered); // Fire and forget
                        }

                        // Достигли лимита — завершаем (только для фиксированного режима)
                        if (!isContinuous && connections.Count >= MaxConnections)
                        {
                            progress?.Report($"Достигнут лимит соединений ({MaxConnections}), завершение захвата");
                            break;
                        }
                    }
                }

                // Итоговое логирование шума и полезных Flow-событий
                if (flowCount > 0)
                {
                    var percentTarget = (matchCount * 100.0) / flowCount;
                    progress?.Report($"[FLOW] Обработано событий: {flowCount}, совпадений с целевыми PID: {matchCount} ({percentTarget:F1}% целевых)");
                }
                else
                {
                    progress?.Report("[FLOW] Обработано событий: 0 (целевых событий не обнаружено)");
                }
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
        /// Сниффер DNS-пакетов для построения кеша IP→hostname из DNS-ответов процесса
        /// </summary>
        private static void RunDnsSniffer(
            ConcurrentDictionary<string, string> dnsCache,
            IProgress<string>? progress,
            CancellationToken token)
        {
            WinDivertNative.SafeHandle? handle = null;
            int dnsPacketsCount = 0;
            int parsedCount = 0;

            try
            {
                progress?.Report("[DNS] Открытие WinDivert Network layer для DNS...");
                
                // Фильтр: только UDP port 53 (DNS)
                var filter = "udp.DstPort == 53 or udp.SrcPort == 53";
                
                try
                {
                    handle = WinDivertNative.Open(filter, WinDivertNative.Layer.Network, 0, WinDivertNative.OpenFlags.Sniff);
                    progress?.Report("[DNS] ✓ DNS sniffer запущен");
                }
                catch (System.ComponentModel.Win32Exception wx)
                {
                    progress?.Report($"[DNS] Ошибка открытия: {wx.NativeErrorCode} - {wx.Message}");
                    return;
                }

                var buffer = new byte[1500]; // Достаточно для DNS
                var addr = new WinDivertNative.Address();

                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, out var readLen, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted)
                            break;
                        
                        Thread.Sleep(50);
                        continue;
                    }

                    dnsPacketsCount++;

                    // Парсим DNS-ответ (только входящие пакеты с SrcPort=53)
                    if (!addr.Outbound && TryParseDnsResponse(buffer, (int)readLen, dnsCache))
                    {
                        parsedCount++;
                    }
                }

                progress?.Report($"[DNS] Обработано DNS-пакетов: {dnsPacketsCount}, распарсено ответов: {parsedCount}, кеш: {dnsCache.Count} записей");
            }
            catch (Exception ex)
            {
                progress?.Report($"[DNS] ОШИБКА: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                progress?.Report("[DNS] Закрытие DNS sniffer");
                handle?.Dispose();
            }
        }

        /// <summary>
        /// Парсит DNS-ответ и извлекает A-записи в кеш
        /// </summary>
        private static bool TryParseDnsResponse(byte[] buffer, int length, ConcurrentDictionary<string, string> dnsCache)
        {
            try
            {
                // Расчёт смещения до DNS-данных
                if (length < 20) return false;
                
                int ipHeaderLen = (buffer[0] & 0x0F) * 4;
                int udpHeaderLen = 8;
                int dnsOffset = ipHeaderLen + udpHeaderLen;
                
                if (length < dnsOffset + 12) return false;

                // Проверка: это ответ (QR=1) и без ошибок (RCODE=0)
                byte flags = buffer[dnsOffset + 2];
                if ((flags & 0x80) == 0) return false; // Не ответ
                if ((buffer[dnsOffset + 3] & 0x0F) != 0) return false; // Есть ошибка

                int answersCount = (buffer[dnsOffset + 6] << 8) | buffer[dnsOffset + 7];
                if (answersCount == 0) return false;

                int questionsCount = (buffer[dnsOffset + 4] << 8) | buffer[dnsOffset + 5];
                int pos = dnsOffset + 12;

                // Пропускаем секцию вопросов
                for (int i = 0; i < questionsCount; i++)
                {
                    string? qname = ReadDnsName(buffer, ref pos, length, dnsOffset);
                    if (qname == null || pos + 4 > length) return false;
                    pos += 4; // QTYPE + QCLASS
                }

                // Парсим секцию ответов
                bool foundAny = false;
                for (int i = 0; i < answersCount && pos < length; i++)
                {
                    string? name = ReadDnsName(buffer, ref pos, length, dnsOffset);
                    if (name == null || pos + 10 > length) return false;

                    int rrType = (buffer[pos] << 8) | buffer[pos + 1];
                    pos += 8; // TYPE + CLASS + TTL

                    int rdLength = (buffer[pos] << 8) | buffer[pos + 1];
                    pos += 2;

                    if (pos + rdLength > length) return false;

                    // A-запись (IPv4)
                    if (rrType == 1 && rdLength == 4)
                    {
                        var ip = new IPAddress(new byte[] { buffer[pos], buffer[pos + 1], buffer[pos + 2], buffer[pos + 3] });
                        dnsCache[ip.ToString()] = name.ToLowerInvariant();
                        foundAny = true;
                    }

                    pos += rdLength;
                }

                return foundAny;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Читает DNS-имя с поддержкой сжатия (compression pointers)
        /// </summary>
        private static string? ReadDnsName(byte[] buffer, ref int pos, int totalLength, int dnsOffset)
        {
            var labels = new List<string>();
            int jumps = 0;
            int originalPos = -1;

            while (pos < totalLength && jumps < 10)
            {
                int len = buffer[pos];
                if (len == 0)
                {
                    pos++;
                    break;
                }

                // Compression pointer (первые 2 бита = 11)
                if ((len & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= totalLength) return null;
                    if (originalPos == -1) originalPos = pos + 2;
                    int offset = ((len & 0x3F) << 8) | buffer[pos + 1];
                    pos = dnsOffset + offset;
                    jumps++;
                    continue;
                }

                // Обычная метка
                if (pos + 1 + len > totalLength) return null;
                string label = System.Text.Encoding.ASCII.GetString(buffer, pos + 1, len);
                labels.Add(label);
                pos += 1 + len;
            }

            if (originalPos != -1) pos = originalPos;
            return labels.Count > 0 ? string.Join(".", labels) : null;
        }

        /// <summary>
        /// Обогащение соединений hostname: сначала из DNS-кеша, потом через reverse DNS
        /// <summary>
        /// Обогащение соединений hostname: сначала из DNS-кеша, потом через reverse DNS
        /// </summary>
        private static async Task EnrichWithHostnamesAsync(
            ConcurrentDictionary<string, ConnectionInfo> connections,
            ConcurrentDictionary<string, string> dnsCache,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            progress?.Report($"Обогащение hostname для {connections.Count} соединений...");
            int fromCache = 0;
            int fromReverseDns = 0;

            // Шаг 1: Заполняем из DNS-кеша (самые точные данные)
            foreach (var conn in connections.Values)
            {
                string ipStr = conn.RemoteIp.ToString();
                if (dnsCache.TryGetValue(ipStr, out string? hostname))
                {
                    conn.Hostname = hostname;
                    fromCache++;
                }
            }

            // Шаг 2: Для оставшихся пробуем reverse DNS (может дать технические имена провайдера)
            var remainingConnections = connections.Values.Where(c => c.Hostname == null).ToList();
            if (remainingConnections.Any())
            {
                var tasks = remainingConnections.Select(async conn =>
                {
                    try
                    {
                        var entry = await Dns.GetHostEntryAsync(conn.RemoteIp.ToString(), AddressFamily.InterNetwork, cancellationToken)
                            .ConfigureAwait(false);
                        if (entry.HostName != null)
                        {
                            conn.Hostname = entry.HostName.ToLowerInvariant();
                            Interlocked.Increment(ref fromReverseDns);
                        }
                    }
                    catch
                    {
                        // Игнорируем ошибки reverse DNS
                    }
                });

                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            
            progress?.Report($"✓ Hostname resolved: {fromCache + fromReverseDns}/{connections.Count} (DNS-кеш: {fromCache}, reverse: {fromReverseDns})");
        }

        /// <summary>
        /// Получает список дочерних процессов через WMI
        /// </summary>
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static List<int> GetChildProcesses(int parentPid)
        {
            var childPids = new List<int>();
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId={parentPid}");
                using var results = searcher.Get();
                
                foreach (System.Management.ManagementObject mo in results)
                {
                    var pid = Convert.ToInt32(mo["ProcessId"]);
                    childPids.Add(pid);
                    
                    // Рекурсивно ищем дочерние процессы дочерних процессов
                    childPids.AddRange(GetChildProcesses(pid));
                }
            }
            catch
            {
                // Игнорируем ошибки WMI (нет прав или процесс завершился)
            }
            return childPids;
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
                
                // Берём первый IP из группы как fallback (все соединения в группе имеют одинаковый hostname)
                var firstConnection = group.First();
                var fallbackIp = firstConnection.RemoteIp.ToString();

                var target = new TargetDefinition
                {
                    Name = hostname,
                    Host = hostname,
                    Service = DetermineService(hostname, portsUsed, protocols),
                    Critical = false,
                    FallbackIp = fallbackIp,
                    Ports = portsUsed.Select(p => (int)p).ToList(),
                    Protocols = protocols.Select(p => p.ToString()).ToList()
                };
                
                targets.Add(target);
                progress?.Report($"  • {hostname} ({fallbackIp}): порты {string.Join(", ", portsUsed)} ({string.Join(", ", protocols)})");
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
        private static string DetermineService(string hostname, List<ushort> ports, List<TransportProtocol> protocols)
        {
            bool hasUdp = protocols.Contains(TransportProtocol.UDP);
            bool hasTcp = protocols.Contains(TransportProtocol.TCP);
            
            // DNS всегда через UDP
            if (ports.Contains(53) && hasUdp) return "dns";
            
            // Web-сервисы (HTTP/HTTPS) всегда TCP
            if ((ports.Contains(443) || ports.Contains(80)) && hasTcp) return "web";
            
            // Игровые порты
            if (ports.Any(p => p >= 27000 && p <= 28000))
            {
                return hasUdp ? "game-udp" : "game-tcp";
            }
            
            // Голосовой чат обычно UDP
            if (ports.Any(p => p >= 64000 && p <= 65000))
            {
                return hasUdp ? "voice-udp" : "voice-tcp";
            }
            
            // По умолчанию определяем по протоколу
            if (hasUdp && !hasTcp) return "unknown-udp";
            if (hasTcp && !hasUdp) return "unknown-tcp";
            
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
