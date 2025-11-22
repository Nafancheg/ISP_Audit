using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    /// <summary>
    /// Сервис для отслеживания PIDs процессов (включая дочерние и launcher-процессы).
    /// </summary>
    public class PidTrackerService
    {
        private readonly HashSet<int> _trackedPids;
        private readonly string? _processName;
        private readonly IProgress<string>? _progress;
        private Task? _trackerTask;
        private CancellationTokenSource? _cts;
        
        public IReadOnlyCollection<int> TrackedPids => _trackedPids;
        public int NewPidsDiscovered { get; private set; }
        
        /// <summary>
        /// Событие срабатывает при обнаружении новых PIDs (для немедленной реакции подписчиков)
        /// </summary>
        public event Action<IReadOnlyCollection<int>>? OnNewPidsDiscovered;

        public PidTrackerService(int initialPid, IProgress<string>? progress = null)
        {
            _trackedPids = new HashSet<int> { initialPid };
            _progress = progress;
            
            try
            {
                using var proc = Process.GetProcessById(initialPid);
                _processName = proc.ProcessName;
                
                // Сразу собираем все PIDs с таким же именем
                var allProcesses = Process.GetProcessesByName(_processName);
                foreach (var p in allProcesses)
                {
                    _trackedPids.Add(p.Id);
                }
                
                // Ищем дочерние процессы
                if (OperatingSystem.IsWindows())
                {
                    var childPids = GetChildProcesses(initialPid);
                    foreach (var childPid in childPids)
                    {
                        _trackedPids.Add(childPid);
                    }
                    
                    if (childPids.Count > 0)
                    {
                        _progress?.Report($"[PidTracker] Найдено дочерних процессов: {childPids.Count}");
                    }
                }
                
                _progress?.Report($"[PidTracker] Процесс: '{_processName}' (PID={initialPid}), всего отслеживается: {_trackedPids.Count}");
            }
            catch (Exception ex)
            {
                _progress?.Report($"[PidTracker] Ошибка инициализации: {ex.Message}");
            }
        }

        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _trackerTask = Task.Run(() => UpdatePidsLoop(_cts.Token), _cts.Token);
            return Task.CompletedTask;
        }

        private async Task UpdatePidsLoop(CancellationToken token)
        {
            try
            {
                int updateCount = 0;
                
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(500, token).ConfigureAwait(false); // Проверка каждые 0.5 секунды (быстрая реакция на новые PIDs)
                    
                    if (string.IsNullOrEmpty(_processName))
                        continue;
                    
                    // Запускаем операции параллельно для скорости
                    var newPidsFound = await Task.Run(async () =>
                    {
                        var foundPids = new List<int>();
                        
                        // 1. Проверяем новые процессы с тем же именем (быстрая операция)
                        var currentProcesses = Process.GetProcessesByName(_processName);
                        foreach (var proc in currentProcesses)
                        {
                            lock (_trackedPids)
                            {
                                if (_trackedPids.Add(proc.Id))
                                {
                                    foundPids.Add(proc.Id);
                                }
                            }
                        }
                        
                        // 2. Проверяем дочерние процессы параллельно (медленные WMI запросы)
                        if (OperatingSystem.IsWindows())
                        {
                            List<int> knownPids;
                            lock (_trackedPids)
                            {
                                knownPids = _trackedPids.ToList();
                            }
                            
                            // Параллельный опрос WMI для каждого родительского PID
                            var childPidTasks = knownPids.Select(parentPid => Task.Run(() =>
                            {
                                if (!OperatingSystem.IsWindows())
                                    return new List<int>();
                                    
                                try
                                {
                                    return GetChildProcesses(parentPid);
                                }
                                catch
                                {
                                    return new List<int>(); // Процесс мог завершиться
                                }
                            }));
                            
                            var allChildPids = (await Task.WhenAll(childPidTasks).ConfigureAwait(false))
                                .SelectMany(x => x)
                                .ToList();
                            
                            foreach (var childPid in allChildPids)
                            {
                                lock (_trackedPids)
                                {
                                    if (_trackedPids.Add(childPid))
                                    {
                                        foundPids.Add(childPid);
                                    }
                                }
                            }
                        }
                        
                        return foundPids;
                    }, token).ConfigureAwait(false);
                    
                    if (newPidsFound.Any())
                    {
                        NewPidsDiscovered += newPidsFound.Count;
                        updateCount++;
                        _progress?.Report($"[PidTracker] Добавлено новых PIDs: {string.Join(", ", newPidsFound)} (всего: {_trackedPids.Count})");
                        
                        // Уведомляем подписчиков немедленно
                        OnNewPidsDiscovered?.Invoke(newPidsFound);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
            catch (Exception ex)
            {
                _progress?.Report($"[PidTracker] Ошибка: {ex.Message}");
            }
        }

        [SupportedOSPlatform("windows")]
        private static List<int> GetChildProcesses(int parentPid)
        {
            var childPids = new List<int>();
            
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentPid}");
                
                foreach (var obj in searcher.Get())
                {
                    var pid = Convert.ToInt32(obj["ProcessId"]);
                    childPids.Add(pid);
                }
            }
            catch
            {
                // WMI может быть недоступен
            }
            
            return childPids;
        }

        public async Task StopAsync()
        {
            _cts?.Cancel();
            
            if (_trackerTask != null)
            {
                try
                {
                    await _trackerTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Ожидаемое
                }
            }
        }

        public void Dispose()
        {
            StopAsync().GetAwaiter().GetResult();
            _cts?.Dispose();
        }
    }
}
