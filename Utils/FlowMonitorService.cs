using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;

namespace IspAudit.Utils
{
    /// <summary>
    /// Сервис для мониторинга сетевой активности.
    /// Поддерживает два режима:
    /// 1. WinDivert Flow Layer (событийная модель, высокая точность)
    /// 2. TcpConnectionWatcher (polling модель, совместимость с RST blocker)
    /// </summary>
    public class FlowMonitorService : IDisposable
    {
        private WinDivertNative.SafeHandle? _handle;
        private Task? _monitorTask;
        private CancellationTokenSource? _cts;
        private readonly IProgress<string>? _progress;
        private bool _isRunning;
        private readonly TaskCompletionSource<bool> _readySignal = new();
        private readonly TcpConnectionWatcher _watcher = new();
        
        public DateTime? FlowOpenedUtc { get; private set; }
        public DateTime? FirstEventUtc { get; private set; }
        public int TotalEventsCount { get; private set; }

        /// <summary>
        /// Если true, используется TcpConnectionWatcher (polling) вместо WinDivert Flow Layer.
        /// </summary>
        public bool UseWatcherMode { get; set; }
        
        /// <summary>
        /// Событие, вызываемое при получении Flow события.
        /// Args: (eventCount, pid, protocol, remoteIp, remotePort, localPort)
        /// </summary>
        public event Action<int, int, byte, IPAddress, ushort, ushort>? OnFlowEvent;

        public FlowMonitorService(IProgress<string>? progress = null)
        {
            _progress = progress;
        }

        /// <summary>
        /// Запускает мониторинг Flow layer в фоновом режиме.
        /// </summary>
        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            if (_isRunning)
            {
                throw new InvalidOperationException("FlowMonitorService уже запущен");
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _isRunning = true;

            if (UseWatcherMode)
            {
                _monitorTask = Task.Run(() => RunWatcherLoop(_cts.Token), _cts.Token);
            }
            else
            {
                _monitorTask = Task.Run(() => RunMonitorLoop(_cts.Token), _cts.Token);
            }
            
            // Ждем, пока WinDivert откроется (или Watcher запустится)
            return _readySignal.Task;
        }

        private async Task RunWatcherLoop(CancellationToken token)
        {
            try
            {
                _progress?.Report("[FlowMonitor] Запуск в режиме Watcher (Polling)...");
                FlowOpenedUtc = DateTime.UtcNow;
                _readySignal.TrySetResult(true);

                var seenConnections = new HashSet<string>();

                while (!token.IsCancellationRequested)
                {
                    var snapshot = await _watcher.GetSnapshotAsync(token).ConfigureAwait(false);
                    
                    foreach (var conn in snapshot)
                    {
                        // Формируем уникальный ключ соединения
                        var key = $"{conn.RemoteIp}:{conn.RemotePort}:{conn.LocalPort}:{conn.Protocol}";
                        
                        if (seenConnections.Add(key))
                        {
                            TotalEventsCount++;
                            if (TotalEventsCount == 1)
                            {
                                FirstEventUtc = DateTime.UtcNow;
                            }

                            byte proto = conn.Protocol == TransportProtocol.TCP ? (byte)6 : (byte)17;
                            OnFlowEvent?.Invoke(TotalEventsCount, conn.ProcessId, proto, conn.RemoteIp, conn.RemotePort, conn.LocalPort);
                        }
                    }

                    // Пауза между опросами (1 секунда)
                    await Task.Delay(1000, token).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[FlowMonitor] Watcher Error: {ex.Message}");
            }
            finally
            {
                _isRunning = false;
            }
        }

        private void RunMonitorLoop(CancellationToken token)
        {
            try
            {
                _progress?.Report("[FlowMonitor] Открытие WinDivert Flow layer...");
                
                const string flowFilter = "true"; // Слушаем все Flow события в системе
                // A1: Используем низкий приоритет (-1000), чтобы не конфликтовать с Network слоем (RST blocker)
                _handle = WinDivertNative.Open(flowFilter, WinDivertNative.Layer.Flow, -1000, 
                    WinDivertNative.OpenFlags.Sniff | WinDivertNative.OpenFlags.RecvOnly);
                
                FlowOpenedUtc = DateTime.UtcNow;
                _progress?.Report($"[FlowMonitor] ✓ Flow layer открыт (Utc={FlowOpenedUtc:O})");
                
                // Сигнализируем, что готовы принимать события
                _readySignal.TrySetResult(true);

                var addr = new WinDivertNative.Address();

                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(_handle, IntPtr.Zero, 0, out var _, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted)
                        {
                            break;
                        }
                        
                        Thread.Sleep(50);
                        continue;
                    }

                    TotalEventsCount++;
                    
                    if (TotalEventsCount == 1)
                    {
                        FirstEventUtc = DateTime.UtcNow;
                        var delta = (FirstEventUtc.Value - FlowOpenedUtc.Value).TotalMilliseconds;
                        _progress?.Report($"[FlowMonitor] Первое событие через {delta:F0}ms");
                    }

                    // Обрабатываем только события FLOW_ESTABLISHED
                    if (addr.Event != WinDivertNative.WINDIVERT_EVENT_FLOW_ESTABLISHED)
                        continue;

                    // Пропускаем loopback
                    if (addr.Loopback)
                        continue;

                    var pid = (int)addr.Data.Flow.ProcessId;
                    var protocol = addr.Data.Flow.Protocol;
                    
                    // Конвертируем IP из WinDivert (Network Byte Order) в IPAddress
                    uint remoteAddrRaw = addr.Data.Flow.RemoteAddr1;
                    var ipBytes = BitConverter.GetBytes(remoteAddrRaw);
                    // WinDivert возвращает в Big Endian (Network Order), IPAddress конструктор ожидает байты в правильном порядке
                    // Но BitConverter зависит от архитектуры (Little Endian на x86/x64).
                    // Если мы на Little Endian, GetBytes перевернет порядок.
                    // Нам нужно получить байты так, как они лежат в памяти (Big Endian от сети).
                    // addr.Data.Flow.RemoteAddr1 - это uint.
                    // Если это IPv4, то это 4 байта.
                    
                    // FIX: Используем проверенный метод из TrafficAnalyzer
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(ipBytes);
                    }
                    var remoteIp = new IPAddress(ipBytes);

                    var remotePort = addr.Data.Flow.RemotePort;
                    var localPort = addr.Data.Flow.LocalPort;

                    // Передаем событие подписчикам
                    OnFlowEvent?.Invoke(TotalEventsCount, pid, protocol, remoteIp, remotePort, localPort);
                }

                _progress?.Report($"[FlowMonitor] Завершение. Обработано событий: {TotalEventsCount}");
            }
            catch (System.ComponentModel.Win32Exception wx)
            {
                _readySignal.TrySetException(wx);
                
                if (wx.NativeErrorCode == 1058)
                {
                    _progress?.Report("[FlowMonitor] Ошибка: служба драйвера отключена (код 1058). Требуются права администратора.");
                }
                else
                {
                    _progress?.Report($"[FlowMonitor] Ошибка WinDivertOpen: {wx.NativeErrorCode} - {wx.Message}");
                }
            }
            catch (Exception ex)
            {
                _readySignal.TrySetException(ex);
                _progress?.Report($"[FlowMonitor] Критическая ошибка: {ex.Message}");
            }
            finally
            {
                _progress?.Report("[FlowMonitor] Закрытие Flow layer");
                _handle?.Dispose();
                _handle = null;
                _isRunning = false;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
                return;

            _cts?.Cancel();
            
            if (_monitorTask != null)
            {
                try
                {
                    await _monitorTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Ожидаемое исключение при отмене
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
