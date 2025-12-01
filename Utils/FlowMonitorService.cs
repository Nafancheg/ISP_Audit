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
    /// 1. WinDivert Socket Layer — основной режим (событийная модель, Sniff+RecvOnly — не конфликтует с bypass)
    /// 2. TcpConnectionWatcher — fallback (polling через IP Helper API, для систем без WinDivert)
    /// </summary>
    public class FlowMonitorService : IDisposable
    {
        private WinDivertNative.SafeHandle? _socketHandle;
        private Task? _monitorTask;
        private Task? _socketMonitorTask;
        private CancellationTokenSource? _cts;
        private readonly IProgress<string>? _progress;
        private bool _isRunning;
        private readonly TaskCompletionSource<bool> _readySignal = new();
        private readonly TcpConnectionWatcher _watcher = new();
        
        public DateTime? FlowOpenedUtc { get; private set; }
        public DateTime? FirstEventUtc { get; private set; }
        private int _totalEventsCount;
        public int TotalEventsCount => _totalEventsCount;

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
        /// Запускает мониторинг в фоновом режиме.
        /// Socket Layer — основной режим (Sniff+RecvOnly — не конфликтует с bypass).
        /// Watcher Mode — fallback для систем без WinDivert.
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
                // Watcher mode: polling через IP Helper API (fallback для систем без WinDivert)
                _monitorTask = Task.Run(() => RunWatcherLoop(_cts.Token), _cts.Token);
            }
            else
            {
                // Socket Layer: событийная модель через WinDivert (основной режим)
                _socketMonitorTask = Task.Run(() => RunSocketMonitorLoop(_cts.Token), _cts.Token);
            }
            
            // Ждём, пока выбранный режим откроется
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
                            int count = Interlocked.Increment(ref _totalEventsCount);
                            if (count == 1)
                            {
                                FirstEventUtc = DateTime.UtcNow;
                            }

                            byte proto = conn.Protocol == TransportProtocol.TCP ? (byte)6 : (byte)17;
                            OnFlowEvent?.Invoke(count, conn.ProcessId, proto, conn.RemoteIp, conn.RemotePort, conn.LocalPort);
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

        private void RunSocketMonitorLoop(CancellationToken token)
        {
            try
            {
                _progress?.Report("[FlowMonitor] Открытие WinDivert Socket layer...");
                
                const string socketFilter = "true"; 
                _socketHandle = WinDivertNative.Open(socketFilter, WinDivertNative.Layer.Socket, -1000, 
                    WinDivertNative.OpenFlags.Sniff | WinDivertNative.OpenFlags.RecvOnly);
                
                FlowOpenedUtc = DateTime.UtcNow;
                _progress?.Report($"[FlowMonitor] ✓ Socket layer открыт (Utc={FlowOpenedUtc:O})");
                
                // Сигнализируем готовность (теперь Socket Layer — основной режим)
                _readySignal.TrySetResult(true);
                
                var addr = new WinDivertNative.Address();

                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(_socketHandle, IntPtr.Zero, 0, out var _, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted)
                            break;
                        
                        Thread.Sleep(50);
                        continue;
                    }

                    // Обрабатываем только события SOCKET_CONNECT (попытка соединения)
                    if (addr.Event != WinDivertNative.WINDIVERT_EVENT_SOCKET_CONNECT)
                        continue;

                    // Пропускаем loopback
                    if (addr.Loopback)
                        continue;

                    var pid = (int)addr.Data.Socket.ProcessId;
                    var protocol = addr.Data.Socket.Protocol;
                    
                    IPAddress remoteIp;
                    if (addr.IPv6)
                    {
                        var parts = new uint[] 
                        { 
                            addr.Data.Socket.RemoteAddr1, 
                            addr.Data.Socket.RemoteAddr2, 
                            addr.Data.Socket.RemoteAddr3, 
                            addr.Data.Socket.RemoteAddr4 
                        };
                        
                        var bytes = new byte[16];
                        for (int i = 0; i < 4; i++)
                        {
                            var b = BitConverter.GetBytes(parts[i]);
                            // WinDivert возвращает в Host Byte Order (Little Endian на x64)
                            // BitConverter.GetBytes возвращает Little Endian
                            // IPAddress ожидает Network Byte Order (Big Endian)
                            // Поэтому нужно реверсировать
                            if (BitConverter.IsLittleEndian)
                            {
                                Array.Reverse(b);
                            }
                            Array.Copy(b, 0, bytes, i * 4, 4);
                        }
                        remoteIp = new IPAddress(bytes);
                    }
                    else
                    {
                        uint remoteAddrRaw = addr.Data.Socket.RemoteAddr1;
                        var ipBytes = BitConverter.GetBytes(remoteAddrRaw);
                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(ipBytes);
                        }
                        remoteIp = new IPAddress(ipBytes);
                    }

                    var remotePort = addr.Data.Socket.RemotePort;
                    var localPort = addr.Data.Socket.LocalPort;

                    // Передаем событие подписчикам (используем тот же event, так как это тоже "поток")
                    int count = Interlocked.Increment(ref _totalEventsCount);
                    
                    if (count == 1)
                    {
                        FirstEventUtc = DateTime.UtcNow;
                        var delta = (FirstEventUtc.Value - FlowOpenedUtc!.Value).TotalMilliseconds;
                        _progress?.Report($"[FlowMonitor] Первое событие через {delta:F0}ms");
                    }
                    
                    OnFlowEvent?.Invoke(count, pid, protocol, remoteIp, remotePort, localPort);
                }
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
                _progress?.Report($"[FlowMonitor] Socket Layer Error: {ex.Message}");
            }
            finally
            {
                _socketHandle?.Dispose();
                _socketHandle = null;
                _isRunning = false;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
                return;

            _cts?.Cancel();
            
            var tasks = new List<Task>();
            if (_monitorTask != null) tasks.Add(_monitorTask);
            if (_socketMonitorTask != null) tasks.Add(_socketMonitorTask);

            try
            {
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Ожидаемое исключение при отмене
            }
        }

        public void Dispose()
        {
            StopAsync().GetAwaiter().GetResult();
            _cts?.Dispose();
        }
    }
}
