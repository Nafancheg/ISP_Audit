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
    /// Сервис мониторинга сетевых соединений процессов.
    /// Основной режим: WinDivert Socket Layer (Sniff+RecvOnly) — событийная модель, не конфликтует с bypass.
    /// Fallback: TcpConnectionWatcher (polling через IP Helper API) — для систем без WinDivert.
    /// </summary>
    public class ConnectionMonitorService : IDisposable
    {
        private WinDivertNative.SafeHandle? _socketHandle;
        private Task? _pollingTask;
        private Task? _socketTask;
        private CancellationTokenSource? _cts;
        private readonly IProgress<string>? _progress;
        private bool _isRunning;
        private readonly TaskCompletionSource<bool> _readySignal = new();
        private readonly TcpConnectionWatcher _watcher = new();
        private const bool VerboseSocketLogging = false;
        
        /// <summary>Время открытия мониторинга (UTC)</summary>
        public DateTime? MonitorStartedUtc { get; private set; }
        /// <summary>Время первого события (UTC)</summary>
        public DateTime? FirstEventUtc { get; private set; }
        private int _totalEventsCount;
        public int TotalEventsCount => _totalEventsCount;

        /// <summary>
        /// Режим polling через IP Helper API (fallback). 
        /// false = WinDivert Socket Layer (основной режим).
        /// </summary>
        public bool UsePollingMode { get; set; }
        
        /// <summary>
        /// Событие нового соединения.
        /// Args: (eventCount, pid, protocol, remoteIp, remotePort, localPort)
        /// </summary>
        public event Action<int, int, byte, IPAddress, ushort, ushort>? OnConnectionEvent;

        public ConnectionMonitorService(IProgress<string>? progress = null)
        {
            _progress = progress;
        }

        /// <summary>
        /// Запускает мониторинг соединений.
        /// </summary>
        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            if (_isRunning)
            {
                throw new InvalidOperationException("ConnectionMonitorService уже запущен");
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _isRunning = true;

            if (UsePollingMode)
            {
                // Polling через IP Helper API (fallback для систем без WinDivert)
                _pollingTask = Task.Run(() => RunPollingLoop(_cts.Token), _cts.Token);
            }
            else
            {
                // WinDivert Socket Layer — основной режим (событийная модель)
                _socketTask = Task.Run(() => RunSocketLoop(_cts.Token), _cts.Token);
            }
            
            return _readySignal.Task;
        }

        private async Task RunPollingLoop(CancellationToken token)
        {
            try
            {
                _progress?.Report("[ConnectionMonitor] Запуск в режиме Polling (IP Helper API)...");
                MonitorStartedUtc = DateTime.UtcNow;
                _readySignal.TrySetResult(true);

                var seenConnections = new HashSet<string>();

                while (!token.IsCancellationRequested)
                {
                    var snapshot = await _watcher.GetSnapshotAsync(token).ConfigureAwait(false);
                    
                    foreach (var conn in snapshot)
                    {
                        var key = $"{conn.RemoteIp}:{conn.RemotePort}:{conn.LocalPort}:{conn.Protocol}";
                        
                        if (seenConnections.Add(key))
                        {
                            int count = Interlocked.Increment(ref _totalEventsCount);
                            if (count == 1)
                            {
                                FirstEventUtc = DateTime.UtcNow;
                            }

                            byte proto = conn.Protocol == TransportProtocol.TCP ? (byte)6 : (byte)17;
                            OnConnectionEvent?.Invoke(count, conn.ProcessId, proto, conn.RemoteIp, conn.RemotePort, conn.LocalPort);
                        }
                    }

                    await Task.Delay(1000, token).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[ConnectionMonitor] Polling Error: {ex.Message}");
            }
            finally
            {
                _isRunning = false;
            }
        }

        private void RunSocketLoop(CancellationToken token)
        {
            try
            {
                _progress?.Report("[ConnectionMonitor] Открытие WinDivert Socket Layer...");
                
                const string socketFilter = "true"; 
                _socketHandle = WinDivertNative.Open(socketFilter, WinDivertNative.Layer.Socket, -1000, 
                    WinDivertNative.OpenFlags.Sniff | WinDivertNative.OpenFlags.RecvOnly);
                
                MonitorStartedUtc = DateTime.UtcNow;
                _progress?.Report($"[ConnectionMonitor] ✓ Socket Layer активен");
                
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

                    // SOCKET_CONNECT = попытка соединения
                    if (addr.Event != WinDivertNative.WINDIVERT_EVENT_SOCKET_CONNECT)
                        continue;

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

                    if (VerboseSocketLogging)
                    {
                        _progress?.Report($"[ConnectionMonitor][Raw] pid={pid} proto={(protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : protocol.ToString())} {remoteIp}:{remotePort} local:{localPort}");
                    }

                    int count = Interlocked.Increment(ref _totalEventsCount);
                    
                    if (count == 1)
                    {
                        FirstEventUtc = DateTime.UtcNow;
                        var delta = (FirstEventUtc.Value - MonitorStartedUtc!.Value).TotalMilliseconds;
                        _progress?.Report($"[ConnectionMonitor] Первое событие через {delta:F0}ms");
                    }
                    
                    OnConnectionEvent?.Invoke(count, pid, protocol, remoteIp, remotePort, localPort);
                }
            }
            catch (System.ComponentModel.Win32Exception wx)
            {
                _readySignal.TrySetException(wx);
                
                if (wx.NativeErrorCode == 1058)
                {
                    _progress?.Report("[ConnectionMonitor] Ошибка: служба драйвера отключена (код 1058). Требуются права администратора.");
                }
                else
                {
                    _progress?.Report($"[ConnectionMonitor] Ошибка WinDivert: {wx.NativeErrorCode} - {wx.Message}");
                }
            }
            catch (Exception ex)
            {
                _readySignal.TrySetException(ex);
                _progress?.Report($"[ConnectionMonitor] Socket Layer Error: {ex.Message}");
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
            
            // Force close handle to unblock WinDivertRecv
            try { _socketHandle?.Dispose(); } catch { }
            
            var tasks = new List<Task>();
            if (_pollingTask != null) tasks.Add(_pollingTask);
            if (_socketTask != null) tasks.Add(_socketTask);

            try
            {
                // Wait with timeout to avoid deadlocks
                await Task.WhenAny(Task.WhenAll(tasks), Task.Delay(2000)).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Ignore errors during stop
            }
        }

        public void Dispose()
        {
            StopAsync().GetAwaiter().GetResult();
            _cts?.Dispose();
        }
    }
}
