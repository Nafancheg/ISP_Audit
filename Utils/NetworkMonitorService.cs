using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;

namespace IspAudit.Utils
{
    /// <summary>
    /// Данные захваченного пакета.
    /// </summary>
    public class PacketData
    {
        public int PacketNumber { get; set; }
        public byte[] Buffer { get; set; } = Array.Empty<byte>();
        public int Length { get; set; }
        public bool IsOutbound { get; set; }
        public bool IsLoopback { get; set; }
    }

    /// <summary>
    /// Сервис для мониторинга WinDivert Network Layer.
    /// Открывается один раз с настраиваемым фильтром и предоставляет пакеты всем подписчикам.
    /// </summary>
    public class NetworkMonitorService : IDisposable
    {
        private WinDivertNative.SafeHandle? _handle;
        private Task? _monitorTask;
        private CancellationTokenSource? _cts;
        private readonly IProgress<string>? _progress;
        private readonly string _filter;
        private bool _isRunning;
        private readonly TaskCompletionSource<bool> _readySignal = new();
        
        public int PacketsCount { get; private set; }
        
        /// <summary>
        /// Событие, вызываемое при получении пакета.
        /// </summary>
        public event Action<PacketData>? OnPacketReceived;

        public NetworkMonitorService(string filter = "true", IProgress<string>? progress = null)
        {
            _filter = filter;
            _progress = progress;
        }

        /// <summary>
        /// Запускает мониторинг Network layer в фоновом режиме.
        /// </summary>
        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            if (_isRunning)
            {
                throw new InvalidOperationException("NetworkMonitorService уже запущен");
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _isRunning = true;

            _monitorTask = Task.Run(() => RunMonitorLoop(_cts.Token), _cts.Token);
            
            // Ждем, пока WinDivert откроется
            return _readySignal.Task;
        }

        private void RunMonitorLoop(CancellationToken token)
        {
            try
            {
                _progress?.Report($"[NetworkMonitor] Открытие WinDivert Network layer (Filter='{_filter}')...");
                
                try
                {
                    _handle = WinDivertNative.Open(_filter, WinDivertNative.Layer.Network, 0, 
                        WinDivertNative.OpenFlags.Sniff);
                    _progress?.Report("[NetworkMonitor] ✓ Network layer открыт");
                    
                    // Сигнализируем, что готовы принимать пакеты
                    _readySignal.TrySetResult(true);
                }
                catch (System.ComponentModel.Win32Exception wx)
                {
                    _readySignal.TrySetException(wx);
                    _progress?.Report($"[NetworkMonitor] Ошибка открытия: {wx.NativeErrorCode} - {wx.Message}");
                    return;
                }

                var buffer = new byte[1500]; // Достаточно для большинства пакетов
                var addr = new WinDivertNative.Address();

                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(_handle, buffer, (uint)buffer.Length, out var readLen, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorNoData || error == WinDivertNative.ErrorOperationAborted)
                        {
                            break;
                        }
                        
                        Thread.Sleep(50);
                        continue;
                    }

                    PacketsCount++;

                    // Передаем пакет подписчикам (копируем буфер, так как он переиспользуется)
                    var packetCopy = new byte[readLen];
                    Array.Copy(buffer, packetCopy, readLen);
                    
                    var packetData = new PacketData
                    {
                        PacketNumber = PacketsCount,
                        Buffer = packetCopy,
                        Length = (int)readLen,
                        IsOutbound = addr.Outbound,
                        IsLoopback = addr.Loopback
                    };
                    
                    OnPacketReceived?.Invoke(packetData);
                }

                _progress?.Report($"[NetworkMonitor] Завершение. Обработано пакетов: {PacketsCount}");
            }
            catch (Exception ex)
            {
                _progress?.Report($"[NetworkMonitor] Критическая ошибка: {ex.Message}");
            }
            finally
            {
                _progress?.Report("[NetworkMonitor] Закрытие Network layer");
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
