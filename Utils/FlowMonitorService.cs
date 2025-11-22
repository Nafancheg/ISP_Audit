using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;

namespace IspAudit.Utils
{
    /// <summary>
    /// Сервис для мониторинга WinDivert Flow Layer.
    /// Открывается один раз и предоставляет события соединений всем подписчикам.
    /// </summary>
    public class FlowMonitorService : IDisposable
    {
        private WinDivertNative.SafeHandle? _handle;
        private Task? _monitorTask;
        private CancellationTokenSource? _cts;
        private readonly IProgress<string>? _progress;
        private bool _isRunning;
        private readonly TaskCompletionSource<bool> _readySignal = new();
        
        public DateTime? FlowOpenedUtc { get; private set; }
        public DateTime? FirstEventUtc { get; private set; }
        public int TotalEventsCount { get; private set; }
        
        /// <summary>
        /// Событие, вызываемое при получении Flow события.
        /// Args: (eventCount, pid, protocol, remoteIp, remotePort, localPort)
        /// </summary>
        public event Action<int, int, byte, uint, ushort, ushort>? OnFlowEvent;

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

            _monitorTask = Task.Run(() => RunMonitorLoop(_cts.Token), _cts.Token);
            
            // Ждем, пока WinDivert откроется
            return _readySignal.Task;
        }

        private void RunMonitorLoop(CancellationToken token)
        {
            try
            {
                _progress?.Report("[FlowMonitor] Открытие WinDivert Flow layer...");
                
                const string flowFilter = "true"; // Слушаем все Flow события в системе
                _handle = WinDivertNative.Open(flowFilter, WinDivertNative.Layer.Flow, 0, 
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
                    var remoteIp = addr.Data.Flow.RemoteAddr1; // IPv4 (first 32 bits)
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
