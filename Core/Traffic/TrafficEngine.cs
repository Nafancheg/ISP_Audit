using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;

namespace IspAudit.Core.Traffic
{
    public class TrafficEngine : IDisposable
    {
        private readonly List<IPacketFilter> _filters = new();
        private WinDivertNative.SafeHandle? _handle;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;
        private readonly IProgress<string>? _progress;
        
        // Filter: Capture all IP packets (TCP/UDP/ICMP) to allow filters to decide
        // We exclude loopback to avoid noise if not needed, but for local testing we might need it.
        // Let's stick to "ip" for now.
        private const string Filter = "ip"; 
        private const short Priority = 0; // Default priority

        public bool IsRunning => _loopTask != null && !_loopTask.IsCompleted;

        public TrafficEngine(IProgress<string>? progress = null)
        {
            _progress = progress;
        }

        public void RegisterFilter(IPacketFilter filter)
        {
            lock (_filters)
            {
                _filters.Add(filter);
            }
        }

        public void ClearFilters()
        {
            lock (_filters)
            {
                _filters.Clear();
            }
        }

        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            if (IsRunning) return Task.CompletedTask;

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            
            try 
            {
                _progress?.Report("[TrafficEngine] Opening WinDivert handle...");
                // Open in Active mode (no Sniff flag) to allow modification/dropping
                _handle = WinDivertNative.Open(Filter, WinDivertNative.Layer.Network, Priority, WinDivertNative.OpenFlags.None);
                
                if (_handle.IsInvalid)
                {
                     throw new Exception("Failed to open WinDivert handle. Check admin privileges or driver installation.");
                }

                _loopTask = Task.Run(() => Loop(_cts.Token), _cts.Token);
                _progress?.Report("[TrafficEngine] Started.");
            }
            catch (Exception ex)
            {
                _progress?.Report($"[TrafficEngine] Failed to start: {ex.Message}");
                throw;
            }

            return Task.CompletedTask;
        }

        public async Task StopAsync()
        {
            if (!IsRunning) return;

            _progress?.Report("[TrafficEngine] Stopping...");
            _cts?.Cancel();
            
            // Closing handle breaks the Recv loop
            _handle?.Dispose();
            _handle = null;

            if (_loopTask != null)
            {
                try
                {
                    await _loopTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[TrafficEngine] Error during stop: {ex.Message}");
                }
            }
            
            _loopTask = null;
            _progress?.Report("[TrafficEngine] Stopped.");
        }

        private void Loop(CancellationToken token)
        {
            var buffer = new byte[WinDivertNative.MaxPacketSize];
            var addr = new WinDivertNative.Address();
            
            try
            {
                while (!token.IsCancellationRequested)
                {
                    if (_handle == null || _handle.IsInvalid || _handle.IsClosed) break;

                    // This blocks until packet received or handle closed
                    if (!WinDivertNative.WinDivertRecv(_handle, buffer, (uint)buffer.Length, out var readLen, out addr))
                    {
                        // If handle closed, this returns false.
                        continue;
                    }

                    var packet = new InterceptedPacket(buffer, (int)readLen);
                    var ctx = new PacketContext(addr);
                    
                    bool drop = false;
                    
                    lock (_filters)
                    {
                        foreach (var filter in _filters)
                        {
                            try 
                            {
                                if (!filter.Process(packet, ctx))
                                {
                                    drop = true;
                                    break;
                                }
                            }
                            catch (Exception ex)
                            {
                                _progress?.Report($"[TrafficEngine] Filter error: {ex.Message}");
                                // Safer to pass through if filter fails
                            }
                        }
                    }

                    if (!drop)
                    {
                        // Recalculate checksums if modified
                        WinDivertNative.WinDivertHelperCalcChecksums(packet.Buffer, (uint)packet.Length, ref addr, 0);
                        
                        WinDivertNative.WinDivertSend(_handle, packet.Buffer, (uint)packet.Length, out _, in addr);
                    }
                }
            }
            catch (Exception ex)
            {
                // Log unexpected loop errors
                _progress?.Report($"[TrafficEngine] Loop crashed: {ex.Message}");
            }
        }

        public void Dispose()
        {
            StopAsync().GetAwaiter().GetResult();
            _cts?.Dispose();
        }
    }
}
