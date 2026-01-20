using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;

namespace IspAudit.Core.Traffic
{
    public class TrafficEngine : IDisposable, IPacketSender, IPacketSenderEx
    {
        private readonly List<IPacketFilter> _filters = new();
        private WinDivertNative.SafeHandle? _handle;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;
        private readonly IProgress<string>? _progress;
        private readonly object _stateLock = new();
        private bool _isStopping;

        // Throttle логов от падающих фильтров: иначе можно залить UI-лог десятками тысяч строк/сек.
        private readonly ConcurrentDictionary<string, long> _lastFilterErrorLogTick = new();

        // Performance metrics
        public event Action<double>? OnPerformanceUpdate;
        private long _totalProcessingTicks;
        private int _processedPacketsCount;
        private DateTime _lastPerformanceReport = DateTime.MinValue;

        // Filter: Capture all IP packets (TCP/UDP/ICMP) to allow filters to decide
        // We exclude loopback to avoid noise if not needed, but for local testing we might need it.
        // Let's stick to "ip" for now.
        private const string Filter = "ip";
        private const short Priority = 0; // Default priority

        public bool IsRunning => _loopTask != null && !_loopTask.IsCompleted;

        public static bool HasAdministratorRights
        {
            get
            {
                if (!OperatingSystem.IsWindows()) return false;
                try
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch
                {
                    return false;
                }
            }
        }

        public TrafficEngine(IProgress<string>? progress = null)
        {
            _progress = progress;
        }

        public void RegisterFilter(IPacketFilter filter)
        {
            BypassStateManagerGuard.WarnIfBypassed(_progress, "TrafficEngine.RegisterFilter");
            lock (_filters)
            {
                _filters.Add(filter);
                // Sort by priority (descending)
                _filters.Sort((a, b) => b.Priority.CompareTo(a.Priority));
            }
        }

        public void RemoveFilter(string filterName)
        {
            BypassStateManagerGuard.WarnIfBypassed(_progress, "TrafficEngine.RemoveFilter");
            lock (_filters)
            {
                _filters.RemoveAll(f => f.Name == filterName);
            }
        }

        public void ClearFilters()
        {
            BypassStateManagerGuard.WarnIfBypassed(_progress, "TrafficEngine.ClearFilters");
            lock (_filters)
            {
                _filters.Clear();
            }
        }

        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            BypassStateManagerGuard.WarnIfBypassed(_progress, "TrafficEngine.StartAsync");
            lock (_stateLock)
            {
                if (IsRunning || _isStopping) return Task.CompletedTask;
            }

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
                _progress?.Report($"[TrafficEngine][ERROR] Failed to start (thread {Environment.CurrentManagedThreadId}): {ex}");
                throw;
            }

            return Task.CompletedTask;
        }

        public async Task StopAsync()
        {
            BypassStateManagerGuard.WarnIfBypassed(_progress, "TrafficEngine.StopAsync");
            Task? loopTask;
            lock (_stateLock)
            {
                if (_isStopping) return;
                _isStopping = true;
                loopTask = _loopTask;
                if (loopTask == null)
                {
                    _isStopping = false;
                    return;
                }
            }

            _progress?.Report("[TrafficEngine] Stopping...");
            _cts?.Cancel();

            // Closing handle breaks the Recv loop
            // Важно: не обнуляем _handle до завершения loop, иначе loop может передать null в WinDivertSend.
            try
            {
                _handle?.Dispose();
            }
            catch
            {
                // Игнорируем ошибки при закрытии handle во время остановки
            }

            if (loopTask != null)
            {
                try
                {
                    await loopTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[TrafficEngine][ERROR] Error during stop (thread {Environment.CurrentManagedThreadId}): {ex}");
                }
            }

            lock (_stateLock)
            {
                _loopTask = null;
                _handle = null;
                _cts?.Dispose();
                _cts = null;
                _isStopping = false;
            }
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
                    var handle = _handle;
                    if (handle == null || handle.IsInvalid || handle.IsClosed) break;

                    // This blocks until packet received or handle closed
                    if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, out var readLen, out addr))
                    {
                        // If handle closed, this returns false.
                        continue;
                    }

                    var startTicks = DateTime.UtcNow.Ticks;

                    var packet = new InterceptedPacket(buffer, (int)readLen);
                    var ctx = new PacketContext(addr);

                    bool drop = false;

                    lock (_filters)
                    {
                        foreach (var filter in _filters)
                        {
                            try
                            {
                                if (!filter.Process(packet, ctx, this))
                                {
                                    drop = true;
                                    break;
                                }
                            }
                            catch (Exception ex)
                            {
                                // Ограничиваем частоту логов: фильтр может падать на каждом пакете.
                                var filterName = string.IsNullOrWhiteSpace(filter.Name) ? "<unnamed>" : filter.Name;
                                var nowTick = Environment.TickCount64;
                                var lastTick = _lastFilterErrorLogTick.GetOrAdd(filterName, 0);
                                var shouldLog = lastTick == 0 || (nowTick - lastTick) >= 2000;
                                if (shouldLog)
                                {
                                    _lastFilterErrorLogTick[filterName] = nowTick;
                                    _progress?.Report($"[TrafficEngine][ERROR] Filter error in '{filterName}' (thread {Environment.CurrentManagedThreadId}): {ex}");
                                }
                                // Safer to pass through if filter fails
                            }
                        }
                    }

                    if (!drop)
                    {
                        try
                        {
                            // Recalculate checksums if modified
                            WinDivertNative.WinDivertHelperCalcChecksums(packet.Buffer, (uint)packet.Length, ref addr, 0);
                            WinDivertNative.WinDivertSend(handle, packet.Buffer, (uint)packet.Length, out _, in addr);
                        }
                        catch (ObjectDisposedException)
                        {
                            // Остановка: handle мог быть закрыт между Recv и Send
                            break;
                        }
                        catch (ArgumentNullException)
                        {
                            // Защита от гонки: не должен происходить, но лучше не падать
                            break;
                        }
                    }

                    var endTicks = DateTime.UtcNow.Ticks;
                    _totalProcessingTicks += (endTicks - startTicks);
                    _processedPacketsCount++;

                    if (DateTime.UtcNow - _lastPerformanceReport > TimeSpan.FromSeconds(1))
                    {
                        double avgMs = 0;
                        if (_processedPacketsCount > 0)
                        {
                            var avgTicks = (double)_totalProcessingTicks / _processedPacketsCount;
                            avgMs = avgTicks / 10000.0; // 10000 ticks in 1 ms
                        }

                        // Report even if 0 packets (to show idle state)
                        OnPerformanceUpdate?.Invoke(avgMs);

                        _totalProcessingTicks = 0;
                        _processedPacketsCount = 0;
                        _lastPerformanceReport = DateTime.UtcNow;
                    }
                }
            }
            catch (Exception ex)
            {
                // Log unexpected loop errors
                _progress?.Report($"[TrafficEngine][ERROR] Loop crashed (thread {Environment.CurrentManagedThreadId}): {ex}");
            }
        }

        public bool Send(byte[] packet, int length, ref WinDivertNative.Address addr)
        {
            var handle = _handle;
            if (handle == null || handle.IsInvalid) return false;

            // Recalculate checksums before sending
            WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)length, ref addr, 0);

            return WinDivertNative.WinDivertSend(handle, packet, (uint)length, out _, in addr);
        }

        public bool SendEx(byte[] packet, int length, ref WinDivertNative.Address addr, PacketSendOptions options)
        {
            var handle = _handle;
            if (handle == null || handle.IsInvalid) return false;

            if (options.UnsetChecksumFlagsInAddress)
            {
                WinDivertNative.UnsetChecksumFlags(ref addr);
            }

            if (options.RecalculateChecksums)
            {
                WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)length, ref addr, options.CalcChecksumsFlags);
            }

            return WinDivertNative.WinDivertSend(handle, packet, (uint)length, out _, in addr);
        }

        public void Dispose()
        {
            StopAsync().GetAwaiter().GetResult();
            _cts?.Dispose();
        }
    }
}
