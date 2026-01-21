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
        internal sealed record TrafficEngineMutationContext(
            long Seq,
            string CorrelationId,
            string Operation,
            string Details,
            string TimestampUtc);

        private readonly List<IPacketFilter> _filters = new();
        private WinDivertNative.SafeHandle? _handle;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;
        private readonly IProgress<string>? _progress;
        private readonly object _stateLock = new();
        private bool _isStopping;

        private long _mutationSeq;
        private TrafficEngineMutationContext? _lastMutation;

        // Throttle логов от падающих фильтров: иначе можно залить UI-лог десятками тысяч строк/сек.
        private readonly ConcurrentDictionary<string, long> _lastFilterErrorLogTick = new();

        // Защита от падений подписчиков метрик: обработчики могут трогать UI/коллекции.
        private long _lastPerfHandlerErrorTick;

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

        internal void SetLastMutationContext(string correlationId, string operation, string? details)
        {
            try
            {
                var safeCorrelationId = string.IsNullOrWhiteSpace(correlationId) ? "-" : correlationId.Trim();
                var safeOperation = string.IsNullOrWhiteSpace(operation) ? "unknown" : operation.Trim();
                var safeDetails = string.IsNullOrWhiteSpace(details) ? string.Empty : details.Trim();

                if (safeDetails.Length > 256)
                {
                    safeDetails = safeDetails.Substring(0, 256);
                }

                var seq = Interlocked.Increment(ref _mutationSeq);
                Volatile.Write(ref _lastMutation, new TrafficEngineMutationContext(
                    Seq: seq,
                    CorrelationId: safeCorrelationId,
                    Operation: safeOperation,
                    Details: safeDetails,
                    TimestampUtc: DateTimeOffset.UtcNow.ToString("u").TrimEnd()));
            }
            catch
            {
                // best-effort: диагностика не должна ломать bypass
            }
        }

        internal TrafficEngineMutationContext? GetLastMutationContextSnapshot()
            => Volatile.Read(ref _lastMutation);

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

                    try
                    {
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
                            try
                            {
                                OnPerformanceUpdate?.Invoke(avgMs);
                            }
                            catch (Exception ex)
                            {
                                // Не даём подписчику уронить loop; ограничиваем частоту логов.
                                var nowTick = Environment.TickCount64;
                                if (_lastPerfHandlerErrorTick == 0 || (nowTick - _lastPerfHandlerErrorTick) >= 2000)
                                {
                                    _lastPerfHandlerErrorTick = nowTick;
                                    _progress?.Report($"[TrafficEngine][ERROR] OnPerformanceUpdate handler crashed (thread {Environment.CurrentManagedThreadId}): {ex}");
                                }
                            }

                            _totalProcessingTicks = 0;
                            _processedPacketsCount = 0;
                            _lastPerformanceReport = DateTime.UtcNow;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        // Остановка: handle мог быть закрыт параллельно.
                        break;
                    }
                    catch (Exception ex)
                    {
                        // Не даём единичной ошибке уронить весь loop.
                        _progress?.Report($"[TrafficEngine][ERROR] Packet processing failed (thread {Environment.CurrentManagedThreadId}): {ex}");
                    }
                }
            }
            catch (Exception ex)
            {
                // Log unexpected loop errors
                var lastMutation = GetLastMutationContextSnapshot();
                var mutationText = lastMutation == null
                    ? string.Empty
                    : $" | lastMutation seq={lastMutation.Seq} id={lastMutation.CorrelationId} op={lastMutation.Operation} utc={lastMutation.TimestampUtc} details={lastMutation.Details}";

                _progress?.Report($"[TrafficEngine][ERROR] Loop crashed (thread {Environment.CurrentManagedThreadId}): {ex}{mutationText}");
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
