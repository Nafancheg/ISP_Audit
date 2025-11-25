using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Bypass
{
    public enum BypassState
    {
        Disabled,
        Enabling,
        Enabled,
        Disabling,
        Faulted
    }

    public sealed class WinDivertBypassManager : IDisposable, IAsyncDisposable
    {
        // Centralized Priority Constants
        private const short PriorityRstBlocker = 0;
        private const short PriorityRedirector = 0;
        private const short PriorityTlsFragmenter = 200;

        private readonly object _sync = new();
        private WinDivertNative.SafeHandle? _rstHandle;
        private WinDivertNative.SafeHandle? _tlsHandle;
        private WinDivertNative.SafeHandle? _redirectHandle;
        private CancellationTokenSource? _cts;
        private Task? _rstTask;
        private Task? _tlsTask;
        private Task? _redirectTask;
        private Task? _cleanupTask;
        private BypassState _state = BypassState.Disabled;
        private Exception? _lastError;
        private IReadOnlyList<RuntimeRedirectRule> _runtimeRedirectRules = Array.Empty<RuntimeRedirectRule>();
        private BypassProfile _profile = BypassProfile.CreateDefault();
        
        // State management for "Fake" strategy to avoid spamming
        // Key: Connection, Value: Last Seen Ticks
        private readonly ConcurrentDictionary<ConnectionKey, long> _processedConnections = new();

        // Metrics
        private long _packetsProcessed;
        private long _rstDropped;
        private long _clientHellosFragmented;

        public long PacketsProcessed => Interlocked.Read(ref _packetsProcessed);
        public long RstDropped => Interlocked.Read(ref _rstDropped);
        public long ClientHellosFragmented => Interlocked.Read(ref _clientHellosFragmented);
        public int ActiveConnections => _processedConnections.Count;

        public bool IsRstBlockerActive { get; private set; }

        // Диагностика WinDivert handles
        private static void LogHandleState(string operation, string filter, int priority, WinDivertNative.OpenFlags flags)
        {
            ISPAudit.Utils.DebugLogger.Log($"[WinDivert] {operation}: filter='{filter}', priority={priority}, flags={flags}");
        }

        private static void LogHandleError(string operation, string filter, int errorCode)
        {
            ISPAudit.Utils.DebugLogger.Log($"[WinDivert] ERROR {operation}: filter='{filter}', error={errorCode} ({GetErrorDescription(errorCode)})");
        }

        private static string GetErrorDescription(int errorCode)
        {
            return errorCode switch
            {
                2 => "ERROR_FILE_NOT_FOUND (driver not found)",
                5 => "ERROR_ACCESS_DENIED (not administrator)",
                87 => "ERROR_INVALID_PARAMETER (invalid filter/priority/flags)",
                577 => "ERROR_INVALID_IMAGE_HASH (driver signature invalid)",
                654 => "ERROR_DRIVER_FAILED_PRIOR_UNLOAD (incompatible driver version)",
                1060 => "ERROR_SERVICE_DOES_NOT_EXIST (driver not installed)",
                1275 => "ERROR_DRIVER_BLOCKED (blocked by security software)",
                1753 => "EPT_S_NOT_REGISTERED (Base Filtering Engine disabled)",
                _ => $"Unknown error code {errorCode}"
            };
        }

        /// <summary>
        /// Безопасное открытие WinDivert handle с диагностикой
        /// </summary>
        private bool TryOpenWinDivert(
            string filter, 
            WinDivertNative.Layer layer,
            short priority, 
            WinDivertNative.OpenFlags flags,
            out WinDivertNative.SafeHandle? handle)
        {
            handle = null;
            
            LogHandleState("Opening", filter, priority, flags);
            
            try
            {
                handle = WinDivertNative.Open(filter, layer, priority, flags);
                
                if (handle.IsInvalid)
                {
                    var error = Marshal.GetLastWin32Error();
                    LogHandleError("Open failed", filter, error);
                    handle?.Dispose();
                    handle = null;
                    return false;
                }
                
                ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Successfully opened handle for filter: {filter}");
                return true;
            }
            catch (Exception ex)
            {
                ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Exception opening handle: {ex.Message}");
                handle?.Dispose();
                handle = null;
                return false;
            }
        }

        public event EventHandler? StateChanged;

        public static bool IsPlatformSupported => OperatingSystem.IsWindows();

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

        public BypassState State
        {
            get
            {
                lock (_sync)
                {
                    return _state;
                }
            }
        }

        public Exception? LastError
        {
            get
            {
                lock (_sync)
                {
                    return _lastError;
                }
            }
        }

        public async Task EnableAsync(BypassProfile? profile = null, CancellationToken cancellationToken = default)
        {
            if (!IsPlatformSupported)
            {
                throw new PlatformNotSupportedException("WinDivert поддерживается только на Windows.");
            }
            if (!HasAdministratorRights)
            {
                throw new InvalidOperationException("Для работы WinDivert требуется запуск от имени администратора.");
            }

            lock (_sync)
            {
                if (_state == BypassState.Enabling || _state == BypassState.Enabled)
                {
                    return;
                }
                _state = BypassState.Enabling;
                _lastError = null;
            }
            OnStateChanged();

            profile ??= BypassProfile.CreateDefault();

            try
            {
                // Use InitializeAsync directly
                await InitializeAsync(profile!, cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    _state = BypassState.Enabled;
                }
                OnStateChanged();
            }
            catch (Exception ex)
            {
                lock (_sync)
                {
                    _state = BypassState.Faulted;
                    _lastError = ex;
                }
                OnStateChanged();
                await DisableAsync().ConfigureAwait(false);
                throw;
            }
        }

        public async Task DisableAsync()
        {
            WinDivertNative.SafeHandle? rstHandle;
            WinDivertNative.SafeHandle? tlsHandle;
            WinDivertNative.SafeHandle? redirectHandle;
            CancellationTokenSource? cts;
            Task? rstTask;
            Task? tlsTask;
            Task? redirectTask;
            Task? cleanupTask;

            bool raiseDisablingEvent = false;
            lock (_sync)
            {
                if (_state == BypassState.Disabled || _state == BypassState.Disabling)
                {
                    return;
                }
                _state = BypassState.Disabling;
                raiseDisablingEvent = true;

                rstHandle = _rstHandle;
                tlsHandle = _tlsHandle;
                redirectHandle = _redirectHandle;
                rstTask = _rstTask;
                tlsTask = _tlsTask;
                redirectTask = _redirectTask;
                cleanupTask = _cleanupTask;
                cts = _cts;

                _rstHandle = null;
                _tlsHandle = null;
                _redirectHandle = null;
                _rstTask = null;
                _tlsTask = null;
                _redirectTask = null;
                _cleanupTask = null;
                _cts = null;
                _runtimeRedirectRules = Array.Empty<RuntimeRedirectRule>();
                IsRstBlockerActive = false;
                _processedConnections.Clear(); // Clear state on disable
            }

            if (raiseDisablingEvent)
            {
                OnStateChanged();
            }

            try
            {
                cts?.Cancel();

                if (rstHandle != null && !rstHandle.IsInvalid)
                {
                    WinDivertNative.WinDivertShutdown(rstHandle, WinDivertNative.ShutdownHow.Both);
                }
                if (tlsHandle != null && !tlsHandle.IsInvalid)
                {
                    WinDivertNative.WinDivertShutdown(tlsHandle, WinDivertNative.ShutdownHow.Both);
                }
                if (redirectHandle != null && !redirectHandle.IsInvalid)
                {
                    WinDivertNative.WinDivertShutdown(redirectHandle, WinDivertNative.ShutdownHow.Both);
                }

                var tasks = new List<Task>();
                if (rstTask != null) tasks.Add(rstTask);
                if (tlsTask != null) tasks.Add(tlsTask);
                if (redirectTask != null) tasks.Add(redirectTask);
                if (cleanupTask != null) tasks.Add(cleanupTask);

                if (tasks.Count > 0)
                {
                    try
                    {
                        await Task.WhenAll(tasks.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default))).ConfigureAwait(false);
                    }
                    catch
                    {
                        // игнорируем ошибки при остановке
                    }
                }
            }
            finally
            {
                rstHandle?.Dispose();
                tlsHandle?.Dispose();
                redirectHandle?.Dispose();

                bool raiseDisabledEvent = false;
                lock (_sync)
                {
                    _state = BypassState.Disabled;
                    _lastError = null;
                    _profile = BypassProfile.CreateDefault();
                    raiseDisabledEvent = true;
                }
                if (raiseDisabledEvent)
                {
                    OnStateChanged();
                }
            }
        }

        /// <summary>
        /// Динамическое включение TLS bypass для конкретного хоста
        /// </summary>
        public async Task EnableTlsBypassAsync(System.Net.IPAddress targetIp, int targetPort = 443, TlsBypassStrategy strategy = TlsBypassStrategy.Fragment)
        {
            // ✅ Всегда активируем TLS bypass (глобальный HTTPS фильтр работает для всех хостов)
            lock (_sync)
            {
                // Если TLS bypass уже активен с той же стратегией - ничего не делаем
                if (_state == BypassState.Enabled && _profile.TlsStrategy == strategy && _tlsHandle != null && !_tlsHandle.IsInvalid)
                {
                    ISPAudit.Utils.DebugLogger.Log($"[WinDivert] TLS bypass ({strategy}) already active");
                    return;
                }
            }

            // Нужно включить TLS bypass
            ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Enabling TLS bypass: {strategy} for {targetIp}:{targetPort}");
            
            // Если уже что-то запущено - перезапускаем
            if (_state == BypassState.Enabled)
            {
                await DisableAsync().ConfigureAwait(false);
            }

            // Запускаем ТОЛЬКО TLS bypass (БЕЗ RST blocker - он конфликтует с Flow layer)
            var profile = new BypassProfile
            {
                DropTcpRst = false,  // ⚠ НЕ включать RST blocker (конфликт с TrafficAnalyzer Flow layer)
                FragmentTlsClientHello = strategy == TlsBypassStrategy.Fragment || strategy == TlsBypassStrategy.FakeFragment,
                TlsStrategy = strategy,
                TlsFirstFragmentSize = 2,  // ✅ УЛЬТРА-ЭКСТРЕМАЛЬНАЯ фрагментация
                TlsFragmentThreshold = 16,
                RedirectRules = Array.Empty<BypassRedirectRule>()
            };
            await EnableAsync(profile).ConfigureAwait(false);
        }

        /// <summary>
        /// Динамическое включение блокировки TCP RST пакетов
        /// </summary>
        public async Task EnableRstBlockingAsync()
        {
            lock (_sync)
            {
                if (_state == BypassState.Enabled && _profile.DropTcpRst && _rstHandle != null && !_rstHandle.IsInvalid)
                {
                    // RST blocking уже активен
                    ISPAudit.Utils.DebugLogger.Log("[WinDivert] RST blocking already active");
                    return;
                }
            }

            // ⚠️ ВНИМАНИЕ: RST blocker конфликтует с TrafficAnalyzer Flow layer
            // Если Flow layer активен (TrafficAnalyzer), RST blocker может не открыться
            ISPAudit.Utils.DebugLogger.Log("[WinDivert] WARNING: RST blocking may conflict with active Flow layer");

            // Нужно перезапустить с новым профилем
            var currentProfile = _profile;
            await DisableAsync().ConfigureAwait(false);

            var newProfile = new BypassProfile
            {
                DropTcpRst = true,
                FragmentTlsClientHello = currentProfile.FragmentTlsClientHello,
                TlsFirstFragmentSize = currentProfile.TlsFirstFragmentSize,
                TlsFragmentThreshold = currentProfile.TlsFragmentThreshold,
                RedirectRules = currentProfile.RedirectRules
            };

            await EnableAsync(newProfile).ConfigureAwait(false);
        }

        /// <summary>
        /// Упрощенный метод для применения bypass стратегии по типу блокировки
        /// </summary>
        public async Task ApplyBypassStrategyAsync(string strategy, System.Net.IPAddress? targetIp = null, int targetPort = 443)
        {
            ISPAudit.Utils.DebugLogger.Log($"[WinDivert] ApplyBypassStrategyAsync: strategy={strategy}, target={targetIp}:{targetPort}");

            switch (strategy)
            {
                case "DROP_RST":
                    // ⚠️ RST blocker может конфликтовать с TrafficAnalyzer Flow layer
                    ISPAudit.Utils.DebugLogger.Log("[WinDivert] DROP_RST strategy requested - may conflict with Flow layer");
                    await EnableRstBlockingAsync().ConfigureAwait(false);
                    break;

                case "TLS_FRAGMENT":
                    if (targetIp != null)
                    {
                        await EnableTlsBypassAsync(targetIp, targetPort, TlsBypassStrategy.Fragment).ConfigureAwait(false);
                    }
                    else
                    {
                        // Общая TLS fragmentation
                        await EnableTlsBypassAsync(IPAddress.Any, 443, TlsBypassStrategy.Fragment).ConfigureAwait(false);
                    }
                    break;

                case "TLS_FAKE":
                    if (targetIp != null)
                    {
                        await EnableTlsBypassAsync(targetIp, targetPort, TlsBypassStrategy.Fake).ConfigureAwait(false);
                    }
                    else
                    {
                        await EnableTlsBypassAsync(IPAddress.Any, 443, TlsBypassStrategy.Fake).ConfigureAwait(false);
                    }
                    break;

                case "TLS_FAKE_FRAGMENT":
                    if (targetIp != null)
                    {
                        await EnableTlsBypassAsync(targetIp, targetPort, TlsBypassStrategy.FakeFragment).ConfigureAwait(false);
                    }
                    else
                    {
                        await EnableTlsBypassAsync(IPAddress.Any, 443, TlsBypassStrategy.FakeFragment).ConfigureAwait(false);
                    }
                    break;

                case "DOH":
                case "PROXY":
                case "NONE":
                case "UNKNOWN":
                    // Эти стратегии требуют внешнего вмешательства (системные настройки)
                    ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Strategy {strategy} requires external intervention - skipping");
                    break;
            }
        }

        private async Task InitializeAsync(BypassProfile profile, CancellationToken cancellationToken)
        {
            // 1. Validation
            if (!NativeLibrary.TryLoad("WinDivert.dll", out var libHandle))
            {
                throw new DllNotFoundException("WinDivert.dll не найден. Поместите библиотеку рядом с исполняемым файлом.");
            }
            NativeLibrary.Free(libHandle);

            // 2. Configuration Building (Async DNS resolution)
            var runtimeRedirectRules = await BuildRuntimeRedirectsAsync(profile, cancellationToken).ConfigureAwait(false);

            // 3. Open Handles (Atomic-ish)
            WinDivertNative.SafeHandle? rstHandle = null;
            WinDivertNative.SafeHandle? tlsHandle = null;
            WinDivertNative.SafeHandle? redirectHandle = null;

            try
            {
                if (profile.DropTcpRst)
                {
                    const string rstFilter = "tcp.Rst == 1";
                    if (TryOpenWinDivert(rstFilter, WinDivertNative.Layer.Network, PriorityRstBlocker, WinDivertNative.OpenFlags.None, out var h))
                    {
                        rstHandle = h;
                        ISPAudit.Utils.DebugLogger.Log($"[WinDivert] RST blocker started with filter: {rstFilter}");
                    }
                    else
                    {
                        ISPAudit.Utils.DebugLogger.Log("[WinDivert] WARNING: RST blocker failed to open (likely conflict with Flow layer) - continuing without it");
                    }
                }

                if (profile.TlsStrategy != TlsBypassStrategy.None)
                {
                    if (TryOpenWinDivert("outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0", WinDivertNative.Layer.Network, PriorityTlsFragmenter, WinDivertNative.OpenFlags.None, out var h))
                    {
                        tlsHandle = h;
                    }
                    else
                    {
                        throw new InvalidOperationException("Failed to open WinDivert handle for TLS bypass");
                    }
                }

                if (runtimeRedirectRules.Count > 0)
                {
                    var redirectFilter = BuildRedirectFilter(runtimeRedirectRules);
                    if (TryOpenWinDivert(redirectFilter, WinDivertNative.Layer.Network, PriorityRedirector, WinDivertNative.OpenFlags.None, out var h))
                    {
                        redirectHandle = h;
                    }
                    else
                    {
                        throw new InvalidOperationException("Failed to open WinDivert handle for redirects");
                    }
                }
            }
            catch
            {
                rstHandle?.Dispose();
                tlsHandle?.Dispose();
                redirectHandle?.Dispose();
                throw;
            }

            // 4. Commit State & Start Tasks
            _profile = profile;
            _runtimeRedirectRules = runtimeRedirectRules;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            
            _rstHandle = rstHandle;
            _tlsHandle = tlsHandle;
            _redirectHandle = redirectHandle;

            ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Initialize: DropTcpRst={profile.DropTcpRst}, TlsStrategy={profile.TlsStrategy}, Redirects={_runtimeRedirectRules.Count}");

            if (_rstHandle != null) 
            {
                IsRstBlockerActive = true;
                _rstTask = RunWorkerAsync(() => PumpPacketsWorker(_rstHandle, _cts.Token));
            }
            else
            {
                IsRstBlockerActive = false;
            }

            if (_tlsHandle != null) 
                _tlsTask = RunWorkerAsync(() => TlsFragmenterWorker(_tlsHandle, _cts.Token, profile));
            
            if (_redirectHandle != null) 
                _redirectTask = RunWorkerAsync(() => RedirectorWorker(_redirectHandle, _cts.Token, _runtimeRedirectRules));

            // Start cleanup task
            _cleanupTask = RunWorkerAsync(() => CleanupWorker(_cts.Token));
        }

        private async Task RunWorkerAsync(Action worker)
        {
            try
            {
                await Task.Run(worker).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Worker task failed: {ex.Message}");
                lock (_sync)
                {
                    if (_state == BypassState.Enabled)
                    {
                        _state = BypassState.Faulted;
                        _lastError = ex;
                        OnStateChanged();
                    }
                }
            }
        }

        /// <summary>
        /// Создает WinDivert фильтр для TLS fragmentation (опционально для конкретного хоста)
        /// </summary>
        private static string BuildTlsFragmentFilter(IPAddress? targetIp, int targetPort)
        {
            if (targetIp != null)
            {
                // Хост-специфичный фильтр
                return $"outbound and ip.DstAddr == {targetIp} and tcp.DstPort == {targetPort} and tcp.PayloadLength > 0";
            }
            // Глобальный HTTPS фильтр
            return "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0";
        }

        private static async Task<IReadOnlyList<RuntimeRedirectRule>> BuildRuntimeRedirectsAsync(BypassProfile profile, CancellationToken token)
        {
            var result = new List<RuntimeRedirectRule>();
            foreach (var rule in profile.RedirectRules.Where(r => r.Enabled))
            {
                try
                {
                    var address = rule.GetRedirectAddress();
                    var hosts = new HashSet<IPAddress>();
                    foreach (var host in rule.Hosts)
                    {
                        try
                        {
                            // Async DNS resolution with timeout
                            var ips = await ResolveHostAsync(host, token).ConfigureAwait(false);
                            foreach (var ip in ips)
                            {
                                if (ip.AddressFamily == address.AddressFamily)
                                {
                                    hosts.Add(ip);
                                }
                            }
                        }
                        catch
                        {
                            // игнорируем
                        }
                    }

                    result.Add(new RuntimeRedirectRule(rule, address, hosts));
                }
                catch
                {
                    // пропускаем некорректные правила
                }
            }
            return result;
        }

        private static async Task<IPAddress[]> ResolveHostAsync(string host, CancellationToken token)
        {
            try
            {
                // Short timeout for DNS to avoid hanging initialization
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(2));
                return await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false);
            }
            catch
            {
                return Array.Empty<IPAddress>();
            }
        }

        private static string BuildRedirectFilter(IReadOnlyList<RuntimeRedirectRule> rules)
        {
            var parts = new List<string>();
            foreach (var group in rules.GroupBy(r => r.Rule.Protocol))
            {
                var portConditions = string.Join(" or ", group.Select(r => $"tcp.DstPort == {r.Rule.Port}").Distinct());
                if (group.Key == TransportProtocol.Udp)
                {
                    portConditions = string.Join(" or ", group.Select(r => $"udp.DstPort == {r.Rule.Port}").Distinct());
                    parts.Add("outbound and udp and (" + portConditions + ")");
                }
                else
                {
                    parts.Add("outbound and tcp and (" + portConditions + ")");
                }
            }

            return parts.Count == 0 ? "false" : string.Join(" or ", parts);
        }

        private void PumpPacketsWorker(WinDivertNative.SafeHandle handle, CancellationToken token)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(WinDivertNative.MaxPacketSize);
            var addr = new WinDivertNative.Address();
            long rstPackets = 0;

            try
            {
                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, out var readLen, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorOperationAborted) break;
                        continue;
                    }

                    Interlocked.Increment(ref _packetsProcessed);
                    int length = (int)readLen;
                    var packet = PacketHelper.Parse(buffer, length);

                    if (packet.IsValid && packet.IsTcp && packet.IsRst)
                    {
                        rstPackets++;
                        Interlocked.Increment(ref _rstDropped);
                        if (rstPackets <= 10 || rstPackets % 50 == 0)
                        {
                            ISPAudit.Utils.DebugLogger.Log($"[WinDivert] RST DROPPED: {packet.SrcIp}:{packet.SrcPort} -> {packet.DstIp}:{packet.DstPort}, total={rstPackets}");
                        }
                        // Drop packet (do not call Send)
                    }
                    else
                    {
                        // Should not happen with filter "tcp.Rst == 1", but if it does, reinject
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private void TlsFragmenterWorker(WinDivertNative.SafeHandle handle, CancellationToken token, BypassProfile profile)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(WinDivertNative.MaxPacketSize);
            var addr = new WinDivertNative.Address();
            
            // Initialize strategies
            var strategies = new List<ITlsStrategy>();
            if (profile.TlsStrategy == TlsBypassStrategy.Fake || profile.TlsStrategy == TlsBypassStrategy.FakeFragment)
            {
                strategies.Add(new FakeStrategy());
            }
            if (profile.TlsStrategy == TlsBypassStrategy.Fragment || profile.TlsStrategy == TlsBypassStrategy.FakeFragment)
            {
                strategies.Add(new FragmentStrategy());
            }

            ISPAudit.Utils.DebugLogger.Log($"[WinDivert] TLS fragmenter started (Strategies={strategies.Count})");

            try
            {
                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, out var read, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorOperationAborted) break;
                        continue;
                    }

                    Interlocked.Increment(ref _packetsProcessed);
                    int length = (int)read;
                    var packet = PacketHelper.Parse(buffer, length);

                    if (!packet.IsValid || !packet.IsIpv4 || !packet.IsTcp || packet.PayloadLength < profile.TlsFragmentThreshold)
                    {
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                        continue;
                    }

                    if (!IsClientHello(buffer.AsSpan(packet.PayloadOffset, packet.PayloadLength)))
                    {
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                        continue;
                    }

                    // ClientHello detected
                    var connectionKey = new ConnectionKey(packet.SrcIpInt, packet.DstIpInt, packet.SrcPort, packet.DstPort);
                    bool isNewConnection = !_processedConnections.ContainsKey(connectionKey);
                    _processedConnections[connectionKey] = Environment.TickCount64; // Update timestamp

                    if (isNewConnection)
                    {
                        ISPAudit.Utils.DebugLogger.Log($"[WinDivert] ClientHello detected: {packet.SrcIp} → {packet.DstIp}:{packet.DstPort}");
                    }

                    bool handled = false;
                    foreach (var strategy in strategies)
                    {
                        if (strategy.Process(handle, buffer, length, packet, ref addr, profile, isNewConnection))
                        {
                            handled = true;
                            if (strategy is FragmentStrategy) Interlocked.Increment(ref _clientHellosFragmented);
                        }
                    }

                    if (!handled)
                    {
                        // If not fragmented (e.g. Fake only, or fragmentation failed), send original
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private interface ITlsStrategy
        {
            bool Process(WinDivertNative.SafeHandle handle, byte[] buffer, int length, in PacketHelper.PacketInfo packet, ref WinDivertNative.Address addr, BypassProfile profile, bool isNewConnection);
        }

        private class FakeStrategy : ITlsStrategy
        {
            public bool Process(WinDivertNative.SafeHandle handle, byte[] buffer, int length, in PacketHelper.PacketInfo packet, ref WinDivertNative.Address addr, BypassProfile profile, bool isNewConnection)
            {
                if (!isNewConnection) return false;
                
                // Rent a buffer for the fake packet
                var fakeBuffer = ArrayPool<byte>.Shared.Rent(length);
                try
                {
                    Buffer.BlockCopy(buffer, 0, fakeBuffer, 0, length);
                    
                    // Modify Sequence Number (BadSeq): Seq - 10000
                    int seqOffset = packet.IpHeaderLength + 4;
                    uint seq = BinaryPrimitives.ReadUInt32BigEndian(fakeBuffer.AsSpan(seqOffset, 4));
                    BinaryPrimitives.WriteUInt32BigEndian(fakeBuffer.AsSpan(seqOffset, 4), seq - 10000);
                    
                    WinDivertNative.WinDivertHelperCalcChecksums(fakeBuffer, (uint)length, ref addr, 0);
                    WinDivertNative.WinDivertSend(handle, fakeBuffer, (uint)length, out _, in addr);
                    
                    ISPAudit.Utils.DebugLogger.Log($"[WinDivert] FAKE packet sent for {packet.DstIp}:{packet.DstPort}");
                    return true;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(fakeBuffer);
                }
            }
        }

        private class FragmentStrategy : ITlsStrategy
        {
            public bool Process(WinDivertNative.SafeHandle handle, byte[] buffer, int length, in PacketHelper.PacketInfo packet, ref WinDivertNative.Address addr, BypassProfile profile, bool isNewConnection)
            {
                int firstLen = Math.Min(profile.TlsFirstFragmentSize, packet.PayloadLength - 1);
                int secondLen = packet.PayloadLength - firstLen;
                
                if (firstLen <= 0 || secondLen <= 0) return false;

                // Rent buffers for fragments
                // Note: We need slightly larger buffers for headers + payload
                int headerLen = packet.IpHeaderLength + packet.TcpHeaderLength;
                var firstBuffer = ArrayPool<byte>.Shared.Rent(headerLen + firstLen);
                var secondBuffer = ArrayPool<byte>.Shared.Rent(headerLen + secondLen);

                try
                {
                    // First Fragment
                    Buffer.BlockCopy(buffer, 0, firstBuffer, 0, headerLen); // Headers
                    Buffer.BlockCopy(buffer, packet.PayloadOffset, firstBuffer, headerLen, firstLen); // Payload 1
                    AdjustPacketLengths(firstBuffer, packet.IpHeaderLength, packet.TcpHeaderLength, firstLen, packet.IsIpv4);
                    WinDivertNative.WinDivertHelperCalcChecksums(firstBuffer, (uint)(headerLen + firstLen), ref addr, 0);
                    WinDivertNative.WinDivertSend(handle, firstBuffer, (uint)(headerLen + firstLen), out _, in addr);

                    // Second Fragment
                    Buffer.BlockCopy(buffer, 0, secondBuffer, 0, headerLen); // Headers
                    Buffer.BlockCopy(buffer, packet.PayloadOffset + firstLen, secondBuffer, headerLen, secondLen); // Payload 2
                    IncrementTcpSequence(secondBuffer, packet.IpHeaderLength, (uint)firstLen);
                    AdjustPacketLengths(secondBuffer, packet.IpHeaderLength, packet.TcpHeaderLength, secondLen, packet.IsIpv4);
                    WinDivertNative.WinDivertHelperCalcChecksums(secondBuffer, (uint)(headerLen + secondLen), ref addr, 0);
                    WinDivertNative.WinDivertSend(handle, secondBuffer, (uint)(headerLen + secondLen), out _, in addr);

                    return true;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(firstBuffer);
                    ArrayPool<byte>.Shared.Return(secondBuffer);
                }
            }
        }

        private void RedirectorWorker(WinDivertNative.SafeHandle handle, CancellationToken token, IReadOnlyList<RuntimeRedirectRule> rules)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(WinDivertNative.MaxPacketSize);
            var addr = new WinDivertNative.Address();

            try
            {
                while (!token.IsCancellationRequested)
                {
                    if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, out var read, out addr))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == WinDivertNative.ErrorOperationAborted) break;
                        continue;
                    }

                    int length = (int)read;
                    var packet = PacketHelper.Parse(buffer, length);

                    if (!packet.IsValid)
                    {
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                        continue;
                    }

                    var rule = rules.FirstOrDefault(r => r.Rule.Protocol == (packet.IsTcp ? TransportProtocol.Tcp : TransportProtocol.Udp) && r.Rule.Port == packet.DstPort);
                    
                    if (rule == null)
                    {
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                        continue;
                    }

                    if (rule.AllowedDestinations.Count > 0 && !rule.AllowedDestinations.Contains(packet.DstIp))
                    {
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                        continue;
                    }

                    if (packet.DstIp.AddressFamily != rule.RedirectAddress.AddressFamily)
                    {
                        WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                        continue;
                    }

                    // Apply Redirect
                    if (rule.RedirectAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var bytes = rule.RedirectAddress.GetAddressBytes();
                        Buffer.BlockCopy(bytes, 0, buffer, 16, 4);
                    }
                    else if (rule.RedirectAddress.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        var bytes = rule.RedirectAddress.GetAddressBytes();
                        Buffer.BlockCopy(bytes, 0, buffer, 24, 16);
                    }

                    // Update Port
                    // Transport offset is IpHeaderLength
                    BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(packet.IpHeaderLength + 2, 2), rule.Rule.RedirectPort);

                    WinDivertNative.WinDivertHelperCalcChecksums(buffer, (uint)length, ref addr, 0);
                    WinDivertNative.WinDivertSend(handle, buffer, (uint)length, out _, in addr);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private static bool IsClientHello(ReadOnlySpan<byte> payload)
        {
            if (payload.Length < 7) return false;
            if (payload[0] != 0x16) return false; // TLS Handshake
            if (payload[5] != 0x01) return false; // ClientHello
            return true;
        }

        private static void AdjustPacketLengths(byte[] packet, int ipHeaderLength, int tcpHeaderLength, int payloadLength, bool isIpv4)
        {
            if (isIpv4)
            {
                ushort total = (ushort)(ipHeaderLength + tcpHeaderLength + payloadLength);
                packet[2] = (byte)(total >> 8);
                packet[3] = (byte)(total & 0xFF);
            }
            else
            {
                ushort payload = (ushort)(tcpHeaderLength + payloadLength);
                packet[4] = (byte)(payload >> 8);
                packet[5] = (byte)(payload & 0xFF);
            }
        }

        private static void IncrementTcpSequence(byte[] packet, int ipHeaderLength, uint delta)
        {
            int offset = ipHeaderLength + 4;
            uint sequence = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset, 4));
            sequence += delta;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(offset, 4), sequence);
        }

        private void OnStateChanged()
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }

        public void Dispose()
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        public async ValueTask DisposeAsync()
        {
            await DisableAsync().ConfigureAwait(false);
        }

        private sealed record RuntimeRedirectRule(BypassRedirectRule Rule, IPAddress RedirectAddress, HashSet<IPAddress> AllowedDestinations);

        private readonly struct ConnectionKey : IEquatable<ConnectionKey>
        {
            public static readonly ConnectionKey Empty = new(0, 0, 0, 0);

            public readonly uint SrcIp;
            public readonly uint DstIp;
            public readonly ushort SrcPort;
            public readonly ushort DstPort;

            public ConnectionKey(uint srcIp, uint dstIp, ushort srcPort, ushort dstPort)
            {
                SrcIp = srcIp;
                DstIp = dstIp;
                SrcPort = srcPort;
                DstPort = dstPort;
            }

            public bool Equals(ConnectionKey other)
            {
                return SrcIp == other.SrcIp && DstIp == other.DstIp && SrcPort == other.SrcPort && DstPort == other.DstPort;
            }

            public override bool Equals(object? obj)
            {
                return obj is ConnectionKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(SrcIp, DstIp, SrcPort, DstPort);
            }
        }

        // Unified Packet Parsing Helper
        private static class PacketHelper
        {
            public readonly struct PacketInfo
            {
                public readonly bool IsValid;
                public readonly bool IsIpv4;
                public readonly bool IsTcp;
                public readonly bool IsUdp;
                public readonly bool IsRst;
                public readonly int IpHeaderLength;
                public readonly int TcpHeaderLength;
                public readonly int PayloadOffset;
                public readonly int PayloadLength;
                
                private readonly uint _srcIpInt;
                private readonly uint _dstIpInt;
                private readonly byte[]? _srcIpBytes;
                private readonly byte[]? _dstIpBytes;

                public IPAddress SrcIp => IsIpv4 ? new IPAddress(_srcIpInt) : new IPAddress(_srcIpBytes ?? Array.Empty<byte>());
                public IPAddress DstIp => IsIpv4 ? new IPAddress(_dstIpInt) : new IPAddress(_dstIpBytes ?? Array.Empty<byte>());

                public readonly uint SrcIpInt => _srcIpInt;
                public readonly uint DstIpInt => _dstIpInt;
                
                public readonly ushort SrcPort;
                public readonly ushort DstPort;

                public PacketInfo(bool isValid, bool isIpv4, bool isTcp, bool isUdp, bool isRst, int ipHeaderLen, int tcpHeaderLen, int payloadOffset, int payloadLen, uint srcInt, uint dstInt, byte[]? srcBytes, byte[]? dstBytes, ushort srcPort, ushort dstPort)
                {
                    IsValid = isValid;
                    IsIpv4 = isIpv4;
                    IsTcp = isTcp;
                    IsUdp = isUdp;
                    IsRst = isRst;
                    IpHeaderLength = ipHeaderLen;
                    TcpHeaderLength = tcpHeaderLen;
                    PayloadOffset = payloadOffset;
                    PayloadLength = payloadLen;
                    _srcIpInt = srcInt;
                    _dstIpInt = dstInt;
                    _srcIpBytes = srcBytes;
                    _dstIpBytes = dstBytes;
                    SrcPort = srcPort;
                    DstPort = dstPort;
                }
            }

            public static PacketInfo Parse(byte[] buffer, int length)
            {
                if (length < 20) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, null, 0, 0);

                int version = buffer[0] >> 4;
                bool isIpv4 = version == 4;
                int ipHeaderLength = 0;
                int protocol = 0;
                uint srcIpInt = 0;
                uint dstIpInt = 0;
                byte[]? srcIpBytes = null;
                byte[]? dstIpBytes = null;

                if (isIpv4)
                {
                    ipHeaderLength = (buffer[0] & 0x0F) * 4;
                    if (length < ipHeaderLength) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, null, 0, 0);
                    protocol = buffer[9];
                    srcIpInt = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(12, 4));
                    dstIpInt = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(16, 4));
                }
                else
                {
                    ipHeaderLength = 40;
                    if (length < ipHeaderLength) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, null, 0, 0);
                    protocol = buffer[6]; // NextHeader
                    srcIpBytes = buffer.AsSpan(8, 16).ToArray();
                    dstIpBytes = buffer.AsSpan(24, 16).ToArray();
                }

                bool isTcp = protocol == 6;
                bool isUdp = protocol == 17;
                int tcpHeaderLength = 0;
                int payloadOffset = 0;
                int payloadLength = 0;
                ushort srcPort = 0;
                ushort dstPort = 0;
                bool isRst = false;

                if (isTcp)
                {
                    if (length < ipHeaderLength + 20) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, null, 0, 0);
                    srcPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength, 2));
                    dstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength + 2, 2));
                    tcpHeaderLength = ((buffer[ipHeaderLength + 12] >> 4) & 0xF) * 4;
                    payloadOffset = ipHeaderLength + tcpHeaderLength;
                    payloadLength = length - payloadOffset;
                    isRst = (buffer[ipHeaderLength + 13] & 0x04) != 0;
                }
                else if (isUdp)
                {
                    if (length < ipHeaderLength + 8) return new PacketInfo(false, false, false, false, false, 0, 0, 0, 0, 0, 0, null, null, 0, 0);
                    srcPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength, 2));
                    dstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength + 2, 2));
                    payloadOffset = ipHeaderLength + 8;
                    payloadLength = length - payloadOffset;
                }

                return new PacketInfo(true, isIpv4, isTcp, isUdp, isRst, ipHeaderLength, tcpHeaderLength, payloadOffset, payloadLength, srcIpInt, dstIpInt, srcIpBytes, dstIpBytes, srcPort, dstPort);
            }
        }

        private async void CleanupWorker(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), token).ConfigureAwait(false);

                    long now = Environment.TickCount64;
                    long expiration = TimeSpan.FromMinutes(5).Milliseconds; // 5 minutes TTL

                    var keysToRemove = new List<ConnectionKey>();
                    foreach (var kvp in _processedConnections)
                    {
                        if (now - kvp.Value > expiration)
                        {
                            keysToRemove.Add(kvp.Key);
                        }
                    }

                    foreach (var key in keysToRemove)
                    {
                        _processedConnections.TryRemove(key, out _);
                    }
                    
                    if (keysToRemove.Count > 0)
                    {
                        ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Cleanup: Removed {keysToRemove.Count} expired connections. Active: {_processedConnections.Count}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception ex)
            {
                ISPAudit.Utils.DebugLogger.Log($"[WinDivert] Cleanup worker error: {ex.Message}");
            }
        }
    }
}
