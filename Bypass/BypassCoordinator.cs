using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using ISPAudit.Models;
using IspAudit.Output;

namespace IspAudit.Bypass
{
    public class FixResult
    {
        public bool Success { get; set; }
        public string Strategy { get; set; } = "NONE";
        public TargetReport? FinalReport { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class BypassCoordinator
    {
        private readonly WinDivertBypassManager _manager;
        private readonly Dictionary<string, string> _workingStrategies = new(); // Host -> Strategy

        public BypassCoordinator(WinDivertBypassManager manager)
        {
            _manager = manager;
        }

        public List<string> SuggestFixes(TargetReport report)
        {
            return StrategyMapping.GetStrategiesFor(report).GetAll();
        }

        public async Task<FixResult> AutoFixAsync(
            Target target, 
            TargetReport initialReport,
            Func<Target, Task<TargetReport>> retestCallback, 
            CancellationToken ct)
        {
            // 1. Check cache
            if (_workingStrategies.TryGetValue(target.Host, out var cachedStrategy))
            {
                ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Trying cached strategy '{cachedStrategy}' for {target.Host}");
                
                await ApplyStrategyAsync(cachedStrategy, target, ct).ConfigureAwait(false);
                
                var report = await retestCallback(target).ConfigureAwait(false);
                if (IsFixed(report))
                {
                    return new FixResult { Success = true, Strategy = cachedStrategy, FinalReport = report, Message = "Used cached strategy" };
                }
                
                // Cached failed, remove
                _workingStrategies.Remove(target.Host);
                ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Cached strategy '{cachedStrategy}' failed for {target.Host}");
            }

            // 2. Get strategies
            var rec = StrategyMapping.GetStrategiesFor(initialReport);
            var strategies = rec.Applicable; // Only try applicable strategies automatically

            if (strategies.Count == 0)
            {
                return new FixResult { Success = false, Message = "No applicable strategies available" };
            }

            ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Auto-fix strategies for {target.Host}: {string.Join(", ", strategies)}");

            // 3. Try loop
            foreach (var strategy in strategies)
            {
                if (ct.IsCancellationRequested) break;

                ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Applying '{strategy}' for {target.Host}...");
                await ApplyStrategyAsync(strategy, target, ct).ConfigureAwait(false);

                // Retest
                await Task.Delay(500, ct).ConfigureAwait(false); // Give it a moment
                var report = await retestCallback(target).ConfigureAwait(false);

                if (IsFixed(report))
                {
                    ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Strategy '{strategy}' SUCCESS for {target.Host}");
                    _workingStrategies[target.Host] = strategy;
                    return new FixResult { Success = true, Strategy = strategy, FinalReport = report, Message = "Strategy successful" };
                }
                else
                {
                    ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Strategy '{strategy}' FAILED for {target.Host}");
                }
            }

            // 4. Cleanup if failed
            // We don't necessarily want to disable everything if we failed this target, 
            // but if we leave a broken strategy active it might affect others.
            // However, WinDivertBypassManager is global.
            // If we failed, we should probably revert to Disabled or previous state?
            // For now, let's disable to be safe.
            await _manager.DisableAsync().ConfigureAwait(false);
            
            return new FixResult { Success = false, Message = "All strategies failed" };
        }

        public async Task<FixResult> AutoFixLiveAsync(
            IspAudit.Core.Models.HostTested initialResult,
            Func<IspAudit.Core.Models.HostTested, Task<IspAudit.Core.Models.HostTested>> retestCallback,
            CancellationToken ct)
        {
            var hostKey = initialResult.Host.Key;

            // 1. Check cache
            if (_workingStrategies.TryGetValue(hostKey, out var cachedStrategy))
            {
                ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Trying cached strategy '{cachedStrategy}' for {hostKey}");
                
                await ApplyStrategyLiveAsync(cachedStrategy, initialResult.Host.RemoteIp, ct).ConfigureAwait(false);
                
                var result = await retestCallback(initialResult).ConfigureAwait(false);
                if (IsFixed(result))
                {
                    return new FixResult { Success = true, Strategy = cachedStrategy, Message = "Used cached strategy" };
                }
                
                _workingStrategies.Remove(hostKey);
            }

            // 2. Get strategies
            var rec = StrategyMapping.GetStrategiesFor(initialResult);
            var strategies = rec.Applicable; // Only try applicable strategies automatically

            if (strategies.Count == 0)
            {
                return new FixResult { Success = false, Message = "No applicable strategies available" };
            }

            // 3. Try loop
            foreach (var strategy in strategies)
            {
                if (ct.IsCancellationRequested) break;

                await ApplyStrategyLiveAsync(strategy, initialResult.Host.RemoteIp, ct).ConfigureAwait(false);

                // Retest
                await Task.Delay(500, ct).ConfigureAwait(false);
                var result = await retestCallback(initialResult).ConfigureAwait(false);

                if (IsFixed(result))
                {
                    _workingStrategies[hostKey] = strategy;
                    return new FixResult { Success = true, Strategy = strategy, Message = "Strategy successful" };
                }
            }

            await _manager.DisableAsync().ConfigureAwait(false);
            return new FixResult { Success = false, Message = "All strategies failed" };
        }

        private async Task ApplyStrategyLiveAsync(string strategy, IPAddress ip, CancellationToken ct)
        {
            try
            {
                await _manager.ApplyBypassStrategyAsync(strategy, ip).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Failed to apply strategy '{strategy}': {ex.Message}");
            }
        }

        private bool IsFixed(IspAudit.Core.Models.HostTested result)
        {
            return result.TcpOk && result.TlsOk;
        }

        private async Task ApplyStrategyAsync(string strategy, Target target, CancellationToken ct)
        {
            IPAddress? ip = null;
            try 
            {
                // Try to resolve host to IP for specific targeting
                var ips = await Dns.GetHostAddressesAsync(target.Host, ct).ConfigureAwait(false);
                ip = ips.FirstOrDefault(i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            } 
            catch 
            {
                // Resolution failed, ip remains null (Global apply)
            }

            // If we have a fallback IP and resolution failed, maybe use that?
            if (ip == null && !string.IsNullOrEmpty(target.FallbackIp) && IPAddress.TryParse(target.FallbackIp, out var fallback))
            {
                ip = fallback;
            }

            try
            {
                await _manager.ApplyBypassStrategyAsync(strategy, ip).ConfigureAwait(false);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("администратора"))
            {
                ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Failed to apply strategy '{strategy}': Admin rights required.");
                throw; // Re-throw to be handled by caller or let it fail the fix
            }
            catch (Exception ex)
            {
                ISPAudit.Utils.DebugLogger.Log($"[Coordinator] Failed to apply strategy '{strategy}': {ex.Message}");
            }
        }

        private bool IsFixed(TargetReport report)
        {
            // Logic to determine if fixed
            // TCP must be open (if enabled)
            bool tcpOk = !report.tcp_enabled || report.tcp.Any(t => t.open);
            
            // HTTP must be success (if enabled) AND not a block page
            bool httpOk = !report.http_enabled || report.http.Any(h => h.success && h.status is >= 200 and < 400 && h.is_block_page != true);
            
            return tcpOk && httpOk;
        }
    }
}
