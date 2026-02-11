using System;
using System.Linq;
using System.Threading.Tasks;
using IspAudit.Core.Diagnostics;
using IspAudit.Models;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        #region DNS Resolution

        /// <summary>
        /// Предварительное разрешение целей
        /// </summary>
        public Task PreResolveTargetsAsync()
        {
            try
            {
                Log("[PreResolve] Starting target resolution...");
                _resolvedIpMap.Clear();

                // В новой архитектуре цели формируются динамически, поэтому
                // предварительное разрешение по статическому каталогу не требуется.
                Log($"[PreResolve] Skipped: dynamic targets mode");

                // Обновляем существующие результаты
                UiPost(() =>
                {
                    foreach (var result in TestResults)
                    {
                        if (result.Target.Name == result.Target.Host &&
                            _resolvedIpMap.TryGetValue(result.Target.Host, out var resolvedTarget))
                        {
                            result.Target = resolvedTarget;
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                Log($"[PreResolve] Error: {ex.Message}");
            }

            // Никакой асинхронной работы здесь больше нет
            return Task.CompletedTask;
        }

        private async Task ResolveUnknownHostAsync(string ip)
        {
            if (_resolvedIpMap.ContainsKey(ip) || _pendingResolutions.ContainsKey(ip)) return;

            _pendingResolutions.TryAdd(ip, true);

            try
            {
                var dnsResult = await IspAudit.Utils.NetUtils.ResolveWithFallbackAsync(ip);
                if (dnsResult.Addresses.Count > 0)
                {
                    string hostName = ip;
                    try
                    {
                        var entry = await System.Net.Dns.GetHostEntryAsync(ip);
                        if (!string.IsNullOrEmpty(entry.HostName)) hostName = entry.HostName;
                    }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[TestResults] GetHostEntry({ip}): {ex.Message}"); }

                    var newTarget = new Target
                    {
                        Name = hostName,
                        Host = ip,
                        Service = "Resolved"
                    };

                    _resolvedIpMap[ip] = newTarget;

                    UiPost(() =>
                    {
                        var result = TestResults.FirstOrDefault(t => t.Target.Host == ip);
                        if (result != null)
                        {
                            result.Target = newTarget;

                            if (dnsResult.SystemDnsFailed)
                            {
                                result.Details += "\n⚠️ Имя хоста разрешено через DoH (системный DNS недоступен/фильтруется)";
                                if (result.Status == TestStatus.Pass) result.Status = TestStatus.Warn;
                            }
                        }
                    });
                }
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[TestResults] ResolveUnknownHost({ip}): {ex.Message}"); }
            finally
            {
                _pendingResolutions.TryRemove(ip, out _);
            }
        }

        #endregion
    }
}
