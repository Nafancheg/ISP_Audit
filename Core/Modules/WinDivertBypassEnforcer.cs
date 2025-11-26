using System;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Net;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Bypass;

namespace IspAudit.Core.Modules
{
    public class WinDivertBypassEnforcer : IBypassEnforcer
    {
        private readonly IspAudit.Bypass.WinDivertBypassManager? _bypassManager;
        private readonly IHostTester _tester;
        private readonly IProgress<string>? _progress;
        private readonly SemaphoreSlim _bypassLock = new(1, 1);
        private static string? _globalWorkingStrategy;

        public WinDivertBypassEnforcer(
            IspAudit.Bypass.WinDivertBypassManager? bypassManager,
            IHostTester tester,
            IProgress<string>? progress)
        {
            _bypassManager = bypassManager;
            _tester = tester;
            _progress = progress;
        }

        public async Task ApplyBypassAsync(HostBlocked blocked, CancellationToken ct)
        {
            var ip = blocked.TestResult.Host.RemoteIp;
            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.None) || ip.ToString() == "0.0.0.0")
            {
                _progress?.Report($"⚠ Пропуск bypass для некорректного IP: {ip}");
                return;
            }

            // Ensure sequential execution of bypass strategies
            await _bypassLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                // 0. Optimization: Try globally working strategy first if it exists
                if (_globalWorkingStrategy != null && _globalWorkingStrategy != blocked.BypassStrategy && IsTechnicalStrategy(_globalWorkingStrategy))
                {
                    _progress?.Report($"[BYPASS] Пробую ранее успешную стратегию: {_globalWorkingStrategy}...");
                    if (await ApplySingleStrategyAsync(_globalWorkingStrategy, blocked, ct).ConfigureAwait(false))
                    {
                        return;
                    }
                }

                // 1. Try the recommended strategy first
                bool success = await ApplySingleStrategyAsync(blocked.BypassStrategy, blocked, ct).ConfigureAwait(false);
                if (success) 
                {
                    if (IsTechnicalStrategy(blocked.BypassStrategy)) _globalWorkingStrategy = blocked.BypassStrategy;
                    return;
                }

                // 2. If failed, try other strategies from StrategyMapping
                if (_bypassManager != null && IsTechnicalStrategy(blocked.BypassStrategy))
                {
                    var rec = StrategyMapping.GetStrategiesFor(blocked.TestResult);
                    var strategies = rec.Applicable; // Only try applicable strategies automatically

                    foreach (var strategy in strategies)
                    {
                        if (strategy == blocked.BypassStrategy) continue; // Already tried
                        if (strategy == _globalWorkingStrategy) continue; // Already tried in step 0

                        _progress?.Report($"[BYPASS] Пробую альтернативную стратегию: {strategy}...");
                        // Report in a format that MainViewModel parses to update the UI state
                        _progress?.Report($"   → Стратегия: {strategy}");
                        
                        success = await ApplySingleStrategyAsync(strategy, blocked, ct).ConfigureAwait(false);
                        if (success) 
                        {
                            _globalWorkingStrategy = strategy;
                            return;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[BYPASS] Ошибка применения bypass: {ex.Message}");
            }
            finally
            {
                _bypassLock.Release();
            }
        }

        private bool IsTechnicalStrategy(string strategy)
        {
            return strategy != "DOH" && strategy != "PROXY" && strategy != "ROUTER_REDIRECT" && strategy != "NONE" && strategy != "UNKNOWN";
        }

        private async Task<bool> ApplySingleStrategyAsync(string strategy, HostBlocked blocked, CancellationToken ct)
        {
            var host = blocked.TestResult.Hostname ?? blocked.TestResult.Host.RemoteIp.ToString();
            var ip = blocked.TestResult.Host.RemoteIp;
            var port = blocked.TestResult.Host.RemotePort;

            switch (strategy)
            {
                case "DROP_RST":
                    _progress?.Report($"[BYPASS] Применяю DROP_RST (Global) для {ip}:{port}...");
                    
                    if (_bypassManager != null)
                    {
                        // Pass null for targetIp to enable Global Mode
                        await _bypassManager.ApplyBypassStrategyAsync("DROP_RST", null, port).ConfigureAwait(false);
                        _progress?.Report($"✓ DROP_RST bypass активен (Global)");
                        
                        // Ретест: проверяем что bypass работает
                        _progress?.Report($"[BYPASS] Проверяю эффективность bypass для {ip}:{port}...");
                        await Task.Delay(500, ct).ConfigureAwait(false);
                        
                        var retestResult = await _tester.TestHostAsync(blocked.TestResult.Host, ct).ConfigureAwait(false);
                        if (retestResult.TcpOk && retestResult.BlockageType != "TCP_RST")
                        {
                            _progress?.Report($"✓✓ BYPASS РАБОТАЕТ! {ip}:{port} теперь доступен (TCP RST заблокирован)");
                            return true;
                        }
                        else
                        {
                            _progress?.Report($"⚠ Bypass применен, но {ip}:{port} все еще заблокирован.");
                            return false;
                        }
                    }
                    else
                    {
                        _progress?.Report($"⚠ DROP_RST bypass требует прав администратора (WinDivert)");
                        return false;
                    }

                case "TLS_FRAGMENT":
                case "TLS_FAKE":
                case "TLS_FAKE_FRAGMENT":
                    _progress?.Report($"[BYPASS] Применяю комбинированный bypass ({strategy} + DROP_RST) (Global) для {host}...");
                    
                    if (_bypassManager != null)
                    {
                        // ✅ СНАЧАЛА активируем TLS стратегию (настраивает профиль) - Global (null IP)
                        await _bypassManager.ApplyBypassStrategyAsync(strategy, null, port).ConfigureAwait(false);
                        _progress?.Report($"✓ {strategy} активен (Global)");
                        
                        // ✅ ЗАТЕМ активируем DROP_RST (добавляет RST blocking к текущему профилю) - Global (null IP)
                        await _bypassManager.ApplyBypassStrategyAsync("DROP_RST", null, port).ConfigureAwait(false);
                        _progress?.Report($"✓ DROP_RST активен (защита от RST injection)");
                        
                        // ✅ Принудительно сбрасываем все TCP соединения к цели
                        _progress?.Report($"[BYPASS] Сброс существующих TCP соединений к {ip}:{port}...");
                        try
                        {
                            using var resetSocket = new System.Net.Sockets.TcpClient();
                            await resetSocket.ConnectAsync(ip, port, ct).ConfigureAwait(false);
                            resetSocket.Client.Close(); // Отправит FIN/RST
                        }
                        catch { /* Игнорируем ошибки сброса */ }
                        
                        // Ретест: проверяем что bypass работает (увеличена задержка до 3 сек)
                        _progress?.Report($"[BYPASS] Проверяю эффективность комбинированного bypass для {host}...");
                        await Task.Delay(3000, ct).ConfigureAwait(false); // ✅ 3 секунды для инициализации
                        
                        var retestResult = await _tester.TestHostAsync(blocked.TestResult.Host, ct).ConfigureAwait(false);
                        if (retestResult.TlsOk)
                        {
                            _progress?.Report($"✓✓ КОМБИНИРОВАННЫЙ BYPASS РАБОТАЕТ! {host} теперь доступен (TLS: OK)");
                            return true;
                        }
                        else
                        {
                            _progress?.Report($"✗ Комбинированный bypass ({strategy} + DROP_RST) не помог. Блокировка не обходится.");
                            return false;
                        }
                    }
                    else
                    {
                        _progress?.Report($"⚠ {strategy} bypass требует прав администратора (WinDivert)");
                        return false;
                    }

                case "DOH":
                    _progress?.Report($"[BYPASS] DNS блокировка для {host} - используйте DoH (1.1.1.1, 8.8.8.8)");
                    _progress?.Report($"ℹ Для {host}: рекомендуется настроить DoH в системе или использовать hosts файл");
                    return true;

                case "PROXY":
                    _progress?.Report($"[BYPASS] TCP таймаут для {ip}:{port} - возможна блокировка маршрутизации");
                    _progress?.Report($"ℹ Для {ip}:{port}: рекомендуется использовать VPN или прокси");
                    return true;

                case "ROUTER_REDIRECT":
                    _progress?.Report($"[BYPASS] Обнаружен фейковый IP {ip} (диапазон 198.18.0.0/15)");
                    _progress?.Report($"ℹ Это признак перехвата трафика роутером или DPI. Проверьте настройки роутера или используйте VPN.");
                    return true;

                case "NONE":
                    // Порт закрыт - не применяем bypass
                    return true;

                case "UNKNOWN":
                    _progress?.Report($"⚠ Неизвестный тип блокировки для {host}:{port}");
                    return false;

                default:
                    _progress?.Report($"⚠ Неизвестная стратегия: {strategy}");
                    return false;
            }
        }
    }
}