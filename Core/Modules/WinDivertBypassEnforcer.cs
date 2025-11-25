using System;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;

namespace IspAudit.Core.Modules
{
    public class WinDivertBypassEnforcer : IBypassEnforcer
    {
        private readonly IspAudit.Bypass.WinDivertBypassManager? _bypassManager;
        private readonly IHostTester _tester;
        private readonly IProgress<string>? _progress;

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
            try
            {
                var host = blocked.TestResult.Hostname ?? blocked.TestResult.Host.RemoteIp.ToString();
                var ip = blocked.TestResult.Host.RemoteIp;
                var port = blocked.TestResult.Host.RemotePort;

                switch (blocked.BypassStrategy)
                {
                    case "DROP_RST":
                        _progress?.Report($"[BYPASS] Применяю DROP_RST для {ip}:{port}...");
                        
                        if (_bypassManager != null)
                        {
                            await _bypassManager.ApplyBypassStrategyAsync("DROP_RST", ip, port).ConfigureAwait(false);
                            _progress?.Report($"✓ DROP_RST bypass активен для {ip}:{port}");
                            
                            // Ретест: проверяем что bypass работает
                            _progress?.Report($"[BYPASS] Проверяю эффективность bypass для {ip}:{port}...");
                            await Task.Delay(500, ct).ConfigureAwait(false);
                            
                            var retestResult = await _tester.TestHostAsync(blocked.TestResult.Host, ct).ConfigureAwait(false);
                            if (retestResult.TcpOk && retestResult.BlockageType != "TCP_RST")
                            {
                                _progress?.Report($"✓✓ BYPASS РАБОТАЕТ! {ip}:{port} теперь доступен (TCP RST заблокирован)");
                            }
                            else
                            {
                                _progress?.Report($"⚠ Bypass применен, но {ip}:{port} все еще заблокирован.");
                            }
                        }
                        else
                        {
                            _progress?.Report($"⚠ DROP_RST bypass требует прав администратора (WinDivert)");
                        }
                        break;

                    case "TLS_FRAGMENT":
                    case "TLS_FAKE_FRAGMENT":
                        _progress?.Report($"[BYPASS] Применяю комбинированный bypass ({blocked.BypassStrategy} + DROP_RST) для {host}...");
                        
                        if (_bypassManager != null)
                        {
                            // ✅ СНАЧАЛА активируем TLS стратегию (настраивает профиль)
                            await _bypassManager.ApplyBypassStrategyAsync(blocked.BypassStrategy, ip, port).ConfigureAwait(false);
                            _progress?.Report($"✓ {blocked.BypassStrategy} активен");
                            
                            // ✅ ЗАТЕМ активируем DROP_RST (добавляет RST blocking к текущему профилю)
                            await _bypassManager.ApplyBypassStrategyAsync("DROP_RST", ip, port).ConfigureAwait(false);
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
                            }
                            else
                            {
                                _progress?.Report($"✗ Комбинированный bypass ({blocked.BypassStrategy} + DROP_RST) не помог. Блокировка не обходится.");
                            }
                        }
                        else
                        {
                            _progress?.Report($"⚠ {blocked.BypassStrategy} bypass требует прав администратора (WinDivert)");
                        }
                        break;

                    case "DOH":
                        _progress?.Report($"[BYPASS] DNS блокировка для {host} - используйте DoH (1.1.1.1, 8.8.8.8)");
                        _progress?.Report($"ℹ Для {host}: рекомендуется настроить DoH в системе или использовать hosts файл");
                        break;

                    case "PROXY":
                        _progress?.Report($"[BYPASS] TCP таймаут для {ip}:{port} - возможна блокировка маршрутизации");
                        _progress?.Report($"ℹ Для {ip}:{port}: рекомендуется использовать VPN или прокси");
                        break;

                    case "ROUTER_REDIRECT":
                        _progress?.Report($"[BYPASS] Обнаружен фейковый IP {ip} (диапазон 198.18.0.0/15)");
                        _progress?.Report($"ℹ Это признак перехвата трафика роутером или DPI. Проверьте настройки роутера или используйте VPN.");
                        break;

                    case "NONE":
                        // Порт закрыт - не применяем bypass
                        break;

                    case "UNKNOWN":
                        _progress?.Report($"⚠ Неизвестный тип блокировки для {host}:{port}");
                        break;
                }
            }
            catch (Exception ex)
            {
                _progress?.Report($"[BYPASS] Ошибка применения bypass: {ex.Message}");
            }
        }
    }
}