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
    /// <summary>
    /// УПРОЩЁННЫЙ WinDivertBypassEnforcer.
    /// 
    /// НОВАЯ АРХИТЕКТУРА (Preemptive-only):
    /// - Bypass включается ОДИН РАЗ при старте сессии (preemptive в MainViewModel)
    /// - Этот класс НЕ переключает стратегии на лету
    /// - Если хост не работает после preemptive bypass — показываем "Требуется VPN"
    /// 
    /// ПРИЧИНА УПРОЩЕНИЯ:
    /// - Динамическое переключение стратегий создавало хаос (Яндекс работал, но система пыталась "улучшить")
    /// - YouTube не работает НИ С КАКОЙ стратегией (Google DPI умнее российского)
    /// - Каждое переключение закрывало WinDivert handles и прерывало текущие соединения
    /// </summary>
    public class WinDivertBypassEnforcer : IBypassEnforcer
    {
        private readonly IspAudit.Bypass.WinDivertBypassManager? _bypassManager;
        private readonly IHostTester _tester;
        private readonly IProgress<string>? _progress;

        public WinDivertBypassEnforcer(
            IspAudit.Bypass.WinDivertBypassManager? bypassManager,
            IHostTester tester,
            IProgress<string>? progress,
            DiagnosisCache? cache = null)
        {
            _bypassManager = bypassManager;
            _tester = tester;
            _progress = progress;
            // DiagnosisCache больше не используется для adaptive bypass
        }

        /// <summary>
        /// УПРОЩЁННАЯ РЕАЛИЗАЦИЯ: Bypass уже активен (preemptive).
        /// Этот метод теперь только логирует рекомендации, не переключает стратегии.
        /// </summary>
        public Task ApplyBypassAsync(HostBlocked blocked, CancellationToken ct)
        {
            var host = blocked.TestResult.Hostname ?? blocked.TestResult.Host.RemoteIp.ToString();
            var blockageType = blocked.TestResult.BlockageType ?? "UNKNOWN";
            
            // Bypass уже активен (preemptive). Если хост всё равно заблокирован — bypass не помогает.
            // НЕ пытаемся переключать стратегии — это создавало хаос.
            
            switch (blockageType)
            {
                case "DNS_FILTERED":
                case "DNS_BOGUS":
                    _progress?.Report($"ℹ DNS блокировка {host}: рекомендуется настроить DoH (1.1.1.1, 8.8.8.8)");
                    break;
                    
                case "TCP_RST":
                    _progress?.Report($"ℹ TCP RST для {host}: bypass активен, но RST всё ещё приходят. Рекомендуется VPN.");
                    break;
                    
                case "TCP_TIMEOUT":
                    _progress?.Report($"ℹ TCP таймаут для {host}: возможна блокировка маршрутизации. Рекомендуется VPN.");
                    break;
                    
                case "TLS_TIMEOUT":
                case "TLS_ERROR":
                case "TLS_DPI":
                    _progress?.Report($"ℹ TLS блокировка для {host}: текущий bypass не эффективен. Рекомендуется VPN.");
                    break;
                    
                case "PORT_CLOSED":
                    _progress?.Report($"ℹ Порт закрыт для {host}: это не блокировка провайдера.");
                    break;
                    
                default:
                    _progress?.Report($"ℹ Проблема с {host} ({blockageType}): проверьте сеть или используйте VPN.");
                    break;
            }
            
            return Task.CompletedTask;
        }
    }
}