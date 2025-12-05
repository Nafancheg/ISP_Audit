using System;
using System.Collections.Concurrent;
using System.Net;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;

namespace IspAudit.Core.Modules
{
    /// <summary>
    /// Простое in-memory хранилище состояния блокировок per-host.
    /// Потокобезопасно и не требует внешних зависимостей.
    /// </summary>
    public sealed class InMemoryBlockageStateStore : IBlockageStateStore
    {
        private readonly ConcurrentDictionary<string, HostBlockageState> _states = new();
        private readonly TcpRetransmissionTracker? _retransmissionTracker;
        private readonly HttpRedirectDetector? _httpRedirectDetector;
        private readonly RstInspectionService? _rstInspectionService;
        private readonly UdpInspectionService? _udpInspectionService;

        public InMemoryBlockageStateStore()
        {
        }

        public InMemoryBlockageStateStore(
            TcpRetransmissionTracker retransmissionTracker, 
            HttpRedirectDetector? httpRedirectDetector = null,
            RstInspectionService? rstInspectionService = null,
            UdpInspectionService? udpInspectionService = null)
        {
            _retransmissionTracker = retransmissionTracker ?? throw new ArgumentNullException(nameof(retransmissionTracker));
            _httpRedirectDetector = httpRedirectDetector;
            _rstInspectionService = rstInspectionService;
            _udpInspectionService = udpInspectionService;
        }

        public void RegisterResult(HostTested tested)
        {
            if (tested.Host.RemoteIp == null)
            {
                return;
            }

            var key = BuildKey(tested.Host.RemoteIp, tested.Host.RemotePort, tested.Hostname);
            var state = _states.GetOrAdd(key, k => new HostBlockageState(k));
            state.Register(tested);
        }

        public FailWindowStats GetFailStats(HostTested tested, TimeSpan window)
        {
            if (tested.Host.RemoteIp == null)
            {
                return new FailWindowStats(0, 0, null, window);
            }

            var key = BuildKey(tested.Host.RemoteIp, tested.Host.RemotePort, tested.Hostname);
            if (_states.TryGetValue(key, out var state))
            {
                return state.GetStats(window);
            }

            return new FailWindowStats(0, 0, null, window);
        }

        public BlockageSignals GetSignals(HostTested tested, TimeSpan window)
        {
            // Пока агрегатор сигналов является тонким слоем над FailWindowStats
            // с добавлением оценки ретрансмиссий (если передан внешний трекер).
            var stats = GetFailStats(tested, window);
            var retransmissions = 0;
            bool hasHttpRedirect = false;
            string? redirectTo = null;
            bool hasSuspiciousRst = false;
            string? suspiciousRstDetails = null;

            if (_retransmissionTracker != null && tested.Host.RemoteIp != null)
            {
                try
                {
                    retransmissions = _retransmissionTracker.GetRetransmissionCountForIp(tested.Host.RemoteIp);
                }
                catch
                {
                    // Логика детекции не должна падать из-за проблем трекера
                    retransmissions = 0;
                }
            }

            if (_httpRedirectDetector != null && tested.Host.RemoteIp != null)
            {
                try
                {
                    if (_httpRedirectDetector.TryGetRedirectHost(tested.Host.RemoteIp, out var target))
                    {
                        hasHttpRedirect = true;
                        redirectTo = target;
                    }
                }
                catch
                {
                    hasHttpRedirect = false;
                    redirectTo = null;
                }
            }

            if (_rstInspectionService != null && tested.Host.RemoteIp != null)
            {
                try
                {
                    if (_rstInspectionService.HasSuspiciousRst(tested.Host.RemoteIp, out var details))
                    {
                        hasSuspiciousRst = true;
                        suspiciousRstDetails = details;
                    }
                }
                catch
                {
                    hasSuspiciousRst = false;
                    suspiciousRstDetails = null;
                }
            }

            int udpUnanswered = 0;
            if (_udpInspectionService != null && tested.Host.RemoteIp != null)
            {
                try
                {
                    udpUnanswered = _udpInspectionService.GetUnansweredHandshakeCount(tested.Host.RemoteIp);
                }
                catch
                {
                    udpUnanswered = 0;
                }
            }

            return new BlockageSignals(
                stats.FailCount,
                stats.HardFailCount,
                stats.LastFailAt,
                stats.Window,
                retransmissions,
                hasHttpRedirect,
                redirectTo,
                hasSuspiciousRst,
                suspiciousRstDetails,
                udpUnanswered);
        }

        private static string BuildKey(IPAddress ip, int port, string? hostname)
        {
            // Для детекции важнее IP+порт, hostname добавляем только как доп. контекст.
            return hostname is { Length: > 0 }
                ? $"{ip}:{port}:{hostname}"
                : $"{ip}:{port}";
        }
    }
}

