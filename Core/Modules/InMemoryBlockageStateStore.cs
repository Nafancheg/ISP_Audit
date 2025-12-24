using System;
using System.Collections.Concurrent;
using System.Net;
using IspAudit.Core.Interfaces;
using IspAudit.Core.IntelligenceV2.Signals;
using IspAudit.Core.Models;

namespace IspAudit.Core.Modules
{
    /// <summary>
    /// Простое in-memory хранилище состояния блокировок per-host.
    /// Потокобезопасно и не требует внешних зависимостей.
    /// </summary>
    public sealed class InMemoryBlockageStateStore : IBlockageStateStore, IInspectionSignalsProvider
    {
        private readonly ConcurrentDictionary<string, HostBlockageState> _states = new();
        private readonly ConcurrentDictionary<string, TargetTestGate> _seenTargets = new();
        private readonly TcpRetransmissionTracker? _retransmissionTracker;
        private readonly HttpRedirectDetector? _httpRedirectDetector;
        private readonly RstInspectionService? _rstInspectionService;
        private readonly UdpInspectionService? _udpInspectionService;

        // Важно для V2: чтобы накопить факты (SignalSequence) по проблемной цели,
        // одной попытки часто недостаточно. Но бесконечно гонять тесты тоже нельзя.
        private static readonly TimeSpan RetestCooldown = TimeSpan.FromSeconds(8);
        private const int MaxAttemptsPerTargetPerRun = 3;

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

        public bool TryBeginHostTest(HostDiscovered host, string? hostname = null)
        {
            // Дедупликация/гейтинг: не даём спамить тестами одну и ту же цель,
            // но разрешаем ограниченное число повторов, чтобы диагностика успевала накопить факты.
            // Ключ строим по лучшему имени (SNI/DNS), иначе по IP.
            var bestName =
                host.SniHostname ??
                hostname ??
                host.Hostname;

            var keyName = string.IsNullOrWhiteSpace(bestName)
                ? host.RemoteIp.ToString()
                : bestName.Trim().ToLowerInvariant();

            // Протокол и порт влияют на смысл цели (TCP/UDP и конкретный сервис).
            var dedupeKey = $"{keyName}:{host.RemotePort}:{host.Protocol}";

            var nowUtc = DateTimeOffset.UtcNow;

            while (true)
            {
                if (!_seenTargets.TryGetValue(dedupeKey, out var gate))
                {
                    var created = new TargetTestGate(Attempts: 1, LastAttemptUtc: nowUtc);
                    if (_seenTargets.TryAdd(dedupeKey, created))
                    {
                        return true;
                    }

                    continue;
                }

                // Слишком часто — отбрасываем.
                if (nowUtc - gate.LastAttemptUtc < RetestCooldown)
                {
                    return false;
                }

                // Достигли лимита на текущий прогон.
                if (gate.Attempts >= MaxAttemptsPerTargetPerRun)
                {
                    return false;
                }

                var updated = gate with
                {
                    Attempts = gate.Attempts + 1,
                    LastAttemptUtc = nowUtc
                };

                if (_seenTargets.TryUpdate(dedupeKey, updated, gate))
                {
                    return true;
                }
            }
        }

        private sealed record TargetTestGate(int Attempts, DateTimeOffset LastAttemptUtc);

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
            var totalPackets = 0;
            bool hasHttpRedirect = false;
            string? redirectTo = null;
            bool hasSuspiciousRst = false;
            string? suspiciousRstDetails = null;

            if (_retransmissionTracker != null && tested.Host.RemoteIp != null)
            {
                try
                {
                    var tStats = _retransmissionTracker.GetStatsForIp(tested.Host.RemoteIp);
                    retransmissions = tStats.Retransmissions;
                    totalPackets = tStats.TotalPackets;
                }
                catch
                {
                    // Логика детекции не должна падать из-за проблем трекера
                    retransmissions = 0;
                    totalPackets = 0;
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
                totalPackets,
                hasHttpRedirect,
                redirectTo,
                hasSuspiciousRst,
                suspiciousRstDetails,
                udpUnanswered);
        }

        public InspectionSignalsSnapshot GetInspectionSignalsSnapshot(HostTested tested)
        {
            if (tested.Host.RemoteIp == null)
            {
                return InspectionSignalsSnapshot.Empty;
            }

            var ip = tested.Host.RemoteIp;

            var retransmissions = 0;
            var totalPackets = 0;
            if (_retransmissionTracker != null)
            {
                try
                {
                    var tStats = _retransmissionTracker.GetStatsForIp(ip);
                    retransmissions = tStats.Retransmissions;
                    totalPackets = tStats.TotalPackets;
                }
                catch
                {
                    retransmissions = 0;
                    totalPackets = 0;
                }
            }

            var hasHttpRedirect = false;
            string? redirectTo = null;
            if (_httpRedirectDetector != null)
            {
                try
                {
                    if (_httpRedirectDetector.TryGetRedirectHost(ip, out var target))
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

            var hasSuspiciousRst = false;
            string? suspiciousRstDetails = null;
            if (_rstInspectionService != null)
            {
                try
                {
                    if (_rstInspectionService.HasSuspiciousRst(ip, out var details))
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

            var udpUnanswered = 0;
            if (_udpInspectionService != null)
            {
                try
                {
                    udpUnanswered = _udpInspectionService.GetUnansweredHandshakeCount(ip);
                }
                catch
                {
                    udpUnanswered = 0;
                }
            }

            return new InspectionSignalsSnapshot(
                Retransmissions: Math.Max(0, retransmissions),
                TotalPackets: Math.Max(0, totalPackets),
                HasHttpRedirect: hasHttpRedirect,
                RedirectToHost: redirectTo,
                HasSuspiciousRst: hasSuspiciousRst,
                SuspiciousRstDetails: suspiciousRstDetails,
                UdpUnansweredHandshakes: Math.Max(0, udpUnanswered));
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

