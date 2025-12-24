using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Core.IntelligenceV2.Signals;
using IspAudit.Core.Models;

namespace IspAudit.Utils
{
    /// <summary>
    /// Автоматический сбор кандидатов в hostlist на основе сигналов блокировок.
    /// Цель: подсказать пользователю, какие хосты стоит добавить в ручной hostlist (инкремент B).
    /// </summary>
    public sealed class AutoHostlistService
    {
        private readonly object _sync = new();
        private readonly ConcurrentDictionary<string, CandidateState> _candidates = new(StringComparer.OrdinalIgnoreCase);
        private DateTime _lastPublishUtc;

        public event Action? Changed;

        /// <summary>
        /// Включен ли сбор hostlist.
        /// </summary>
        public bool Enabled { get; set; }

        /// <summary>
        /// Максимальное количество записей (защита от бесконечного роста).
        /// </summary>
        public int MaxEntries { get; set; } = 120;

        /// <summary>
        /// Минимальное количество попаданий, после которого хост показывается в UI.
        /// </summary>
        public int MinHitsToShow { get; set; } = 1;

        /// <summary>
        /// Минимальный интервал между публикациями изменений (защита от спама в UI).
        /// </summary>
        public TimeSpan PublishThrottle { get; set; } = TimeSpan.FromSeconds(1);

        public void Clear()
        {
            lock (_sync)
            {
                _candidates.Clear();
            }
            Changed?.Invoke();
        }

        /// <summary>
        /// Наблюдать результат теста и агрегированные сигналы.
        /// </summary>
        [Obsolete("Legacy overload отключён: используйте Observe(..., InspectionSignalsSnapshot, ...) (v2).", error: true)]
        public void Observe(HostTested tested, BlockageSignals signals, string? hostname)
        {
            if (!Enabled)
            {
                return;
            }

            // Берем только те хосты, по которым реально есть подозрительные сигналы.
            var isCandidate =
                signals.HasSignificantRetransmissions ||
                signals.HasHttpRedirectDpi ||
                signals.HasSuspiciousRst ||
                // UDP/QUIC сигнал сам по себе (при TCP/TLS OK) часто не означает проблему для пользователя.
                // Добавляем по UDP только если есть реальные фейлы/неуспехи.
                (signals.HasUdpBlockage && (signals.HardFailCount > 0 || !tested.TlsOk || !tested.TcpOk));

            if (!isCandidate)
            {
                return;
            }

            var key = BuildKey(tested, hostname);
            if (string.IsNullOrWhiteSpace(key))
            {
                return;
            }

            // Для hostlist нужны именно доменные имена. Голые IP мало полезны и только засоряют список.
            if (System.Net.IPAddress.TryParse(key, out _))
            {
                return;
            }

            // Шумовые/служебные домены не добавляем в hostlist.
            // Важно: фильтруем именно ключ кандидата (а не только «внешний» hostname),
            // иначе в UI будут всплывать rDNS вида *.1e100.net, когда SNI отсутствует.
            if (LooksLikeHostname(key) && NoiseHostFilter.Instance.IsNoiseHost(key))
            {
                return;
            }

            var nowUtc = DateTime.UtcNow;

            var state = _candidates.AddOrUpdate(
                key,
                _ => new CandidateState(key, nowUtc, signals),
                (_, existing) => existing.Merge(nowUtc, signals));

            EnforceLimit();
            PublishIfNeeded(nowUtc, state);
        }

        /// <summary>
        /// Наблюдать результат теста и инспекционные сигналы (v2, без зависимости от legacy BlockageSignals).
        /// </summary>
        public void Observe(HostTested tested, InspectionSignalsSnapshot signals, string? hostname)
        {
            if (!Enabled)
            {
                return;
            }

            // В legacy пути использовался HardFailCount из агрегата. Здесь считаем простой эквивалент:
            // сколько базовых тестов (DNS/TCP/TLS) не прошло для данного результата.
            var hardFailCount = (tested.DnsOk ? 0 : 1) + (tested.TcpOk ? 0 : 1) + (tested.TlsOk ? 0 : 1);

            // Берем только те хосты, по которым реально есть подозрительные сигналы.
            // Стараемся сохранить семантику legacy эвристик:
            // - significant retransmissions: >5% при total>10
            // - UDP: считаем кандидатом только если есть реальные фейлы/неуспехи
            var hasSignificantRetransmissions = signals.TotalPackets > 10 && ((double)signals.Retransmissions / signals.TotalPackets) > 0.05;
            var hasUdpBlockage = signals.UdpUnansweredHandshakes > 2;

            var isCandidate =
                hasSignificantRetransmissions ||
                signals.HasHttpRedirect ||
                signals.HasSuspiciousRst ||
                // UDP/QUIC сигнал сам по себе (при TCP/TLS OK) часто не означает проблему для пользователя.
                // Добавляем по UDP только если есть реальные фейлы/неуспехи.
                (hasUdpBlockage && (hardFailCount > 0 || !tested.TlsOk || !tested.TcpOk));

            if (!isCandidate)
            {
                return;
            }

            var key = BuildKey(tested, hostname);
            if (string.IsNullOrWhiteSpace(key))
            {
                return;
            }

            // Для hostlist нужны именно доменные имена. Голые IP мало полезны и только засоряют список.
            if (System.Net.IPAddress.TryParse(key, out _))
            {
                return;
            }

            // Шумовые/служебные домены не добавляем в hostlist.
            if (LooksLikeHostname(key) && NoiseHostFilter.Instance.IsNoiseHost(key))
            {
                return;
            }

            var nowUtc = DateTime.UtcNow;

            var state = _candidates.AddOrUpdate(
                key,
                _ => new CandidateState(key, nowUtc, signals, hasSignificantRetransmissions, hasUdpBlockage, hardFailCount),
                (_, existing) => existing.Merge(nowUtc, signals, hasSignificantRetransmissions, hasUdpBlockage, hardFailCount));

            EnforceLimit();
            PublishIfNeeded(nowUtc, state);
        }

        public IReadOnlyList<AutoHostCandidate> GetSnapshot()
        {
            var list = _candidates.Values
                .Where(v => v.Hits >= MinHitsToShow)
                .OrderByDescending(v => v.Score)
                .ThenByDescending(v => v.LastSeenUtc)
                .Select(v => v.ToCandidate())
                .ToList();

            return list;
        }

        public string GetDisplayText()
        {
            var items = GetSnapshot();
            if (items.Count == 0)
            {
                return "(пока пусто)";
            }

            return string.Join(Environment.NewLine, items.Select(i => i.DisplayLine));
        }

        public int VisibleCount => _candidates.Values.Count(v => v.Hits >= MinHitsToShow);

        private void PublishIfNeeded(DateTime nowUtc, CandidateState updated)
        {
            // Публикуем только если хост стал видимым или это не слишком часто.
            if (updated.Hits == MinHitsToShow)
            {
                Changed?.Invoke();
                return;
            }

            lock (_sync)
            {
                if (nowUtc - _lastPublishUtc < PublishThrottle)
                {
                    return;
                }
                _lastPublishUtc = nowUtc;
            }

            Changed?.Invoke();
        }

        private void EnforceLimit()
        {
            if (_candidates.Count <= MaxEntries)
            {
                return;
            }

            // Удаляем самых "слабых" кандидатов.
            // Делается редко, поэтому позволяем себе LINQ.
            var toRemove = _candidates.Values
                .OrderBy(v => v.Score)
                .ThenBy(v => v.LastSeenUtc)
                .Take(Math.Max(1, _candidates.Count - MaxEntries))
                .Select(v => v.Key)
                .ToList();

            foreach (var k in toRemove)
            {
                _candidates.TryRemove(k, out _);
            }
        }

        private static string BuildKey(HostTested tested, string? hostname)
        {
            // Порядок предпочтения: SNI -> hostname -> rDNS -> IP.
            var host =
                tested.SniHostname ??
                tested.Hostname ??
                tested.ReverseDnsHostname ??
                hostname;

            if (!string.IsNullOrWhiteSpace(host))
            {
                return host.Trim();
            }

            return tested.Host.RemoteIp?.ToString() ?? string.Empty;
        }

        private static bool LooksLikeHostname(string value)
        {
            // Простой признак: в домене обычно есть точка. IP адреса и пустые строки не фильтруем через NoiseHostFilter.
            return value.Contains('.') && !System.Net.IPAddress.TryParse(value, out _);
        }

        private sealed record CandidateState
        {
            public string Key { get; }
            public int Hits { get; private set; }
            public int Score { get; private set; }
            public DateTime FirstSeenUtc { get; private set; }
            public DateTime LastSeenUtc { get; private set; }

            public int RetransmissionMax { get; private set; }
            public int UdpUnansweredMax { get; private set; }
            public bool HasHttpRedirectDpi { get; private set; }
            public bool HasSuspiciousRst { get; private set; }

            public CandidateState(string key, DateTime firstSeenUtc, InspectionSignalsSnapshot signals, bool hasSignificantRetransmissions, bool hasUdpBlockage, int hardFailCount)
            {
                Key = key;
                FirstSeenUtc = firstSeenUtc;
                LastSeenUtc = firstSeenUtc;
                Hits = 1;

                ApplySignals(signals, hasSignificantRetransmissions, hasUdpBlockage, hardFailCount);
            }

            public CandidateState(string key, DateTime firstSeenUtc, BlockageSignals signals)
            {
                Key = key;
                FirstSeenUtc = firstSeenUtc;
                LastSeenUtc = firstSeenUtc;
                Hits = 1;

                ApplySignals(signals);
            }

            public CandidateState Merge(DateTime nowUtc, BlockageSignals signals)
            {
                Hits++;
                LastSeenUtc = nowUtc;
                ApplySignals(signals);
                return this;
            }

            public CandidateState Merge(DateTime nowUtc, InspectionSignalsSnapshot signals, bool hasSignificantRetransmissions, bool hasUdpBlockage, int hardFailCount)
            {
                Hits++;
                LastSeenUtc = nowUtc;
                ApplySignals(signals, hasSignificantRetransmissions, hasUdpBlockage, hardFailCount);
                return this;
            }

            private void ApplySignals(BlockageSignals signals)
            {
                RetransmissionMax = Math.Max(RetransmissionMax, signals.RetransmissionCount);
                UdpUnansweredMax = Math.Max(UdpUnansweredMax, signals.UdpUnansweredHandshakes);
                HasHttpRedirectDpi |= signals.HasHttpRedirectDpi;
                HasSuspiciousRst |= signals.HasSuspiciousRst;

                // Простой скоринг: чем больше "жёстких" сигналов, тем выше.
                var score = 0;
                if (signals.HasSignificantRetransmissions) score += 2;
                if (signals.HasHttpRedirectDpi) score += 3;
                if (signals.HasSuspiciousRst) score += 2;
                if (signals.HasUdpBlockage) score += 2;
                if (signals.HardFailCount > 0) score += 1;

                Score = Math.Max(Score, score);
            }

            private void ApplySignals(InspectionSignalsSnapshot signals, bool hasSignificantRetransmissions, bool hasUdpBlockage, int hardFailCount)
            {
                RetransmissionMax = Math.Max(RetransmissionMax, signals.Retransmissions);
                UdpUnansweredMax = Math.Max(UdpUnansweredMax, signals.UdpUnansweredHandshakes);
                HasHttpRedirectDpi |= signals.HasHttpRedirect;
                HasSuspiciousRst |= signals.HasSuspiciousRst;

                // Простой скоринг: чем больше "жёстких" сигналов, тем выше.
                var score = 0;
                if (hasSignificantRetransmissions) score += 2;
                if (signals.HasHttpRedirect) score += 3;
                if (signals.HasSuspiciousRst) score += 2;
                if (hasUdpBlockage) score += 2;
                if (hardFailCount > 0) score += 1;

                Score = Math.Max(Score, score);
            }

            public AutoHostCandidate ToCandidate()
            {
                var reasons = new List<string>();
                if (RetransmissionMax > 0) reasons.Add($"retrans={RetransmissionMax}");
                if (UdpUnansweredMax > 0) reasons.Add($"udpLoss={UdpUnansweredMax}");
                if (HasHttpRedirectDpi) reasons.Add("httpRedirect");
                if (HasSuspiciousRst) reasons.Add("rstTtl");

                var suffix = reasons.Count > 0 ? string.Join(", ", reasons) : "signals";
                var line = $"{Key} (hits={Hits}, score={Score}, {suffix})";

                return new AutoHostCandidate(Key, Hits, Score, LastSeenUtc, line);
            }
        }
    }

    public readonly record struct AutoHostCandidate(
        string Host,
        int Hits,
        int Score,
        DateTime LastSeenUtc,
        string DisplayLine);
}
