using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;

namespace IspAudit.Core.Intelligence.Signals;

/// <summary>
/// Адаптер сигналов INTEL: принимает результаты (HostTested + InspectionSignalsSnapshot)
/// и записывает их в последовательность событий (SignalSequence) с TTL.
/// Дополнительно умеет построить агрегированный срез BlockageSignals по окну.
/// </summary>
public sealed class SignalsAdapter
{
    private readonly InMemorySignalSequenceStore _store;

    // Парсим строку из legacy RST-инспектора.
    // Поддерживаем 2 формата:
    // - "TTL=64 (обычный=50-55)"
    // - "TTL=64 (expected 50-55)" (smoke)
    private static readonly Regex RstTtlRangeRegex = new(
        @"TTL=(?<ttl>\d+).*?\((?:обычный=|expected\s+)(?<min>\d+)-(?<max>\d+)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // Парсим строку из RstInspectionService для IPID.
    // Ожидаемый формат (runtime):
    // - "IPID=12345 (обычный=10-20, last=15)"
    // Допускаем английский вариант "expected" для smoke.
    private static readonly Regex RstIpIdRangeRegex = new(
        @"IPID=(?<ipid>\d+).*?\((?:обычный=|expected\s+)(?<min>\d+)-(?<max>\d+),\s*(?:last=|last\s+)(?<last>\d+)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // Ограничитель логов Gate 1→2: не чаще 1 раза в минуту на HostKey
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastGateLogUtc = new(StringComparer.Ordinal);
    private static readonly TimeSpan GateLogCooldown = TimeSpan.FromSeconds(60);

    // Простейший анти-спам для событий одного типа
    private static readonly TimeSpan SameTypeDebounce = TimeSpan.FromSeconds(5);

    public SignalsAdapter(InMemorySignalSequenceStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public static string BuildStableHostKey(HostTested tested)
    {
        // Самый простой и реально «склеивающий» вариант для MVP: IP-only.
        // Так сигналы от IP-based сенсоров (RST/retx/redirect) попадают в ту же цепочку.
        var ip = tested.Host.RemoteIp;
        if (ip != null)
        {
            return ip.ToString();
        }

        // Фолбэк: стабильный ключ из pipeline (IP:Port:Proto)
        if (!string.IsNullOrWhiteSpace(tested.Host.Key))
        {
            return tested.Host.Key;
        }

        // Последний фолбэк: никогда не возвращаем пустую строку
        return "<unknown>";
    }

    public void Observe(HostTested tested, InspectionSignalsSnapshot inspectionSignals, IProgress<string>? progress = null)
    {
        var hostKey = BuildStableHostKey(tested);
        var tsUtc = DateTimeOffset.UtcNow;

        // Важно: НЕ «двигаем время в будущее» искусственно (AddMilliseconds), иначе при грубой
        // дискретности таймера Windows BuildSnapshot() может взять capturedAtUtc <= ObservedAtUtc
        // и не увидеть часть событий в окне. Порядок обеспечивается порядком Append(...) в store.
        AppendHostTested(hostKey, tested, tsUtc);

        AppendFromInspectionSignals(hostKey, inspectionSignals, ref tsUtc);

        // Gate 1→2: показываем компактную строку, если у хоста уже накопилась "цепочка".
        TryReportGate1To2(hostKey, tsUtc, progress);
    }

    public IspAudit.Core.Intelligence.Contracts.BlockageSignals BuildSnapshot(HostTested tested, InspectionSignalsSnapshot inspectionSignals, TimeSpan window)
    {
        var hostKey = BuildStableHostKey(tested);
        var capturedAtUtc = DateTimeOffset.UtcNow;
        var fromUtc = capturedAtUtc - window;

        var windowEvents = _store.ReadWindow(hostKey, fromUtc, capturedAtUtc);

        // Устойчивость RST-улик: считаем, сколько раз в окне было событие suspicious RST.
        // Важно: не хотим классифицировать ActiveDpiEdge/StatefulDpi по единичному событию.
        var suspiciousRstCount = 0;
        for (var i = 0; i < windowEvents.Count; i++)
        {
            if (windowEvents[i].Type == SignalEventType.SuspiciousRstObserved)
            {
                suspiciousRstCount++;
            }
        }
        if (inspectionSignals.HasSuspiciousRst && suspiciousRstCount == 0)
        {
            // Фолбэк: если события не попали в окно из-за debounce/тайминга, но факт известен из последнего снимка.
            suspiciousRstCount = 1;
        }

        // HostTested count + no-SNI ratio
        var hostTestedCount = 0;
        var hostTestedNoSniCount = 0;
        var http3AttemptCount = 0;
        var http3SuccessCount = 0;
        var http3FailureCount = 0;
        var http3TimeoutCount = 0;
        var http3NotSupportedCount = 0;
        for (var i = 0; i < windowEvents.Count; i++)
        {
            var e = windowEvents[i];
            if (e.Type != SignalEventType.HostTested) continue;
            hostTestedCount++;

            // SNI кладём в metadata только если он есть (см. BuildHostMeta).
            if (e.Metadata == null || !e.Metadata.TryGetValue("sni", out var sni) || string.IsNullOrWhiteSpace(sni))
            {
                hostTestedNoSniCount++;
            }

            if (e.Value is HostTested ht && !string.IsNullOrWhiteSpace(ht.Http3Status))
            {
                // Считаем только реальные попытки (ProbeHttp3Async заполняет статус при попытке).
                if (!string.Equals(ht.Http3Status, "H3_NOT_ATTEMPTED", StringComparison.Ordinal))
                {
                    http3AttemptCount++;

                    if (string.Equals(ht.Http3Status, "H3_OK", StringComparison.Ordinal))
                    {
                        http3SuccessCount++;
                    }
                    else if (string.Equals(ht.Http3Status, "H3_TIMEOUT", StringComparison.Ordinal))
                    {
                        http3TimeoutCount++;
                        http3FailureCount++;
                    }
                    else if (string.Equals(ht.Http3Status, "H3_NOT_SUPPORTED", StringComparison.Ordinal))
                    {
                        http3NotSupportedCount++;
                    }
                    else
                    {
                        // H3_FAILED / H3_DOWNGRADED_* и прочие статусы считаем как failure.
                        http3FailureCount++;
                    }
                }
            }
        }

        var normalizedCode = BlockageCode.Normalize(tested.BlockageType);

        var hasDnsFailure = !tested.DnsOk || (!string.IsNullOrWhiteSpace(tested.DnsStatus) && !string.Equals(tested.DnsStatus, BlockageCode.StatusOk, StringComparison.OrdinalIgnoreCase));
        var hasTcpTimeout = string.Equals(normalizedCode, BlockageCode.TcpConnectTimeout, StringComparison.Ordinal);

        var hasTcpReset =
            string.Equals(normalizedCode, BlockageCode.TcpConnectionReset, StringComparison.Ordinal) ||
            inspectionSignals.HasSuspiciousRst ||
            windowEvents.HasType(SignalEventType.SuspiciousRstObserved);

        var hasTlsTimeout = string.Equals(normalizedCode, BlockageCode.TlsHandshakeTimeout, StringComparison.Ordinal);
        // ВАЖНО: TLS_AUTH_FAILURE — это фактически "TLS authentication failure" (AuthenticationException) из HostTester.
        // Это наблюдаемый факт о сбое рукопожатия, а не утверждение про DPI.
        var hasTlsAuthFailure = string.Equals(normalizedCode, BlockageCode.TlsAuthFailure, StringComparison.Ordinal);

        double? retxRate = null;
        if (inspectionSignals.TotalPackets > 0)
        {
            retxRate = Math.Clamp((double)inspectionSignals.Retransmissions / inspectionSignals.TotalPackets, 0.0, 1.0);
        }

        var hasFakeIp = IsFakeIp(tested.Host.RemoteIp);

        var hasHttpRedirect = inspectionSignals.HasHttpRedirect || windowEvents.HasType(SignalEventType.HttpRedirectObserved);

        string? redirectToHost = inspectionSignals.RedirectToHost;
        if (string.IsNullOrWhiteSpace(redirectToHost))
        {
            for (var i = windowEvents.Count - 1; i >= 0; i--)
            {
                var e = windowEvents[i];
                if (e.Type != SignalEventType.HttpRedirectObserved) continue;
                if (e.Value is string s && !string.IsNullOrWhiteSpace(s))
                {
                    redirectToHost = s;
                    break;
                }
            }
        }

        // UDP unanswered: берём максимум между последним инспекционным срезом и событиями в окне.
        var udpUnanswered = Math.Max(0, inspectionSignals.UdpUnansweredHandshakes);
        for (var i = windowEvents.Count - 1; i >= 0; i--)
        {
            var e = windowEvents[i];
            if (e.Type != SignalEventType.UdpHandshakeUnanswered) continue;
            if (e.Value is int v)
            {
                udpUnanswered = Math.Max(udpUnanswered, v);
                break;
            }
        }

        var rstTtlDelta = TryExtractRstTtlDelta(inspectionSignals, windowEvents);
        var rstIpIdDelta = TryExtractRstIpIdDelta(inspectionSignals, windowEvents);
        TimeSpan? rstLatency = null;
        if (hasTcpReset && tested.TcpLatencyMs is int latencyMs && latencyMs > 0)
        {
            // Это приблизительная метрика (время попытки TCP connect до reset/исключения).
            // Для INTEL достаточно как сигнал "быстро" vs "медленно".
            rstLatency = TimeSpan.FromMilliseconds(latencyMs);
        }

        return new IspAudit.Core.Intelligence.Contracts.BlockageSignals
        {
            HostKey = hostKey,
            CapturedAtUtc = capturedAtUtc,
            AggregationWindow = window,

            HasTcpReset = hasTcpReset,
            HasTcpTimeout = hasTcpTimeout,
            RetransmissionRate = retxRate,

            RstTtlDelta = rstTtlDelta,
            RstIpIdDelta = rstIpIdDelta,
            SuspiciousRstCount = suspiciousRstCount,
            RstLatency = rstLatency,

            HasDnsFailure = hasDnsFailure,
            HasFakeIp = hasFakeIp,

            HasHttpRedirect = hasHttpRedirect,
            RedirectToHost = redirectToHost,

            UdpUnansweredHandshakes = udpUnanswered,
            Http3AttemptCount = http3AttemptCount,
            Http3SuccessCount = http3SuccessCount,
            Http3FailureCount = http3FailureCount,
            Http3TimeoutCount = http3TimeoutCount,
            Http3NotSupportedCount = http3NotSupportedCount,
            HostTestedCount = hostTestedCount,
            HostTestedNoSniCount = hostTestedNoSniCount,

            HasTlsTimeout = hasTlsTimeout,
            HasTlsAuthFailure = hasTlsAuthFailure,
            HasTlsReset = false,

            SampleSize = windowEvents.Count,
            // Если в окне мало событий, но есть «сильный» наблюдаемый факт (TLS timeout, DNS failure и т.п.)
            // — это уже достаточная база для консервативного диагноза.
            IsUnreliable = windowEvents.Count < 2 && !(hasDnsFailure || hasTcpTimeout || hasTcpReset || hasTlsTimeout || hasTlsAuthFailure || hasHttpRedirect || (http3FailureCount > 0) || retxRate != null)
        };
    }

    private static int? TryExtractRstTtlDelta(InspectionSignalsSnapshot inspectionSignals, IReadOnlyList<SignalEvent> windowEvents)
    {
        string? details = null;
        if (inspectionSignals.HasSuspiciousRst && !string.IsNullOrWhiteSpace(inspectionSignals.SuspiciousRstDetails))
        {
            details = inspectionSignals.SuspiciousRstDetails;
        }
        else
        {
            // Фолбэк: возьмём строку из последнего события RST в окне.
            for (var i = windowEvents.Count - 1; i >= 0; i--)
            {
                var e = windowEvents[i];
                if (e.Type != SignalEventType.SuspiciousRstObserved) continue;
                if (e.Value is string s && !string.IsNullOrWhiteSpace(s))
                {
                    details = s;
                    break;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(details)) return null;

        var m = RstTtlRangeRegex.Match(details);
        if (!m.Success) return null;

        if (!int.TryParse(m.Groups["ttl"].Value, out var ttl)) return null;
        if (!int.TryParse(m.Groups["min"].Value, out var min)) return null;
        if (!int.TryParse(m.Groups["max"].Value, out var max)) return null;

        var diffMin = Math.Abs(ttl - min);
        var diffMax = Math.Abs(ttl - max);
        return Math.Min(diffMin, diffMax);
    }

    private static int? TryExtractRstIpIdDelta(InspectionSignalsSnapshot inspectionSignals, IReadOnlyList<SignalEvent> windowEvents)
    {
        string? details = null;
        if (inspectionSignals.HasSuspiciousRst && !string.IsNullOrWhiteSpace(inspectionSignals.SuspiciousRstDetails))
        {
            details = inspectionSignals.SuspiciousRstDetails;
        }
        else
        {
            // Фолбэк: возьмём строку из последнего события RST в окне.
            for (var i = windowEvents.Count - 1; i >= 0; i--)
            {
                var e = windowEvents[i];
                if (e.Type != SignalEventType.SuspiciousRstObserved) continue;
                if (e.Value is string s && !string.IsNullOrWhiteSpace(s))
                {
                    details = s;
                    break;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(details)) return null;

        var m = RstIpIdRangeRegex.Match(details);
        if (!m.Success) return null;

        if (!int.TryParse(m.Groups["ipid"].Value, out var ipid)) return null;
        if (!int.TryParse(m.Groups["min"].Value, out var min)) return null;
        if (!int.TryParse(m.Groups["max"].Value, out var max)) return null;
        if (!int.TryParse(m.Groups["last"].Value, out var last)) return null;

        var diffMin = Math.Abs(ipid - min);
        var diffMax = Math.Abs(ipid - max);
        var diffLast = Math.Abs(ipid - last);

        return Math.Min(Math.Min(diffMin, diffMax), diffLast);
    }

    private void AppendHostTested(string hostKey, HostTested tested, DateTimeOffset nowUtc)
    {
        var ev = new SignalEvent
        {
            HostKey = hostKey,
            Type = SignalEventType.HostTested,
            ObservedAtUtc = nowUtc,
            Source = "HostTester",
            Value = tested,
            Reason = tested.BlockageType,
            Metadata = BuildHostMeta(tested)
        };

        _store.Append(ev);
    }

    private void AppendFromInspectionSignals(string hostKey, InspectionSignalsSnapshot signals, ref DateTimeOffset tsUtc)
    {
        // TcpRetransStats (дедуплим очень часто)
        if (signals.TotalPackets > 0)
        {
            if (AppendDebounced(hostKey,
                SignalEventType.TcpRetransStats,
                tsUtc,
                source: "TcpRetransmissionTracker",
                value: new TcpRetransPayload(signals.Retransmissions, signals.TotalPackets),
                reason: null))
            {
                tsUtc = tsUtc.AddMilliseconds(1);
            }
        }

        if (signals.HasSuspiciousRst)
        {
            if (AppendDebounced(hostKey,
                SignalEventType.SuspiciousRstObserved,
                tsUtc,
                source: "RstInspectionService",
                value: signals.SuspiciousRstDetails,
                reason: signals.SuspiciousRstDetails))
            {
                tsUtc = tsUtc.AddMilliseconds(1);
            }
        }

        if (signals.HasHttpRedirect)
        {
            if (AppendDebounced(hostKey,
                SignalEventType.HttpRedirectObserved,
                tsUtc,
                source: "HttpRedirectDetector",
                value: signals.RedirectToHost,
                reason: signals.RedirectToHost))
            {
                tsUtc = tsUtc.AddMilliseconds(1);
            }
        }

        if (signals.UdpUnansweredHandshakes > 0)
        {
            if (AppendDebounced(hostKey,
                SignalEventType.UdpHandshakeUnanswered,
                tsUtc,
                source: "UdpInspectionService",
                value: signals.UdpUnansweredHandshakes,
                reason: signals.UdpUnansweredHandshakes.ToString()))
            {
                tsUtc = tsUtc.AddMilliseconds(1);
            }
        }
    }

    private bool AppendDebounced(
        string hostKey,
        SignalEventType type,
        DateTimeOffset nowUtc,
        string source,
        object? value,
        string? reason)
    {
        var last = _store.TryGetLatest(hostKey, type);
        if (last != null && (nowUtc - last.ObservedAtUtc) < SameTypeDebounce)
        {
            // Слишком часто — пропускаем, чтобы не раздувать sequence.
            return false;
        }

        _store.Append(new SignalEvent
        {
            HostKey = hostKey,
            Type = type,
            ObservedAtUtc = nowUtc,
            Source = source,
            Value = value,
            Reason = reason,
            Metadata = null
        });

        return true;
    }

    private void TryReportGate1To2(string hostKey, DateTimeOffset nowUtc, IProgress<string>? progress)
    {
        if (progress is null) return;

        // Кулдаун по хосту
        if (_lastGateLogUtc.TryGetValue(hostKey, out var lastUtc) && (nowUtc - lastUtc) < GateLogCooldown)
        {
            return;
        }

        var fromUtc = nowUtc - IntelligenceContractDefaults.DefaultAggregationWindow;
        var recent = _store.ReadWindow(hostKey, fromUtc, nowUtc);

        // Для Gate 1→2 нам важно качество цепочки, иначе диагностика будет работать по шуму.
        // Требования:
        // - минимум 3 события
        // - минимум 3 разных типа
        // - обязательно HostTested + минимум 2 события "других слоёв"
        // - временная последовательность восстанавливается (ObservedAtUtc не убывает)
        if (recent.Count < 3) return;
        if (!recent.HasType(SignalEventType.HostTested)) return;

        var distinctTypes = new HashSet<SignalEventType>();
        foreach (var e in recent)
        {
            distinctTypes.Add(e.Type);
        }
        if (distinctTypes.Count < 3) return;

        var hasOtherLayer =
            recent.HasType(SignalEventType.TcpRetransStats) ||
            recent.HasType(SignalEventType.SuspiciousRstObserved) ||
            recent.HasType(SignalEventType.HttpRedirectObserved) ||
            recent.HasType(SignalEventType.UdpHandshakeUnanswered);
        if (!hasOtherLayer) return;

        for (var i = 1; i < recent.Count; i++)
        {
            // На Windows DateTimeOffset.UtcNow может иметь грубую дискретность,
            // поэтому допустимы одинаковые метки времени у соседних событий.
            if (recent[i - 1].ObservedAtUtc > recent[i].ObservedAtUtc)
            {
                return;
            }
        }

        // Важно для Gate 1→2: по логу должна восстанавливаться *последовательность* событий.
        // Поэтому печатаем компактный tail в порядке прихода: Type(+deltaMs) → Type(+deltaMs) ...
        // (без спама: 1 строка и кулдаун по хосту)
        var tailCount = Math.Min(6, recent.Count);
        var start = recent.Count - tailCount;
        var baseTs = recent[start].ObservedAtUtc;

        var parts = new List<string>(capacity: tailCount);
        for (var i = start; i < recent.Count; i++)
        {
            var e = recent[i];
            var deltaMs = (int)Math.Max(0, (e.ObservedAtUtc - baseTs).TotalMilliseconds);
            parts.Add($"{e.Type}(+{deltaMs}ms)");
        }

        var timeline = string.Join("→", parts);
        progress.Report($"[INTEL][GATE1] hostKey={hostKey} recentCount={recent.Count} timeline={timeline}");
        _lastGateLogUtc[hostKey] = nowUtc;
    }

    private static bool IsFakeIp(IPAddress? ip)
    {
        if (ip is null) return false;
        return NetUtils.IsBypassIPv4(ip);
    }

    private static IReadOnlyDictionary<string, string> BuildHostMeta(HostTested tested)
    {
        // Минимальный набор метаданных (для восстановления цепочки в логах/отладке)
        var dict = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ip"] = tested.Host.RemoteIp?.ToString() ?? "",
            ["port"] = tested.Host.RemotePort.ToString(),
            ["proto"] = tested.Host.Protocol.ToString(),
            ["dns"] = tested.DnsOk ? "1" : "0",
            ["tcp"] = tested.TcpOk ? "1" : "0",
            ["tls"] = tested.TlsOk ? "1" : "0",
        };

        if (!string.IsNullOrWhiteSpace(tested.DnsStatus)) dict["dnsStatus"] = tested.DnsStatus!;
        if (!string.IsNullOrWhiteSpace(tested.Hostname)) dict["hostname"] = tested.Hostname!;
        if (!string.IsNullOrWhiteSpace(tested.SniHostname)) dict["sni"] = tested.SniHostname!;
        if (!string.IsNullOrWhiteSpace(tested.Http3Status)) dict["h3"] = tested.Http3Status!;
        if (!string.IsNullOrWhiteSpace(tested.VerdictStatus)) dict["verdictStatus"] = tested.VerdictStatus!;
        if (!string.IsNullOrWhiteSpace(tested.UnknownReason)) dict["unknownReason"] = tested.UnknownReason!;

        return dict;
    }

    private sealed record TcpRetransPayload(int Retransmissions, int TotalPackets);
}
