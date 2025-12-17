using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using IspAudit.Core.IntelligenceV2.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;

namespace IspAudit.Core.IntelligenceV2.Signals;

/// <summary>
/// Адаптер сигналов v2: принимает существующие результаты (HostTested + legacy BlockageSignals)
/// и записывает их в последовательность событий (SignalSequence) с TTL.
/// Дополнительно умеет построить агрегированный срез BlockageSignalsV2 по окну.
/// </summary>
public sealed class SignalsAdapterV2
{
    private readonly InMemorySignalSequenceStore _store;

    // Ограничитель логов Gate 1→2: не чаще 1 раза в минуту на HostKey
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastGateLogUtc = new(StringComparer.Ordinal);
    private static readonly TimeSpan GateLogCooldown = TimeSpan.FromSeconds(60);

    // Простейший анти-спам для событий одного типа
    private static readonly TimeSpan SameTypeDebounce = TimeSpan.FromSeconds(5);

    public SignalsAdapterV2(InMemorySignalSequenceStore store)
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

    public void Observe(HostTested tested, BlockageSignals legacySignals, IProgress<string>? progress = null)
    {
        var hostKey = BuildStableHostKey(tested);
        var nowUtc = DateTimeOffset.UtcNow;

        AppendHostTested(hostKey, tested, nowUtc);
        AppendFromLegacySignals(hostKey, legacySignals, nowUtc);

        // Gate 1→2: показываем компактную строку, если у хоста уже накопилась "цепочка".
        TryReportGate1To2(hostKey, nowUtc, progress);
    }

    public BlockageSignalsV2 BuildSnapshot(HostTested tested, BlockageSignals legacySignals, TimeSpan window)
    {
        var hostKey = BuildStableHostKey(tested);
        var capturedAtUtc = DateTimeOffset.UtcNow;
        var fromUtc = capturedAtUtc - window;

        var windowEvents = _store.ReadWindow(hostKey, fromUtc, capturedAtUtc);

        var hasDnsFailure = !tested.DnsOk || (!string.IsNullOrWhiteSpace(tested.DnsStatus) && !string.Equals(tested.DnsStatus, "OK", StringComparison.OrdinalIgnoreCase));
        var hasTcpTimeout = string.Equals(tested.BlockageType, "TCP_TIMEOUT", StringComparison.Ordinal);
        var hasTcpReset = string.Equals(tested.BlockageType, "TCP_RST", StringComparison.Ordinal) || legacySignals.HasSuspiciousRst || windowEvents.HasType(SignalEventType.SuspiciousRstObserved);
        var hasTlsTimeout = string.Equals(tested.BlockageType, "TLS_TIMEOUT", StringComparison.Ordinal);
        // ВАЖНО: TLS_DPI — это фактически "TLS authentication failure" (AuthenticationException) из HostTester.
        // Это наблюдаемый факт о сбое рукопожатия, а не утверждение про DPI.
        var hasTlsAuthFailure = string.Equals(tested.BlockageType, "TLS_DPI", StringComparison.Ordinal);

        double? retxRate = null;
        if (legacySignals.TotalPackets > 0)
        {
            retxRate = Math.Clamp((double)legacySignals.RetransmissionCount / legacySignals.TotalPackets, 0.0, 1.0);
        }

        var hasFakeIp = IsFakeIp(tested.Host.RemoteIp);

        var hasHttpRedirect = legacySignals.HasHttpRedirectDpi || windowEvents.HasType(SignalEventType.HttpRedirectObserved);

        return new BlockageSignalsV2
        {
            HostKey = hostKey,
            CapturedAtUtc = capturedAtUtc,
            AggregationWindow = window,

            HasTcpReset = hasTcpReset,
            HasTcpTimeout = hasTcpTimeout,
            RetransmissionRate = retxRate,

            RstTtlDelta = null,
            RstLatency = null,

            HasDnsFailure = hasDnsFailure,
            HasFakeIp = hasFakeIp,

            HasHttpRedirect = hasHttpRedirect,

            HasTlsTimeout = hasTlsTimeout,
            HasTlsAuthFailure = hasTlsAuthFailure,
            HasTlsReset = false,

            SampleSize = windowEvents.Count,
            IsUnreliable = windowEvents.Count < 2
        };
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

    private void AppendFromLegacySignals(string hostKey, BlockageSignals signals, DateTimeOffset nowUtc)
    {
        // TcpRetransStats (дедуплим очень часто)
        if (signals.TotalPackets > 0)
        {
            AppendDebounced(hostKey,
                SignalEventType.TcpRetransStats,
                nowUtc,
                source: "TcpRetransmissionTracker",
                value: new TcpRetransPayload(signals.RetransmissionCount, signals.TotalPackets),
                reason: null);
        }

        if (signals.HasSuspiciousRst)
        {
            AppendDebounced(hostKey,
                SignalEventType.SuspiciousRstObserved,
                nowUtc,
                source: "RstInspectionService",
                value: signals.SuspiciousRstDetails,
                reason: signals.SuspiciousRstDetails);
        }

        if (signals.HasHttpRedirectDpi)
        {
            AppendDebounced(hostKey,
                SignalEventType.HttpRedirectObserved,
                nowUtc,
                source: "HttpRedirectDetector",
                value: signals.RedirectToHost,
                reason: signals.RedirectToHost);
        }

        if (signals.UdpUnansweredHandshakes > 0)
        {
            AppendDebounced(hostKey,
                SignalEventType.UdpHandshakeUnanswered,
                nowUtc,
                source: "UdpInspectionService",
                value: signals.UdpUnansweredHandshakes,
                reason: signals.UdpUnansweredHandshakes.ToString());
        }
    }

    private void AppendDebounced(
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
            return;
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
    }

    private void TryReportGate1To2(string hostKey, DateTimeOffset nowUtc, IProgress<string>? progress)
    {
        if (progress is null) return;

        // Кулдаун по хосту
        if (_lastGateLogUtc.TryGetValue(hostKey, out var lastUtc) && (nowUtc - lastUtc) < GateLogCooldown)
        {
            return;
        }

        var fromUtc = nowUtc - IntelligenceV2ContractDefaults.DefaultAggregationWindow;
        var recent = _store.ReadWindow(hostKey, fromUtc, nowUtc);

        // Для Gate 1→2 нам важно, чтобы у хоста было минимум 2 события
        // и чтобы в цепочке был HostTested.
        if (recent.Count < 2) return;
        if (!recent.HasType(SignalEventType.HostTested)) return;

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
        progress.Report($"[V2][GATE1] hostKey={hostKey} recentCount={recent.Count} timeline={timeline}");
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

        return dict;
    }

    private sealed record TcpRetransPayload(int Retransmissions, int TotalPackets);
}
