using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using IspAudit.Bypass;

namespace IspAudit.Core.RuntimeAdaptation;

/// <summary>
/// Runtime Adaptation Layer: принимает runtime-сигналы и синхронизирует execution-state (targets/snapshots)
/// без принятия «политических» решений (без UI, без auto-apply, без выбора стратегий).
/// </summary>
public sealed class ReactiveTargetSyncService
{
    private static readonly StringComparer KeyComparer = StringComparer.OrdinalIgnoreCase;

    private readonly BypassStateManager _stateManager;
    private readonly Action<string>? _log;

    private readonly ConcurrentDictionary<string, long> _recentEvents = new(KeyComparer);
    private readonly long _dedupWindowStopwatchTicks;

    public ReactiveTargetSyncService(
        BypassStateManager stateManager,
        Action<string>? log = null,
        TimeSpan? dedupWindow = null)
    {
        _stateManager = stateManager ?? throw new ArgumentNullException(nameof(stateManager));
        _log = log;

        var window = dedupWindow ?? TimeSpan.FromSeconds(2);
        _dedupWindowStopwatchTicks = (long)(window.TotalSeconds * Stopwatch.Frequency);
    }

    /// <summary>
    /// Runtime-сигнал: обнаружена UDP blockage (часто QUIC/HTTP3/DTLS). Сервис best-effort «догоняет» targets
    /// для селективного QUIC→TCP (DROP UDP/443), если он уже включён пользователем.
    /// </summary>
    public void OnUdpBlockage(IPAddress ip, ReactiveTargetSyncContext context)
    {
        if (ip == null) return;

        try
        {
            if (!context.IsQuicFallbackEnabled) return;
            if (context.IsQuicFallbackGlobal) return;

            var ipKey = ip.ToString();
            var existingTarget = context.CurrentOutcomeTargetHost;

            var resolvedHost = context.TryResolveHostFromIp?.Invoke(ip);
            var candidateTarget = !string.IsNullOrWhiteSpace(resolvedHost)
                ? resolvedHost!.Trim()
                : ipKey;

            var dedupKey = $"udp_blockage|{existingTarget ?? ""}|{candidateTarget}|{ipKey}";
            if (IsDeduped(dedupKey)) return;

            // Важно: селективный QUIC→TCP требует целей. Здесь мы не «включаем обход»,
            // а синхронизируем execution-state под уже включённый режим.
            if (!string.IsNullOrWhiteSpace(existingTarget))
            {
                _stateManager.RefreshUdp443SelectiveTargetsFromObservedIpBestEffort(existingTarget!, ip);
            }

            if (!string.IsNullOrWhiteSpace(candidateTarget)
                && !string.Equals(existingTarget, candidateTarget, StringComparison.OrdinalIgnoreCase))
            {
                _stateManager.RefreshUdp443SelectiveTargetsFromObservedIpBestEffort(candidateTarget, ip);
            }

            // Best-effort: обновляем OutcomeTargetHost, чтобы UI/логика outcome не «залипали» на старой цели.
            if (context.SetOutcomeTargetHost != null)
            {
                var shouldUpdateTarget = string.IsNullOrWhiteSpace(existingTarget)
                    || !string.Equals(existingTarget, candidateTarget, StringComparison.OrdinalIgnoreCase);

                if (shouldUpdateTarget)
                {
                    context.SetOutcomeTargetHost(candidateTarget);
                    _log?.Invoke($"[ReactiveTargetSync] Outcome target host updated from UDP blockage: {ipKey} -> {candidateTarget}");
                }
            }
        }
        catch (Exception ex)
        {
            // Не даём runtime-adaptation ломать диагностику.
            _log?.Invoke($"[ReactiveTargetSync] Ошибка обработки UDP blockage: {ex.Message}");
        }
    }

    /// <summary>
    /// Runtime-сигнал: интерференция на TLS (например, ECH/SNI mismatch, сбой ClientHello, DPI).
    /// Контракт зарезервирован: конкретные действия зависят от того, какие runtime-факты/метрики будут доступны.
    /// </summary>
    public void OnTlsInterference(string host, ReactiveTargetSyncContext context)
    {
        // TODO: зарезервировано под будущие runtime-сигналы (без политики).
        _ = host;
        _ = context;
    }

    /// <summary>
    /// Runtime-сигнал: обнаружено расхождение endpoint-ов (old→new) в рамках одной цели.
    /// </summary>
    public void OnEndpointMismatch(string oldTarget, string newTarget, ReactiveTargetSyncContext context)
    {
        // TODO: зарезервировано под общий механизм "догоняющей" синхронизации targets.
        _ = oldTarget;
        _ = newTarget;
        _ = context;
    }

    private bool IsDeduped(string key)
    {
        var now = Stopwatch.GetTimestamp();

        if (_recentEvents.TryGetValue(key, out var last) && now - last < _dedupWindowStopwatchTicks)
        {
            return true;
        }

        _recentEvents[key] = now;
        return false;
    }
}

/// <summary>
/// Контекст runtime-сигнала для слоя Runtime Adaptation.
/// Содержит только "факты" и способы best-effort обновления состояния, без UI и без политических решений.
/// </summary>
public sealed record ReactiveTargetSyncContext(
    bool IsQuicFallbackEnabled,
    bool IsQuicFallbackGlobal,
    string? CurrentOutcomeTargetHost,
    Func<IPAddress, string?>? TryResolveHostFromIp,
    Action<string>? SetOutcomeTargetHost);
