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

            // Runtime Adaptation слой не должен заниматься резолвингом или UI-целями.
            // Он получает только "факты": какие hostKey сейчас релевантны для синхронизации.
            var primaryTarget = context.PrimaryTargetHostKey;
            var secondaryTarget = context.SecondaryTargetHostKey;

            var dedupKey = $"udp_blockage|{primaryTarget ?? ""}|{secondaryTarget ?? ""}|{ipKey}";
            if (IsDeduped(dedupKey)) return;

            // Важно: селективный QUIC→TCP требует целей. Здесь мы не «включаем обход»,
            // а синхронизируем execution-state под уже включённый режим.
            if (!string.IsNullOrWhiteSpace(primaryTarget))
            {
                _stateManager.RefreshUdp443SelectiveTargetsFromObservedIpBestEffort(primaryTarget!, ip);
            }

            if (!string.IsNullOrWhiteSpace(secondaryTarget)
                && !string.Equals(primaryTarget, secondaryTarget, StringComparison.OrdinalIgnoreCase))
            {
                _stateManager.RefreshUdp443SelectiveTargetsFromObservedIpBestEffort(secondaryTarget!, ip);
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
    string? PrimaryTargetHostKey,
    string? SecondaryTargetHostKey);
