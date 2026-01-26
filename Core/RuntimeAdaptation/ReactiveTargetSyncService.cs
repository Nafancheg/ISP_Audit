using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using IspAudit.Bypass;

namespace IspAudit.Core.RuntimeAdaptation;

/// <summary>
/// Runtime Adaptation Layer: принимает runtime-сигналы и синхронизирует execution-state (targets/snapshots)
/// без принятия «политических» решений (без UI, без auto-apply, без выбора стратегий).
/// </summary>
public sealed class ReactiveTargetSyncService
{
    private readonly BypassStateManager _stateManager;
    private readonly Action<string>? _log;

    private readonly Channel<string> _queue;
    private readonly ConcurrentDictionary<string, PendingEvent> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;

    private readonly long _ttlTicks;
    private readonly int _maxAttempts;

    public ReactiveTargetSyncService(
        BypassStateManager stateManager,
        Action<string>? log = null,
        ReactiveTargetSyncOptions? options = null)
    {
        _stateManager = stateManager ?? throw new ArgumentNullException(nameof(stateManager));
        _log = log;

        var opt = options ?? ReactiveTargetSyncOptions.Default;
        _ttlTicks = (long)(opt.EventTtl.TotalSeconds * Stopwatch.Frequency);
        _maxAttempts = opt.MaxAttempts;

        _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(opt.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });

        _worker = Task.Run(ProcessLoopAsync);
    }

    public void Dispose()
    {
        try
        {
            _cts.Cancel();
        }
        catch
        {
        }
    }

    /// <summary>
    /// Форсирует попытку доставки всех pending событий (best-effort).
    /// Используется как lifecycle-hook при engine restart и после Apply.
    /// </summary>
    public void Nudge()
    {
        try
        {
            var now = Stopwatch.GetTimestamp();

            foreach (var kv in _pending)
            {
                var key = kv.Key;
                var ev = kv.Value;
                _pending[key] = ev with { NextAttemptTick = now };
                _queue.Writer.TryWrite(key);
            }
        }
        catch
        {
        }
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

            EnqueueCoalesced("udp_blockage", context.PrimaryTargetHostKey, ip);
            if (!string.Equals(context.PrimaryTargetHostKey, context.SecondaryTargetHostKey, StringComparison.OrdinalIgnoreCase))
            {
                EnqueueCoalesced("udp_blockage", context.SecondaryTargetHostKey, ip);
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

    private void EnqueueCoalesced(string type, string? hostKey, IPAddress ip)
    {
        try
        {
            hostKey = (hostKey ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(hostKey)) return;

            var now = Stopwatch.GetTimestamp();
            var key = $"{type}|{hostKey}|{ip}";

            _pending.AddOrUpdate(
                key,
                _ => new PendingEvent(type, hostKey, ip, Attempts: 0, NextAttemptTick: now, DeadlineTick: now + _ttlTicks),
                (_, existing) =>
                {
                    // Coalescing: продлеваем TTL и сбрасываем план попытки на ближайшее время.
                    var next = now;
                    var deadline = now + _ttlTicks;
                    return existing with { NextAttemptTick = Math.Min(existing.NextAttemptTick, next), DeadlineTick = Math.Max(existing.DeadlineTick, deadline) };
                });

            _queue.Writer.TryWrite(key);
        }
        catch
        {
            // best-effort
        }
    }

    private async Task ProcessLoopAsync()
    {
        try
        {
            while (await _queue.Reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
            {
                while (_queue.Reader.TryRead(out var key))
                {
                    if (!_pending.TryGetValue(key, out var ev))
                    {
                        continue;
                    }

                    var now = Stopwatch.GetTimestamp();
                    if (now > ev.DeadlineTick)
                    {
                        _pending.TryRemove(key, out _);
                        continue;
                    }

                    if (now < ev.NextAttemptTick)
                    {
                        // Ещё рано пытаться — возвращаем в очередь (bounded, DropOldest).
                        _queue.Writer.TryWrite(key);
                        await Task.Delay(15, _cts.Token).ConfigureAwait(false);
                        continue;
                    }

                    var delivered = false;
                    try
                    {
                        var result = _stateManager.TrySyncUdp443SelectiveTargetsFromObservedIp(ev.HostKey, ev.Ip);

                        // Критерий доставки:
                        // - legacy: targets реально применены в active filter, или
                        // - policy: DecisionGraphSnapshot обновлён (пересобран).
                        delivered = result.LegacyTargetsDeliveredToFilter || result.PolicySnapshotUpdated;
                    }
                    catch
                    {
                        delivered = false;
                    }

                    if (delivered)
                    {
                        _pending.TryRemove(key, out _);
                        continue;
                    }

                    var attempts = ev.Attempts + 1;
                    if (attempts >= _maxAttempts)
                    {
                        _pending.TryRemove(key, out _);
                        continue;
                    }

                    var backoffMs = ComputeBackoffMs(attempts);
                    var nextAttempt = now + (long)(backoffMs / 1000.0 * Stopwatch.Frequency);
                    _pending[key] = ev with { Attempts = attempts, NextAttemptTick = nextAttempt };
                    _queue.Writer.TryWrite(key);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[ReactiveTargetSync] Worker crashed: {ex.Message}");
        }
    }

    private static int ComputeBackoffMs(int attempts)
    {
        // 1: 50ms, 2: 100ms, 3: 200ms, 4+: 400ms (cap)
        var ms = 50 * (1 << Math.Min(attempts - 1, 3));
        return Math.Min(ms, 400);
    }

    private readonly record struct PendingEvent(
        string Type,
        string HostKey,
        IPAddress Ip,
        int Attempts,
        long NextAttemptTick,
        long DeadlineTick);
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

public sealed record ReactiveTargetSyncOptions(
    int QueueCapacity,
    int MaxAttempts,
    TimeSpan EventTtl)
{
    public static readonly ReactiveTargetSyncOptions Default = new(
        QueueCapacity: 256,
        MaxAttempts: 30,
        EventTtl: TimeSpan.FromSeconds(10));
}
