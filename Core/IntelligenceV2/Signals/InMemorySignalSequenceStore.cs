using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Core.IntelligenceV2.Contracts;

namespace IspAudit.Core.IntelligenceV2.Signals;

/// <summary>
/// In-memory хранилище последовательностей событий v2 (SignalSequence) с TTL.
/// Потокобезопасность: отдельная блокировка на каждый HostKey.
/// Важно: очистка по TTL выполняется строго при Append(...), без таймеров.
/// </summary>
public sealed class InMemorySignalSequenceStore
{
    private sealed class SequenceBucket
    {
        public object Gate { get; } = new();
        public SignalSequence Sequence { get; }

        public SequenceBucket(string hostKey, DateTimeOffset createdAtUtc)
        {
            Sequence = new SignalSequence
            {
                HostKey = hostKey,
                FirstSeenUtc = createdAtUtc,
                LastUpdatedUtc = createdAtUtc
            };
        }
    }

    private readonly ConcurrentDictionary<string, SequenceBucket> _buckets = new(StringComparer.Ordinal);
    private long _appendCounter;

    public void Append(SignalEvent signalEvent)
    {
        if (signalEvent is null) throw new ArgumentNullException(nameof(signalEvent));
        if (string.IsNullOrWhiteSpace(signalEvent.HostKey))
        {
            throw new ArgumentException("HostKey должен быть непустым", nameof(signalEvent));
        }

        var nowUtc = DateTimeOffset.UtcNow;
        var cutoffUtc = nowUtc - IntelligenceV2ContractDefaults.EventTtl;

        var bucket = _buckets.GetOrAdd(signalEvent.HostKey, hk => new SequenceBucket(hk, nowUtc));
        lock (bucket.Gate)
        {
            // TTL-очистка выполняется только при Append
            var events = bucket.Sequence.Events;

            // Удаляем старые события (в начале списка чаще всего именно они)
            // При необходимости — fallback на RemoveAll.
            var removed = 0;
            while (events.Count > 0)
            {
                if (events[0].ObservedAtUtc >= cutoffUtc) break;
                events.RemoveAt(0);
                removed++;
            }

            // Если события приходят нестрого по времени, возможны старые элементы в середине.
            // Это редкий, но возможный случай: подчистим остатки.
            if (removed == 0)
            {
                events.RemoveAll(e => e.ObservedAtUtc < cutoffUtc);
            }

            events.Add(signalEvent);
            bucket.Sequence.LastUpdatedUtc = nowUtc;
        }

        // Доп. защита от роста памяти: на каждом N-ом Append делаем лёгкую "общую" очистку.
        // Важно: это всё ещё выполняется только в рамках Append (без таймеров).
        var n = System.Threading.Interlocked.Increment(ref _appendCounter);
        if ((n & 0x3F) == 0) // раз в 64 события
        {
            CleanupStaleBuckets(nowUtc, cutoffUtc);
        }
    }

    private void CleanupStaleBuckets(DateTimeOffset nowUtc, DateTimeOffset cutoffUtc)
    {
        foreach (var kvp in _buckets)
        {
            var bucket = kvp.Value;
            var shouldRemove = false;

            lock (bucket.Gate)
            {
                bucket.Sequence.Events.RemoveAll(e => e.ObservedAtUtc < cutoffUtc);

                // Если в bucket больше нет событий и он давно не обновлялся — удаляем ключ целиком.
                if (bucket.Sequence.Events.Count == 0 && bucket.Sequence.LastUpdatedUtc < cutoffUtc)
                {
                    shouldRemove = true;
                }
            }

            if (shouldRemove)
            {
                _buckets.TryRemove(new KeyValuePair<string, SequenceBucket>(kvp.Key, bucket));
            }
        }
    }

    public IReadOnlyList<SignalEvent> ReadWindow(string hostKey, DateTimeOffset fromUtc, DateTimeOffset toUtc)
    {
        if (string.IsNullOrWhiteSpace(hostKey)) return Array.Empty<SignalEvent>();
        if (toUtc < fromUtc) return Array.Empty<SignalEvent>();

        if (!_buckets.TryGetValue(hostKey, out var bucket)) return Array.Empty<SignalEvent>();

        lock (bucket.Gate)
        {
            // Возвращаем копию для потокобезопасности.
            return bucket.Sequence.Events
                .Where(e => e.ObservedAtUtc >= fromUtc && e.ObservedAtUtc <= toUtc)
                .ToArray();
        }
    }

    public SignalEvent? TryGetLatest(string hostKey, SignalEventType type)
    {
        if (string.IsNullOrWhiteSpace(hostKey)) return null;
        if (!_buckets.TryGetValue(hostKey, out var bucket)) return null;

        lock (bucket.Gate)
        {
            // Ищем с конца (обычно события добавляются по времени)
            for (var i = bucket.Sequence.Events.Count - 1; i >= 0; i--)
            {
                var e = bucket.Sequence.Events[i];
                if (e.Type == type)
                {
                    return e;
                }
            }

            return null;
        }
    }

    public int CountHostKeys() => _buckets.Count;
}
