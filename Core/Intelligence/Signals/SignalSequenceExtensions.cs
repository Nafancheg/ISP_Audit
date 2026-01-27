using System;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Core.Intelligence.Contracts;

namespace IspAudit.Core.Intelligence.Signals;

public static class SignalSequenceExtensions
{
    public static IReadOnlyList<SignalEvent> FilterWindow(
        this IEnumerable<SignalEvent> events,
        DateTimeOffset capturedAtUtc,
        TimeSpan window)
    {
        if (events is null) throw new ArgumentNullException(nameof(events));
        if (window <= TimeSpan.Zero) return Array.Empty<SignalEvent>();

        var fromUtc = capturedAtUtc - window;
        return events
            .Where(e => e.ObservedAtUtc >= fromUtc && e.ObservedAtUtc <= capturedAtUtc)
            .ToArray();
    }

    public static bool HasType(this IEnumerable<SignalEvent> events, SignalEventType type)
    {
        if (events is null) throw new ArgumentNullException(nameof(events));
        return events.Any(e => e.Type == type);
    }
}
