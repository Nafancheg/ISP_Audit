using System;
using IspAudit.Core.Models;

namespace IspAudit.Core.IntelligenceV2.Signals;

/// <summary>
/// Снимок сигналов «инспекции трафика» (RST/HTTP redirect/UDP handshake/ретрансмиссии),
/// пригодный для v2 контура без зависимости от legacy агрегата <see cref="BlockageSignals"/>.
/// </summary>
public readonly record struct InspectionSignalsSnapshot(
    int Retransmissions,
    int TotalPackets,
    bool HasHttpRedirect,
    string? RedirectToHost,
    bool HasSuspiciousRst,
    string? SuspiciousRstDetails,
    int UdpUnansweredHandshakes)
{
    public static InspectionSignalsSnapshot Empty => new(
        Retransmissions: 0,
        TotalPackets: 0,
        HasHttpRedirect: false,
        RedirectToHost: null,
        HasSuspiciousRst: false,
        SuspiciousRstDetails: null,
        UdpUnansweredHandshakes: 0);

    public static InspectionSignalsSnapshot FromLegacy(BlockageSignals legacy)
    {
        return new InspectionSignalsSnapshot(
            Retransmissions: Math.Max(0, legacy.RetransmissionCount),
            TotalPackets: Math.Max(0, legacy.TotalPackets),
            HasHttpRedirect: legacy.HasHttpRedirectDpi,
            RedirectToHost: legacy.RedirectToHost,
            HasSuspiciousRst: legacy.HasSuspiciousRst,
            SuspiciousRstDetails: legacy.SuspiciousRstDetails,
            UdpUnansweredHandshakes: Math.Max(0, legacy.UdpUnansweredHandshakes));
    }
}
