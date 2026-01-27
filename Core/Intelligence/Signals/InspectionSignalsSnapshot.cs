using System;

namespace IspAudit.Core.Intelligence.Signals;

/// <summary>
/// Снимок сигналов «инспекции трафика» (RST/HTTP redirect/UDP handshake/ретрансмиссии),
/// пригодный для контура INTEL без зависимости от legacy агрегатов/типов.
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
}
