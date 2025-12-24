using IspAudit.Core.IntelligenceV2.Signals;
using IspAudit.Core.Models;

namespace IspAudit.Core.Interfaces;

/// <summary>
/// Источник «сырых» инспекционных сигналов (RST/HTTP redirect/UDP handshake/ретрансмиссии)
/// для v2 контура, без зависимости от legacy агрегата <see cref="IspAudit.Core.Models.BlockageSignals"/>.
/// </summary>
public interface IInspectionSignalsProvider
{
    /// <summary>
    /// Снять текущий снимок инспекционных сигналов для хоста.
    /// </summary>
    InspectionSignalsSnapshot GetInspectionSignalsSnapshot(HostTested tested);
}
