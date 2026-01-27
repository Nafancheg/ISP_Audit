using IspAudit.Core.Intelligence.Signals;
using IspAudit.Core.Models;

namespace IspAudit.Core.Interfaces;

/// <summary>
/// Источник «сырых» инспекционных сигналов (RST/HTTP redirect/UDP handshake/ретрансмиссии)
/// для контура INTEL, без зависимости от legacy агрегатов/типов.
/// </summary>
public interface IInspectionSignalsProvider
{
    /// <summary>
    /// Снять текущий снимок инспекционных сигналов для хоста.
    /// </summary>
    InspectionSignalsSnapshot GetInspectionSignalsSnapshot(HostTested tested);
}
