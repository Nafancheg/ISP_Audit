using System;
using IspAudit.Core.Interfaces;

namespace IspAudit.Core.Modules
{
    public sealed class InMemoryBlockageStateStoreFactory : IBlockageStateStoreFactory
    {
        public InMemoryBlockageStateStore CreateDefault()
        {
            return new InMemoryBlockageStateStore();
        }

        public InMemoryBlockageStateStore CreateWithTrackers(
            TcpRetransmissionTracker retransmissionTracker,
            HttpRedirectDetector? httpRedirectDetector,
            RstInspectionService? rstInspectionService,
            UdpInspectionService? udpInspectionService)
        {
            if (retransmissionTracker == null) throw new ArgumentNullException(nameof(retransmissionTracker));
            return new InMemoryBlockageStateStore(retransmissionTracker, httpRedirectDetector, rstInspectionService, udpInspectionService);
        }
    }
}
