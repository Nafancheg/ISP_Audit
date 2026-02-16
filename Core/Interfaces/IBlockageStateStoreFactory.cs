using IspAudit.Core.Modules;

namespace IspAudit.Core.Interfaces
{
    public interface IBlockageStateStoreFactory
    {
        InMemoryBlockageStateStore CreateDefault();

        InMemoryBlockageStateStore CreateWithTrackers(
            TcpRetransmissionTracker retransmissionTracker,
            HttpRedirectDetector? httpRedirectDetector,
            RstInspectionService? rstInspectionService,
            UdpInspectionService? udpInspectionService);
    }
}
