using IspAudit.Bypass;

namespace IspAudit.Core.Traffic
{
    public interface IPacketSender
    {
        bool Send(byte[] packet, int length, ref WinDivertNative.Address addr);
    }
}
