using IspAudit.Bypass;

namespace IspAudit.Core.Traffic
{
    /// <summary>
    /// Расширенный контракт отправки пакетов.
    /// Используется точечно: большинству фильтров достаточно IPacketSender.
    /// </summary>
    public interface IPacketSenderEx : IPacketSender
    {
        bool SendEx(byte[] packet, int length, ref WinDivertNative.Address addr, PacketSendOptions options);
    }
}
