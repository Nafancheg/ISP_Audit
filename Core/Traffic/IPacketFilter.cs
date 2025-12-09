namespace IspAudit.Core.Traffic
{
    public interface IPacketFilter
    {
        /// <summary>
        /// Process a packet.
        /// </summary>
        /// <param name="packet">The packet data (can be modified).</param>
        /// <param name="context">Context information.</param>
        /// <returns>True to pass to next filter, False to drop/stop processing.</returns>
        bool Process(InterceptedPacket packet, PacketContext context);
    }
}
