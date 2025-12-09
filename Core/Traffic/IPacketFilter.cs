namespace IspAudit.Core.Traffic
{
    public interface IPacketFilter
    {
        string Name { get; }
        int Priority { get; }

        /// <summary>
        /// Process a packet.
        /// </summary>
        /// <param name="packet">The packet data (can be modified).</param>
        /// <param name="context">Context information.</param>
        /// <param name="sender">Interface to send new packets (e.g. fragments).</param>
        /// <returns>True to pass to next filter, False to drop/stop processing.</returns>
        bool Process(InterceptedPacket packet, PacketContext context, IPacketSender sender);
    }
}
