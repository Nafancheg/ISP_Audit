using System;
using System.Net;

namespace IspAudit.Utils
{
    /// <summary>
    /// Представляет сетевое подключение, обнаруженное при анализе трафика.
    /// </summary>
    public class NetworkConnection
    {
        /// <summary>
        /// Удалённый IP-адрес.
        /// </summary>
        public required IPAddress RemoteIp { get; init; }

        /// <summary>
        /// Удалённый порт.
        /// </summary>
        public required ushort RemotePort { get; init; }

        /// <summary>
        /// Протокол (TCP/UDP).
        /// </summary>
        public required TransportProtocol Protocol { get; init; }

        /// <summary>
        /// Hostname (если удалось определить через reverse DNS), иначе null.
        /// </summary>
        public string? Hostname { get; set; }

        /// <summary>
        /// Количество пакетов/событий для этого подключения.
        /// </summary>
        public int PacketCount { get; set; } = 1;

        /// <summary>
        /// Общий объем переданных данных в байтах.
        /// </summary>
        public long TotalBytes { get; set; } = 0;

        /// <summary>
        /// Временная метка первого обнаруженного пакета.
        /// </summary>
        public DateTime FirstSeen { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Временная метка последнего обнаруженного пакета.
        /// </summary>
        public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Протокол транспортного уровня
    /// </summary>
    public enum TransportProtocol
    {
        TCP,
        UDP
    }
}
