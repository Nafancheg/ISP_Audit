using System;
using System.Net;

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Ключ TCP-потока (направление-агностичный).
    /// Используется для агрегации ретрансмиссий.
    /// </summary>
    public readonly record struct TcpFlowKey(IPAddress A, int PortA, IPAddress B, int PortB)
    {
        public static TcpFlowKey Create(IPAddress srcIp, int srcPort, IPAddress dstIp, int dstPort)
        {
            if (srcIp is null) throw new ArgumentNullException(nameof(srcIp));
            if (dstIp is null) throw new ArgumentNullException(nameof(dstIp));

            // Нормализуем порядок, чтобы поток не зависел от направления (клиент/сервер).
            var src = srcIp.ToString();
            var dst = dstIp.ToString();

            return string.CompareOrdinal(src, dst) <= 0
                ? new TcpFlowKey(srcIp, srcPort, dstIp, dstPort)
                : new TcpFlowKey(dstIp, dstPort, srcIp, srcPort);
        }
    }
}
