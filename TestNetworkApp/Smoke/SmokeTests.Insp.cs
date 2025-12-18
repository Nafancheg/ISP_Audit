using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic.Filters;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> Insp_RstInspection_TtlInjectionDetected(CancellationToken ct)
            => RunAsync("INSP-001", "RST-инжекция по TTL: аномальный TTL в RST помечается как подозрительный", () =>
            {
                var filter = new TrafficMonitorFilter();
                var rst = new RstInspectionService();
                rst.Attach(filter);

                var serverIp = IPAddress.Parse("203.0.113.10");
                var localIp = IPAddress.Parse("192.0.2.10");

                // Накопим базу «нормальных» TTL (минимум 3 пакета)
                for (ushort i = 0; i < 3; i++)
                {
                    var p = BuildIpv4TcpPacket(
                        srcIp: serverIp,
                        dstIp: localIp,
                        srcPort: 443,
                        dstPort: 55555,
                        ttl: 64,
                        ipId: (ushort)(1000 + i),
                        seq: (uint)(10000 + i),
                        tcpFlags: 0x10); // ACK

                    FeedPacket(filter, p, isOutbound: false);
                }

                // Подозрительный RST: TTL сильно отличается
                var rstPacket = BuildIpv4TcpPacket(
                    srcIp: serverIp,
                    dstIp: localIp,
                    srcPort: 443,
                    dstPort: 55555,
                    ttl: 5,
                    ipId: 2000,
                    seq: 20000,
                    tcpFlags: 0x04); // RST

                FeedPacket(filter, rstPacket, isOutbound: false);

                if (!rst.HasSuspiciousRst(serverIp, out var details))
                {
                    return new SmokeTestResult("INSP-001", "RST-инжекция по TTL: аномальный TTL в RST помечается как подозрительный", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали HasSuspiciousRst=true после RST с аномальным TTL");
                }

                if (!details.Contains("TTL=5", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("INSP-001", "RST-инжекция по TTL: аномальный TTL в RST помечается как подозрительный", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что details содержит TTL=5, но получили: {details}");
                }

                return new SmokeTestResult("INSP-001", "RST-инжекция по TTL: аномальный TTL в RST помечается как подозрительный", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {details}");
            }, ct);

        public static Task<SmokeTestResult> Insp_RstInspection_IpIdAnomalyDetected(CancellationToken ct)
            => RunAsync("INSP-002", "RST-инжекция по IPID: аномальный IPv4 Identification помечается как подозрительный", () =>
            {
                var filter = new TrafficMonitorFilter();
                var rst = new RstInspectionService();
                rst.Attach(filter);

                var serverIp = IPAddress.Parse("203.0.113.11");
                var localIp = IPAddress.Parse("192.0.2.11");

                // База «обычных» пакетов: TTL одинаковый, IPID небольшой
                for (ushort i = 0; i < 3; i++)
                {
                    var p = BuildIpv4TcpPacket(
                        srcIp: serverIp,
                        dstIp: localIp,
                        srcPort: 443,
                        dstPort: 55556,
                        ttl: 64,
                        ipId: (ushort)(1000 + i),
                        seq: (uint)(30000 + i),
                        tcpFlags: 0x10);

                    FeedPacket(filter, p, isOutbound: false);
                }

                // RST с «очень другим» IPID при нормальном TTL
                var rstPacket = BuildIpv4TcpPacket(
                    srcIp: serverIp,
                    dstIp: localIp,
                    srcPort: 443,
                    dstPort: 55556,
                    ttl: 64,
                    ipId: 50000,
                    seq: 40000,
                    tcpFlags: 0x04);

                FeedPacket(filter, rstPacket, isOutbound: false);

                if (!rst.HasSuspiciousRst(serverIp, out var details))
                {
                    return new SmokeTestResult("INSP-002", "RST-инжекция по IPID: аномальный IPv4 Identification помечается как подозрительный", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали HasSuspiciousRst=true после RST с аномальным IPID");
                }

                if (!details.Contains("IPID=50000", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("INSP-002", "RST-инжекция по IPID: аномальный IPv4 Identification помечается как подозрительный", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что details содержит IPID=50000, но получили: {details}");
                }

                return new SmokeTestResult("INSP-002", "RST-инжекция по IPID: аномальный IPv4 Identification помечается как подозрительный", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {details}");
            }, ct);

        public static Task<SmokeTestResult> Insp_UdpInspection_QuicBlockageDetected(CancellationToken ct)
            => RunAsync("INSP-003", "UDP/QUIC: QUIC Initial на UDP:443 учитывается и при отсутствии ответов даёт сигнал", () =>
            {
                var filter = new TrafficMonitorFilter();
                var udp = new UdpInspectionService();

                IPAddress? detectedIp = null;
                udp.OnBlockageDetected += ip => detectedIp = ip;
                udp.Attach(filter);

                var localIp = IPAddress.Parse("192.0.2.20");
                var remoteIp = IPAddress.Parse("203.0.113.99");

                // QUIC Initial должен быть >= 1200 байт, первый байт 0xC0 (Long Header + Fixed) и type=0.
                var payload = new byte[1200];
                payload[0] = 0xC0;

                for (ushort i = 0; i < 5; i++)
                {
                    var p = BuildIpv4UdpPacket(
                        srcIp: localIp,
                        dstIp: remoteIp,
                        srcPort: 55557,
                        dstPort: 443,
                        ttl: 64,
                        ipId: (ushort)(6000 + i),
                        payload: payload);

                    FeedPacket(filter, p, isOutbound: true);
                }

                var count = udp.GetUnansweredHandshakeCount(remoteIp);
                if (count < 5)
                {
                    return new SmokeTestResult("INSP-003", "UDP/QUIC: QUIC Initial на UDP:443 учитывается и при отсутствии ответов даёт сигнал", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали unanswered>=5, получили {count}");
                }

                if (detectedIp == null || !detectedIp.Equals(remoteIp))
                {
                    return new SmokeTestResult("INSP-003", "UDP/QUIC: QUIC Initial на UDP:443 учитывается и при отсутствии ответов даёт сигнал", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали событие OnBlockageDetected для {remoteIp}, но получили: {(detectedIp == null ? "null" : detectedIp.ToString())}");
                }

                return new SmokeTestResult("INSP-003", "UDP/QUIC: QUIC Initial на UDP:443 учитывается и при отсутствии ответов даёт сигнал", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: unanswered={count}, detected={detectedIp}");
            }, ct);

        public static Task<SmokeTestResult> Insp_TcpRetransmissionTracker_DropSuspicion(CancellationToken ct)
            => RunAsync("INSP-004", "TCP ретрансмиссии: доля >10% даёт сигнал подозрения на Drop", () =>
            {
                var filter = new TrafficMonitorFilter();
                var tracker = new TcpRetransmissionTracker();
                tracker.Attach(filter);

                var localIp = IPAddress.Parse("192.0.2.30");
                var remoteIp = IPAddress.Parse("203.0.113.77");

                // Делаем 20 пакетов в одном потоке, из них 3 ретрансмиссии (15%).
                uint seq = 1000;
                for (int i = 1; i <= 20; i++)
                {
                    bool makeRetrans = i is 5 or 10 or 15; // ровно 3 раза повторяем предыдущий seq
                    if (!makeRetrans)
                    {
                        seq += 100;
                    }

                    var p = BuildIpv4TcpPacket(
                        srcIp: localIp,
                        dstIp: remoteIp,
                        srcPort: 55558,
                        dstPort: 443,
                        ttl: 64,
                        ipId: (ushort)(7000 + i),
                        seq: seq,
                        tcpFlags: 0x18); // PSH+ACK

                    FeedPacket(filter, p, isOutbound: true);
                }

                var (retrans, total) = tracker.GetStatsForIp(remoteIp);
                if (total < 20)
                {
                    return new SmokeTestResult("INSP-004", "TCP ретрансмиссии: доля >10% даёт сигнал подозрения на Drop", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали total>=20, получили total={total}, retrans={retrans}");
                }

                if (!tracker.TryGetSuspiciousDrop(remoteIp, out var details))
                {
                    return new SmokeTestResult("INSP-004", "TCP ретрансмиссии: доля >10% даёт сигнал подозрения на Drop", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали TryGetSuspiciousDrop=true, но получили false. retrans={retrans}, total={total}");
                }

                return new SmokeTestResult("INSP-004", "TCP ретрансмиссии: доля >10% даёт сигнал подозрения на Drop", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {details}");
            }, ct);

        public static Task<SmokeTestResult> Insp_HttpRedirectDetector_BlockpageHost(CancellationToken ct)
            => RunAsync("INSP-005", "HTTP redirect: 302 + Location распознаётся и извлекается host", () =>
            {
                var filter = new TrafficMonitorFilter();
                var detector = new HttpRedirectDetector();
                detector.Attach(filter);

                var serverIp = IPAddress.Parse("203.0.113.80");
                var localIp = IPAddress.Parse("192.0.2.80");

                var http = "HTTP/1.1 302 Found\r\n" +
                           "Location: http://warning.rt.ru\r\n" +
                           "Content-Length: 0\r\n" +
                           "\r\n";

                var payload = Encoding.ASCII.GetBytes(http);

                var packet = BuildIpv4TcpPacket(
                    srcIp: serverIp,
                    dstIp: localIp,
                    srcPort: 80,
                    dstPort: 55559,
                    ttl: 64,
                    ipId: 9000,
                    seq: 50000,
                    tcpFlags: 0x18,
                    payload: payload);

                FeedPacket(filter, packet, isOutbound: false);

                if (!detector.TryGetRedirectHost(serverIp, out var host) || string.IsNullOrWhiteSpace(host))
                {
                    return new SmokeTestResult("INSP-005", "HTTP redirect: 302 + Location распознаётся и извлекается host", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали TryGetRedirectHost=true и непустой host");
                }

                if (!string.Equals(host, "warning.rt.ru", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("INSP-005", "HTTP redirect: 302 + Location распознаётся и извлекается host", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали host=warning.rt.ru, получили {host}");
                }

                return new SmokeTestResult("INSP-005", "HTTP redirect: 302 + Location распознаётся и извлекается host", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: host={host}");
            }, ct);
    }
}
