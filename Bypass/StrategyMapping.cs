using System.Collections.Generic;
using System.Linq;
using IspAudit.Core.Models;

namespace IspAudit.Bypass
{
    public class StrategyRecommendation
    {
        // Use HashSet internally to prevent duplicates while maintaining insertion order (mostly)
        // Actually HashSet doesn't guarantee order, but we want priority.
        // So let's use List and check Contains before adding.
        private readonly List<string> _applicable = new();
        private readonly List<string> _manual = new();

        public List<string> Applicable => _applicable;
        public List<string> Manual => _manual;
        
        public void AddApplicable(string strategy)
        {
            if (!_applicable.Contains(strategy)) _applicable.Add(strategy);
        }

        public void AddManual(string strategy)
        {
            if (!_manual.Contains(strategy)) _manual.Add(strategy);
        }

        public List<string> GetAll() => _applicable.Concat(_manual).Distinct().ToList();
    }

    public static class StrategyMapping
    {

        public static StrategyRecommendation GetStrategiesFor(HostTested result)
        {
            var rec = new StrategyRecommendation();

            // 0. Analyze DNS issues
            if (result.DnsStatus == "DNS_FILTERED" || result.DnsStatus == "DNS_BOGUS")
            {
                rec.AddManual("DOH");
            }

            // 1. Analyze TLS/HTTP issues (TCP OK, but TLS Failed)
            if (result.TcpOk && !result.TlsOk)
            {
                bool isTimeout =
                    result.BlockageType == "TLS_HANDSHAKE_TIMEOUT" ||
                    result.BlockageType == "TLS_TIMEOUT" ||
                    result.BlockageType == "HTTP_TIMEOUT";

                if (!isTimeout)
                {
                    // Prioritize DROP_RST as it's faster and often sufficient for RST injection on TLS ClientHello
                    rec.AddApplicable("DROP_RST");
                }

                AddTlsStrategies(rec);

                if (isTimeout)
                {
                    // For timeouts, DROP_RST is unlikely to help, but we can add it as a fallback
                    rec.AddApplicable("DROP_RST");
                }
            }

            // 2. Analyze TCP issues (TCP Failed)
            if (!result.TcpOk)
            {
                long elapsed = result.TcpLatencyMs ?? 0;
                AnalyzeTcpFailure(rec, elapsed, result.BlockageType);
            }

            // 3. Analyze HTTP Redirect DPI
            if (result.BlockageType == "HTTP_REDIRECT_DPI")
            {
                // Для HTTP редиректов (заглушек) часто помогает отправка фейкового запроса
                // или фрагментация, чтобы DPI не распознал Host.
                rec.AddApplicable("SAFE_MODE");
                rec.AddApplicable("TTL_TRICK");
                rec.AddApplicable("TLS_FAKE");
                rec.AddApplicable("TLS_DISORDER");
            }

            // 4. Analyze UDP issues
            if (result.BlockageType == "UDP_BLOCKAGE")
            {
                // Если порт 443, это чаще всего QUIC/HTTP3.
                // В этом случае браузер обычно откатывается на TCP/HTTPS и сайт продолжает работать.
                // TLS-трюки (особенно TLS_FAKE) могут ухудшить ситуацию, поэтому здесь их НЕ рекомендуем.
                // Оставляем только ручные рекомендации.
                rec.AddManual("Отключить QUIC/HTTP3 в браузере");
                rec.AddManual("VPN");
            }

            return rec;
        }

        private static void AddTlsStrategies(StrategyRecommendation rec)
        {
            // Более безопасный порядок:
            // 1) TLS_DISORDER / TLS_FRAGMENT — обычно меньше ломают сайты
            // 2) TLS_FAKE / TLS_FAKE_FRAGMENT — более агрессивны и могут ухудшать совместимость
            rec.AddApplicable("TLS_DISORDER");
            rec.AddApplicable("TLS_FRAGMENT");
            rec.AddApplicable("TLS_FAKE_FRAGMENT");
            rec.AddApplicable("TLS_FAKE");
        }

        private static void AnalyzeTcpFailure(StrategyRecommendation rec, long minElapsed, string? blockageType)
        {
            if (blockageType == "PORT_CLOSED") return;

            // TCP_CONNECT_TIMEOUT_CONFIRMED - это усиленный TCP_CONNECT_TIMEOUT (много фейлов подряд).
            // Стратегии те же, что и для обычного таймаута.
            bool isTimeout =
                blockageType == "TCP_CONNECT_TIMEOUT" ||
                blockageType == "TCP_CONNECT_TIMEOUT_CONFIRMED" ||
                blockageType == "TCP_TIMEOUT" ||
                blockageType == "TCP_TIMEOUT_CONFIRMED" ||
                minElapsed > 2000;
            
            // TCP_RST_INJECTION - это усиленный TCP_RST (обнаружен аномальный TTL).
            // Стратегии те же, что и для обычного RST.
            bool isRst =
                blockageType == "TCP_CONNECTION_RESET" ||
                blockageType == "TCP_RST" ||
                blockageType == "TCP_RST_INJECTION" ||
                minElapsed < 200;

            if (isRst)
            {
                if (blockageType == "TCP_RST_INJECTION")
                {
                    rec.AddApplicable("SAFE_MODE");
                }
                rec.AddApplicable("DROP_RST");
            }
            else if (isTimeout)
            {
                rec.AddManual("PROXY");
            }
            else
            {
                // Intermediate timing or unknown -> Try DROP_RST just in case
                rec.AddApplicable("DROP_RST");
            }

            // Fallback: sometimes TCP "fails" but it's actually TLS-level block (DPI drops packet)
            // Add TLS strategies with lower priority
            AddTlsStrategies(rec);
        }
    }
}
