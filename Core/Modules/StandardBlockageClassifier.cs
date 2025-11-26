using System;
using System.Net;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Bypass;

namespace IspAudit.Core.Modules
{
    public class StandardBlockageClassifier : IBlockageClassifier
    {
        public HostBlocked ClassifyBlockage(HostTested tested)
        {
            // Use StrategyMapping to get recommendations
            var rec = StrategyMapping.GetStrategiesFor(tested);
            
            string strategy;
            string action;
            
            // Проверка на Fake IP (198.18.0.0/15) или openwrt.lan
            if (IsFakeIp(tested.Host.RemoteIp) || 
                (tested.Hostname != null && tested.Hostname.Equals("openwrt.lan", StringComparison.OrdinalIgnoreCase)))
            {
                strategy = "ROUTER_REDIRECT";
                action = $"Обнаружен служебный адрес ({tested.Hostname ?? tested.Host.RemoteIp.ToString()}). Трафик маршрутизируется через VPN или локальный шлюз.";
                // Обновляем BlockageType в результате теста для UI
                tested = tested with { BlockageType = "FAKE_IP" };
            }
            else if (tested.BlockageType == "PORT_CLOSED")
            {
                // Порт закрыт - не блокировка, просто сервис недоступен
                strategy = "NONE";
                action = $"Порт {tested.Host.RemotePort} закрыт на {tested.Host.RemoteIp} (не блокировка)";
            }
            else if (tested.DnsOk && tested.TcpOk && tested.TlsOk)
            {
                // Все проверки прошли успешно
                strategy = "NONE";
                action = "OK";
            }
            else
            {
                // Use the first applicable strategy if available, otherwise the first manual one
                if (rec.Applicable.Count > 0)
                {
                    strategy = rec.Applicable[0];
                    action = $"Рекомендуемая стратегия: {strategy}";
                }
                else if (rec.Manual.Count > 0)
                {
                    strategy = rec.Manual[0];
                    action = $"Требуется ручное вмешательство: {strategy}";
                }
                else
                {
                    strategy = "UNKNOWN";
                    action = $"Неизвестная проблема с {tested.Host.RemoteIp}:{tested.Host.RemotePort}";
                }
            }
            
            return new HostBlocked(tested, strategy, action);
        }

        private bool IsFakeIp(IPAddress ip)
        {
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                // 198.18.0.0/15 => 198.18.0.0 - 198.19.255.255
                return bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19);
            }
            return false;
        }
    }
}