using System;
using System.Net;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;

namespace IspAudit.Core.Modules
{
    public class StandardBlockageClassifier : IBlockageClassifier
    {
        public HostBlocked ClassifyBlockage(HostTested tested)
        {
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
            // Приоритет: DNS -> TCP -> TLS
            else if (tested.DnsStatus == "DNS_FILTERED" || tested.DnsStatus == "DNS_BOGUS")
            {
                strategy = "DOH";
                action = $"DNS блокировка: использовать DoH для {tested.Hostname ?? tested.Host.RemoteIp.ToString()}";
            }
            else if (tested.BlockageType == "TCP_RST")
            {
                strategy = "DROP_RST";
                action = $"TCP RST injection: блокировать RST пакеты для {tested.Host.RemoteIp}:{tested.Host.RemotePort}";
            }
            else if (tested.BlockageType == "TLS_DPI")
            {
                strategy = "TLS_FRAGMENT";
                action = $"DPI блокировка TLS: фрагментация ClientHello для {tested.Hostname ?? tested.Host.RemoteIp.ToString()}";
            }
            else if (tested.BlockageType == "TLS_TIMEOUT" && tested.TcpOk)
            {
                // TCP работает, но TLS таймаут - вероятно DPI
                strategy = "TLS_FRAGMENT";
                action = $"TLS таймаут (возможно DPI): фрагментация для {tested.Hostname ?? tested.Host.RemoteIp.ToString()}";
            }
            else if (tested.BlockageType == "TCP_TIMEOUT")
            {
                // TCP таймаут - может быть firewall или route block
                strategy = "PROXY";
                action = $"TCP таймаут: возможна блокировка на уровне маршрутизации для {tested.Host.RemoteIp}:{tested.Host.RemotePort}";
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
                // Неопределенная проблема
                strategy = "UNKNOWN";
                action = $"Неизвестная проблема с {tested.Host.RemoteIp}:{tested.Host.RemotePort}";
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