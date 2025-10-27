using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace IspAudit.Bypass
{
    public enum TransportProtocol
    {
        Tcp,
        Udp
    }

    public sealed class BypassRedirectRule
    {
        public string Name { get; init; } = string.Empty;
        public TransportProtocol Protocol { get; init; } = TransportProtocol.Tcp;
        public ushort Port { get; init; }
        public string RedirectIp { get; init; } = string.Empty;
        public ushort RedirectPort { get; init; }
        public bool Enabled { get; init; } = true;
        public IReadOnlyList<string> Hosts { get; init; } = Array.Empty<string>();

        public IPAddress GetRedirectAddress()
        {
            if (!IPAddress.TryParse(RedirectIp, out var address))
            {
                throw new InvalidOperationException($"Невалидный адрес переадресации '{RedirectIp}' для правила '{Name}'.");
            }

            return address;
        }

        public bool IsMatchHost(IPAddress destination)
        {
            if (Hosts.Count == 0) return true;

            foreach (var host in Hosts)
            {
                try
                {
                    var addresses = Dns.GetHostAddresses(host);
                    if (addresses.Any(a => a.Equals(destination)))
                    {
                        return true;
                    }
                }
                catch
                {
                    // игнорируем временные проблемы DNS
                }
            }

            return false;
        }
    }
}
