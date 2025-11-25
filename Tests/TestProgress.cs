using System;

namespace IspAudit.Tests
{
    public enum TestKind { DNS, TCP, HTTP, TRACEROUTE, UDP, RST, FIREWALL, ISP, ROUTER, SOFTWARE, INFO }

    public record TestProgress(TestKind Kind, string Status, bool? Success = null, string? Message = null);
}

