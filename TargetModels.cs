using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace IspAudit
{
    public record class TargetDefinition
    {
        public string Name { get; init; } = string.Empty;
        public string Host { get; init; } = string.Empty;
        public string Service { get; init; } = string.Empty;

        public TargetDefinition Clone() => this with { };
    }

    public enum UdpProbeKind
    {
        Raw,
        Dns
    }

    public record class UdpProbeDefinition
    {
        public string Name { get; init; } = string.Empty;
        public string Host { get; init; } = string.Empty;
        public int Port { get; init; }
        public string Service { get; init; } = string.Empty;
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public UdpProbeKind Kind { get; init; } = UdpProbeKind.Raw;
        public bool ExpectReply { get; init; } = false;
        public string? PayloadHex { get; init; }
        public string? Note { get; init; }

        public UdpProbeDefinition Clone() => this with { };
    }

    public class TargetCatalogData
    {
        public List<TargetDefinition> Targets { get; set; } = new();
        public List<int> TcpPorts { get; set; } = new();
        public List<UdpProbeDefinition> UdpProbes { get; set; } = new();
    }
}
