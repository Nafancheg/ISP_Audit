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
        public bool Critical { get; init; } = false;
        public string? FallbackIp { get; init; } = null;
        public List<int>? Ports { get; init; } = null; // Реальные порты из снифа (только для захваченных профилей)
        public List<string>? Protocols { get; init; } = null; // Протоколы: TCP, UDP (только для захваченных профилей)

        public TargetDefinition Copy() => this with { Ports = Ports?.ToList(), Protocols = Protocols?.ToList() };
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

        public UdpProbeDefinition Copy() => this with { };
    }

    public class DiagnosticProfile
    {
        public string Name { get; set; } = string.Empty;
        public string TestMode { get; set; } = string.Empty;
        public string ExePath { get; set; } = string.Empty;
        public List<TargetDefinition> Targets { get; set; } = new();
    }
}
