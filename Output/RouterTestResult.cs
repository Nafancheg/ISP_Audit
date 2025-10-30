namespace IspAudit.Output;

public record RouterTestResult(
    string? GatewayIp,
    bool UpnpEnabled,
    bool SipAlgDetected,
    double AvgPingMs,
    double MaxPingMs,
    int PacketLossPercent,
    string Status
);
