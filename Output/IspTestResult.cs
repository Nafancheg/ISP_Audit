namespace IspAudit.Output;

public record IspTestResult(
    string? Isp,
    string? Country,
    string? City,
    bool CgnatDetected,
    bool DpiDetected,
    bool DnsFiltered,
    List<string> KnownProblematicISPs,
    string Status
);
