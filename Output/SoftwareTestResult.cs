namespace IspAudit.Output;

public record SoftwareTestResult(
    List<string> AntivirusDetected,
    List<string> VpnClientsDetected,
    bool ProxyEnabled,
    bool HostsFileIssues,
    List<string> HostsFileEntries,
    string Status
);
