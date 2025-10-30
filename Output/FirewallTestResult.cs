namespace IspAudit.Output;

public record FirewallTestResult(
    bool WindowsFirewallEnabled,
    List<string> BlockedPorts,
    bool WindowsDefenderActive,
    List<string> BlockingRules,
    string Status
);
