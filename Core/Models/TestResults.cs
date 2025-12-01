// Результаты тестов — перенесено из Output/
// Содержит модели результатов для FirewallTest, IspTest, RouterTest, SoftwareTest, UdpProbe

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Результат проверки Windows Firewall
    /// </summary>
    public record FirewallTestResult(
        bool WindowsFirewallEnabled,
        List<string> BlockedPorts,
        bool WindowsDefenderActive,
        List<string> BlockingRules,
        string Status
    );

    /// <summary>
    /// Результат проверки ISP (провайдера)
    /// </summary>
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

    /// <summary>
    /// Результат проверки роутера
    /// </summary>
    public record RouterTestResult(
        string? GatewayIp,
        bool UpnpEnabled,
        bool SipAlgDetected,
        double AvgPingMs,
        double MaxPingMs,
        int PacketLossPercent,
        string Status
    );

    /// <summary>
    /// Результат проверки программного обеспечения
    /// </summary>
    public record SoftwareTestResult(
        List<string> AntivirusDetected,
        List<string> VpnClientsDetected,
        bool ProxyEnabled,
        bool HostsFileIssues,
        List<string> HostsFileEntries,
        string Status
    );

    /// <summary>
    /// Результат UDP probe теста
    /// </summary>
    public class UdpProbeResult
    {
        public string name { get; set; } = string.Empty;
        public string host { get; set; } = string.Empty;
        public int port { get; set; }
        public string service { get; set; } = string.Empty;
        public bool expect_reply { get; set; }
        public bool success { get; set; }
        public bool reply { get; set; }
        public int? rtt_ms { get; set; }
        public int reply_bytes { get; set; }
        public string? note { get; set; }
        public string? description { get; set; }

        /// <summary>
        /// Уровень достоверности результата теста.
        /// "high" = expect_reply=true, определённый результат (DNS с ответом)
        /// "low" = expect_reply=false, нет подтверждения (raw probe без ответа)
        /// </summary>
        public string certainty { get; set; } = "high";
    }
}
