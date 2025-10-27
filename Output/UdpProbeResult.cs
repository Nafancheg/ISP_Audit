namespace IspAudit.Output
{
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
    }
}
