namespace ISPAudit.Models
{
    public class Target
    {
        public string Name { get; set; }
        public string Host { get; set; }
        public string Service { get; set; }
        public bool Critical { get; set; }
        public string FallbackIp { get; set; }
    }
}
