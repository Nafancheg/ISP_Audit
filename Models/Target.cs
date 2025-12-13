namespace IspAudit.Models
{
    public class Target
    {
        public string Name { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public bool Critical { get; set; }
        public string FallbackIp { get; set; } = string.Empty;

        // Доп.варианты имени хоста для отображения в UI
        public string SniHost { get; set; } = string.Empty;
        public string ReverseDnsHost { get; set; } = string.Empty;
    }
}
