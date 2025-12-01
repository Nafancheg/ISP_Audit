// Модели для отчётов — перенесено из Output/ReportWriter.cs
// Содержит RunReport, Summary, TargetReport и вспомогательные классы

using System;
using System.Collections.Generic;
using IspAudit.Tests;

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Полный отчёт о запуске тестов
    /// </summary>
    public class RunReport
    {
        public DateTime run_at { get; set; }
        public string cli { get; set; } = string.Empty;
        public string ext_ip { get; set; } = string.Empty;
        public Summary summary { get; set; } = new Summary();
        public Dictionary<string, TargetReport> targets { get; set; } = new();
        public List<UdpProbeResult> udp_tests { get; set; } = new();
        public RstHeuristicResult? rst_heuristic { get; set; }
        public FirewallTestResult? firewall { get; set; }
        public IspTestResult? isp { get; set; }
        public RouterTestResult? router { get; set; }
        public SoftwareTestResult? software { get; set; }
    }

    /// <summary>
    /// Сводка результатов тестов
    /// </summary>
    public class Summary
    {
        public string dns { get; set; } = "UNKNOWN";
        public string tcp { get; set; } = "UNKNOWN";
        public string tcp_portal { get; set; } = "UNKNOWN"; // Порты 80/443 для RSI Portal
        public string tcp_launcher { get; set; } = "UNKNOWN"; // Порты 8000-8020 для Launcher
        public string udp { get; set; } = "UNKNOWN";
        public string tls { get; set; } = "UNKNOWN";
        public string rst_inject { get; set; } = "UNKNOWN";
        public string playable { get; set; } = "UNKNOWN";
        public string firewall { get; set; } = "UNKNOWN";
        public string isp_blocking { get; set; } = "UNKNOWN";
        public string router_issues { get; set; } = "UNKNOWN";
        public string software_conflicts { get; set; } = "UNKNOWN";
    }

    /// <summary>
    /// Отчёт по конкретной цели (хосту)
    /// </summary>
    public class TargetReport
    {
        public string host { get; set; } = string.Empty;
        public string display_name { get; set; } = string.Empty;
        public string service { get; set; } = string.Empty;
        public List<string> system_dns { get; set; } = new();
        public List<string> doh { get; set; } = new();
        public string dns_status { get; set; } = "UNKNOWN";
        public List<TcpResult> tcp { get; set; } = new();
        public List<HttpResult> http { get; set; } = new();
        public TraceResult? traceroute { get; set; }
        public bool dns_enabled { get; set; } = true;
        public bool tcp_enabled { get; set; } = true;
        public bool http_enabled { get; set; } = true;
        public bool trace_enabled { get; set; } = true;
        public List<int> tcp_ports_checked { get; set; } = new();
        public string? bypass_strategy { get; set; } // Стратегия, использованная для исправления
    }
}
