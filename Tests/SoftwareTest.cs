using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using IspAudit.Output;
using Microsoft.Win32;

namespace ISP_Audit.Tests;

public static class SoftwareTest
{
    private static readonly string[] AntivirusProcesses = {
        "avgui", "avguard", "avp", "mcshield", "nswscsvc", "sophossps", "tmccsf",
        "bdagent", "kavfs", "ekrn", "egui", "AvastUI", "MsMpEng", "NortonSecurity",
        "panda", "fsguiexe", "f-secure", "avgemc", "mbam", "wrsa", "ccsvchst"
    };

    private static readonly string[] AntivirusServices = {
        "WinDefend", "AvastSvc", "avgwd", "AVP", "McAfee", "Norton Security",
        "bdredline", "SophosHealth", "ekrn", "FSMA", "mbamservice", "ccSetMgr"
    };

    private static readonly string[] VpnClientProcesses = {
        "nordvpn", "protonvpn", "expressvpn", "windscribe", "surfshark",
        "vyprvpn", "privateinternetaccess", "pia-client", "mullvad-vpn",
        "cyberghost", "tunnelbear", "hotspotshield", "ipvanish", "openvpn-gui",
        "wireguard", "viscosity", "fortivpn", "sonicwall", "pulsesecure"
    };

    private static readonly string[] RsiDomains = {
        "robertsspaceindustries.com",
        "cloudimperiumgames.com",
        "cloudimperiumgames.cn",
        "turbulent.ca",
        "vivox.com"
    };

    /// <summary>
    /// Выполняет проверку программного обеспечения на конфликты
    /// </summary>
    public static async Task<SoftwareTestResult> RunAsync()
    {
        try
        {
            var antivirusDetected = await DetectAntivirusAsync();
            var vpnClientsDetected = await DetectVpnClientsAsync();
            var proxyEnabled = await CheckSystemProxyAsync();
            var (hostsFileIssues, hostsFileEntries) = await CheckHostsFileAsync();

            // Определяем статус
            string status = "OK";
            if (hostsFileIssues)
            {
                status = "BLOCKING"; // Hosts файл может реально блокировать доступ
            }
            else if (antivirusDetected.Count > 0 || vpnClientsDetected.Count > 0 || proxyEnabled)
            {
                status = "WARN"; // Потенциальные проблемы
            }

            return new SoftwareTestResult(
                AntivirusDetected: antivirusDetected,
                VpnClientsDetected: vpnClientsDetected,
                ProxyEnabled: proxyEnabled,
                HostsFileIssues: hostsFileIssues,
                HostsFileEntries: hostsFileEntries,
                Status: status
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SoftwareTest] Error: {ex.Message}");
            return new SoftwareTestResult(
                AntivirusDetected: new List<string>(),
                VpnClientsDetected: new List<string>(),
                ProxyEnabled: false,
                HostsFileIssues: false,
                HostsFileEntries: new List<string>(),
                Status: "UNKNOWN"
            );
        }
    }

    /// <summary>
    /// Детектирует установленные антивирусы по процессам и службам
    /// </summary>
    private static async Task<List<string>> DetectAntivirusAsync()
    {
        var detected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        await Task.Run(() =>
        {
            try
            {
                // Проверка запущенных процессов
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        string processName = process.ProcessName.ToLower();
                        foreach (var avProcess in AntivirusProcesses)
                        {
                            if (processName.Contains(avProcess.ToLower()))
                            {
                                detected.Add(GetAntivirusName(avProcess));
                                break;
                            }
                        }
                    }
                    catch
                    {
                        // Игнорируем процессы, к которым нет доступа
                    }
                }

                // Проверка служб Windows
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    try
                    {
                        foreach (var serviceName in AntivirusServices)
                        {
                            var process = new Process
                            {
                                StartInfo = new ProcessStartInfo
                                {
                                    FileName = "sc",
                                    Arguments = $"query \"{serviceName}\"",
                                    RedirectStandardOutput = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                }
                            };

                            process.Start();
                            string output = process.StandardOutput.ReadToEnd();
                            process.WaitForExit();

                            if (output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
                            {
                                detected.Add(GetAntivirusName(serviceName));
                            }
                        }
                    }
                    catch
                    {
                        // Игнорируем ошибки при проверке служб
                    }
                }
            }
            catch
            {
                // Общие ошибки игнорируем
            }
        });

        return detected.ToList();
    }

    /// <summary>
    /// Детектирует установленные VPN клиенты по процессам
    /// </summary>
    private static async Task<List<string>> DetectVpnClientsAsync()
    {
        var detected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        await Task.Run(() =>
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        string processName = process.ProcessName.ToLower();
                        foreach (var vpnProcess in VpnClientProcesses)
                        {
                            if (processName.Contains(vpnProcess.ToLower()))
                            {
                                detected.Add(GetVpnClientName(vpnProcess));
                                break;
                            }
                        }
                    }
                    catch
                    {
                        // Игнорируем процессы, к которым нет доступа
                    }
                }

                // Дополнительная проверка сетевых интерфейсов на VPN адаптеры
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in networkInterfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up)
                    {
                        string name = ni.Name.ToLower();
                        string description = ni.Description.ToLower();
                        
                        if (name.Contains("vpn") || description.Contains("vpn") ||
                            name.Contains("tap") || description.Contains("tap") ||
                            name.Contains("tun") || description.Contains("tun") ||
                            name.Contains("wireguard") || description.Contains("wireguard"))
                        {
                            detected.Add($"VPN Adapter ({ni.Name})");
                        }
                    }
                }
            }
            catch
            {
                // Игнорируем общие ошибки
            }
        });

        return detected.ToList();
    }

    /// <summary>
    /// Проверяет системный прокси через реестр Windows
    /// </summary>
    private static async Task<bool> CheckSystemProxyAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return false;
                }

                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    false
                );

                if (key == null)
                {
                    return false;
                }

                var proxyEnable = key.GetValue("ProxyEnable");
                if (proxyEnable is int enableValue && enableValue == 1)
                {
                    var proxyServer = key.GetValue("ProxyServer");
                    if (proxyServer != null && !string.IsNullOrWhiteSpace(proxyServer.ToString()))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        });
    }

    /// <summary>
    /// Проверяет hosts файл на записи для RSI доменов
    /// </summary>
    private static async Task<(bool hasIssues, List<string> entries)> CheckHostsFileAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                string hostsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    @"drivers\etc\hosts"
                );

                if (!File.Exists(hostsPath))
                {
                    return (false, new List<string>());
                }

                var problematicEntries = new List<string>();
                var lines = File.ReadAllLines(hostsPath);

                foreach (var line in lines)
                {
                    string trimmedLine = line.Trim();
                    
                    // Пропускаем комментарии и пустые строки
                    if (string.IsNullOrWhiteSpace(trimmedLine) || trimmedLine.StartsWith("#"))
                    {
                        continue;
                    }

                    // Проверяем наличие RSI доменов
                    foreach (var domain in RsiDomains)
                    {
                        if (trimmedLine.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            problematicEntries.Add(trimmedLine);
                            break;
                        }
                    }
                }

                bool hasIssues = problematicEntries.Count > 0;
                return (hasIssues, problematicEntries);
            }
            catch (UnauthorizedAccessException)
            {
                // Нет доступа к hosts файлу - возвращаем как нет проблем
                return (false, new List<string>());
            }
            catch
            {
                return (false, new List<string>());
            }
        });
    }

    /// <summary>
    /// Получает читаемое имя антивируса по процессу/службе
    /// </summary>
    private static string GetAntivirusName(string processOrService)
    {
        string lower = processOrService.ToLower();
        
        if (lower.Contains("avg")) return "AVG Antivirus";
        if (lower.Contains("avast")) return "Avast Antivirus";
        if (lower.Contains("avp") || lower.Contains("kaspersky")) return "Kaspersky";
        if (lower.Contains("mcafee") || lower.Contains("mcshield")) return "McAfee";
        if (lower.Contains("norton")) return "Norton Security";
        if (lower.Contains("bitdefender") || lower.Contains("bdagent")) return "Bitdefender";
        if (lower.Contains("sophos")) return "Sophos";
        if (lower.Contains("eset") || lower.Contains("ekrn")) return "ESET";
        if (lower.Contains("fsecure") || lower.Contains("fsma")) return "F-Secure";
        if (lower.Contains("panda")) return "Panda Security";
        if (lower.Contains("trend") || lower.Contains("tmccsf")) return "Trend Micro";
        if (lower.Contains("defender") || lower.Contains("msmpe")) return "Windows Defender";
        if (lower.Contains("malwarebytes") || lower.Contains("mbam")) return "Malwarebytes";
        if (lower.Contains("webroot")) return "Webroot";
        if (lower.Contains("comodo") || lower.Contains("ccsvchst")) return "Comodo";
        
        return processOrService;
    }

    /// <summary>
    /// Получает читаемое имя VPN клиента по процессу
    /// </summary>
    private static string GetVpnClientName(string process)
    {
        string lower = process.ToLower();
        
        if (lower.Contains("nordvpn")) return "NordVPN";
        if (lower.Contains("protonvpn")) return "ProtonVPN";
        if (lower.Contains("expressvpn")) return "ExpressVPN";
        if (lower.Contains("windscribe")) return "Windscribe";
        if (lower.Contains("surfshark")) return "Surfshark";
        if (lower.Contains("vyprvpn")) return "VyprVPN";
        if (lower.Contains("pia") || lower.Contains("privateinternetaccess")) return "Private Internet Access";
        if (lower.Contains("mullvad")) return "Mullvad VPN";
        if (lower.Contains("cyberghost")) return "CyberGhost";
        if (lower.Contains("tunnelbear")) return "TunnelBear";
        if (lower.Contains("hotspot")) return "Hotspot Shield";
        if (lower.Contains("ipvanish")) return "IPVanish";
        if (lower.Contains("openvpn")) return "OpenVPN";
        if (lower.Contains("wireguard")) return "WireGuard";
        if (lower.Contains("viscosity")) return "Viscosity";
        if (lower.Contains("fortivpn")) return "FortiClient VPN";
        if (lower.Contains("sonicwall")) return "SonicWall VPN";
        if (lower.Contains("pulse")) return "Pulse Secure";
        
        return process;
    }

    // ==================== UNIT TESTS ====================
    
    #region Unit Tests Support
    
    /// <summary>
    /// Тестовый метод для проверки GetAntivirusName
    /// </summary>
    public static string TestGetAntivirusName(string processOrService)
    {
        return GetAntivirusName(processOrService);
    }
    
    /// <summary>
    /// Тестовый метод для проверки GetVpnClientName
    /// </summary>
    public static string TestGetVpnClientName(string process)
    {
        return GetVpnClientName(process);
    }
    
    #endregion
    
    #region Unit Tests
    
    /// <summary>
    /// Unit Test: Проверка распознавания имен антивирусов
    /// </summary>
    public static void UnitTest_GetAntivirusName()
    {
        string test1 = TestGetAntivirusName("avgui.exe");
        string test2 = TestGetAntivirusName("AvastUI");
        string test3 = TestGetAntivirusName("MsMpEng");
        string test4 = TestGetAntivirusName("avp.exe");
        string test5 = TestGetAntivirusName("mcshield");
        
        bool passed = test1.Contains("AVG") && 
                     test2.Contains("Avast") && 
                     test3.Contains("Defender") &&
                     test4.Contains("Kaspersky") &&
                     test5.Contains("McAfee");
        
        Console.WriteLine($"[TEST] GetAntivirusName: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  avgui.exe -> {test1}");
        Console.WriteLine($"  AvastUI -> {test2}");
        Console.WriteLine($"  MsMpEng -> {test3}");
        Console.WriteLine($"  avp.exe -> {test4}");
        Console.WriteLine($"  mcshield -> {test5}");
    }
    
    /// <summary>
    /// Unit Test: Проверка распознавания имен VPN клиентов
    /// </summary>
    public static void UnitTest_GetVpnClientName()
    {
        string test1 = TestGetVpnClientName("nordvpn.exe");
        string test2 = TestGetVpnClientName("protonvpn-app");
        string test3 = TestGetVpnClientName("expressvpn");
        string test4 = TestGetVpnClientName("openvpn-gui");
        string test5 = TestGetVpnClientName("wireguard.exe");
        
        bool passed = test1.Contains("NordVPN") && 
                     test2.Contains("ProtonVPN") && 
                     test3.Contains("ExpressVPN") &&
                     test4.Contains("OpenVPN") &&
                     test5.Contains("WireGuard");
        
        Console.WriteLine($"[TEST] GetVpnClientName: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  nordvpn.exe -> {test1}");
        Console.WriteLine($"  protonvpn-app -> {test2}");
        Console.WriteLine($"  expressvpn -> {test3}");
        Console.WriteLine($"  openvpn-gui -> {test4}");
        Console.WriteLine($"  wireguard.exe -> {test5}");
    }
    
    /// <summary>
    /// Unit Test: Проверка детекции неизвестных антивирусов
    /// </summary>
    public static void UnitTest_GetAntivirusName_Unknown()
    {
        string test1 = TestGetAntivirusName("unknown_antivirus");
        string test2 = TestGetAntivirusName("my_custom_av.exe");
        
        bool passed = test1 == "unknown_antivirus" && test2 == "my_custom_av.exe";
        
        Console.WriteLine($"[TEST] GetAntivirusName_Unknown: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  unknown_antivirus -> {test1}");
        Console.WriteLine($"  my_custom_av.exe -> {test2}");
    }
    
    /// <summary>
    /// Unit Test: Проверка детекции неизвестных VPN клиентов
    /// </summary>
    public static void UnitTest_GetVpnClientName_Unknown()
    {
        string test1 = TestGetVpnClientName("unknown_vpn");
        string test2 = TestGetVpnClientName("my_custom_vpn.exe");
        
        bool passed = test1 == "unknown_vpn" && test2 == "my_custom_vpn.exe";
        
        Console.WriteLine($"[TEST] GetVpnClientName_Unknown: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  unknown_vpn -> {test1}");
        Console.WriteLine($"  my_custom_vpn.exe -> {test2}");
    }
    
    /// <summary>
    /// Unit Test: Проверка case-insensitive распознавания
    /// </summary>
    public static void UnitTest_GetNames_CaseInsensitive()
    {
        string test1 = TestGetAntivirusName("AVGUI");
        string test2 = TestGetAntivirusName("AvAsT");
        string test3 = TestGetVpnClientName("NORDVPN");
        string test4 = TestGetVpnClientName("ProtonVPN");
        
        bool passed = test1.Contains("AVG") && 
                     test2.Contains("Avast") && 
                     test3.Contains("NordVPN") &&
                     test4.Contains("ProtonVPN");
        
        Console.WriteLine($"[TEST] GetNames_CaseInsensitive: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  AVGUI -> {test1}");
        Console.WriteLine($"  AvAsT -> {test2}");
        Console.WriteLine($"  NORDVPN -> {test3}");
        Console.WriteLine($"  ProtonVPN -> {test4}");
    }
    
    /// <summary>
    /// Unit Test: Проверка множественных антивирусов
    /// </summary>
    public static void UnitTest_MultipleAntivirusDetection()
    {
        var detected = new List<string>
        {
            TestGetAntivirusName("avgui"),
            TestGetAntivirusName("MsMpEng"),
            TestGetAntivirusName("AvastUI")
        };
        
        bool passed = detected.Any(a => a.Contains("AVG")) &&
                     detected.Any(a => a.Contains("Defender")) &&
                     detected.Any(a => a.Contains("Avast"));
        
        Console.WriteLine($"[TEST] MultipleAntivirusDetection: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Detected: {string.Join(", ", detected)}");
    }
    
    /// <summary>
    /// Запускает все unit тесты SoftwareTest
    /// </summary>
    public static void RunAllUnitTests()
    {
        Console.WriteLine("========== SoftwareTest Unit Tests ==========");
        UnitTest_GetAntivirusName();
        UnitTest_GetVpnClientName();
        UnitTest_GetAntivirusName_Unknown();
        UnitTest_GetVpnClientName_Unknown();
        UnitTest_GetNames_CaseInsensitive();
        UnitTest_MultipleAntivirusDetection();
        Console.WriteLine("============================================");
    }
    
    #endregion
}
