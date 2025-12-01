using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using IspAudit.Core.Models;

namespace IspAudit.Tests
{
    /// <summary>
    /// Проверяет Windows Firewall, блокирующие правила и Windows Defender.
    /// Требует админ права для полной диагностики.
    /// </summary>
    public class FirewallTest
    {
        private static readonly int[] CommonGamePorts = { 80, 443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019, 8020 };
        private static readonly string[] CommonGamePaths = {
            "Game",
            "Launcher",
            "Client"
        };

        public async Task<FirewallTestResult> RunAsync()
        {
            try
            {
                bool firewallEnabled = !OperatingSystem.IsWindows() ? false : await CheckFirewallEnabledAsync().ConfigureAwait(false);
                List<string> blockedPorts = !OperatingSystem.IsWindows() ? new List<string>() : await GetBlockedPortsAsync().ConfigureAwait(false);
                bool defenderActive = !OperatingSystem.IsWindows() ? false : await CheckDefenderActiveAsync().ConfigureAwait(false);
                List<string> blockingRules = !OperatingSystem.IsWindows() ? new List<string>() : await GetBlockingRulesAsync().ConfigureAwait(false);

                string status = DetermineStatus(firewallEnabled, blockedPorts, defenderActive, blockingRules);

                return new FirewallTestResult(
                    WindowsFirewallEnabled: firewallEnabled,
                    BlockedPorts: blockedPorts,
                    WindowsDefenderActive: defenderActive,
                    BlockingRules: blockingRules,
                    Status: status
                );
            }
            catch (UnauthorizedAccessException)
            {
                // Нет админ прав
                return new FirewallTestResult(
                    WindowsFirewallEnabled: false,
                    BlockedPorts: new List<string>(),
                    WindowsDefenderActive: false,
                    BlockingRules: new List<string>(),
                    Status: "UNKNOWN"
                );
            }
            catch (Exception)
            {
                // Общая ошибка (WMI недоступен, COM ошибка и т.д.)
                return new FirewallTestResult(
                    WindowsFirewallEnabled: false,
                    BlockedPorts: new List<string>(),
                    WindowsDefenderActive: false,
                    BlockingRules: new List<string>(),
                    Status: "UNKNOWN"
                );
            }
        }

        /// <summary>
        /// Проверяет включен ли Windows Firewall через WMI.
        /// Fallback на netsh advfirewall.
        /// </summary>
        [SupportedOSPlatform("windows")]
        private async Task<bool> CheckFirewallEnabledAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Попытка через WMI
                    using var searcher = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT * FROM MSFT_NetFirewallProfile");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        // Проверяем Domain, Public и Private профили
                        bool enabled = Convert.ToBoolean(obj["Enabled"]);
                        if (enabled)
                        {
                            return true;
                        }
                    }
                    return false;
                }
                catch
                {
                    // Fallback на netsh
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "netsh.exe",
                            Arguments = "advfirewall show allprofiles state",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using var proc = Process.Start(psi);
                        if (proc == null) return false;

                        string output = proc.StandardOutput.ReadToEnd();
                        proc.WaitForExit();

                        return output.Contains("State", StringComparison.OrdinalIgnoreCase) &&
                               output.Contains("ON", StringComparison.OrdinalIgnoreCase);
                    }
                    catch
                    {
                        return false;
                    }
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Получает список заблокированных портов для игровых портов.
        /// Проверяет правила через WMI MSFT_NetFirewallRule.
        /// </summary>
        [SupportedOSPlatform("windows")]
        private async Task<List<string>> GetBlockedPortsAsync()
        {
            return await Task.Run(() =>
            {
                var blocked = new List<string>();
                try
                {
                    using var searcher = new ManagementObjectSearcher(@"root\StandardCimv2",
                        "SELECT * FROM MSFT_NetFirewallRule WHERE Enabled = True AND Action = 2"); // Action = 2 = Block

                    foreach (ManagementObject rule in searcher.Get())
                    {
                        try
                        {
                            string? displayName = rule["DisplayName"]?.ToString();
                            string? localPorts = rule["LocalPort"]?.ToString();

                            if (string.IsNullOrEmpty(localPorts))
                                continue;

                            // Проверяем пересечение с игровыми портами
                            foreach (int port in CommonGamePorts)
                            {
                                if (PortMatchesRule(port, localPorts))
                                {
                                    blocked.Add($"{port} (Rule: {displayName ?? "Unknown"})");
                                }
                            }
                        }
                        catch
                        {
                            // Игнорируем ошибки парсинга отдельных правил
                        }
                    }
                }
                catch
                {
                    // WMI недоступен или нет прав
                }

                return blocked.Distinct().ToList();
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Проверяет активен ли Windows Defender.
        /// </summary>
        [SupportedOSPlatform("windows")]
        private async Task<bool> CheckDefenderActiveAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                        "SELECT * FROM MSFT_MpComputerStatus");

                    foreach (ManagementObject obj in searcher.Get())
                    {
                        bool? antivirusEnabled = obj["AntivirusEnabled"] as bool?;
                        bool? realtimeProtectionEnabled = obj["RealTimeProtectionEnabled"] as bool?;

                        return (antivirusEnabled ?? false) || (realtimeProtectionEnabled ?? false);
                    }

                    return false;
                }
                catch
                {
                    // WMI недоступен или Defender не установлен
                    return false;
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Получает список блокирующих правил для Star Citizen.
        /// Проверяет есть ли правила, которые блокируют SC процессы или порты.
        /// </summary>
        [SupportedOSPlatform("windows")]
        private async Task<List<string>> GetBlockingRulesAsync()
        {
            return await Task.Run(() =>
            {
                var blockingRules = new List<string>();
                try
                {
                    using var searcher = new ManagementObjectSearcher(@"root\StandardCimv2",
                        "SELECT * FROM MSFT_NetFirewallRule WHERE Enabled = True AND Action = 2"); // Action = 2 = Block

                    foreach (ManagementObject rule in searcher.Get())
                    {
                        try
                        {
                            string? displayName = rule["DisplayName"]?.ToString();
                            string? applicationName = rule["Program"]?.ToString();

                            if (string.IsNullOrEmpty(displayName))
                                continue;

                            // Проверяем упоминание игровых процессов в правиле
                            bool isGameRule = CommonGamePaths.Any(path =>
                                displayName.Contains(path, StringComparison.OrdinalIgnoreCase) ||
                                (applicationName != null && applicationName.Contains(path, StringComparison.OrdinalIgnoreCase))
                            );

                            if (isGameRule)
                            {
                                blockingRules.Add(displayName);
                            }
                        }
                        catch
                        {
                            // Игнорируем ошибки парсинга отдельных правил
                        }
                    }
                }
                catch
                {
                    // WMI недоступен или нет прав
                }

                return blockingRules.Distinct().ToList();
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Определяет статус на основе результатов проверки.
        /// </summary>
        private string DetermineStatus(bool firewallEnabled, List<string> blockedPorts, bool defenderActive, List<string> blockingRules)
        {
            // Критические порты 8000-8003 (launcher/patcher)
            var criticalPortsBlocked = blockedPorts.Any(p =>
                p.Contains("8000") || p.Contains("8001") || p.Contains("8002") || p.Contains("8003")
            );

            if (criticalPortsBlocked || blockingRules.Any())
            {
                return "BLOCKING";
            }

            if (blockedPorts.Any())
            {
                return "WARN";
            }

            if (firewallEnabled || defenderActive)
            {
                return "WARN";
            }

            return "OK";
        }

        /// <summary>
        /// Проверяет соответствие порта правилу firewall.
        /// Поддерживает форматы: "80", "80-90", "80,443,8000", "Any".
        /// </summary>
        private bool PortMatchesRule(int port, string rulePort)
        {
            if (rulePort.Equals("Any", StringComparison.OrdinalIgnoreCase))
                return true;

            // Диапазон (например "8000-8020")
            if (rulePort.Contains('-'))
            {
                var parts = rulePort.Split('-');
                if (parts.Length == 2 && int.TryParse(parts[0], out int start) && int.TryParse(parts[1], out int end))
                {
                    return port >= start && port <= end;
                }
            }

            // Список портов (например "80,443,8000")
            if (rulePort.Contains(','))
            {
                var ports = rulePort.Split(',');
                return ports.Any(p => int.TryParse(p.Trim(), out int rulePortNum) && rulePortNum == port);
            }

            // Одиночный порт
            if (int.TryParse(rulePort, out int singlePort))
            {
                return singlePort == port;
            }

            return false;
        }

        // ==================== UNIT TESTS ====================
        // Mock-friendly методы для тестирования
        
        #region Unit Tests Support
    
    /// <summary>
    /// Тестовый метод для проверки логики определения статуса
    /// </summary>
    public static string TestDetermineStatus(bool firewallEnabled, List<string> blockedPorts, 
                                            bool defenderActive, List<string> blockingRules)
    {
        var test = new FirewallTest();
        return test.DetermineStatus(firewallEnabled, blockedPorts, defenderActive, blockingRules);
    }
    
    /// <summary>
    /// Тестовый метод для проверки логики соответствия портов правилам
    /// </summary>
    public static bool TestPortMatchesRule(int port, string rulePort)
    {
        var test = new FirewallTest();
        return test.PortMatchesRule(port, rulePort);
    }
    
    #endregion
    
    #region Unit Tests
    
    /// <summary>
    /// Unit Test: Проверка детекции блокировки критических портов
    /// </summary>
    public static void UnitTest_DetermineStatus_CriticalPortsBlocked()
    {
        var blockedPorts = new List<string> { "8000 (Rule: Test)", "8001 (Rule: Test2)" };
        var blockingRules = new List<string>();
        
        string status = TestDetermineStatus(true, blockedPorts, false, blockingRules);
        
        Console.WriteLine($"[TEST] DetermineStatus_CriticalPortsBlocked: {(status == "BLOCKING" ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: BLOCKING, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка детекции блокирующих правил
    /// </summary>
    public static void UnitTest_DetermineStatus_BlockingRules()
    {
        var blockedPorts = new List<string>();
        var blockingRules = new List<string> { "Block Game Traffic" };
        
        string status = TestDetermineStatus(false, blockedPorts, false, blockingRules);
        
        Console.WriteLine($"[TEST] DetermineStatus_BlockingRules: {(status == "BLOCKING" ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: BLOCKING, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка детекции предупреждений (не критичные порты)
    /// </summary>
    public static void UnitTest_DetermineStatus_Warning()
    {
        var blockedPorts = new List<string> { "443 (Rule: Test)" };
        var blockingRules = new List<string>();
        
        string status = TestDetermineStatus(true, blockedPorts, true, blockingRules);
        
        Console.WriteLine($"[TEST] DetermineStatus_Warning: {(status == "WARN" ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: WARN, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка OK статуса
    /// </summary>
    public static void UnitTest_DetermineStatus_OK()
    {
        var blockedPorts = new List<string>();
        var blockingRules = new List<string>();
        
        string status = TestDetermineStatus(false, blockedPorts, false, blockingRules);
        
        Console.WriteLine($"[TEST] DetermineStatus_OK: {(status == "OK" ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: OK, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка соответствия одиночного порта
    /// </summary>
    public static void UnitTest_PortMatchesRule_SinglePort()
    {
        bool match1 = TestPortMatchesRule(80, "80");
        bool match2 = TestPortMatchesRule(80, "443");
        
        Console.WriteLine($"[TEST] PortMatchesRule_SinglePort: {(match1 && !match2 ? "PASS" : "FAIL")}");
        Console.WriteLine($"  80 matches '80': {match1}, 80 matches '443': {match2}");
    }
    
    /// <summary>
    /// Unit Test: Проверка соответствия диапазона портов
    /// </summary>
    public static void UnitTest_PortMatchesRule_Range()
    {
        bool match1 = TestPortMatchesRule(8005, "8000-8020");
        bool match2 = TestPortMatchesRule(7999, "8000-8020");
        bool match3 = TestPortMatchesRule(8021, "8000-8020");
        
        Console.WriteLine($"[TEST] PortMatchesRule_Range: {(match1 && !match2 && !match3 ? "PASS" : "FAIL")}");
        Console.WriteLine($"  8005 in 8000-8020: {match1}, 7999 in 8000-8020: {match2}, 8021 in 8000-8020: {match3}");
    }
    
    /// <summary>
    /// Unit Test: Проверка соответствия списка портов
    /// </summary>
    public static void UnitTest_PortMatchesRule_List()
    {
        bool match1 = TestPortMatchesRule(80, "80,443,8000");
        bool match2 = TestPortMatchesRule(443, "80,443,8000");
        bool match3 = TestPortMatchesRule(8080, "80,443,8000");
        
        Console.WriteLine($"[TEST] PortMatchesRule_List: {(match1 && match2 && !match3 ? "PASS" : "FAIL")}");
        Console.WriteLine($"  80 in list: {match1}, 443 in list: {match2}, 8080 in list: {match3}");
    }
    
    /// <summary>
    /// Unit Test: Проверка соответствия "Any"
    /// </summary>
    public static void UnitTest_PortMatchesRule_Any()
    {
        bool match1 = TestPortMatchesRule(80, "Any");
        bool match2 = TestPortMatchesRule(12345, "Any");
        
        Console.WriteLine($"[TEST] PortMatchesRule_Any: {(match1 && match2 ? "PASS" : "FAIL")}");
        Console.WriteLine($"  80 matches 'Any': {match1}, 12345 matches 'Any': {match2}");
    }
    
    /// <summary>
    /// Запускает все unit тесты FirewallTest
    /// </summary>
    public static void RunAllUnitTests()
    {
        Console.WriteLine("========== FirewallTest Unit Tests ==========");
        UnitTest_DetermineStatus_CriticalPortsBlocked();
        UnitTest_DetermineStatus_BlockingRules();
        UnitTest_DetermineStatus_Warning();
        UnitTest_DetermineStatus_OK();
        UnitTest_PortMatchesRule_SinglePort();
        UnitTest_PortMatchesRule_Range();
        UnitTest_PortMatchesRule_List();
        UnitTest_PortMatchesRule_Any();
        Console.WriteLine("=============================================");
    }
    
    #endregion
    }
}
