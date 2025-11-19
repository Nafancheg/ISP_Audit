using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using ISPAudit.Models;

namespace ISPAudit.Utils
{
    /// <summary>
    /// Сервис для применения и отката системных исправлений
    /// Требует admin прав для DNS/Firewall изменений
    /// </summary>
    public static class FixService
    {
        #region DNS Fix (Cloudflare + DoH)

        /// <summary>
        /// Применить DNS fix: установить Cloudflare 1.1.1.1 + DoH encryption
        /// Возвращает AppliedFix с оригинальными настройками для rollback
        /// </summary>
        public static async Task<(bool success, AppliedFix? fix, string error)> ApplyDnsFixAsync()
        {
            try
            {
                // 1. Найти активный сетевой адаптер
                var adapter = GetActiveNetworkInterface();
                if (adapter == null)
                    return (false, null, "Не найден активный сетевой адаптер");

                // 2. Сохранить текущие DNS настройки
                var originalDns = GetCurrentDnsServers(adapter.Name);
                var originalSettings = new Dictionary<string, string>
                {
                    ["adapter"] = adapter.Name,
                    ["dnsServers"] = string.Join(",", originalDns),
                    ["dohEnabled"] = "false" // Предполагаем DoH был выключен
                };

                // 3. Установить Cloudflare DNS
                var cloudflareServers = new[] { "1.1.1.1", "1.0.0.1" };
                var setDnsSuccess = await SetDnsServersAsync(adapter.Name, cloudflareServers);
                if (!setDnsSuccess)
                    return (false, null, "Не удалось установить DNS серверы");

                // 4. Включить DoH encryption для Cloudflare
                var dohSuccess = await EnableDoHAsync("1.1.1.1", "https://cloudflare-dns.com/dns-query");
                if (!dohSuccess)
                {
                    // Откатить DNS если DoH не удалось
                    await RestoreDnsServersAsync(adapter.Name, originalDns.ToArray());
                    return (false, null, "Не удалось включить DoH encryption");
                }

                // 5. Очистить DNS кэш
                await RunCommandAsync("ipconfig", "/flushdns");

                var fix = new AppliedFix
                {
                    Type = FixType.DnsChange,
                    Description = "DNS серверы (Cloudflare 1.1.1.1 + DoH)",
                    OriginalSettings = originalSettings
                };

                FixHistoryManager.Add(fix);
                return (true, fix, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, null, $"Ошибка применения DNS fix: {ex.Message}");
            }
        }

        /// <summary>
        /// Откатить DNS fix: восстановить оригинальные DNS серверы
        /// </summary>
        public static async Task<(bool success, string error)> RollbackDnsFixAsync(AppliedFix fix)
        {
            try
            {
                var adapter = fix.OriginalSettings["adapter"];
                var dnsServers = fix.OriginalSettings["dnsServers"].Split(',');

                // 1. Восстановить оригинальные DNS
                if (dnsServers.Length > 0 && !string.IsNullOrWhiteSpace(dnsServers[0]))
                {
                    await RestoreDnsServersAsync(adapter, dnsServers);
                }
                else
                {
                    // Если DNS пустой — восстановить DHCP
                    await RestoreDhcpDnsAsync(adapter);
                }

                // 2. Отключить DoH
                await DisableDoHAsync("1.1.1.1");

                // 3. Очистить DNS кэш
                await RunCommandAsync("ipconfig", "/flushdns");

                FixHistoryManager.Remove(fix.FixId);
                return (true, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, $"Ошибка отката DNS fix: {ex.Message}");
            }
        }

        #endregion

        #region Firewall Fix

        /// <summary>
        /// Применить Firewall fix: добавить правило для указанных портов
        /// </summary>
        public static async Task<(bool success, AppliedFix? fix, string error)> ApplyFirewallFixAsync(int[] ports, string ruleName)
        {
            try
            {
                var portsStr = string.Join(",", ports);
                var command = $"netsh advfirewall firewall add rule name=\"{ruleName}\" dir=in action=allow protocol=TCP localport={portsStr}";

                var (success, output) = await RunCommandAsync("powershell", $"-Command \"{command}\"");
                if (!success)
                    return (false, null, $"Не удалось создать firewall правило: {output}");

                var fix = new AppliedFix
                {
                    Type = FixType.FirewallRule,
                    Description = $"Firewall правило (порты {portsStr})",
                    OriginalSettings = new Dictionary<string, string>
                    {
                        ["ruleName"] = ruleName,
                        ["ports"] = portsStr
                    }
                };

                FixHistoryManager.Add(fix);
                return (true, fix, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, null, $"Ошибка применения Firewall fix: {ex.Message}");
            }
        }

        /// <summary>
        /// Откатить Firewall fix: удалить правило
        /// </summary>
        public static async Task<(bool success, string error)> RollbackFirewallFixAsync(AppliedFix fix)
        {
            try
            {
                var ruleName = fix.OriginalSettings["ruleName"];
                var command = $"netsh advfirewall firewall delete rule name=\"{ruleName}\"";

                var (success, output) = await RunCommandAsync("powershell", $"-Command \"{command}\"");
                if (!success)
                    return (false, $"Не удалось удалить firewall правило: {output}");

                FixHistoryManager.Remove(fix.FixId);
                return (true, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, $"Ошибка отката Firewall fix: {ex.Message}");
            }
        }

        #endregion

        #region Helpers

        /// <summary>
        /// Получить активный сетевой адаптер (не Loopback, не VPN, не Tunnel)
        /// </summary>
        private static NetworkInterface? GetActiveNetworkInterface()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
                .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .Where(ni => !ni.Name.Contains("VPN", StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();
        }

        /// <summary>
        /// Получить текущие DNS серверы для адаптера
        /// </summary>
        private static List<string> GetCurrentDnsServers(string adapterName)
        {
            try
            {
                var nic = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.Name == adapterName);

                if (nic == null) return new List<string>();

                var ipProps = nic.GetIPProperties();
                return ipProps.DnsAddresses
                    .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(ip => ip.ToString())
                    .ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        /// <summary>
        /// Установить DNS серверы через netsh
        /// </summary>
        private static async Task<bool> SetDnsServersAsync(string adapterName, string[] dnsServers)
        {
            try
            {
                // Установить primary DNS
                var (success1, _) = await RunCommandAsync("netsh", $"interface ipv4 set dns name=\"{adapterName}\" static {dnsServers[0]}");
                if (!success1) return false;

                // Установить secondary DNS если есть
                if (dnsServers.Length > 1)
                {
                    var (success2, _) = await RunCommandAsync("netsh", $"interface ipv4 add dns name=\"{adapterName}\" {dnsServers[1]} index=2");
                    if (!success2) return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Восстановить оригинальные DNS серверы
        /// </summary>
        private static async Task<bool> RestoreDnsServersAsync(string adapterName, string[] dnsServers)
        {
            return await SetDnsServersAsync(adapterName, dnsServers);
        }

        /// <summary>
        /// Восстановить DHCP DNS (автоматическое получение)
        /// </summary>
        private static async Task<bool> RestoreDhcpDnsAsync(string adapterName)
        {
            var (success, _) = await RunCommandAsync("netsh", $"interface ipv4 set dns name=\"{adapterName}\" dhcp");
            return success;
        }

        /// <summary>
        /// Включить DoH (DNS-over-HTTPS) для указанного DNS сервера
        /// </summary>
        private static async Task<bool> EnableDoHAsync(string dnsIp, string dohTemplate)
        {
            var (success, _) = await RunCommandAsync("netsh", $"dns add encryption server={dnsIp} dohtemplate={dohTemplate} autoupgrade=yes udpfallback=no");
            return success;
        }

        /// <summary>
        /// Отключить DoH для указанного DNS сервера
        /// </summary>
        private static async Task<bool> DisableDoHAsync(string dnsIp)
        {
            var (success, _) = await RunCommandAsync("netsh", $"dns delete encryption server={dnsIp}");
            return success;
        }

        /// <summary>
        /// Выполнить shell команду асинхронно
        /// </summary>
        private static async Task<(bool success, string output)> RunCommandAsync(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    Verb = "runas" // Требует UAC elevation
                };

                using var process = Process.Start(psi);
                if (process == null)
                    return (false, "Process failed to start");

                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                return (process.ExitCode == 0, string.IsNullOrEmpty(error) ? output : error);
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }

        #endregion
    }
}
