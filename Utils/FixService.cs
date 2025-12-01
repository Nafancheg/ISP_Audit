using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace ISPAudit.Utils
{
    /// <summary>
    /// Сервис для применения системных исправлений DNS
    /// Требует admin прав для DNS изменений
    /// </summary>
    public static class FixService
    {
        #region DNS Fix (Cloudflare + DoH)

        /// <summary>
        /// Применить DNS fix: установить Cloudflare 1.1.1.1 + DoH encryption
        /// </summary>
        public static async Task<(bool success, string error)> ApplyDnsFixAsync()
        {
            try
            {
                // 1. Найти активный сетевой адаптер
                var adapter = GetActiveNetworkInterface();
                if (adapter == null)
                    return (false, "Не найден активный сетевой адаптер");

                // 2. Установить Cloudflare DNS
                var cloudflareServers = new[] { "1.1.1.1", "1.0.0.1" };
                var setDnsSuccess = await SetDnsServersAsync(adapter.Name, cloudflareServers);
                if (!setDnsSuccess)
                    return (false, "Не удалось установить DNS серверы");

                // 3. Включить DoH encryption для Cloudflare
                var dohSuccess = await EnableDoHAsync("1.1.1.1", "https://cloudflare-dns.com/dns-query");
                if (!dohSuccess)
                {
                    // DoH не удалось, но DNS уже установлен — продолжаем
                    Log("[FixService] DoH не удалось, но DNS Cloudflare установлен");
                }

                // 4. Очистить DNS кэш
                await RunCommandAsync("ipconfig", "/flushdns");

                return (true, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, $"Ошибка применения DNS fix: {ex.Message}");
            }
        }

        #endregion

        #region Helpers

        private static void Log(string message)
        {
            System.Diagnostics.Debug.WriteLine($"[FixService] {message}");
        }

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
        /// Включить DoH (DNS-over-HTTPS) для указанного DNS сервера
        /// </summary>
        private static async Task<bool> EnableDoHAsync(string dnsIp, string dohTemplate)
        {
            var (success, _) = await RunCommandAsync("netsh", $"dns add encryption server={dnsIp} dohtemplate={dohTemplate} autoupgrade=yes udpfallback=no");
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
                    CreateNoWindow = true
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
