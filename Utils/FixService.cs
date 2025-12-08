using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading.Tasks;

namespace ISPAudit.Utils
{
    public record DnsPreset(string Name, string PrimaryIp, string PrimaryDoH, string SecondaryIp, string SecondaryDoH);

    /// <summary>
    /// Сервис для применения системных исправлений DNS
    /// Требует admin прав для DNS изменений
    /// </summary>
    public static class FixService
    {
        public static readonly List<DnsPreset> AvailablePresets = new()
        {
            new("Cloudflare", "1.1.1.1", "https://cloudflare-dns.com/dns-query", "1.0.0.1", "https://cloudflare-dns.com/dns-query"),
            new("Google", "8.8.8.8", "https://dns.google/dns-query", "8.8.4.4", "https://dns.google/dns-query"),
            new("Yandex", "77.88.8.8", "https://dns.yandex.ru/dns-query", "77.88.8.1", "https://dns.yandex.ru/dns-query"),
            new("Hybrid (CF + Yandex)", "1.1.1.1", "https://cloudflare-dns.com/dns-query", "77.88.8.8", "https://dns.yandex.ru/dns-query")
        };

        private const string BackupFileName = "dns_backup.json";
        
        /// <summary>
        /// Существует ли файл бэкапа (значит DoH скорее всего включен)
        /// </summary>
        public static bool HasBackupFile => File.Exists(BackupFileName);

        private static string? _originalDnsConfig = null; // "DHCP" or "Static IP1,IP2"
        private static string? _originalAdapterName = null;

        private class DnsBackupState
        {
            public string AdapterName { get; set; } = "";
            public string Config { get; set; } = "";
            public DateTime Timestamp { get; set; }
        }

        /// <summary>
        /// Определить, активен ли один из пресетов DNS
        /// </summary>
        public static string? DetectActivePreset()
        {
            try
            {
                var adapter = GetActiveNetworkInterface();
                if (adapter == null) return null;

                var props = adapter.GetIPProperties();
                var dns = props.DnsAddresses
                    .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(ip => ip.ToString())
                    .ToList();

                if (dns.Count == 0) return null;

                foreach (var preset in AvailablePresets)
                {
                    // Проверяем совпадение Primary. Secondary проверяем, только если он есть в пресете и в системе.
                    bool primaryMatch = dns[0] == preset.PrimaryIp;
                    
                    // Если в системе есть второй DNS, он должен совпадать с пресетом
                    bool secondaryMatch = true;
                    if (dns.Count > 1)
                    {
                        secondaryMatch = dns[1] == preset.SecondaryIp;
                    }

                    if (primaryMatch && secondaryMatch) return preset.Name;
                }
            }
            catch { }
            return null;
        }

        #region DNS Fix (Cloudflare + DoH)

        /// <summary>
        /// Применить DNS fix: установить выбранный пресет (по умолчанию Cloudflare)
        /// </summary>
        public static async Task<(bool success, string error)> ApplyDnsFixAsync(string presetName = "Cloudflare")
        {
            try
            {
                var preset = AvailablePresets.FirstOrDefault(p => p.Name.Equals(presetName, StringComparison.OrdinalIgnoreCase)) 
                             ?? AvailablePresets[0];

                // 1. Найти активный сетевой адаптер
                var adapter = GetActiveNetworkInterface();
                if (adapter == null)
                    return (false, "Не найден активный сетевой адаптер");

                Log($"[FixService] Found adapter: {adapter.Name} ({adapter.Description})");

                // Сохраняем оригинальные настройки, если еще не сохранены
                if (_originalDnsConfig == null)
                {
                    // Пытаемся загрузить из файла, если есть
                    if (File.Exists(BackupFileName))
                    {
                        try 
                        {
                            var json = await File.ReadAllTextAsync(BackupFileName);
                            var state = JsonSerializer.Deserialize<DnsBackupState>(json);
                            if (state != null && state.AdapterName == adapter.Name)
                            {
                                _originalDnsConfig = state.Config;
                                _originalAdapterName = state.AdapterName;
                                Log($"[FixService] Loaded backup from file: {_originalDnsConfig}");
                            }
                        }
                        catch { /* ignore corrupt file */ }
                    }

                    // Если все еще нет бэкапа, делаем новый
                    if (_originalDnsConfig == null)
                    {
                        await BackupDnsSettingsAsync(adapter.Name);
                    }
                }

                // 2. Установить DNS серверы
                var dnsServers = new[] { preset.PrimaryIp, preset.SecondaryIp };
                var setDnsSuccess = await SetDnsServersAsync(adapter.Name, dnsServers);
                if (!setDnsSuccess)
                    return (false, "Не удалось установить DNS серверы");

                // Небольшая пауза, чтобы система осознала смену DNS
                await Task.Delay(500);

                // 3. Включить DoH encryption (Primary + Secondary)
                await EnableDoHAsync(preset.PrimaryIp, preset.PrimaryDoH);
                await EnableDoHAsync(preset.SecondaryIp, preset.SecondaryDoH);

                // Проверка (для логов)
                var (_, checkOutput) = await RunCommandAsync("netsh", "dns show encryption");
                Log($"[FixService] Current DoH rules:\n{checkOutput}");

                // 4. Очистить DNS кэш
                await RunCommandAsync("ipconfig", "/flushdns");

                return (true, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, $"Ошибка применения DNS fix: {ex.Message}");
            }
        }

        /// <summary>
        /// Восстановить оригинальные настройки DNS
        /// </summary>
        public static async Task<(bool success, string error)> RestoreDnsAsync()
        {
            // Если в памяти пусто, пробуем загрузить с диска
            if (_originalDnsConfig == null && File.Exists(BackupFileName))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(BackupFileName);
                    var state = JsonSerializer.Deserialize<DnsBackupState>(json);
                    if (state != null)
                    {
                        _originalDnsConfig = state.Config;
                        _originalAdapterName = state.AdapterName;
                    }
                }
                catch (Exception ex)
                {
                    Log($"[FixService] Failed to load backup: {ex.Message}");
                }
            }

            if (_originalDnsConfig == null || _originalAdapterName == null)
                return (false, "Нет сохраненных настроек DNS");

            try
            {
                Log($"[FixService] Restoring DNS for {_originalAdapterName}: {_originalDnsConfig}");

                if (_originalDnsConfig == "DHCP")
                {
                    var (success, _) = await RunCommandAsync("netsh", $"interface ipv4 set dns name=\"{_originalAdapterName}\" source=dhcp");
                    if (!success) return (false, "Не удалось восстановить DHCP");
                }
                else
                {
                    var ips = _originalDnsConfig.Split(',', StringSplitOptions.RemoveEmptyEntries);
                    if (ips.Length > 0)
                    {
                        await SetDnsServersAsync(_originalAdapterName, ips);
                    }
                }

                await RunCommandAsync("ipconfig", "/flushdns");
                
                // Очищаем состояние и удаляем файл бэкапа
                _originalDnsConfig = null;
                _originalAdapterName = null;
                if (File.Exists(BackupFileName))
                {
                    try { File.Delete(BackupFileName); } catch { }
                }
                
                return (true, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, $"Ошибка восстановления DNS: {ex.Message}");
            }
        }

        #endregion

        #region Helpers

        private static async Task BackupDnsSettingsAsync(string adapterName)
        {
            try
            {
                // Проверяем, используется ли DHCP
                var (success, output) = await RunCommandAsync("netsh", $"interface ipv4 show dns name=\"{adapterName}\"");
                if (success)
                {
                    _originalAdapterName = adapterName;
                    
                    // Простой парсинг: если есть "DHCP", то DHCP. Иначе собираем IP.
                    // В русской Windows: "DHCP включен: Да"
                    // В английской: "DHCP enabled: Yes"
                    // Но это для IP. Для DNS netsh показывает "Statically Configured" vs "DHCP".
                    
                    if (output.Contains("DHCP") && !output.Contains("Statically Configured") && !output.Contains("Настроено статически"))
                    {
                        _originalDnsConfig = "DHCP";
                    }
                    else
                    {
                        // Собираем IP
                        var ips = new List<string>();
                        var ni = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == adapterName);
                        if (ni != null)
                        {
                            foreach (var dns in ni.GetIPProperties().DnsAddresses)
                            {
                                if (dns.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                {
                                    ips.Add(dns.ToString());
                                }
                            }
                        }
                        
                        if (ips.Count > 0)
                            _originalDnsConfig = string.Join(",", ips);
                        else
                            _originalDnsConfig = "DHCP"; // Fallback
                    }
                    
                    Log($"[FixService] Backup DNS: {_originalDnsConfig}");

                    // Сохраняем в файл
                    try
                    {
                        var state = new DnsBackupState 
                        { 
                            AdapterName = _originalAdapterName, 
                            Config = _originalDnsConfig,
                            Timestamp = DateTime.Now
                        };
                        var json = JsonSerializer.Serialize(state);
                        await File.WriteAllTextAsync(BackupFileName, json);
                    }
                    catch (Exception ex)
                    {
                        Log($"[FixService] Failed to write backup file: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[FixService] Backup failed: {ex.Message}");
            }
        }

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
        /// Установить DNS серверы (PowerShell + netsh fallback)
        /// </summary>
        private static async Task<bool> SetDnsServersAsync(string adapterName, string[] dnsServers)
        {
            try
            {
                // Попытка 1: PowerShell (Set-DnsClientServerAddress)
                string servers = string.Join(",", dnsServers.Select(s => $"'{s}'"));
                string psCommand = $"Set-DnsClientServerAddress -InterfaceAlias '{adapterName}' -ServerAddresses ({servers})";
                
                var (psSuccess, psOutput) = await RunCommandAsync("powershell", $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCommand}\"");
                
                if (psSuccess) 
                {
                    Log($"[FixService] DNS servers set via PowerShell for {adapterName}");
                    return true;
                }
                
                Log($"[FixService] PowerShell Set-DNS failed: {psOutput}. Fallback to netsh.");

                // Попытка 2: netsh (fallback)
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
            catch (Exception ex)
            {
                Log($"[FixService] SetDnsServers error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Включить DoH (DNS-over-HTTPS) для указанного DNS сервера
        /// </summary>
        private static async Task<bool> EnableDoHAsync(string dnsIp, string dohTemplate)
        {
            // 0. Убедиться, что AutoDoH разрешен в реестре (для некоторых версий Windows)
            try
            {
                await RunCommandAsync("reg", "add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\" /v EnableAutoDoh /t REG_DWORD /d 2 /f");
            }
            catch { }

            // Попытка 1: PowerShell (предпочтительно для Win11)
            try 
            {
                // Удаляем старое правило и добавляем новое
                // Исправлено: AllowFallbackToUdp (вместо AllowFallback), убран Force (не поддерживается)
                string psCommand = $"Remove-DnsClientDohServerAddress -ServerAddress '{dnsIp}' -ErrorAction SilentlyContinue; " +
                                   $"Add-DnsClientDohServerAddress -ServerAddress '{dnsIp}' -DohTemplate '{dohTemplate}' -AllowFallbackToUdp $false -AutoUpgrade $true";
                
                var (success, output) = await RunCommandAsync("powershell", $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCommand}\"");
                
                // Проверка результата
                var (checkSuccess, checkOutput) = await RunCommandAsync("powershell", $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-DnsClientDohServerAddress -ServerAddress '{dnsIp}' | Format-List\"");
                Log($"[FixService] DoH Check for {dnsIp}:\n{checkOutput}");

                if (success) 
                {
                    Log($"[FixService] DoH enabled via PowerShell for {dnsIp}");
                    return true;
                }
                
                Log($"[FixService] PowerShell failed: {output}. Trying netsh...");
            }
            catch (Exception ex)
            {
                Log($"[FixService] PowerShell exception: {ex.Message}");
            }

            // Попытка 2: netsh (fallback)
            // 1. Удаляем существующее правило (игнорируем ошибку, если его нет)
            await RunCommandAsync("netsh", $"dns delete encryption server={dnsIp}");

            // 2. Добавляем новое правило (важно: кавычки вокруг шаблона)
            var (netshSuccess, netshOutput) = await RunCommandAsync("netsh", $"dns add encryption server={dnsIp} dohtemplate=\"{dohTemplate}\" autoupgrade=yes udpfallback=no");
            
            if (!netshSuccess)
            {
                Log($"[FixService] Ошибка включения DoH для {dnsIp} (netsh): {netshOutput}");
            }
            else
            {
                Log($"[FixService] DoH enabled via netsh for {dnsIp}");
            }
            
            return netshSuccess;
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
