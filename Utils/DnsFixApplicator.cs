using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    /// <summary>
    /// Применяет исправления DNS для обхода блокировок
    /// </summary>
    internal static class DnsFixApplicator
    {
        private static readonly HttpClient _httpClient = new();

        /// <summary>
        /// DoH провайдеры с приоритетами
        /// </summary>
        private static readonly DnsProvider[] _dohProviders = new[]
        {
            new DnsProvider 
            { 
                Name = "Cloudflare", 
                PrimaryDns = "1.1.1.1", 
                SecondaryDns = "1.0.0.1",
                TestUrl = "https://1.1.1.1/dns-query",
                Priority = 1
            },
            new DnsProvider 
            { 
                Name = "Google", 
                PrimaryDns = "8.8.8.8", 
                SecondaryDns = "8.8.4.4",
                TestUrl = "https://dns.google/resolve?name=google.com",
                Priority = 2
            },
            new DnsProvider 
            { 
                Name = "Quad9", 
                PrimaryDns = "9.9.9.9", 
                SecondaryDns = "149.112.112.112",
                TestUrl = "https://dns.quad9.net/dns-query",
                Priority = 3
            },
            new DnsProvider 
            { 
                Name = "AdGuard", 
                PrimaryDns = "94.140.14.14", 
                SecondaryDns = "94.140.15.15",
                TestUrl = "https://dns.adguard-dns.com/dns-query",
                Priority = 4
            }
        };

        /// <summary>
        /// Применяет исправление DNS (смена на DoH провайдера)
        /// </summary>
        public static async Task<DnsFixResult> ApplyDnsFixAsync(
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            progress?.Report("Проверка прав администратора...");

            if (!IsAdministrator())
            {
                return new DnsFixResult
                {
                    Success = false,
                    Error = "Требуются права администратора для изменения DNS",
                    RequiresElevation = true
                };
            }

            progress?.Report("Проверка доступности DoH провайдеров...");

            // Тестируем доступность провайдеров
            var availableProviders = await TestProvidersAsync(progress, cancellationToken).ConfigureAwait(false);

            if (!availableProviders.Any())
            {
                return new DnsFixResult
                {
                    Success = false,
                    Error = "Все DoH провайдеры недоступны. Возможна блокировка DoH.",
                    RequiresVpn = true
                };
            }

            // Выбираем лучший доступный провайдер
            var provider = availableProviders.OrderBy(p => p.Priority).First();
            progress?.Report($"Выбран провайдер: {provider.Name}");

            // Получаем текущие DNS настройки для отката
            var originalDns = await GetCurrentDnsAsync(cancellationToken).ConfigureAwait(false);

            // Применяем новые DNS через netsh
            progress?.Report($"Применение DNS: {provider.PrimaryDns}, {provider.SecondaryDns}...");

            var success = await SetDnsViaNetshAsync(provider, progress, cancellationToken).ConfigureAwait(false);

            if (!success)
            {
                return new DnsFixResult
                {
                    Success = false,
                    Error = "Не удалось применить DNS через netsh"
                };
            }

            // Сброс DNS кэша
            progress?.Report("Сброс DNS кэша...");
            await FlushDnsCacheAsync(cancellationToken).ConfigureAwait(false);

            return new DnsFixResult
            {
                Success = true,
                AppliedProvider = provider.Name,
                PrimaryDns = provider.PrimaryDns,
                SecondaryDns = provider.SecondaryDns,
                OriginalDns = originalDns
            };
        }

        /// <summary>
        /// Откатывает DNS настройки к исходным (автоматический DHCP)
        /// </summary>
        public static async Task<bool> RevertDnsAsync(
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            progress?.Report("Откат DNS на автоматический (DHCP)...");

            if (!IsAdministrator())
            {
                progress?.Report("Требуются права администратора");
                return false;
            }

            // Получаем активные сетевые интерфейсы
            var interfaces = await GetActiveNetworkInterfacesAsync(cancellationToken).ConfigureAwait(false);

            foreach (var iface in interfaces)
            {
                // Сброс на DHCP
                var success = await RunNetshCommandAsync(
                    $"interface ip set dns name=\"{iface}\" source=dhcp",
                    progress,
                    cancellationToken
                ).ConfigureAwait(false);

                if (success)
                {
                    progress?.Report($"  - {iface}: DNS сброшен на DHCP");
                }
            }

            // Сброс DNS кэша
            await FlushDnsCacheAsync(cancellationToken).ConfigureAwait(false);

            progress?.Report("Откат DNS завершен");
            return true;
        }

        /// <summary>
        /// Тестирует доступность DoH провайдеров
        /// </summary>
        private static async Task<List<DnsProvider>> TestProvidersAsync(
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var available = new List<DnsProvider>();

            foreach (var provider in _dohProviders)
            {
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    cts.CancelAfter(TimeSpan.FromSeconds(3));

                    var response = await _httpClient.GetAsync(provider.TestUrl, cts.Token).ConfigureAwait(false);

                    if (response.IsSuccessStatusCode)
                    {
                        available.Add(provider);
                        progress?.Report($"  ✓ {provider.Name} доступен");
                    }
                    else
                    {
                        progress?.Report($"  ✗ {provider.Name} недоступен (HTTP {response.StatusCode})");
                    }
                }
                catch (Exception ex)
                {
                    progress?.Report($"  ✗ {provider.Name} недоступен: {ex.Message}");
                }
            }

            return available;
        }

        /// <summary>
        /// Применяет DNS через netsh
        /// </summary>
        private static async Task<bool> SetDnsViaNetshAsync(
            DnsProvider provider,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            // Получаем активные сетевые интерфейсы
            var interfaces = await GetActiveNetworkInterfacesAsync(cancellationToken).ConfigureAwait(false);

            if (!interfaces.Any())
            {
                progress?.Report("Не найдено активных сетевых интерфейсов");
                return false;
            }

            bool allSuccess = true;

            foreach (var iface in interfaces)
            {
                // Устанавливаем primary DNS
                var success1 = await RunNetshCommandAsync(
                    $"interface ip set dns name=\"{iface}\" static {provider.PrimaryDns} primary",
                    progress,
                    cancellationToken
                ).ConfigureAwait(false);

                // Добавляем secondary DNS
                var success2 = await RunNetshCommandAsync(
                    $"interface ip add dns name=\"{iface}\" {provider.SecondaryDns} index=2",
                    progress,
                    cancellationToken
                ).ConfigureAwait(false);

                if (success1 && success2)
                {
                    progress?.Report($"  ✓ {iface}: DNS установлен");
                }
                else
                {
                    progress?.Report($"  ✗ {iface}: ошибка установки DNS");
                    allSuccess = false;
                }
            }

            return allSuccess;
        }

        /// <summary>
        /// Получает список активных сетевых интерфейсов
        /// </summary>
        private static async Task<List<string>> GetActiveNetworkInterfacesAsync(CancellationToken cancellationToken)
        {
            var interfaces = new List<string>();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface show interface",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.GetEncoding(866) // OEM866 для русской Windows
                };

                using var process = Process.Start(psi);
                if (process == null)
                    return interfaces;

                var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

                // Парсим вывод netsh (формат: Enabled Connected Dedicated InterfaceName)
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                foreach (var line in lines)
                {
                    // Ищем строки с "Enabled" и "Connected"
                    if (line.Contains("Enabled", StringComparison.OrdinalIgnoreCase) &&
                        line.Contains("Connected", StringComparison.OrdinalIgnoreCase))
                    {
                        // Последнее слово в строке — имя интерфейса
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 0)
                        {
                            var interfaceName = parts[^1];
                            interfaces.Add(interfaceName);
                        }
                    }
                }
            }
            catch
            {
                // Fallback: используем общие имена интерфейсов
                interfaces.Add("Ethernet");
                interfaces.Add("Wi-Fi");
            }

            return interfaces;
        }

        /// <summary>
        /// Получает текущие DNS настройки
        /// </summary>
        private static async Task<string> GetCurrentDnsAsync(CancellationToken cancellationToken)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "interface ip show dns",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.GetEncoding(866)
                };

                using var process = Process.Start(psi);
                if (process == null)
                    return "DHCP";

                var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

                return string.IsNullOrWhiteSpace(output) ? "DHCP" : output.Trim();
            }
            catch
            {
                return "DHCP";
            }
        }

        /// <summary>
        /// Выполняет команду netsh
        /// </summary>
        private static async Task<bool> RunNetshCommandAsync(
            string arguments,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.GetEncoding(866),
                    StandardErrorEncoding = System.Text.Encoding.GetEncoding(866)
                };

                using var process = Process.Start(psi);
                if (process == null)
                    return false;

                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                progress?.Report($"Ошибка netsh: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Сбрасывает DNS кэш
        /// </summary>
        private static async Task FlushDnsCacheAsync(CancellationToken cancellationToken)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                // Игнорируем ошибки flush DNS
            }
        }

        /// <summary>
        /// Проверяет, запущено ли приложение с правами администратора
        /// </summary>
        private static bool IsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// DoH провайдер
    /// </summary>
    internal class DnsProvider
    {
        public required string Name { get; init; }
        public required string PrimaryDns { get; init; }
        public required string SecondaryDns { get; init; }
        public required string TestUrl { get; init; }
        public int Priority { get; init; }
    }

    /// <summary>
    /// Результат применения DNS исправления
    /// </summary>
    public class DnsFixResult
    {
        /// <summary>Успешность операции</summary>
        public bool Success { get; init; }

        /// <summary>Примененный провайдер</summary>
        public string? AppliedProvider { get; init; }

        /// <summary>Primary DNS</summary>
        public string? PrimaryDns { get; init; }

        /// <summary>Secondary DNS</summary>
        public string? SecondaryDns { get; init; }

        /// <summary>Исходные DNS настройки</summary>
        public string? OriginalDns { get; init; }

        /// <summary>Ошибка</summary>
        public string? Error { get; init; }

        /// <summary>Требуется повышение прав</summary>
        public bool RequiresElevation { get; init; }

        /// <summary>Требуется VPN (все DoH заблокированы)</summary>
        public bool RequiresVpn { get; init; }
    }
}
