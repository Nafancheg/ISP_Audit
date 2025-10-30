using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using IspAudit.Output;

namespace ISP_Audit.Tests;

public class IspTest
{
    private static readonly HttpClient _httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(5)
    };

    private static readonly List<string> _problematicIsps = new()
    {
        "Rostelecom",
        "ROSTELECOM",
        "RTK",
        "Beeline",
        "BEELINE",
        "VimpelCom",
        "MTS",
        "МТС",
        "Mobile TeleSystems",
        "ER-Telecom",
        "Dom.ru",
        "TTK"
    };

    public static async Task<IspTestResult> RunAsync()
    {
        try
        {
            // 1. Получить ISP информацию через API
            var (isp, country, city) = await GetIspInfoAsync();

            // 2. Проверить CGNAT
            bool cgnatDetected = await DetectCgnatAsync();

            // 3. Проверить DNS фильтрацию
            bool dnsFiltered = await DetectDnsFilteringAsync();

            // 4. Проверить DPI
            bool dpiDetected = await DetectDpiAsync();

            // 5. Проверить ISP в списке проблемных
            var knownProblematic = _problematicIsps
                .Where(p => isp != null && isp.Contains(p, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Определить статус
            string status = DetermineStatus(cgnatDetected, dpiDetected, dnsFiltered, knownProblematic.Count > 0);

            return new IspTestResult(
                isp,
                country,
                city,
                cgnatDetected,
                dpiDetected,
                dnsFiltered,
                knownProblematic,
                status
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ISP Test] Error: {ex.Message}");
            return new IspTestResult(
                null,
                null,
                null,
                false,
                false,
                false,
                new List<string>(),
                "UNKNOWN"
            );
        }
    }

    private static async Task<(string? isp, string? country, string? city)> GetIspInfoAsync()
    {
        try
        {
            // Попытка 1: ip-api.com (rate limit 45 req/min)
            var response = await _httpClient.GetStringAsync("http://ip-api.com/json/?fields=isp,country,city");
            var json = JsonDocument.Parse(response);
            var root = json.RootElement;

            string? isp = root.TryGetProperty("isp", out var ispProp) ? ispProp.GetString() : null;
            string? country = root.TryGetProperty("country", out var countryProp) ? countryProp.GetString() : null;
            string? city = root.TryGetProperty("city", out var cityProp) ? cityProp.GetString() : null;

            return (isp, country, city);
        }
        catch
        {
            // Fallback: ipify.org (только IP, без ISP информации)
            try
            {
                var ip = await _httpClient.GetStringAsync("https://api.ipify.org");
                return ($"Unknown (IP: {ip})", null, null);
            }
            catch
            {
                return (null, null, null);
            }
        }
    }

    private static async Task<bool> DetectCgnatAsync()
    {
        try
        {
            // Получить внешний IP
            var externalIp = await _httpClient.GetStringAsync("https://api.ipify.org");
            
            // Получить локальный IP
            var localIp = GetLocalIpAddress();

            if (localIp == null || !IPAddress.TryParse(externalIp.Trim(), out var extIp))
                return false;

            // Проверить диапазон CGNAT (100.64.0.0/10)
            if (IsInCgnatRange(localIp))
                return true;

            // Дополнительная проверка: если локальный IP приватный, но внешний тоже приватный
            if (IPAddress.TryParse(localIp, out var localAddr) && IsPrivateIp(localAddr) && IsPrivateIp(extIp))
                return true;

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> DetectDnsFilteringAsync()
    {
        try
        {
            string testDomain = "robertsspaceindustries.com";

            // 1. System DNS
            var systemDnsIps = await Dns.GetHostAddressesAsync(testDomain);
            var systemIp = systemDnsIps.FirstOrDefault()?.ToString();

            // 2. Google DNS (8.8.8.8)
            var googleDnsIps = await QueryDnsViaGoogleAsync(testDomain);
            var googleIp = googleDnsIps.FirstOrDefault();

            // 3. Cloudflare DoH (через DnsTest если есть, иначе упрощенная версия)
            var cloudflareIps = await QueryDnsViaCloudflareAsync(testDomain);
            var cloudflareIp = cloudflareIps.FirstOrDefault();

            // Если System DNS отличается от обоих (Google и Cloudflare)
            if (systemIp != null && googleIp != null && cloudflareIp != null)
            {
                if (systemIp != googleIp && systemIp != cloudflareIp)
                    return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> DetectDpiAsync()
    {
        try
        {
            // Проверка DPI через модификацию HTTP заголовков
            // Метод 1: Split Host header
            var request1 = new HttpRequestMessage(HttpMethod.Get, "http://robertsspaceindustries.com");
            request1.Headers.TryAddWithoutValidation("Host", "roberts" + "spaceindustries.com");
            
            var response1 = await _httpClient.SendAsync(request1);
            if (!response1.IsSuccessStatusCode)
                return true;

            // Метод 2: Case modification
            var request2 = new HttpRequestMessage(HttpMethod.Get, "http://robertsspaceindustries.com");
            request2.Headers.TryAddWithoutValidation("Host", "RoBeRtSpAcEiNdUsTrIeS.CoM");
            
            var response2 = await _httpClient.SendAsync(request2);
            if (!response2.IsSuccessStatusCode)
                return true;

            return false;
        }
        catch
        {
            // Если запросы не проходят - возможно DPI
            return true;
        }
    }

    private static async Task<List<string>> QueryDnsViaGoogleAsync(string hostname)
    {
        try
        {
            // Использовать Google DNS через прямой UDP запрос или HTTP API
            // Упрощенная версия через DNS-over-HTTPS Google
            var url = $"https://dns.google/resolve?name={hostname}&type=A";
            var response = await _httpClient.GetStringAsync(url);
            var json = JsonDocument.Parse(response);

            var ips = new List<string>();
            if (json.RootElement.TryGetProperty("Answer", out var answers))
            {
                foreach (var answer in answers.EnumerateArray())
                {
                    if (answer.TryGetProperty("data", out var data))
                    {
                        ips.Add(data.GetString() ?? string.Empty);
                    }
                }
            }

            return ips;
        }
        catch
        {
            return new List<string>();
        }
    }

    private static async Task<List<string>> QueryDnsViaCloudflareAsync(string hostname)
    {
        try
        {
            // DNS-over-HTTPS Cloudflare
            var url = $"https://cloudflare-dns.com/dns-query?name={hostname}&type=A";
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("accept", "application/dns-json");

            var response = await _httpClient.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();
            var json = JsonDocument.Parse(content);

            var ips = new List<string>();
            if (json.RootElement.TryGetProperty("Answer", out var answers))
            {
                foreach (var answer in answers.EnumerateArray())
                {
                    if (answer.TryGetProperty("data", out var data))
                    {
                        ips.Add(data.GetString() ?? string.Empty);
                    }
                }
            }

            return ips;
        }
        catch
        {
            return new List<string>();
        }
    }

    private static string? GetLocalIpAddress()
    {
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsInCgnatRange(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return false;

        var bytes = address.GetAddressBytes();
        // CGNAT диапазон: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
        return bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127;
    }

    private static bool IsPrivateIp(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        
        // 10.0.0.0/8
        if (bytes[0] == 10)
            return true;
        
        // 172.16.0.0/12
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            return true;
        
        // 192.168.0.0/16
        if (bytes[0] == 192 && bytes[1] == 168)
            return true;

        // 100.64.0.0/10 (CGNAT)
        if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
            return true;

        return false;
    }

    private static string DetermineStatus(bool cgnat, bool dpi, bool dnsFiltered, bool knownProblematic)
    {
        if (dpi)
            return "DPI_DETECTED";
        
        if (dnsFiltered)
            return "DNS_FILTERED";
        
        if (cgnat && knownProblematic)
            return "CGNAT_AND_PROBLEMATIC_ISP";
        
        if (cgnat)
            return "CGNAT_DETECTED";
        
        if (knownProblematic)
            return "PROBLEMATIC_ISP";

        return "OK";
    }

    // ==================== UNIT TESTS ====================
    
    #region Unit Tests Support
    
    /// <summary>
    /// Тестовый метод для проверки IsInCgnatRange
    /// </summary>
    public static bool TestIsInCgnatRange(string ip)
    {
        return IsInCgnatRange(ip);
    }
    
    /// <summary>
    /// Тестовый метод для проверки IsPrivateIp
    /// </summary>
    public static bool TestIsPrivateIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return false;
        return IsPrivateIp(address);
    }
    
    /// <summary>
    /// Тестовый метод для проверки DetermineStatus
    /// </summary>
    public static string TestDetermineStatus(bool cgnat, bool dpi, bool dnsFiltered, bool knownProblematic)
    {
        return DetermineStatus(cgnat, dpi, dnsFiltered, knownProblematic);
    }
    
    #endregion
    
    #region Unit Tests
    
    /// <summary>
    /// Unit Test: Проверка детекции CGNAT диапазона
    /// </summary>
    public static void UnitTest_IsInCgnatRange()
    {
        bool test1 = TestIsInCgnatRange("100.64.0.1");   // В диапазоне
        bool test2 = TestIsInCgnatRange("100.127.255.255"); // В диапазоне
        bool test3 = TestIsInCgnatRange("100.63.255.255");  // Вне диапазона
        bool test4 = TestIsInCgnatRange("100.128.0.0");     // Вне диапазона
        bool test5 = TestIsInCgnatRange("192.168.1.1");     // Вне диапазона
        
        bool passed = test1 && test2 && !test3 && !test4 && !test5;
        Console.WriteLine($"[TEST] IsInCgnatRange: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  100.64.0.1: {test1}, 100.127.255.255: {test2}, 100.63.255.255: {test3}");
        Console.WriteLine($"  100.128.0.0: {test4}, 192.168.1.1: {test5}");
    }
    
    /// <summary>
    /// Unit Test: Проверка детекции приватных IP
    /// </summary>
    public static void UnitTest_IsPrivateIp()
    {
        bool test1 = TestIsPrivateIp("10.0.0.1");      // Приватный
        bool test2 = TestIsPrivateIp("172.16.0.1");    // Приватный
        bool test3 = TestIsPrivateIp("192.168.1.1");   // Приватный
        bool test4 = TestIsPrivateIp("100.64.0.1");    // CGNAT (считается приватным)
        bool test5 = TestIsPrivateIp("8.8.8.8");       // Публичный
        bool test6 = TestIsPrivateIp("1.1.1.1");       // Публичный
        
        bool passed = test1 && test2 && test3 && test4 && !test5 && !test6;
        Console.WriteLine($"[TEST] IsPrivateIp: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  10.0.0.1: {test1}, 172.16.0.1: {test2}, 192.168.1.1: {test3}");
        Console.WriteLine($"  100.64.0.1: {test4}, 8.8.8.8: {test5}, 1.1.1.1: {test6}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения статуса при DPI
    /// </summary>
    public static void UnitTest_DetermineStatus_DPI()
    {
        string status = TestDetermineStatus(false, true, false, false);
        bool passed = status == "DPI_DETECTED";
        
        Console.WriteLine($"[TEST] DetermineStatus_DPI: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: DPI_DETECTED, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения статуса при DNS фильтрации
    /// </summary>
    public static void UnitTest_DetermineStatus_DnsFiltered()
    {
        string status = TestDetermineStatus(false, false, true, false);
        bool passed = status == "DNS_FILTERED";
        
        Console.WriteLine($"[TEST] DetermineStatus_DnsFiltered: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: DNS_FILTERED, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения статуса при CGNAT и проблемном ISP
    /// </summary>
    public static void UnitTest_DetermineStatus_CgnatAndProblematic()
    {
        string status = TestDetermineStatus(true, false, false, true);
        bool passed = status == "CGNAT_AND_PROBLEMATIC_ISP";
        
        Console.WriteLine($"[TEST] DetermineStatus_CgnatAndProblematic: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: CGNAT_AND_PROBLEMATIC_ISP, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения статуса при только CGNAT
    /// </summary>
    public static void UnitTest_DetermineStatus_CgnatOnly()
    {
        string status = TestDetermineStatus(true, false, false, false);
        bool passed = status == "CGNAT_DETECTED";
        
        Console.WriteLine($"[TEST] DetermineStatus_CgnatOnly: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: CGNAT_DETECTED, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения статуса при только проблемном ISP
    /// </summary>
    public static void UnitTest_DetermineStatus_ProblematicOnly()
    {
        string status = TestDetermineStatus(false, false, false, true);
        bool passed = status == "PROBLEMATIC_ISP";
        
        Console.WriteLine($"[TEST] DetermineStatus_ProblematicOnly: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: PROBLEMATIC_ISP, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения OK статуса
    /// </summary>
    public static void UnitTest_DetermineStatus_OK()
    {
        string status = TestDetermineStatus(false, false, false, false);
        bool passed = status == "OK";
        
        Console.WriteLine($"[TEST] DetermineStatus_OK: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: OK, Got: {status}");
    }
    
    /// <summary>
    /// Запускает все unit тесты IspTest
    /// </summary>
    public static void RunAllUnitTests()
    {
        Console.WriteLine("========== IspTest Unit Tests ==========");
        UnitTest_IsInCgnatRange();
        UnitTest_IsPrivateIp();
        UnitTest_DetermineStatus_DPI();
        UnitTest_DetermineStatus_DnsFiltered();
        UnitTest_DetermineStatus_CgnatAndProblematic();
        UnitTest_DetermineStatus_CgnatOnly();
        UnitTest_DetermineStatus_ProblematicOnly();
        UnitTest_DetermineStatus_OK();
        Console.WriteLine("==========================================");
    }
    
    #endregion
}
