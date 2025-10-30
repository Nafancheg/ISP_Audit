using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using IspAudit.Output;

namespace ISP_Audit.Tests;

public class RouterTest
{
    /// <summary>
    /// Запускает диагностику роутера: пинг шлюза, проверка UPnP, SIP ALG
    /// </summary>
    public static async Task<RouterTestResult> RunAsync()
    {
        try
        {
            // 1. Получить IP адрес шлюза (default gateway)
            string? gatewayIp = GetDefaultGateway();
            
            if (string.IsNullOrEmpty(gatewayIp))
            {
                return new RouterTestResult(
                    GatewayIp: null,
                    UpnpEnabled: false,
                    SipAlgDetected: false,
                    AvgPingMs: 0,
                    MaxPingMs: 0,
                    PacketLossPercent: 0,
                    Status: "NO_GATEWAY"
                );
            }

            // 2. Пинговать шлюз 20 раз
            var pingResults = await PingGatewayAsync(gatewayIp, 20);

            // 3. Проверить UPnP через COM Interop
            bool upnpEnabled = await CheckUpnpAsync();

            // 4. Проверить SIP ALG (эвристика на основе типа шлюза)
            bool sipAlgDetected = CheckSipAlg(gatewayIp);

            // Определить статус
            string status = DetermineStatus(pingResults.AvgPing, pingResults.MaxPing, 
                                           pingResults.PacketLoss, upnpEnabled, sipAlgDetected);

            return new RouterTestResult(
                GatewayIp: gatewayIp,
                UpnpEnabled: upnpEnabled,
                SipAlgDetected: sipAlgDetected,
                AvgPingMs: pingResults.AvgPing,
                MaxPingMs: pingResults.MaxPing,
                PacketLossPercent: pingResults.PacketLoss,
                Status: status
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[RouterTest] Error: {ex.Message}");
            return new RouterTestResult(
                GatewayIp: null,
                UpnpEnabled: false,
                SipAlgDetected: false,
                AvgPingMs: 0,
                MaxPingMs: 0,
                PacketLossPercent: 0,
                Status: "ERROR"
            );
        }
    }

    /// <summary>
    /// Получает IP адрес шлюза по умолчанию
    /// </summary>
    private static string? GetDefaultGateway()
    {
        try
        {
            var gateways = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses ?? Enumerable.Empty<GatewayIPAddressInformation>())
                .Select(g => g?.Address)
                .Where(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .FirstOrDefault();

            return gateways?.ToString();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[RouterTest] Failed to get gateway: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Пингует шлюз N раз и возвращает статистику
    /// </summary>
    private static async Task<(double AvgPing, double MaxPing, int PacketLoss)> PingGatewayAsync(string gatewayIp, int count)
    {
        var pingSender = new Ping();
        var successfulPings = new List<long>();
        int failures = 0;

        for (int i = 0; i < count; i++)
        {
            try
            {
                PingReply reply = await pingSender.SendPingAsync(gatewayIp, 2000); // 2s timeout
                
                if (reply.Status == IPStatus.Success)
                {
                    successfulPings.Add(reply.RoundtripTime);
                }
                else
                {
                    failures++;
                }
            }
            catch
            {
                failures++;
            }

            // Небольшая задержка между пингами
            await Task.Delay(50);
        }

        double avgPing = successfulPings.Count > 0 ? successfulPings.Average() : 0;
        double maxPing = successfulPings.Count > 0 ? successfulPings.Max() : 0;
        int packetLoss = (failures * 100) / count;

        return (avgPing, maxPing, packetLoss);
    }

    /// <summary>
    /// Проверяет UPnP через COM Interop (UPnP.UPnPDeviceFinder)
    /// </summary>
    private static async Task<bool> CheckUpnpAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                // Попытка использовать COM объект UPnP.UPnPDeviceFinder
                Type? upnpFinderType = Type.GetTypeFromProgID("UPnP.UPnPDeviceFinder");
                
                if (upnpFinderType == null)
                {
                    // COM объект не зарегистрирован
                    return false;
                }

                dynamic? upnpFinder = Activator.CreateInstance(upnpFinderType);
                
                if (upnpFinder == null)
                {
                    return false;
                }

                // Поиск устройств UPnP с таймаутом 3 секунды
                // FindByType ищет устройства определённого типа
                // "urn:schemas-upnp-org:device:InternetGatewayDevice:1" - стандартный тип роутера
                dynamic devices = upnpFinder.FindByType("urn:schemas-upnp-org:device:InternetGatewayDevice:1", 0);
                
                // Если найдено хотя бы одно устройство - UPnP работает
                int deviceCount = devices?.Count ?? 0;
                
                // Освобождаем COM объект
                if (upnpFinder != null)
                {
                    Marshal.ReleaseComObject(upnpFinder);
                }
                
                if (devices != null)
                {
                    Marshal.ReleaseComObject(devices);
                }

                return deviceCount > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[RouterTest] UPnP check failed: {ex.Message}");
                return false;
            }
        });
    }

    /// <summary>
    /// Проверяет наличие SIP ALG (эвристика на основе типа роутера)
    /// Это упрощённая проверка, точная детекция требует доступа к админке роутера
    /// </summary>
    private static bool CheckSipAlg(string gatewayIp)
    {
        try
        {
            // SIP ALG чаще встречается на потребительских роутерах с определёнными IP диапазонами
            // Это эвристика, не 100% точная проверка
            
            if (IPAddress.TryParse(gatewayIp, out IPAddress? address))
            {
                byte[] bytes = address.GetAddressBytes();
                
                // Типичные IP роутеров, где часто включен SIP ALG:
                // 192.168.0.1, 192.168.1.1 (большинство consumer роутеров)
                // 10.0.0.1 (некоторые ISP роутеры)
                
                if (bytes[0] == 192 && bytes[1] == 168)
                {
                    // Предполагаем что на consumer роутерах SIP ALG скорее всего включен
                    return true;
                }
                else if (bytes[0] == 10 && bytes[1] == 0)
                {
                    // ISP роутеры - возможно SIP ALG
                    return true;
                }
            }
            
            // В остальных случаях - неизвестно, возвращаем false
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Определяет общий статус роутера
    /// </summary>
    private static string DetermineStatus(double avgPing, double maxPing, int packetLoss, 
                                         bool upnpEnabled, bool sipAlgDetected)
    {
        var issues = new List<string>();

        // Проблемы с пингом
        if (avgPing > 50)
            issues.Add("HIGH_PING");
        
        if (maxPing > 200)
            issues.Add("PING_SPIKES");
        
        if (packetLoss > 5)
            issues.Add("PACKET_LOSS");

        // Проблемы с конфигурацией
        if (!upnpEnabled)
            issues.Add("NO_UPNP");
        
        if (sipAlgDetected)
            issues.Add("SIP_ALG");

        // Определяем итоговый статус
        if (packetLoss > 10 || avgPing > 100)
            return "BAD";
        
        if (issues.Count >= 3)
            return "WARNING";
        
        if (issues.Count > 0)
            return "ISSUES_DETECTED";

        return "OK";
    }

    // ==================== UNIT TESTS ====================
    
    #region Unit Tests Support
    
    /// <summary>
    /// Тестовый метод для проверки DetermineStatus
    /// </summary>
    public static string TestDetermineStatus(double avgPing, double maxPing, int packetLoss, 
                                            bool upnpEnabled, bool sipAlgDetected)
    {
        return DetermineStatus(avgPing, maxPing, packetLoss, upnpEnabled, sipAlgDetected);
    }
    
    /// <summary>
    /// Тестовый метод для проверки CheckSipAlg
    /// </summary>
    public static bool TestCheckSipAlg(string gatewayIp)
    {
        return CheckSipAlg(gatewayIp);
    }
    
    #endregion
    
    #region Unit Tests
    
    /// <summary>
    /// Unit Test: Проверка определения BAD статуса при высоком packet loss
    /// </summary>
    public static void UnitTest_DetermineStatus_BadPacketLoss()
    {
        string status = TestDetermineStatus(50, 100, 15, true, false);
        bool passed = status == "BAD";
        
        Console.WriteLine($"[TEST] DetermineStatus_BadPacketLoss: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: BAD, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения BAD статуса при высоком пинге
    /// </summary>
    public static void UnitTest_DetermineStatus_BadPing()
    {
        string status = TestDetermineStatus(150, 200, 2, true, false);
        bool passed = status == "BAD";
        
        Console.WriteLine($"[TEST] DetermineStatus_BadPing: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: BAD, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения WARNING статуса при множественных проблемах
    /// </summary>
    public static void UnitTest_DetermineStatus_Warning()
    {
        string status = TestDetermineStatus(60, 150, 7, false, true);
        bool passed = status == "WARNING";
        
        Console.WriteLine($"[TEST] DetermineStatus_Warning: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: WARNING, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения ISSUES_DETECTED статуса
    /// </summary>
    public static void UnitTest_DetermineStatus_Issues()
    {
        string status = TestDetermineStatus(40, 100, 3, false, false);
        bool passed = status == "ISSUES_DETECTED";
        
        Console.WriteLine($"[TEST] DetermineStatus_Issues: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: ISSUES_DETECTED, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка определения OK статуса
    /// </summary>
    public static void UnitTest_DetermineStatus_OK()
    {
        string status = TestDetermineStatus(10, 50, 0, true, false);
        bool passed = status == "OK";
        
        Console.WriteLine($"[TEST] DetermineStatus_OK: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  Expected: OK, Got: {status}");
    }
    
    /// <summary>
    /// Unit Test: Проверка детекции SIP ALG для consumer роутеров
    /// </summary>
    public static void UnitTest_CheckSipAlg_ConsumerRouter()
    {
        bool test1 = TestCheckSipAlg("192.168.0.1");  // Consumer router
        bool test2 = TestCheckSipAlg("192.168.1.1");  // Consumer router
        bool test3 = TestCheckSipAlg("10.0.0.1");     // ISP router
        bool test4 = TestCheckSipAlg("172.16.0.1");   // Corporate router
        
        bool passed = test1 && test2 && test3 && !test4;
        Console.WriteLine($"[TEST] CheckSipAlg_ConsumerRouter: {(passed ? "PASS" : "FAIL")}");
        Console.WriteLine($"  192.168.0.1: {test1}, 192.168.1.1: {test2}");
        Console.WriteLine($"  10.0.0.1: {test3}, 172.16.0.1: {test4}");
    }
    
    /// <summary>
    /// Unit Test: Проверка пограничных случаев для пинга и packet loss
    /// </summary>
    public static void UnitTest_DetermineStatus_EdgeCases()
    {
        // Ровно на границе HIGH_PING (50ms)
        string status1 = TestDetermineStatus(50, 100, 0, true, false);
        
        // Ровно на границе PING_SPIKES (200ms)
        string status2 = TestDetermineStatus(30, 200, 0, true, false);
        
        // Ровно на границе PACKET_LOSS (5%)
        string status3 = TestDetermineStatus(20, 50, 5, true, false);
        
        bool passed1 = status1 == "ISSUES_DETECTED";
        bool passed2 = status2 == "ISSUES_DETECTED";
        bool passed3 = status3 == "OK"; // 5% на границе, не считается проблемой
        
        Console.WriteLine($"[TEST] DetermineStatus_EdgeCases: {(passed1 && passed2 && passed3 ? "PASS" : "FAIL")}");
        Console.WriteLine($"  50ms ping: {status1} (expected ISSUES_DETECTED)");
        Console.WriteLine($"  200ms spike: {status2} (expected ISSUES_DETECTED)");
        Console.WriteLine($"  5% loss: {status3} (expected OK)");
    }
    
    /// <summary>
    /// Запускает все unit тесты RouterTest
    /// </summary>
    public static void RunAllUnitTests()
    {
        Console.WriteLine("========== RouterTest Unit Tests ==========");
        UnitTest_DetermineStatus_BadPacketLoss();
        UnitTest_DetermineStatus_BadPing();
        UnitTest_DetermineStatus_Warning();
        UnitTest_DetermineStatus_Issues();
        UnitTest_DetermineStatus_OK();
        UnitTest_CheckSipAlg_ConsumerRouter();
        UnitTest_DetermineStatus_EdgeCases();
        Console.WriteLine("===========================================");
    }
    
    #endregion
}
