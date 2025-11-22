using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace TestNetworkApp
{
    /// <summary>
    /// Простое тестовое приложение для калибровки Traffic Analyzer
    /// Устанавливает HTTP/HTTPS соединения к известным адресам
    /// </summary>
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("=== ISP_Audit Test Network Application ===");
            Console.WriteLine($"PID: {Environment.ProcessId}");
            Console.WriteLine("Запуск тестовых сетевых запросов...\n");

            using var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(10);

            var targets = new[]
            {
                ("https://google.com", "Google"),
                ("https://youtube.com", "YouTube"),
                ("https://discord.com", "Discord"),
                ("https://github.com", "GitHub"),
                ("https://api.ipify.org?format=json", "IP Check"),
                ("https://cloudflare.com", "Cloudflare"),
                ("https://1.1.1.1", "Cloudflare DNS"),
            };

            Console.WriteLine("Старт одного цикла запросов...\n");

            int successCount = 0;
            int failCount = 0;

            foreach (var (url, name) in targets)
            {
                try
                {
                    Console.Write($"[{DateTime.Now:HH:mm:ss}] {name,-15} -> ");
                    
                    var response = await client.GetAsync(url);
                    var statusCode = (int)response.StatusCode;
                    
                    Console.ForegroundColor = statusCode >= 200 && statusCode < 300 
                        ? ConsoleColor.Green 
                        : ConsoleColor.Yellow;
                    
                    Console.WriteLine($"{statusCode} {response.StatusCode}");
                    Console.ResetColor();
                    
                    successCount++;
                    
                    // Небольшая пауза между запросами
                    await Task.Delay(500);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"ERROR: {ex.Message}");
                    Console.ResetColor();
                    failCount++;
                }
            }

            Console.WriteLine($"\n--- Статистика: {successCount} OK, {failCount} FAIL ---\n");
            Console.WriteLine("\n=== Тестирование завершено ===");
            Console.WriteLine($"Всего успешных: {successCount}");
            Console.WriteLine($"Всего ошибок: {failCount}");
        }
    }
}
