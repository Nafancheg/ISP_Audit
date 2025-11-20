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

            Console.WriteLine("Старт цикла запросов (60 секунд)...\n");

            var startTime = DateTime.UtcNow;
            int successCount = 0;
            int failCount = 0;

            while ((DateTime.UtcNow - startTime).TotalSeconds < 60)
            {
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

                    // Проверка времени
                    if ((DateTime.UtcNow - startTime).TotalSeconds >= 60)
                        break;
                }

                Console.WriteLine($"\n--- Статистика: {successCount} OK, {failCount} FAIL ---\n");
                
                // Пауза перед следующим циклом
                await Task.Delay(2000);
            }

            Console.WriteLine("\n=== Тестирование завершено ===");
            Console.WriteLine($"Всего успешных: {successCount}");
            Console.WriteLine($"Всего ошибок: {failCount}");
            Console.WriteLine("\nНажмите любую клавишу для выхода...");
            Console.ReadKey();
        }
    }
}
