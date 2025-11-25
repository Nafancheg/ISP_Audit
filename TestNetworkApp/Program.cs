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

            using var handler = new SocketsHttpHandler
            {
                ConnectCallback = async (context, cancellationToken) =>
                {
                    var entry = await System.Net.Dns.GetHostEntryAsync(context.DnsEndPoint.Host, cancellationToken);
                    var ip = Array.Find(entry.AddressList, i => i.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) 
                             ?? entry.AddressList[0];
                    
                    Console.WriteLine($"[DNS] {context.DnsEndPoint.Host} -> {ip}");
                    
                    var socket = new System.Net.Sockets.Socket(ip.AddressFamily, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(ip, context.DnsEndPoint.Port, cancellationToken);
                        return new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            };

            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(2);

            var targets = new[]
            {
                ("https://youtube.com", "YouTube"),
                ("https://discord.com", "Discord"),
                ("https://1.1.1.1", "Cloudflare DNS")
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
                    
                    // Минимальная пауза
                    await Task.Delay(50);
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
            
            // Автоматический выход для использования в пайплайне
            await Task.Delay(1000); 
        }
    }
}
