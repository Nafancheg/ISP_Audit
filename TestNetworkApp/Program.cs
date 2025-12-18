using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Models;
using IspAudit.ViewModels;
using TestNetworkApp.Smoke;

namespace TestNetworkApp
{
    /// <summary>
    /// Простое тестовое приложение для калибровки Traffic Analyzer
    /// Устанавливает HTTP/HTTPS соединения к известным адресам
    /// </summary>
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            // Нужен для CP866/прочих OEM-кодировок на русской Windows.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            if (args.Length > 0 && string.Equals(args[0], "--ui-reducer-smoke", StringComparison.OrdinalIgnoreCase))
            {
                RunUiReducerSmoke();
                return 0;
            }

            if (args.Length > 0 && string.Equals(args[0], "--smoke", StringComparison.OrdinalIgnoreCase))
            {
                // Формат:
                // --smoke [all|infra|pipe|insp|ui|bypass|dpi2] [--no-skip|--strict] [--json <path>]
                var category = "all";
                bool noSkip = false;
                string? jsonOut = null;

                for (int i = 1; i < args.Length; i++)
                {
                    var a = args[i];
                    if (string.Equals(a, "--no-skip", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(a, "--strict", StringComparison.OrdinalIgnoreCase))
                    {
                        noSkip = true;
                        continue;
                    }

                    if (string.Equals(a, "--json", StringComparison.OrdinalIgnoreCase))
                    {
                        if (i + 1 < args.Length)
                        {
                            jsonOut = args[i + 1];
                            i++;
                        }
                        continue;
                    }

                    if (string.Equals(a, "all", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(a, "infra", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(a, "pipe", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(a, "insp", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(a, "ui", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(a, "bypass", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(a, "dpi2", StringComparison.OrdinalIgnoreCase))
                    {
                        category = a;
                        continue;
                    }
                }

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var exitCode = await SmokeRunner.Build(category, new SmokeRunOptions(noSkip, jsonOut)).RunAsync(cts.Token).ConfigureAwait(false);
                return exitCode;
            }

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

            return 0;
        }

        private static void RunUiReducerSmoke()
        {
            Console.WriteLine("=== ISP_Audit UI Reducer Smoke ===\n");

            var mgr = new TestResultsManager();
            mgr.OnLog += s => Console.WriteLine(s);
            mgr.Initialize();

            // Сценарий 1: IP-ключ → DNS-resolve → миграция в hostname.
            // (SNI отсутствует в сообщениях)
            var lines = new[]
            {
                "[Collector] Новое соединение #1: 203.0.113.10:443 (proto=6, pid=1234)",
                "❌ 203.0.113.10:443 | DNS:✓ TCP:✓ TLS:✗ | TLS_HANDSHAKE_TIMEOUT",
                "[Collector] Hostname обновлен: 203.0.113.10 → facebook.com",
                "✓ 203.0.113.10:443 (25ms) SNI=- RDNS=-",

                // Сценарий 2: SNI сразу известен — карточка создаётся по человеко‑понятному ключу.
                "[Collector] Новое соединение #2: 64.233.164.91:443 DNS=1e100.net (proto=6, pid=1234)",
                "[SNI] Detected: 64.233.164.91 -> youtube.com",
                "❌ 64.233.164.91:443 | DNS:✓ TCP:✓ TLS:✗ | TLS_AUTH_FAILURE",
                "✓ 64.233.164.91:443 (18ms) SNI=youtube.com RDNS=1e100.net",
            };

            foreach (var line in lines)
            {
                Console.WriteLine($"> {line}");
                mgr.ParsePipelineMessage(line);
            }

            Console.WriteLine("\n--- Итоговые карточки ---");
            foreach (var r in mgr.TestResults)
            {
                var t = r.Target;
                Console.WriteLine(
                    $"KEY={t.Host} | Status={r.StatusText} | FallbackIp={t.FallbackIp} | SNI={t.SniHost} | RDNS={t.ReverseDnsHost}");
            }

            Console.WriteLine("\nОжидаемое поведение:");
            Console.WriteLine("- facebook.com должен существовать (миграция с IP), а статус при Pass+Fail в окне → 'Нестабильно'.");
            Console.WriteLine("- youtube.com должен быть ключом карточки, а при Fail+Pass в окне → 'Нестабильно'.");
        }

        // Вызов из smoke-раннера без дублирования логики.
        internal static void RunUiReducerSmoke_ForSmokeRunner() => RunUiReducerSmoke();
    }
}
