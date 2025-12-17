using System.Windows;
using IspAudit.Models;

namespace IspAudit.Windows
{
    public partial class TestDetailsWindow : Window
    {
        public TestDetailsWindow(TestResult testResult)
        {
            InitializeComponent();
            DataContext = new TestDetailsViewModel(testResult);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }

    public class TestDetailsViewModel
    {
        public TestDetailsViewModel(TestResult testResult)
        {
            TargetName = testResult.Target?.Name ?? "Неизвестно";
            Host = testResult.Target?.Host ?? "N/A";
            Status = testResult.Status;
            StatusText = testResult.StatusText;
            Error = testResult.Error ?? "";
            FallbackIp = testResult.Target?.FallbackIp ?? "";
            
            // Парсим детали
            ParseDetails(testResult.Details);
        }

        private void ParseDetails(string? rawDetails)
        {
            if (string.IsNullOrEmpty(rawDetails))
            {
                Details = "Детальная информация недоступна";
                return;
            }

            // Сохраняем сырые данные для отладки
            Details = rawDetails;

            // Пытаемся распарсить строку вида:
            // ❌ li-in-f156.1e100.net:443 (166ms) | DNS:✓ TCP:✓ TLS:✗ | TLS_AUTH_FAILURE
            try
            {
                var parts = rawDetails.Split('|');
                if (parts.Length >= 3)
                {
                    // Part 1: Host info
                    // "❌ li-in-f156.1e100.net:443 (166ms) "
                    var hostPart = parts[0].Trim();
                    // Убираем иконку статуса
                    if (hostPart.StartsWith("❌") || hostPart.StartsWith("✓"))
                        hostPart = hostPart.Substring(2).Trim();
                    
                    // Извлекаем latency если есть
                    if (hostPart.Contains("(") && hostPart.Contains("ms)"))
                    {
                        var start = hostPart.LastIndexOf('(');
                        var end = hostPart.LastIndexOf("ms)");
                        if (start != -1 && end != -1)
                        {
                            Latency = hostPart.Substring(start + 1, end - start - 1) + " мс";
                        }
                    }

                    // Part 2: Checks
                    // " DNS:✓ TCP:✓ TLS:✗ "
                    var checksPart = parts[1].Trim();
                    DnsStatus = ParseCheckStatus(checksPart, "DNS");
                    TcpStatus = ParseCheckStatus(checksPart, "TCP");
                    TlsStatus = ParseCheckStatus(checksPart, "TLS");

                    // Part 3: Diagnosis code
                    // " TLS_AUTH_FAILURE (fails: 1...)"
                    var codePart = parts[2].Trim();
                    
                    // Отделяем код от суффикса с деталями
                    var code = codePart;
                    if (codePart.Contains('('))
                    {
                        var idx = codePart.IndexOf('(');
                        code = codePart.Substring(0, idx).Trim();
                    }

                    Diagnosis = GetDiagnosisText(code);
                    Recommendation = GetRecommendationText(code);
                }
                else
                {
                    // Fallback parsing logic if format is different
                    Diagnosis = "Не удалось определить точную причину.";
                }
            }
            catch
            {
                Diagnosis = "Ошибка разбора данных теста.";
            }
        }

        private string ParseCheckStatus(string input, string checkName)
        {
            // Ищем "DNS:✓" или "DNS:✗"
            if (input.Contains($"{checkName}:✓")) return "OK";
            if (input.Contains($"{checkName}:✗")) return "FAIL";
            return "UNKNOWN";
        }

        private string GetDiagnosisText(string code)
        {
            return code switch
            {
                // TLS_AUTH_FAILURE — это наблюдаемый факт: TLS рукопожатие завершилось ошибкой аутентификации.
                // Это НЕ доказательство DPI.
                "TLS_AUTH_FAILURE" or "TLS_DPI" => "TLS рукопожатие завершилось ошибкой аутентификации (auth failure). Это может быть связано с прокси/антивирусом/фильтрацией, но не доказывает DPI.",
                "TCP_CONNECTION_RESET" or "TCP_RST" => "Соединение было сброшено удалённой стороной/сетью (TCP reset).",
                "TCP_RST_INJECTION" => "Соединение сброшено (RST Injection). Обнаружено активное вмешательство DPI.",
                "HTTP_REDIRECT_DPI" => "Подмена ответа (HTTP Redirect). Провайдер перенаправляет на страницу-заглушку.",
                "TCP_RETRY_HEAVY" => "Критическая потеря пакетов. Вероятно, DPI отбрасывает пакеты (Blackhole).",
                "UDP_BLOCKAGE" => "Блокировка UDP/QUIC протокола. Игровой трафик или современные веб-протоколы недоступны.",
                "DNS_FILTERED" => "DNS-запрос был перехвачен или заблокирован провайдером.",
                "DNS_BOGUS" => "DNS вернул некорректный IP-адрес (заглушку).",
                "TCP_CONNECT_TIMEOUT" or "TCP_TIMEOUT" => "TCP connect не завершился за таймаут (сервер/сеть не отвечает).",
                "TCP_CONNECT_TIMEOUT_CONFIRMED" or "TCP_TIMEOUT_CONFIRMED" => "Повторяющийся таймаут TCP connect (сервер/сеть недоступны или фильтрация).",
                "TLS_HANDSHAKE_TIMEOUT" or "TLS_TIMEOUT" => "TLS рукопожатие не завершилось за таймаут.",
                "PORT_CLOSED" => "Порт закрыт на удаленном сервере. Это не блокировка провайдера.",
                "FAKE_IP" => "Используется служебный IP-адрес (198.18.x.x). Трафик маршрутизируется через VPN или локальный шлюз.",
                _ => $"Неизвестная ошибка ({code})"
            };
        }

        private string GetRecommendationText(string code)
        {
            return code switch
            {
                "TLS_AUTH_FAILURE" or "TLS_DPI" => "Проверьте прокси/антивирус/системное время. Если проблема повторяется — попробуйте VPN или другой DNS.",
                "TCP_CONNECTION_RESET" or "TCP_RST" or "TCP_RST_INJECTION" => "Рекомендуется включить защиту от RST-пакетов (Drop RST).",
                "HTTP_REDIRECT_DPI" => "Попробуйте использовать стратегии обхода HTTP (Fake Request).",
                "TCP_RETRY_HEAVY" => "Попробуйте использовать фрагментацию или смену IP.",
                "UDP_BLOCKAGE" => "Для обхода блокировок UDP/QUIC обычно требуется VPN. Если это веб-сайт, попробуйте TLS-стратегии (браузер перейдет на TCP).",
                "DNS_FILTERED" or "DNS_BOGUS" => "Рекомендуется использовать DoH (DNS over HTTPS).",
                "TCP_CONNECT_TIMEOUT" or "TCP_CONNECT_TIMEOUT_CONFIRMED" or "TCP_TIMEOUT" or "TCP_TIMEOUT_CONFIRMED" or "TLS_HANDSHAKE_TIMEOUT" or "TLS_TIMEOUT" => "Попробуйте использовать VPN или прокси.",
                "FAKE_IP" => "Это нормальное поведение при использовании VPN или средств обхода блокировок.",
                _ => "Попробуйте использовать средства обхода блокировок."
            };
        }

        public string TargetName { get; }
        public string Host { get; }
        public TestStatus Status { get; }
        public string StatusText { get; }
        public string Error { get; }
        public string FallbackIp { get; }
        public string Details { get; private set; } = "";
        
        // New parsed properties
        public string Latency { get; private set; } = "-";
        public string DnsStatus { get; private set; } = "UNKNOWN"; // OK, FAIL, UNKNOWN
        public string TcpStatus { get; private set; } = "UNKNOWN";
        public string TlsStatus { get; private set; } = "UNKNOWN";
        public string Diagnosis { get; private set; } = "";
        public string Recommendation { get; private set; } = "";

        public bool HasError => !string.IsNullOrEmpty(Error);
        public bool HasFallbackIp => !string.IsNullOrEmpty(FallbackIp);
        public bool HasDetails => !string.IsNullOrEmpty(Details);
        public bool HasDiagnosis => !string.IsNullOrEmpty(Diagnosis);
        
        // Helpers for UI binding
        public bool IsDnsOk => DnsStatus == "OK";
        public bool IsTcpOk => TcpStatus == "OK";
        public bool IsTlsOk => TlsStatus == "OK";
        public bool IsDnsFail => DnsStatus == "FAIL";
        public bool IsTcpFail => TcpStatus == "FAIL";
        public bool IsTlsFail => TlsStatus == "FAIL";
    }
}
