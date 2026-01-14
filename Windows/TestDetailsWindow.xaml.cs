using System.Linq;
using System.Windows;
using IspAudit.Core.Diagnostics;
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

            // Парсим детали (в т.ч. форматы без разделителей '|')
            ParseDetails(testResult.Details);

            // Fallback: если по деталям ничего не распарсилось, не показываем "UNKNOWN" при успешном статусе карточки.
            if (Status == TestStatus.Pass)
            {
                if (DnsStatus == BlockageCode.StatusUnknown) DnsStatus = BlockageCode.StatusOk;
                if (TcpStatus == BlockageCode.StatusUnknown) TcpStatus = BlockageCode.StatusOk;
                if (TlsStatus == BlockageCode.StatusUnknown) TlsStatus = BlockageCode.StatusOk;
            }
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

                // Вариант 1: канонический формат с '|'
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
                    // Вариант 2: формат без '|', но с маркерами DNS/TCP/TLS
                    if (rawDetails.Contains("DNS:") || rawDetails.Contains("TCP:") || rawDetails.Contains("TLS:"))
                    {
                        DnsStatus = ParseCheckStatus(rawDetails, "DNS");
                        TcpStatus = ParseCheckStatus(rawDetails, "TCP");
                        TlsStatus = ParseCheckStatus(rawDetails, "TLS");

                        // Попробуем вытащить код блокировки (последний токен ALL_CAPS / с подчёркиваниями)
                        var lastToken = rawDetails.Trim().Split(' ').LastOrDefault() ?? string.Empty;
                        var normalized = BlockageCode.Normalize(lastToken) ?? lastToken;
                        Diagnosis = GetDiagnosisText(normalized);
                        Recommendation = GetRecommendationText(normalized);
                    }
                    else
                    {
                        // Совсем другой формат: оставляем статусы UNKNOWN, но даём понятный диагноз.
                        Diagnosis = "Не удалось определить точную причину.";
                    }
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
            if (input.Contains($"{checkName}:✓")) return BlockageCode.StatusOk;
            if (input.Contains($"{checkName}:✗")) return BlockageCode.StatusFail;
            return BlockageCode.StatusUnknown;
        }

        private string GetDiagnosisText(string code)
        {
            var normalized = BlockageCode.Normalize(code) ?? code;
            return normalized switch
            {
                // TLS_AUTH_FAILURE — это наблюдаемый факт: TLS рукопожатие завершилось ошибкой аутентификации.
                // Это НЕ доказательство DPI.
                BlockageCode.TlsAuthFailure => "TLS рукопожатие завершилось ошибкой аутентификации (auth failure). Это может быть связано с прокси/антивирусом/фильтрацией, но не доказывает DPI.",
                BlockageCode.TcpConnectionReset => "Соединение было сброшено удалённой стороной/сетью (TCP reset).",
                BlockageCode.TcpRstInjection => "Соединение сброшено (RST Injection). Обнаружено активное вмешательство DPI.",
                BlockageCode.HttpRedirectDpi => "Подмена ответа (HTTP Redirect). Провайдер перенаправляет на страницу-заглушку.",
                BlockageCode.TcpRetryHeavy => "Критическая потеря пакетов. Вероятно, DPI отбрасывает пакеты (Blackhole).",
                BlockageCode.UdpBlockage => "Блокировка UDP/QUIC протокола. Игровой трафик или современные веб-протоколы недоступны.",
                BlockageCode.DnsFiltered => "DNS-запрос был перехвачен или заблокирован провайдером.",
                BlockageCode.DnsBogus => "DNS вернул некорректный IP-адрес (заглушку).",
                BlockageCode.TcpConnectTimeout => "TCP connect не завершился за таймаут (сервер/сеть не отвечает).",
                BlockageCode.TcpConnectTimeoutConfirmed => "Повторяющийся таймаут TCP connect (сервер/сеть недоступны или фильтрация).",
                BlockageCode.TlsHandshakeTimeout => "TLS рукопожатие не завершилось за таймаут.",
                BlockageCode.PortClosed => "Порт закрыт на удаленном сервере. Это не блокировка провайдера.",
                BlockageCode.FakeIp => "Используется служебный IP-адрес (198.18.x.x). Трафик маршрутизируется через VPN или локальный шлюз.",
                _ => $"Неизвестная ошибка ({code})"
            };
        }

        private string GetRecommendationText(string code)
        {
            var normalized = BlockageCode.Normalize(code) ?? code;
            return normalized switch
            {
                BlockageCode.TlsAuthFailure => "Проверьте прокси/антивирус/системное время. Если проблема повторяется — попробуйте VPN или другой DNS.",
                BlockageCode.TcpConnectionReset or BlockageCode.TcpRstInjection => "Рекомендуется включить защиту от RST-пакетов (Drop RST).",
                BlockageCode.HttpRedirectDpi => "Попробуйте использовать стратегии обхода HTTP (Fake Request).",
                BlockageCode.TcpRetryHeavy => "Попробуйте использовать фрагментацию или смену IP.",
                BlockageCode.UdpBlockage => "Для обхода блокировок UDP/QUIC обычно требуется VPN. Если это веб-сайт, попробуйте TLS-стратегии (браузер перейдет на TCP).",
                BlockageCode.DnsFiltered or BlockageCode.DnsBogus => "Рекомендуется использовать DoH (DNS over HTTPS).",
                BlockageCode.TcpConnectTimeout or BlockageCode.TcpConnectTimeoutConfirmed or BlockageCode.TlsHandshakeTimeout => "Попробуйте использовать VPN или прокси.",
                BlockageCode.FakeIp => "Это нормальное поведение при использовании VPN или средств обхода блокировок.",
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
        public string DnsStatus { get; private set; } = BlockageCode.StatusUnknown; // OK, FAIL, UNKNOWN
        public string TcpStatus { get; private set; } = BlockageCode.StatusUnknown;
        public string TlsStatus { get; private set; } = BlockageCode.StatusUnknown;
        public string Diagnosis { get; private set; } = "";
        public string Recommendation { get; private set; } = "";

        public bool HasError => !string.IsNullOrEmpty(Error);
        public bool HasFallbackIp => !string.IsNullOrEmpty(FallbackIp);
        public bool HasDetails => !string.IsNullOrEmpty(Details);
        public bool HasDiagnosis => !string.IsNullOrEmpty(Diagnosis);
        
        // Helpers for UI binding
        public bool IsDnsOk => DnsStatus == BlockageCode.StatusOk;
        public bool IsTcpOk => TcpStatus == BlockageCode.StatusOk;
        public bool IsTlsOk => TlsStatus == BlockageCode.StatusOk;
        public bool IsDnsFail => DnsStatus == BlockageCode.StatusFail;
        public bool IsTcpFail => TcpStatus == BlockageCode.StatusFail;
        public bool IsTlsFail => TlsStatus == BlockageCode.StatusFail;
    }
}
