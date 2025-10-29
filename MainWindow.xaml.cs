using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using IspAudit.Tests;
using IspAudit.Wpf;
using IspAudit.Output;

namespace IspAudit;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ServiceItemViewModel> _services = new();
    private CancellationTokenSource? _cts;
    private bool _isRunning;

    public MainWindow()
    {
        InitializeComponent();
        InitializeServices();
        ServicesPanel.ItemsSource = _services;
    }

    private void InitializeServices()
    {
        _services.Clear();

        // Добавляем сервисы из каталога
        foreach (var target in Program.Targets.Values)
        {
            string displayName = string.IsNullOrWhiteSpace(target.Service)
                ? target.Name
                : $"{target.Name} ({target.Service})";

            _services.Add(new ServiceItemViewModel
            {
                ServiceName = displayName,
                Details = "ожидание проверки"
            });
        }

        // Добавляем UDP проверку базовой сети
        _services.Add(new ServiceItemViewModel
        {
            ServiceName = "Базовая сеть (UDP)",
            Details = "ожидание проверки"
        });
    }

    private async void RunButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning)
        {
            // Отмена
            _cts?.Cancel();
            return;
        }

        await RunAuditAsync();
    }

    private async Task RunAuditAsync()
    {
        _isRunning = true;
        _cts = new CancellationTokenSource();

        try
        {
            // Меняем кнопку на "ОСТАНОВИТЬ"
            RunButton.Content = "ОСТАНОВИТЬ";
            RunButton.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(244, 67, 54)); // Red

            // Скрываем карточки статуса
            WarningCard.Visibility = Visibility.Collapsed;
            SuccessCard.Visibility = Visibility.Collapsed;

            // Сброс статусов
            foreach (var service in _services)
            {
                service.IsRunning = false;
                service.IsCompleted = false;
                service.Details = "ожидание проверки";
            }

            ProgressBar.Value = 0;
            StatusText.Text = "Запуск диагностики...";

            // Создаём конфигурацию
            var config = Config.Default();
            config.TargetMap = Program.Targets.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.OrdinalIgnoreCase);
            config.Targets = config.TargetMap.Values.Select(t => t.Host).Distinct().ToList();
            config.EnableDns = true;
            config.EnableTcp = true;
            config.EnableHttp = true;
            config.EnableUdp = true;
            config.EnableTrace = false;
            config.EnableRst = false;
            config.HttpTimeoutSeconds = 6;
            config.TcpTimeoutSeconds = 5;
            config.UdpTimeoutSeconds = 3;

            // Progress callback
            var progress = new Progress<TestProgress>(p =>
            {
                UpdateProgress(p);
            });

            // Запуск
            var report = await AuditRunner.RunAsync(config, progress, _cts.Token);

            // Показываем результаты
            ShowResults(report);
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Проверка отменена";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Ошибка: {ex.Message}";
            System.Windows.MessageBox.Show($"Произошла ошибка:\n{ex.Message}", "Ошибка",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
        finally
        {
            _isRunning = false;
            RunButton.Content = "ПРОВЕРИТЬ";
            RunButton.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 150, 243)); // Blue
            ProgressBar.Value = 100;
        }
    }

    private void UpdateProgress(TestProgress p)
    {
        // Обновляем статус
        StatusText.Text = p.Status;

        // Извлекаем имя цели из сообщения формата "RSI Портал: старт"
        string? targetName = ExtractTargetName(p.Status);
        if (targetName == null)
        {
            // Обработка UDP проверки базовой сети
            if (p.Status.Contains("UDP", StringComparison.OrdinalIgnoreCase))
            {
                var udpService = _services.FirstOrDefault(s => s.ServiceName.Contains("Базовая сеть"));
                if (udpService != null)
                {
                    if (p.Status.Contains("старт", StringComparison.OrdinalIgnoreCase))
                    {
                        udpService.SetRunning("проверка UDP");
                    }
                    else if (p.Status.Contains("завершено", StringComparison.OrdinalIgnoreCase))
                    {
                        bool success = p.Success ?? true;
                        udpService.SetSuccess(success ? "✓ Работает" : "⚠ Проблемы");
                    }
                }
            }
            return;
        }

        // Ищем соответствующий сервис в списке
        var service = _services.FirstOrDefault(s =>
            s.ServiceName.Contains(targetName, StringComparison.OrdinalIgnoreCase));

        if (service == null) return;

        // Обновляем статус сервиса
        if (p.Status.Contains("старт", StringComparison.OrdinalIgnoreCase))
        {
            string testDesc = p.Kind switch
            {
                TestKind.DNS => "проверка DNS",
                TestKind.TCP => "проверка портов",
                TestKind.HTTP => "проверка HTTPS",
                TestKind.UDP => "проверка UDP",
                _ => "проверка"
            };
            service.SetRunning(testDesc);
        }
        else if (p.Status.Contains("завершено", StringComparison.OrdinalIgnoreCase) ||
                 p.Status.Contains("готово", StringComparison.OrdinalIgnoreCase))
        {
            bool success = p.Success ?? true;
            if (success)
            {
                service.SetSuccess("✓ Работает");
            }
            else
            {
                service.SetError("⚠ Проблемы");
            }
        }
    }

    private static string? ExtractTargetName(string status)
    {
        int colonIndex = status.IndexOf(':');
        if (colonIndex > 0)
            return status.Substring(0, colonIndex).Trim();
        return null;
    }

    private void ShowResults(RunReport report)
    {
        // Анализируем результаты
        var summary = ReportWriter.BuildSummary(report);

        bool hasProblems = summary.dns == "WARN" ||
                          summary.dns == "DNS_FILTERED" ||
                          summary.dns == "DNS_BOGUS" ||
                          summary.tcp == "FAIL" ||
                          summary.tcp_portal == "FAIL" ||
                          summary.tcp_launcher == "FAIL" ||
                          summary.tcp_portal == "WARN" ||
                          summary.tcp_launcher == "WARN" ||
                          summary.tls == "MITM_SUSPECT" ||
                          summary.tls == "SUSPECT" ||
                          summary.tls == "FAIL";

        if (hasProblems)
        {
            WarningCard.Visibility = Visibility.Visible;
            SuccessCard.Visibility = Visibility.Collapsed;

            // Формируем текст предупреждения
            var warnings = new System.Collections.Generic.List<string>();

            if (summary.dns == "DNS_FILTERED" || summary.dns == "DNS_BOGUS")
            {
                warnings.Add("• DNS провайдера возвращает неправильные адреса серверов");
            }
            if (summary.tcp_portal == "FAIL")
            {
                warnings.Add("• RSI Portal (80/443) недоступен — не удастся скачать лаунчер");
            }
            else if (summary.tcp_portal == "WARN")
            {
                warnings.Add("• RSI Portal (80/443) частично доступен — возможны проблемы");
            }
            if (summary.tcp_launcher == "FAIL")
            {
                warnings.Add("• Лаунчер (8000-8020) заблокирован — игра не обновится");
            }
            else if (summary.tcp_launcher == "WARN")
            {
                warnings.Add("• Лаунчер (8000-8020) частично доступен — обновления могут зависать");
            }
            if (summary.tls == "MITM_SUSPECT")
            {
                warnings.Add("• ⚠ КРИТИЧНО: Обнаружена MITM-атака (подмена сертификатов)!");
            }
            else if (summary.tls == "SUSPECT" || summary.tls == "FAIL")
            {
                warnings.Add("• HTTPS-соединения блокируются или изменяются");
            }

            WarningText.Text = string.Join("\n", warnings) +
                "\n\nРекомендация: используйте VPN или включите защищённый DNS (DoH).";
        }
        else
        {
            SuccessCard.Visibility = Visibility.Visible;
            WarningCard.Visibility = Visibility.Collapsed;
        }

        StatusText.Text = hasProblems
            ? "Проверка завершена — обнаружены проблемы"
            : "Проверка завершена — всё работает!";
    }
}
