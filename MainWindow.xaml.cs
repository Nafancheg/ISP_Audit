using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using Microsoft.Win32;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Globalization;
using System.Windows.Data;
using IspAudit.Tests;
using IspAudit.Wpf;
using IspAudit.Output;

namespace IspAudit;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ServiceItemViewModel> _services = new();
    private CancellationTokenSource? _cts;
    private bool _isRunning;
    private RunReport? _lastRun;
    private Config? _lastConfig;

    public MainWindow()
    {
        InitializeComponent();
        InitializeServices();
        ServicesPanel.ItemsSource = _services;
    }

    private void InitializeServices()
    {
        _services.Clear();

        foreach (var target in Program.Targets.Values)
        {
            string displayName = string.IsNullOrWhiteSpace(target.Service)
                ? target.Name
                : $"{target.Name} ({target.Service})";

            _services.Add(new ServiceItemViewModel
            {
                ServiceName = displayName,
                Details = "Ожидание старта"
            });
        }

        _services.Add(new ServiceItemViewModel
        {
            ServiceName = "Публичный DNS (UDP)",
            Details = "Ожидание старта"
        });
    }

    private async void RunButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning)
        {
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
            RunButton.Content = "ОСТАНОВИТЬ";
            RunButton.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(244, 67, 54)); // Red

            WarningCard.Visibility = Visibility.Collapsed;
            SuccessCard.Visibility = Visibility.Collapsed;
            VpnInfoCard.Visibility = Visibility.Collapsed;

            foreach (var service in _services)
            {
                service.IsRunning = false;
                service.IsCompleted = false;
                service.Details = "Ожидание старта";
            }

            ProgressBar.Value = 0;
            if (SaveButton != null) SaveButton.IsEnabled = false;
            StatusText.Text = "Запуск диагностики...";

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
            config.UdpTimeoutSeconds = 2;
            // Авто-детект VPN профиля для снижения ложных срабатываний
            bool vpnActive = false;
            try
            {
                vpnActive = IspAudit.Utils.NetUtils.LikelyVpnActive();
                config.Profile = vpnActive ? "vpn" : "normal";
                if (vpnActive)
                {
                    // Адаптивные таймауты для VPN (туннелирование медленнее)
                    config.HttpTimeoutSeconds = 12;
                    config.TcpTimeoutSeconds = 8;
                    config.UdpTimeoutSeconds = 4;
                }
            }
            catch { config.Profile = "normal"; }

            // Показать VPN-баннер если VPN активен
            VpnInfoCard.Visibility = vpnActive ? Visibility.Visible : Visibility.Collapsed;

            var progress = new Progress<TestProgress>(p =>
            {
                UpdateProgress(p);
            });

            var report = await AuditRunner.RunAsync(config, progress, _cts.Token);

            _lastRun = report;
            _lastConfig = config;
            if (SaveButton != null) SaveButton.IsEnabled = true;

            ShowResults(report);
        }
        catch (OperationCanceledException){ StatusText.Text = "Диагностика остановлена";
        }
        catch (Exception ex){ StatusText.Text = $"Ошибка: {ex.Message}";
            System.Windows.MessageBox.Show($"Внутренняя ошибка:\n{ex.Message}", "Ошибка",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _isRunning = false;
            RunButton.Content = "ПРОВЕРИТЬ";
            RunButton.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 150, 243)); // Blue
            ProgressBar.Value = 100;
        }
    }

    /// <summary>
    /// Преобразует технические статусы в понятные сообщения для пользователей
    /// </summary>
    private string GetUserFriendlyMessage(TestProgress progress)
    {
        var message = progress.Message?.ToUpperInvariant() ?? "";

        if (progress.Kind == TestKind.DNS)
        {
            if (message.Contains("DNS_FILTERED"))
                return "Системный DNS и защищённый DNS вернули разные адреса. Провайдер может подменять запросы.";
            else if (message.Contains("DNS_BOGUS"))
                return "DNS возвращает некорректные адреса (0.0.0.0 или локальные). Система блокирует доступ.";
            else if (message.Contains("WARN"))
                return "Адреса DNS не полностью совпадают. Это может быть нормально при VPN или кэшировании.";
            else if (message.Contains("OK"))
                return "DNS работает корректно. Сервисы доступны.";
            else if (message.Contains("ПРОПУЩЕНО") || message.Contains("SKIPPED"))
                return "DNS-проверка пропущена (сервис не требует проверки).";
        }

        if (progress.Kind == TestKind.TCP)
        {
            if (message.Contains("ЗАКРЫТО") || message.Contains("ВСЕ ЗАКРЫТО") || message.Contains("CLOSED"))
                return "Все проверенные TCP-порты закрыты. Сервис недоступен — проверьте фаервол или блокировку провайдером.";
            else if (message.Contains("НАЙДЕН") || message.Contains("ОТКРЫТЫ") || message.Contains("OPEN"))
                return "Порты доступны. TCP-соединение устанавливается успешно.";
            else if (message.Contains("ПРОПУЩЕНО") || message.Contains("SKIPPED"))
                return "TCP-проверка пропущена (DNS не вернул адресов или проверка отключена).";
        }

        if (progress.Kind == TestKind.HTTP)
        {
            if (message.Contains("2XX") || message.Contains("3XX") || message.Contains("200") || message.Contains("301"))
                return "HTTPS-соединение работает. Сервер отвечает корректно.";
            else if (message.Contains("ТАЙМАУТ") || message.Contains("TIMEOUT"))
                return "HTTPS-запрос истёк по времени. Сервер может быть перегружен или недоступен.";
            else if (message.Contains("ОШИБКИ") || message.Contains("ERROR") || message.Contains("MITM") || message.Contains("BLOCK"))
                return "HTTPS-запрос не прошёл. Возможен перехват или блокировка трафика.";
            else if (message.Contains("ПРОПУЩЕНО") || message.Contains("SKIPPED"))
                return "HTTPS-проверка пропущена (не требуется для этого сервиса).";
        }

        if (progress.Kind == TestKind.UDP)
        {
            if (progress.Success == true)
                return "UDP-пакет доставлен успешно. Канал работает.";
            else if (progress.Success == false)
                return "UDP-проверка не прошла. Нет ответа или ошибка доставки.";
        }

        return progress.Message ?? string.Empty;
    }

    private void UpdateProgress(TestProgress p)
    {
        StatusText.Text = "Запуск диагностики...";

        string? targetName = ExtractTargetName(p.Status);
        if (targetName == null)
        {
            // Aggregate UDP progress line (no target name in status)
            if (p.Status.Contains("UDP", StringComparison.OrdinalIgnoreCase))
            {
                var udpService = _services.FirstOrDefault(s => s.ServiceName.Contains("DNS (UDP)") || s.ServiceName.Contains("Публичный DNS"));
                if (udpService != null)
                {
                    if (p.Status.Contains("Старт", StringComparison.OrdinalIgnoreCase) || p.Status.Contains("Запуск", StringComparison.OrdinalIgnoreCase) || p.Status.Contains("Start", StringComparison.OrdinalIgnoreCase))
                    {
                        udpService.SetRunning("Проверка UDP");
                        udpService.DetailedMessage = string.Empty;
                    }
                    else if (p.Status.Contains("Завершено", StringComparison.OrdinalIgnoreCase) || p.Status.Contains("Complete", StringComparison.OrdinalIgnoreCase))
                    {
                        bool success = p.Success ?? true;
                        udpService.SetSuccess(success ? "✓ Успех" : "✗ Ошибка");
                        // Установить подробное понятное сообщение для пользователя
                        udpService.DetailedMessage = GetUserFriendlyMessage(p);
                    }
                }
            }
            return;
        }

        var service = _services.FirstOrDefault(s =>
            s.ServiceName.Contains(targetName, StringComparison.OrdinalIgnoreCase));
        if (service == null) return;

        if (p.Status.Contains("Старт", StringComparison.OrdinalIgnoreCase) || p.Status.Contains("Запуск", StringComparison.OrdinalIgnoreCase) || p.Status.Contains("Start", StringComparison.OrdinalIgnoreCase))
        {
            string testDesc = p.Kind switch
            {
                TestKind.DNS => "Проверка DNS",
                TestKind.TCP => "Проверка TCP",
                TestKind.HTTP => "Проверка HTTPS",
                TestKind.UDP => "Проверка UDP",
                _ => "Проверка"
            };
            service.SetRunning(testDesc);
            service.DetailedMessage = string.Empty;
        }
        else if (p.Status.Contains("Завершено", StringComparison.OrdinalIgnoreCase) ||
                 p.Status.Contains("Complete", StringComparison.OrdinalIgnoreCase))
        {
            if (p.Success == null)
            {
                service.SetRunning("ℹ Информационно");
            }
            else if (p.Success == true)
            {
                service.SetSuccess("✓ Успех");
            }
            else
            {
                service.SetError("✗ Ошибка");
            }
            // Установить подробное понятное сообщение для пользователя
            service.DetailedMessage = GetUserFriendlyMessage(p);
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
        var summary = ReportWriter.BuildSummary(report, _lastConfig);

        // Обновить отдельный вердикт
        try { PlayableText.Text = BuildPlayableLabel(summary.playable); } catch { }

        // Показываем зелёную карточку только при PLAYABLE=YES.
        // Всё остальное (NO/MAYBE/UNKNOWN) считаем проблемным состоянием для баннера.
        bool hasProblems = !string.Equals(summary.playable, "YES", StringComparison.OrdinalIgnoreCase);

        if (hasProblems)
        {
            WarningCard.Visibility = Visibility.Visible;
            SuccessCard.Visibility = Visibility.Collapsed;

            var warnings = new System.Collections.Generic.List<string>();

            if (summary.dns == "DNS_FILTERED" || summary.dns == "DNS_BOGUS")
                warnings.Add("• Проблема DNS: системный резолвер возвращает некорректные ответы");
            if (summary.tcp_portal == "FAIL")
                warnings.Add("• RSI Portal (80/443) недоступен — авторизация невозможна");
            else if (summary.tcp_portal == "WARN")
                warnings.Add("• RSI Portal (80/443) частично доступен — возможны перебои");
            if (summary.tcp_launcher == "FAIL")
                warnings.Add("• Лаунчер (8000–8020) недоступен — возможны проблемы с обновлением");
            else if (summary.tcp_launcher == "WARN")
                warnings.Add("• Лаунчер (8000–8020) частично доступен — возможны проблемы");
            if (summary.tls == "MITM_SUSPECT")
                warnings.Add("• Подозрение на перехват HTTPS (MITM) — проверьте антивирус/прокси");
            else if (summary.tls == "SUSPECT" || summary.tls == "FAIL")
                warnings.Add("• Проблемы с HTTPS — проверьте фильтры/прокси");

            WarningText.Text = string.Join("\n", warnings) + "\n\n" + BuildUiRecommendation(summary);
        }
        else
        {
            SuccessCard.Visibility = Visibility.Visible;
            WarningCard.Visibility = Visibility.Collapsed;
        }

        StatusText.Text = hasProblems
            ? "Проверка завершена — обнаружены проблемы"
            : "Проверка завершена — всё в порядке!";
    }

    private static string BuildUiRecommendation(Summary s)
    {
        if (s.dns == "DNS_BOGUS" || s.dns == "DNS_FILTERED")
            return "Рекомендация: включите защищённый DNS (DoH/DoT) или смените DNS‑резолвер (Cloudflare/Google/Quad9). VPN — только как обходной вариант.";

        if (s.tcp_portal == "FAIL")
            return "Рекомендация: проверьте доступность портов 80/443 (роутер/фаервол/провайдер). Убедитесь, что HTTPS не блокируется.";

        if (s.tls == "BLOCK_PAGE")
            return "Рекомендация: обнаружена блок‑страница — проверьте региональные ограничения/DPI или используйте альтернативный канал связи.";

        if (s.tls == "MITM_SUSPECT")
            return "Рекомендация: отключите HTTPS‑сканирование в антивирусе/прокси и повторите проверку.";

        if (s.tls == "SUSPECT")
            return "Рекомендация: перебои HTTPS — проверьте фильтры/прокси/фаервол и повторите позже.";

        if (s.tcp_launcher == "FAIL" || s.tcp_launcher == "WARN")
            return "Рекомендация: проверьте UPnP/NAT на роутере и ограничения провайдера для портов лаунчера (8000–8020).";

        // По умолчанию — нейтральная рекомендация без навязывания VPN
        return "Рекомендация: проверьте настройки сети и DNS, затем повторите проверку.";
    }
}

// Сохранение отчёта и отображение вердикта
public partial class MainWindow
{
    private async void SaveReport_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_lastRun == null)
            {
                System.Windows.MessageBox.Show("Нет данных для сохранения", "Сохранить отчёт", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Сохранить отчёт",
                Filter = "JSON (*.json)|*.json|Все файлы (*.*)|*.*",
                FileName = "isp_report.json"
            };
            if (dlg.ShowDialog() == true)
            {
                await ReportWriter.SaveJsonAsync(_lastRun, dlg.FileName);
                System.Windows.MessageBox.Show($"Отчёт сохранён:\n{dlg.FileName}", "Сохранено", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Ошибка сохранения:\n{ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string BuildPlayableLabel(string? playable)
    {
        var v = (playable ?? "UNKNOWN").ToUpperInvariant();
        return v switch
        {
            "YES" => "Играбельно: Да",
            "NO" => "Играбельно: Нет",
            "MAYBE" => "Играбельно: Погранично",
            _ => "Играбельно: —"
        };
    }
}

/// <summary>
/// Конвертер для преобразования строки в видимость (пустая строка = Collapsed)
/// </summary>
public class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
