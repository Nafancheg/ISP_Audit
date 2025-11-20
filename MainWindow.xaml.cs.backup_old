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
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Diagnostics;
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
    private bool _dnsFixed = false; // Флаг для отслеживания применения DNS Fix
    private string? _selectedProfileName; // Выбранный профиль в ComboBox

    public MainWindow()
    {
        InitializeComponent();
        InitializeServices();
        ServicesPanel.ItemsSource = _services;
        
        // Загрузить доступные профили в ComboBox
        LoadAvailableProfiles();
        
        // Установить название активного профиля
        if (Config.ActiveProfile != null)
        {
            ProfileNameText.Text = $"Активный профиль: {Config.ActiveProfile.Name}";
        }
        else
        {
            ProfileNameText.Text = "Активный профиль: Не загружен";
        }
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

            // Сбросить флаг DNS Fix при новой проверке
            _dnsFixed = false;

            WarningCard.Visibility = Visibility.Collapsed;
            SuccessCard.Visibility = Visibility.Collapsed;
            VpnInfoCard.Visibility = Visibility.Collapsed;
            FirewallCard.Visibility = Visibility.Collapsed;
            IspCard.Visibility = Visibility.Collapsed;
            RouterCard.Visibility = Visibility.Collapsed;
            SoftwareCard.Visibility = Visibility.Collapsed;
            FixDnsButton.Visibility = Visibility.Collapsed;
            ResetDnsButton.Visibility = Visibility.Collapsed;

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
            
            // Использовать цели из активного профиля (если загружен), иначе fallback на Program.Targets
            if (Config.ActiveProfile != null && Config.ActiveProfile.Targets.Count > 0)
            {
                // Конвертируем цели профиля в TargetDefinition
                config.TargetMap = Config.ActiveProfile.Targets.ToDictionary(
                    t => t.Name,
                    t => new TargetDefinition
                    {
                        Name = t.Name,
                        Host = t.Host,
                        Service = t.Service,
                        Critical = t.Critical,
                        FallbackIp = t.FallbackIp
                    },
                    StringComparer.OrdinalIgnoreCase
                );
            }
            else
            {
                // Fallback: использовать старые цели из Program.Targets
                config.TargetMap = Program.Targets.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.OrdinalIgnoreCase);
            }
            
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

        if (progress.Kind == TestKind.FIREWALL)
        {
            if (message.Contains("BLOCKING"))
                return "Windows Firewall блокирует игровые порты. Добавьте Star Citizen в исключения.";
            else if (message.Contains("OK"))
                return "Firewall не блокирует игровые порты.";
        }

        if (progress.Kind == TestKind.ISP)
        {
            if (message.Contains("DPI") || message.Contains("CGNAT") || message.Contains("FILTERED"))
                return "Обнаружены проблемы провайдера (DPI/CGNAT/DNS фильтрация). Рекомендуется VPN.";
            else if (message.Contains("OK"))
                return "Провайдер не создаёт проблем для игры.";
        }

        if (progress.Kind == TestKind.ROUTER)
        {
            if (message.Contains("HIGH_PING") || message.Contains("PACKET_LOSS") || message.Contains("SIP_ALG"))
                return "Обнаружены проблемы с роутером (высокий пинг, потеря пакетов, SIP ALG). Проверьте настройки.";
            else if (message.Contains("OK"))
                return "Роутер работает корректно.";
        }

        if (progress.Kind == TestKind.SOFTWARE)
        {
            if (message.Contains("CONFLICTS") || message.Contains("ANTIVIRUS") || message.Contains("HOSTS"))
                return "Обнаружены конфликтующие программы (антивирус/VPN/hosts). Добавьте игру в исключения.";
            else if (message.Contains("OK"))
                return "Конфликтующее ПО не обнаружено.";
        }

        return progress.Message ?? string.Empty;
    }

    private void UpdateProgress(TestProgress p)
    {
        StatusText.Text = "Запуск диагностики...";

        string? targetName = ExtractTargetName(p.Status);
        if (targetName == null)
        {
            // Aggregate UDP progress line - detect by Kind (status is "Cloudflare DNS: старт")
            if (p.Kind == TestKind.UDP)
            {
                var udpService = _services.FirstOrDefault(s => s.ServiceName.Contains("DNS (UDP)") || s.ServiceName.Contains("Публичный DNS"));
                if (udpService != null)
                {
                    if (p.Status.Contains("старт", StringComparison.OrdinalIgnoreCase))
                    {
                        udpService.SetRunning("Проверка UDP");
                        udpService.DetailedMessage = string.Empty;
                    }
                    else if (p.Status.Contains("завершено", StringComparison.OrdinalIgnoreCase))
                    {
                        bool success = p.Success ?? true;
                        udpService.SetSuccess(success ? "✓ Успех" : "✗ Ошибка");
                        udpService.DetailedMessage = GetUserFriendlyMessage(p);
                    }
                    else if (p.Status.Contains("сводка", StringComparison.OrdinalIgnoreCase))
                    {
                        // Final UDP summary
                        bool success = p.Success ?? true;
                        udpService.SetSuccess(success ? "✓ Успех" : "✗ Ошибка");
                        udpService.Details = p.Message ?? "Проверка завершена";
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
                TestKind.FIREWALL => "Проверка Firewall",
                TestKind.ISP => "Проверка провайдера",
                TestKind.ROUTER => "Проверка роутера",
                TestKind.SOFTWARE => "Проверка ПО",
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

        // Скрыть все карточки перед новым отображением
        WarningCard.Visibility = Visibility.Collapsed;
        SuccessCard.Visibility = Visibility.Collapsed;
        FirewallCard.Visibility = Visibility.Collapsed;
        IspCard.Visibility = Visibility.Collapsed;
        RouterCard.Visibility = Visibility.Collapsed;
        SoftwareCard.Visibility = Visibility.Collapsed;
        FixDnsButton.Visibility = Visibility.Collapsed;
        ResetDnsButton.Visibility = Visibility.Collapsed;

        // Определить DNS статус для управления видимостью кнопок
        bool hasDnsProblems = summary.dns == "DNS_FILTERED" || summary.dns == "DNS_BOGUS";
        
        // Управление видимостью кнопок DNS
        if (hasDnsProblems && !_dnsFixed)
        {
            // Показать кнопку "ИСПРАВИТЬ DNS" если есть проблемы и DNS ещё не исправлен
            FixDnsButton.Visibility = Visibility.Visible;
        }
        else if (_dnsFixed)
        {
            // Показать кнопку "ВЕРНУТЬ DNS" если DNS был исправлен ранее
            ResetDnsButton.Visibility = Visibility.Visible;
        }

        // Показать карточки для каждого типа проблем
        bool hasProblems = false;

        // Firewall проблемы — показывать если Status != "OK"
        if (report.firewall != null && 
            !string.Equals(report.firewall.Status, "OK", StringComparison.OrdinalIgnoreCase))
        {
            hasProblems = true;
            FirewallCard.Visibility = Visibility.Visible;
            FirewallText.Text = BuildFirewallMessage(report.firewall);
        }

        // ISP проблемы — показывать если Status != "OK"
        if (report.isp != null && 
            !string.Equals(report.isp.Status, "OK", StringComparison.OrdinalIgnoreCase))
        {
            hasProblems = true;
            IspCard.Visibility = Visibility.Visible;
            IspText.Text = BuildIspMessage(report.isp);
        }

        // Router проблемы — показывать если Status != "OK"
        if (report.router != null && 
            !string.Equals(report.router.Status, "OK", StringComparison.OrdinalIgnoreCase))
        {
            hasProblems = true;
            RouterCard.Visibility = Visibility.Visible;
            RouterText.Text = BuildRouterMessage(report.router);
        }

        // Software проблемы — показывать если Status != "OK"
        if (report.software != null && 
            !string.Equals(report.software.Status, "OK", StringComparison.OrdinalIgnoreCase))
        {
            hasProblems = true;
            SoftwareCard.Visibility = Visibility.Visible;
            SoftwareText.Text = BuildSoftwareMessage(report.software);
        }

        // Итоговый вердикт — ВСЕГДА показывать
        VerdictCard.Visibility = Visibility.Visible;
        string adviceText = ReportWriter.BuildAdviceText(report, _lastConfig);
        VerdictText.Text = adviceText;

        // Цвет карточки зависит от playable
        if (summary.playable == "NO")
            VerdictCard.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(244, 67, 54)); // Красный
        else if (summary.playable == "MAYBE")
            VerdictCard.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 152, 0)); // Оранжевый
        else if (summary.playable == "YES")
            VerdictCard.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(76, 175, 80)); // Зелёный
        else
            VerdictCard.Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(33, 150, 243)); // Синий

        // Общая карточка предупреждений (для старых проблем DNS/TCP/TLS)
        bool hasLegacyProblems = !string.Equals(summary.playable, "YES", StringComparison.OrdinalIgnoreCase);
        
        if (hasLegacyProblems && !hasProblems)
        {
            WarningCard.Visibility = Visibility.Visible;

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

        // Показать успех только если нет проблем
        if (!hasProblems && !hasLegacyProblems)
        {
            SuccessCard.Visibility = Visibility.Visible;
        }

        StatusText.Text = (hasProblems || hasLegacyProblems)
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

    /// <summary>
    /// Проверяет доступность DoH провайдеров (Cloudflare, Google, Quad9)
    /// </summary>
    /// <returns>Tuple (IP, DoH URL) первого доступного провайдера или null если все недоступны</returns>
    private async Task<(string Ip, string Url)?> CheckDohProviderAvailability()
    {
        var providers = new[]
        {
            (Ip: "1.1.1.1", Url: "https://cloudflare-dns.com/dns-query"),
            (Ip: "8.8.8.8", Url: "https://dns.google/dns-query"),
            (Ip: "9.9.9.9", Url: "https://dns.quad9.net/dns-query")
        };

        foreach (var provider in providers)
        {
            try
            {
                using var cts = new CancellationTokenSource(5000); // 5 сек таймаут
                using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                
                // Простая HEAD запрос к DoH endpoint для проверки доступности
                var request = new HttpRequestMessage(HttpMethod.Head, provider.Url);
                var response = await httpClient.SendAsync(request, cts.Token).ConfigureAwait(false);
                
                if (response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.MethodNotAllowed)
                {
                    // Провайдер доступен (успех или 405 Method Not Allowed - тоже признак работы)
                    return provider;
                }
            }
            catch
            {
                // Провайдер недоступен, пробуем следующий
                continue;
            }
        }

        return null; // Все провайдеры недоступны
    }

    /// <summary>
    /// Обработчик кнопки "ИСПРАВИТЬ DNS"
    /// </summary>
    private async void FixDnsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StatusText.Text = "Проверка доступности DoH провайдеров...";
            
            var provider = await CheckDohProviderAvailability();
            
            if (provider == null)
            {
                System.Windows.MessageBox.Show(
                    "Не удалось найти доступный DoH провайдер.\n\n" +
                    "Возможно, ваше интернет-соединение полностью заблокировано или DoH сервисы недоступны.",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                StatusText.Text = "DoH провайдеры недоступны";
                return;
            }

            StatusText.Text = $"Применение DNS: {provider.Value.Ip}...";

            // Определить имя активного сетевого адаптера
            string? activeInterface = GetActiveNetworkInterface();
            
            if (activeInterface == null)
            {
                System.Windows.MessageBox.Show(
                    "Не удалось определить активный сетевой адаптер.",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                StatusText.Text = "Не удалось определить сетевой адаптер";
                return;
            }

            // Команды netsh для установки DNS и включения DoH
            var commands = new[]
            {
                $"netsh interface ipv4 set dns name=\"{activeInterface}\" static {provider.Value.Ip} primary",
                $"netsh interface ipv4 add dns name=\"{activeInterface}\" {provider.Value.Ip} index=2", // Резервный
                $"netsh dns add encryption server={provider.Value.Ip} dohtemplate={provider.Value.Url} autoupgrade=yes udpfallback=no"
            };

            // Создать батник для запуска с правами администратора
            string tempBatch = Path.Combine(Path.GetTempPath(), "fix_dns_temp.bat");
            await File.WriteAllTextAsync(tempBatch, string.Join("\r\n", commands)).ConfigureAwait(false);

            // Запустить с UAC
            var psi = new ProcessStartInfo
            {
                FileName = tempBatch,
                UseShellExecute = true,
                Verb = "runas", // Запрос UAC
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            var process = Process.Start(psi);
            if (process != null)
            {
                await Task.Run(() => process.WaitForExit()).ConfigureAwait(false);
                
                // Удалить временный батник
                try { File.Delete(tempBatch); } catch { }

                Dispatcher.Invoke(() =>
                {
                    System.Windows.MessageBox.Show(
                        $"DNS успешно изменён на {provider.Value.Ip}.\n\n" +
                        "DoH (DNS-over-HTTPS) включен.\n\n" +
                        "Для применения изменений может потребоваться перезапуск браузера/игры.",
                        "Успех",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    StatusText.Text = "DNS изменён успешно";
                    
                    // Установить флаг и обновить видимость кнопок
                    _dnsFixed = true;
                    FixDnsButton.Visibility = Visibility.Collapsed;
                    ResetDnsButton.Visibility = Visibility.Visible;
                });
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Пользователь отменил UAC
            System.Windows.MessageBox.Show(
                "Для изменения DNS требуются права администратора.",
                "Отменено",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            StatusText.Text = "Изменение DNS отменено";
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                $"Ошибка при изменении DNS:\n{ex.Message}",
                "Ошибка",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            StatusText.Text = "Ошибка при изменении DNS";
        }
    }

    /// <summary>
    /// Обработчик кнопки "ВЕРНУТЬ DNS"
    /// </summary>
    private async void ResetDnsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StatusText.Text = "Восстановление DHCP DNS...";

            // Определить имя активного сетевого адаптера
            string? activeInterface = GetActiveNetworkInterface();
            
            if (activeInterface == null)
            {
                System.Windows.MessageBox.Show(
                    "Не удалось определить активный сетевой адаптер.",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                StatusText.Text = "Не удалось определить сетевой адаптер";
                return;
            }

            // Команды netsh для восстановления DHCP DNS и отключения DoH
            var commands = new[]
            {
                $"netsh interface ipv4 set dns name=\"{activeInterface}\" dhcp",
                $"netsh dns delete encryption server=1.1.1.1",
                $"netsh dns delete encryption server=8.8.8.8",
                $"netsh dns delete encryption server=9.9.9.9"
            };

            // Создать батник для запуска с правами администратора
            string tempBatch = Path.Combine(Path.GetTempPath(), "reset_dns_temp.bat");
            await File.WriteAllTextAsync(tempBatch, string.Join("\r\n", commands)).ConfigureAwait(false);

            // Запустить с UAC
            var psi = new ProcessStartInfo
            {
                FileName = tempBatch,
                UseShellExecute = true,
                Verb = "runas", // Запрос UAC
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            var process = Process.Start(psi);
            if (process != null)
            {
                await Task.Run(() => process.WaitForExit()).ConfigureAwait(false);
                
                // Удалить временный батник
                try { File.Delete(tempBatch); } catch { }

                Dispatcher.Invoke(() =>
                {
                    System.Windows.MessageBox.Show(
                        "DNS восстановлен на автоматические настройки (DHCP).\n\n" +
                        "DoH отключен.\n\n" +
                        "Для применения изменений может потребоваться перезапуск браузера/игры.",
                        "Успех",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                    StatusText.Text = "DNS восстановлен";
                    
                    // Сбросить флаг и обновить видимость кнопок
                    _dnsFixed = false;
                    ResetDnsButton.Visibility = Visibility.Collapsed;
                    FixDnsButton.Visibility = Visibility.Collapsed; // Скрыть обе, пока не будет новой проверки
                });
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Пользователь отменил UAC
            System.Windows.MessageBox.Show(
                "Для восстановления DNS требуются права администратора.",
                "Отменено",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            StatusText.Text = "Восстановление DNS отменено";
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                $"Ошибка при восстановлении DNS:\n{ex.Message}",
                "Ошибка",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            StatusText.Text = "Ошибка при восстановлении DNS";
        }
    }

    /// <summary>
    /// Определяет имя активного сетевого адаптера (не VPN, не виртуальный)
    /// </summary>
    private static string? GetActiveNetworkInterface()
    {
        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
                .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .ToList();

            // Фильтровать VPN адаптеры по названию/описанию
            var physicalInterfaces = interfaces
                .Where(ni =>
                {
                    var name = (ni.Name ?? string.Empty).ToLowerInvariant();
                    var desc = (ni.Description ?? string.Empty).ToLowerInvariant();
                    
                    // Исключить VPN адаптеры
                    bool isVpn = name.Contains("vpn") || desc.Contains("vpn") ||
                                 desc.Contains("wintun") || desc.Contains("wireguard") ||
                                 desc.Contains("openvpn") || desc.Contains("tap-") ||
                                 desc.Contains("tun") || desc.Contains("ikev2");
                    
                    return !isVpn;
                })
                .ToList();

            // Предпочесть Ethernet перед Wi-Fi
            var ethernet = physicalInterfaces.FirstOrDefault(ni => 
                ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                ni.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet);
            
            if (ethernet != null)
                return ethernet.Name;

            // Если нет Ethernet, взять Wi-Fi
            var wireless = physicalInterfaces.FirstOrDefault(ni =>
                ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211);
            
            if (wireless != null)
                return wireless.Name;

            // Если ничего не найдено, взять первый доступный
            return physicalInterfaces.FirstOrDefault()?.Name;
        }
        catch
        {
            return null;
        }
    }

    private string BuildFirewallMessage(FirewallTestResult firewall)
    {
        var lines = new List<string>();
        
        if (firewall.WindowsFirewallEnabled)
            lines.Add("• Windows Firewall активен");
        
        if (firewall.BlockedPorts.Count > 0)
            lines.Add($"• Заблокированы порты: {string.Join(", ", firewall.BlockedPorts)}");
        
        if (firewall.BlockingRules.Count > 0)
            lines.Add($"• Блокирующие правила: {firewall.BlockingRules.Count} шт.");
        
        if (firewall.WindowsDefenderActive)
            lines.Add("• Windows Defender активен (может блокировать игру)");
        
        lines.Add("\nРекомендация: добавьте Star Citizen в исключения Windows Firewall и Defender.");
        lines.Add("Инструкция: Панель управления → Windows Defender Firewall → Дополнительные параметры → Правила для исходящих подключений → Создать правило (Разрешить TCP 8000-8020, 80, 443)");
        
        return string.Join("\n", lines);
    }

    private string BuildIspMessage(IspTestResult isp)
    {
        var lines = new List<string>();
        
        if (!string.IsNullOrEmpty(isp.Isp))
            lines.Add($"Провайдер: {isp.Isp} ({isp.Country ?? "неизвестно"})");
        
        if (isp.DpiDetected)
        {
            lines.Add("• DPI (Deep Packet Inspection) обнаружен — провайдер фильтрует трафик");
            lines.Add("  Это означает: провайдер модифицирует ваши HTTPS-запросы");
        }
        
        if (isp.DnsFiltered)
        {
            lines.Add("• DNS фильтрация активна — запросы подменяются");
            lines.Add("  Это означает: провайдер возвращает другие IP-адреса для заблокированных сайтов");
        }
        
        if (isp.CgnatDetected)
        {
            lines.Add("• CGNAT обнаружен — прямое подключение невозможно");
            lines.Add("  Это означает: ваш IP находится за общим NAT провайдера (100.64.0.0/10)");
        }
        
        if (isp.KnownProblematicISPs.Count > 0)
            lines.Add($"• Проблемный провайдер: {string.Join(", ", isp.KnownProblematicISPs)}");
        
        lines.Add("\nРекомендация:");
        if (isp.DpiDetected || isp.DnsFiltered)
            lines.Add("• Используйте VPN (NordVPN, ProtonVPN, ExpressVPN) для обхода DPI/фильтрации");
        if (isp.CgnatDetected)
            lines.Add("• Свяжитесь с провайдером для получения «белого» IP-адреса (может быть платно)");
        if (isp.DnsFiltered)
            lines.Add("• Смените DNS на Cloudflare (1.1.1.1) или Google (8.8.8.8)");
        
        return string.Join("\n", lines);
    }

    private string BuildRouterMessage(RouterTestResult router)
    {
        var lines = new List<string>();
        
        if (!router.UpnpEnabled)
        {
            lines.Add("• UPnP отключен — автоматическая проброска портов невозможна");
            lines.Add("  Это означает: игра не сможет автоматически открыть порты для мультиплеера");
        }
        
        if (router.SipAlgDetected)
        {
            lines.Add("• SIP ALG активен — может блокировать голосовой чат (Vivox)");
            lines.Add("  Это означает: функция роутера, которая ломает VoIP-трафик");
        }
        
        if (router.PacketLossPercent > 10)
            lines.Add($"• Потеря пакетов: {router.PacketLossPercent:F1}% — плохое качество связи");
        
        if (router.AvgPingMs > 100)
            lines.Add($"• Высокий пинг: {router.AvgPingMs:F0} мс — медленная связь");
        
        lines.Add("\nРекомендация:");
        if (!router.UpnpEnabled)
            lines.Add("• Включите UPnP в настройках роутера (обычно в разделе «Сеть» или «Дополнительно»)");
        if (router.SipAlgDetected)
            lines.Add("• Отключите SIP ALG в настройках роутера (обычно в разделе «NAT» или «Advanced»)");
        if (router.PacketLossPercent > 10 || router.AvgPingMs > 100)
            lines.Add("• Проверьте кабель Ethernet, перезагрузите роутер, свяжитесь с провайдером");
        
        return string.Join("\n", lines);
    }

    private string BuildSoftwareMessage(SoftwareTestResult software)
    {
        var lines = new List<string>();
        
        if (software.AntivirusDetected.Count > 0)
        {
            lines.Add($"• Обнаружены антивирусы: {string.Join(", ", software.AntivirusDetected)}");
            lines.Add("  Антивирусы могут блокировать игровые порты и процессы");
        }
        
        if (software.VpnClientsDetected.Count > 0)
        {
            lines.Add($"• Обнаружены VPN клиенты: {string.Join(", ", software.VpnClientsDetected)}");
            lines.Add("  (Это НЕ проблема — VPN помогает обходить блокировки)");
        }
        
        if (software.ProxyEnabled)
        {
            lines.Add("• Системный прокси активен");
            lines.Add("  Может перенаправлять трафик и вызывать проблемы");
        }
        
        if (software.HostsFileIssues)
        {
            lines.Add("• В hosts файле обнаружены записи для RSI доменов");
            lines.Add($"  Записи: {string.Join(", ", software.HostsFileEntries)}");
            lines.Add("  Это может БЛОКИРОВАТЬ доступ к сайту и лаунчеру");
        }
        
        lines.Add("\nРекомендация:");
        if (software.AntivirusDetected.Count > 0)
            lines.Add("• Добавьте Star Citizen в исключения антивируса (обычно в настройках «Исключения» или «Exclusions»)");
        if (software.HostsFileIssues)
            lines.Add("• Откройте hosts файл (C:\\Windows\\System32\\drivers\\etc\\hosts) с правами администратора и удалите строки с RSI доменами");
        if (software.ProxyEnabled)
            lines.Add("• Отключите системный прокси: Настройки → Сеть и интернет → Прокси → Отключить");
        
        return string.Join("\n", lines);
    }

    private void LoadAvailableProfiles()
    {
        try
        {
            ProfileComboBox.Items.Clear();
            
            string profilesDir = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Profiles");
            if (!Directory.Exists(profilesDir))
            {
                // Если папки нет, создать её
                Directory.CreateDirectory(profilesDir);
                return;
            }
            
            var jsonFiles = Directory.GetFiles(profilesDir, "*.json");
            foreach (var file in jsonFiles)
            {
                string profileName = System.IO.Path.GetFileNameWithoutExtension(file);
                ProfileComboBox.Items.Add(profileName);
            }
            
            // Выбрать активный профиль, если он установлен
            if (Config.ActiveProfile != null)
            {
                ProfileComboBox.SelectedItem = Config.ActiveProfile.Name;
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Ошибка загрузки профилей: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ProfileComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (ProfileComboBox.SelectedItem != null)
        {
            _selectedProfileName = ProfileComboBox.SelectedItem.ToString();
            ApplyProfileButton.IsEnabled = true;
        }
        else
        {
            _selectedProfileName = null;
            ApplyProfileButton.IsEnabled = false;
        }
    }

    private void ApplyProfileButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_selectedProfileName))
        {
            System.Windows.MessageBox.Show("Выберите профиль из списка", "Применить профиль", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        
        try
        {
            // Загрузить профиль
            Config.SetActiveProfile(_selectedProfileName);
            
            // Обновить отображение
            if (Config.ActiveProfile != null)
            {
                ProfileNameText.Text = $"Активный профиль: {Config.ActiveProfile.Name}";
                
                // Очистить результаты предыдущего теста
                ClearResults();
                
                // Переинициализировать список сервисов под новый профиль
                InitializeServices();
                
                System.Windows.MessageBox.Show($"Профиль '{_selectedProfileName}' применён", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Ошибка применения профиля: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ClearResults()
    {
        // Скрыть все карточки
        WarningCard.Visibility = Visibility.Collapsed;
        SuccessCard.Visibility = Visibility.Collapsed;
        FirewallCard.Visibility = Visibility.Collapsed;
        IspCard.Visibility = Visibility.Collapsed;
        RouterCard.Visibility = Visibility.Collapsed;
        SoftwareCard.Visibility = Visibility.Collapsed;
        VerdictCard.Visibility = Visibility.Collapsed;
        VpnInfoCard.Visibility = Visibility.Collapsed;
        FixDnsButton.Visibility = Visibility.Collapsed;
        ResetDnsButton.Visibility = Visibility.Collapsed;
        
        // Очистить список сервисов
        foreach (var service in _services)
        {
            service.Details = "Ожидание старта";
            service.DetailedMessage = "";
        }
        
        // Сбросить флаги
        _lastRun = null;
        _lastConfig = null;
        _dnsFixed = false;
        
        // Обновить статус
        try { PlayableText.Text = "Играбельно: —"; } catch { }
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
