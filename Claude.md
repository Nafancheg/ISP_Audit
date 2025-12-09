# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Сборка и запуск

**Требуется .NET 9 SDK**

### Основные команды сборки
```bash
# Отладочная сборка
dotnet build -c Debug

# Release-сборка single-file exe для Windows
dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true /p:PublishTrimmed=false -o ./publish

# Быстрый запуск GUI в отладочном режиме
dotnet run
```

### GitHub Actions
Workflow `.github/workflows/build.yml` автоматически собирает `ISP_Audit.exe` и публикует артефакт при пуше.

## Архитектура приложения

### Точка входа и режимы работы
- **Program.cs**: Основной entry point.
  - Запускает GUI-режим (WPF + Material Design)
  - Консоль скрывается через Win32 API
  - Запускается `App.xaml` (WPF Application)

### Основные компоненты

**Config.cs**: Конфигурация запуска приложения.

**DiagnosticOrchestrator.cs**: Главный контроллер режима "Live Audit".
- Управляет жизненным циклом мониторинговых сервисов (`ConnectionMonitor`, `NetworkMonitor`).
- Координирует сбор трафика (`TrafficCollector`) и тестирование (`LiveTestingPipeline`).
- Обрабатывает события от пассивных анализаторов (`UdpInspectionService`, `RstInspectionService`) и запускает ретесты.

**LiveTestingPipeline.cs**: Конвейер обработки обнаруженных хостов.
- **Sniffer**: Получает новые хосты от `TrafficCollector` или по сигналу `ForceRetest`.
- **Tester**: Выполняет активные проверки (DNS, TCP, TLS).
- **Classifier**: Определяет тип блокировки на основе результатов тестов и сигналов от пассивных анализаторов.
- **Bypass**: Подбирает стратегии обхода.

**GUI (WPF + MaterialDesignInXaml)**:
- **App.xaml**: Настройка Material Design темы (Light, PrimaryColor=Blue, SecondaryColor=Cyan)
- **MainWindow.xaml**: Основное окно с Material Design компонентами:
  - **Bypass Control Panel**: Панель с кнопками стратегий (`TLS_FRAGMENT`, `TLS_DISORDER`, `TLS_FAKE`, `DROP_RST`, `DOH`).
  - Карточки (materialDesign:Card) для предупреждений (красная) и успеха (зелёная)
  - Большая кнопка "ПРОВЕРИТЬ" с тенью (MaterialDesignRaisedButton)
  - Список сервисов (ItemsControl) с прогресс-индикаторами и иконками статусов
  - Прогресс-бар внизу
- **MainWindow.xaml.cs**: Code-behind с MVVM-паттерном
- **Windows/OverlayWindow.xaml**: Компактное окно статуса (AlwaysOnTop), отображаемое во время Live Testing.
  - Показывает время сессии и количество соединений.
  - При отсутствии активности (60с) переключается в режим таймера с предложением завершить диагностику.
- **Wpf/ServiceItemViewModel.cs**: ViewModel для элементов списка сервисов (INotifyPropertyChanged)
- Старый WinForms GUI сохранён в `GuiForm.cs.old` для истории

### Структура тестов (Tests/)
Каждый тест независимый и содержит свою логику:
- **DnsTest.cs**: System DNS через `Dns.GetHostAddresses()` + DoH запросы к Cloudflare (1.1.1.1), сравнение результатов, эвристика "мусорных" IP (0.0.0.0, 127.x, 10.x, 192.168.x)
- **TcpTest.cs**: TCP-подключения с 1-2 повторными попытками
- **HttpTest.cs**: HTTP(S) запросы с SNI, извлечение CN сертификата через `X509Certificate2`
- **TracerouteTest.cs**: Запуск системного `tracert.exe`, парсинг stdout построчно, фикс кодировки (OEM866)
- **UdpProbeRunner.cs**: UDP-зонды (DNS на 1.1.1.1:53 с парсингом ответа, Raw UDP пакеты на игровые шлюзы)
- **RstHeuristic.cs**: Эвристика RST-инжекции по таймингам (без pcap)

### Эвристика анализа (MainViewModel)
- **AnalyzeHeuristicSeverity**: Фильтрация ложных срабатываний `TLS_DPI`.
  - Инфраструктурные домены (Microsoft, Azure, Analytics) понижаются до статуса `WARN`.
  - Проверка "родственных" сервисов: если основной домен доступен, ошибки на субдоменах считаются некритичными.

### Обход блокировок (Bypass/)
- **WinDivertBypassManager.cs**: Менеджер WinDivert-драйвера для фильтрации пакетов
  - Дроп входящих/исходящих TCP RST
  - Фрагментация TLS ClientHello (Fragment, Disorder)
  - Fake TTL пакеты
  - Опциональная переадресация трафика (UDP/TCP) по правилам
- **BypassProfile.cs**: Конфигурация правил обхода из `bypass_profile.json`
- **WinDivertNative.cs**: P/Invoke обёртка для WinDivert.dll
- **BypassCoordinator.cs**: Координатор стратегий, управляет логикой Auto-Retest (автоматическая перепроверка при смене стратегии).

**Требования**: WinDivert.dll + права администратора. GUI показывает предупреждение и разблокирует кнопку активации только после обнаружения проблем в диагностике.

### Каталог целей и профили
- **TargetCatalog.cs**: Загружает цели из `star_citizen_targets.json` (или использует fallback). Содержит:
  - Предустановленные цели Star Citizen (портал RSI, лаунчер, CDN, игровые шлюзы EU/US/AUS)
  - Список TCP-портов (80, 443, 8000-8020)
  - UDP-пробы для DNS и игровых шлюзов
- **TargetModels.cs**: Модели данных (`TargetDefinition`, `UdpProbeDefinition`)

### Вывод отчётов (Output/)
- **ReportWriter.cs**: Генерация JSON-отчётов, человекочитаемого вывода, HTML/PDF экспорта
  - `BuildSummary()`: Агрегирует статусы (DNS, TCP, TLS, UDP, RST)
  - `PrintHuman()`: Консольный вывод с рекомендациями
  - Экспорт в HTML/PDF для технической поддержки
- **UdpProbeResult.cs**: Модель результата UDP-пробы

### Утилиты (Utils/)
- **NetUtils.cs**: Получение внешнего IP через ifconfig.me
- **GuiProfileStorage.cs**: Сохранение/загрузка профилей диагностики (*.iaprofile) - цели, порты, включённые тесты
- **FlowMonitorService.cs**: Мониторинг сетевой активности процесса. Использует **Гибридную Архитектуру**:
  - **WinDivert Flow Layer**: Для пассивного анализа (Diag Mode).
  - **TcpConnectionWatcher (IP Helper)**: Для активного режима (Bypass Mode), чтобы избежать конфликтов драйвера с RST-блокером.
  - **WinDivert Socket Layer**: Для отслеживания *попыток* соединения (`connect()`), даже если они блокируются.
  - Приоритет драйвера `-1000` (мониторинг не влияет на прохождение трафика).
- **DnsParserService.cs**: Сниффинг DNS-трафика (UDP 53) для сопоставления IP-адресов с доменными именами.
- **TrafficAnalyzer.cs**: Оркестратор захвата трафика. Использует все 3 слоя WinDivert (Flow/Socket/Network) для построения полного профиля целей. Объединяет данные от FlowMonitor, DnsParser и PidTracker.

## Важные файлы данных

- **star_citizen_targets.json**: Каталог целей Star Citizen и предустановки
- **bypass_profile.json**: Конфигурация правил обхода (копируется в output при сборке)
- **isp_report.json**: Выходной JSON-отчёт с результатами всех тестов

## Паттерны кода

### Асинхронность
Все сетевые операции асинхронные (`async/await`). Используется `ConfigureAwait(false)` для избежания захвата контекста.

### Прогресс и отмена
- `IProgress<TestProgress>` для отчётов о прогрессе в GUI
- `CancellationToken` для прерывания длительных операций (traceroute, HTTP-таймауты)

### Traceroute кодировка
Системный `tracert.exe` выводит в OEM866 (кириллица). Фиксится через:
```csharp
process.StandardOutput.CurrentEncoding = Encoding.GetEncoding(866);
```

### Статусы тестов
- **DNS**: `OK`, `WARN`, `DNS_FILTERED`, `DNS_BOGUS` (см. README.md раздел "Правила определения статусов")
- **TCP**: `OK` если хотя бы один порт открыт, иначе `FAIL`
- **TLS**: `SUSPECT` если 443 открыт но HTTPS не проходит, `OK` на 2xx/3xx, `FAIL` иначе
- **UDP**: `OK`/`FAIL`/`INFO` в зависимости от expectReply и результата

## Тестирование

Проект не содержит автоматических тестов. Тестирование выполняется вручную:
1. Запуск GUI и проверка всех сценариев
2. CLI-тесты с разными параметрами
3. Проверка JSON-отчётов на корректность структуры

## Особенности Windows

- **Single-file exe**: Приложение собирается в один .exe файл с embedded runtime (~164MB)
- **WPF + MaterialDesignInXaml**: Современный GUI с Material Design (MaterialDesignThemes 5.1.0)
- **Hybrid WPF+WinForms**: UseWPF=true + UseWindowsForms=true (WinForms нужен для TextRenderer в ReportWriter)
- **Console hiding**: При GUI-запуске консоль скрывается через `ShowWindow(hWnd, 0)`
- **Material Design Theme**: Light theme, Blue primary, Cyan secondary colors

## Безопасность

- Не требуются права администратора для базовой диагностики
- Обход блокировок (WinDivert) требует admin и включается только вручную
- Внешние запросы: только ifconfig.me для получения external IP и DoH к 1.1.1.1
- Локальное хранение отчётов, никуда не загружается без явного флага
