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

# CLI запуск с параметрами
dotnet run -- --targets youtube.com,discord.com --report result.json --verbose
```

### GitHub Actions
Workflow `.github/workflows/build.yml` автоматически собирает `ISP_Audit.exe` и публикует артефакт при пуше.

## Архитектура приложения

### Точка входа и режимы работы
- **Program.cs**: Основной entry point. Определяет режим работы:
  - Без аргументов или `gui` → GUI-режим (WPF + Material Design)
  - С аргументами → CLI-режим
  - При GUI-запуске консоль скрывается через Win32 API
  - В GUI-режиме запускается `App.xaml` (WPF Application)

### Основные компоненты

**Config.cs**: Парсинг аргументов командной строки и конфигурация запуска. Содержит:
- Таймауты для HTTP/TCP/UDP
- Список целей и портов
- Флаги включения/выключения тестов (EnableDns, EnableTcp, EnableHttp, EnableTrace, EnableUdp, EnableRst)
- Метод `ResolveTargets()` для резолва целей из разных источников (JSON/CSV/список)

**AuditRunner.cs**: Оркестратор выполнения всех тестов. Последовательно запускает:
1. DNS-проверки (System DNS vs DoH)
2. TCP-проверки портов
3. HTTP/HTTPS запросы с SNI
4. Traceroute через системный `tracert.exe`
5. UDP-пробы (DNS и игровые шлюзы)
6. RST-инжекция эвристика

Поддерживает `IProgress<TestProgress>` для GUI и `CancellationToken` для отмены.

**GUI (WPF + MaterialDesignInXaml)**:
- **App.xaml**: Настройка Material Design темы (Light, PrimaryColor=Blue, SecondaryColor=Cyan)
- **MainWindow.xaml**: Основное окно с Material Design компонентами:
  - Карточки (materialDesign:Card) для предупреждений (красная) и успеха (зелёная)
  - Большая кнопка "ПРОВЕРИТЬ" с тенью (MaterialDesignRaisedButton)
  - Список сервисов (ItemsControl) с прогресс-индикаторами и иконками статусов
  - Прогресс-бар внизу
- **MainWindow.xaml.cs**: Code-behind с MVVM-паттерном
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

### Обход блокировок (Bypass/)
- **WinDivertBypassManager.cs**: Менеджер WinDivert-драйвера для фильтрации пакетов
  - Дроп входящих/исходящих TCP RST
  - Фрагментация TLS ClientHello
  - Опциональная переадресация трафика (UDP/TCP) по правилам
- **BypassProfile.cs**: Конфигурация правил обхода из `bypass_profile.json`
- **WinDivertNative.cs**: P/Invoke обёртка для WinDivert.dll

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
- **FlowMonitorService.cs**: Мониторинг сетевой активности процесса. Использует гибридный подход:
  - **WinDivert Flow Layer**: Для отслеживания успешных соединений и сбора статистики (PID, IP, Port).
  - **WinDivert Socket Layer**: Для отслеживания *попыток* соединения (`connect()`), даже если они блокируются фаерволом или провайдером.
  - **TcpConnectionWatcher**: Fallback-режим (polling) через IP Helper API, если драйвер недоступен.
  - Приоритет драйвера `-1000` (мониторинг не влияет на прохождение трафика).
- **DnsParserService.cs**: Сниффинг DNS-трафика (UDP 53) для сопоставления IP-адресов с доменными именами.
- **TrafficAnalyzer.cs**: Оркестратор захвата трафика. Объединяет данные от FlowMonitor, DnsParser и PidTracker для построения профиля целей.

## Важные файлы данных

- **star_citizen_targets.json**: Каталог целей Star Citizen и предустановки
- **bypass_profile.json**: Конфигурация правил обхода (копируется в output при сборке)
- **isp_report.json**: Выходной JSON-отчёт с результатами всех тестов

## Паттерны кода

### Асинхронность
Все сетевые операции асинхронные (`async/await`). Используется `ConfigureAwait(false)` для избежания захвата контекста.

### Прогресс и отмена
- `IProgress<TestProgress>` для отчётов о прогрессе из AuditRunner в GUI
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
