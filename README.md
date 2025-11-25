# ISP_Audit (русская версия)

Автономный однофайловый инструмент для Windows (single‑file, self‑contained .NET 9), который выполняет быстрые сетевые проверки для диагностики поведения провайдера и локальной сети. Поддерживает два режима работы:

1. **Профильная диагностика** — автоматические тесты для известных приложений (Star Citizen, Default)
2. **Exe-сценарий** — анализ трафика произвольного приложения через WinDivert, выявление проблем и автоматическое применение обхода

По умолчанию запускается WPF GUI. CLI доступен при запуске с аргументами.

## Возможности

### Профильная диагностика
- DNS‑подмена/фильтрация (System DNS vs DoH Cloudflare)
- Доступность TCP портов с повторными попытками
- Доступность UDP/QUIC (через UDP‑DNS на 1.1.1.1:53)
- HTTPS/TLS/SNI проверка с X.509 CN extraction
- Трассировка (обёртка над `tracert` с OEM866 кодировкой для русского вывода)
- Эвристика RST‑инжекции (timing-based, без pcap)

### Exe-сценарий (WinDivert-based)
**Stage 1: Анализ трафика**
- **Flow Layer**: Мониторинг установленных соединений (PID mapping)
- **Socket Layer**: Отслеживание попыток подключения (connect) для выявления заблокированных IP
- **Network Layer**: Захват DNS-пакетов и TLS ClientHello для определения хостнеймов
- Гибридное определение hostname: DNS cache → SNI → Reverse DNS
- Генерация профиля с захваченными целями

**Stage 2: Классификация проблем**
- ProblemClassifier: DNS filtering, DPI, firewall detection
- BypassStrategyPlanner: автоматическая генерация bypass стратегий
- Анализ Windows Firewall (заблокированные порты, Defender)
- ISP анализ (CGNAT, DPI, известные блокирующие провайдеры)
- Router проблемы (UPnP, SIP ALG, стабильность ping)
- Software конфликты (антивирусы, VPN, proxy, hosts file)

**Stage 3: Применение обхода**
- DNS Fix Applicator с DoH provider testing (Cloudflare/Google/Quad9/AdGuard)
- netsh integration для DNS changes (требует UAC)
- WinDivert bypass activation (TCP RST drop, TLS fragmentation)
- Реверт изменений одной кнопкой

### Результаты и отчётность
- Человекочитаемый вывод с цветовой индикацией
- Структурированный JSON‑отчёт (`isp_report.json`)
- HTML/PDF экспорт для поддержки
- Умный вердикт playable (YES/NO/MAYBE) для Star Citizen
- Информационные карточки с конкретными рекомендациями

## Сборка

Требуется .NET 9 SDK.

- Отладочная сборка: `dotnet build -c Debug`
- Публикация single‑file: `dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true /p:PublishTrimmed=false -o ./publish`

GitHub Actions workflow: `.github/workflows/build.yml` — собирает `ISP_Audit.exe` и выкладывает артефакт.

## Использование (GUI)

### Профильная диагностика

- Запустите `ISP_Audit.exe` без аргументов — откроется окно
- Выберите сценарий: **Профиль** (Star Citizen/Default) или **Хост** (один домен)
- Верхняя панель:
  - Кнопка `Начать проверку` — запуск тестов
  - Выбор профиля: Star Citizen (launcher, game servers, Vivox) или Default
  - Поле ввода хоста для режима "Хост"
- Центральная область:
  - Карточки результатов с цветовой индикацией (зелёный/красный/жёлтый)
  - Прогресс-бар с текущим статусом
  - Подробности по каждому тесту (DNS, TCP, HTTP, ISP, Router, Firewall)
- Информационные карточки (показываются только при проблемах):
  - **FirewallCard**: блокирующие правила Windows → как исправить
  - **IspCard**: CGNAT, DPI, DNS фильтрация → советы по VPN
  - **RouterCard**: UPnP, SIP ALG, нестабильность → инструкции настройки роутера
  - **SoftwareCard**: конфликтующие антивирусы/VPN/прокси → решения
- Кнопки действий:
  - `Сохранить JSON` — экспорт отчёта
  - `Экспорт HTML/PDF` — наглядный отчёт для поддержки
  - `Скопировать итог` — компактный текст со статусами
  - `Применить исправления` — автоматический DNS fix (появляется при проблемах)
  - `Откатить исправления` — реверт изменений

### Exe-сценарий (требует запуска от администратора)

1. **Выберите "Exe-сценарий"** в главном окне
2. **Обзор** → выберите .exe файл приложения
3. **Stage 1: Анализ трафика**
   - Нажмите "Запустить анализ"
   - Приложение запустится автоматически
   - WinDivert захватывает трафик 30 секунд
   - Прогресс: кэш портов, DNS/SNI парсинг, hostname resolution
   - Результат: профиль с захваченными целями
   - Кнопка "Просмотр результатов" → таблица целей (хост, сервис, критичность)
4. **Stage 2: Диагностика**
   - MessageBox предложит перейти к Stage 2
   - Запускаются полные тесты по захваченным целям
   - Классификация проблем: DNS/Firewall/ISP/Router/Software
   - Результат: список проблем и bypass стратегия
5. **Stage 3: Применение обхода**
   - MessageBox предложит перейти к Stage 3
   - DNS Fix: тест DoH провайдеров → выбор лучшего → netsh apply
   - WinDivert Bypass: активация фильтрации RST, TLS fragmentation
   - Результат: приложение запускается с обходом блокировок

**Калибровочное приложение TestNetworkApp.exe**:
- Тестовый инструмент для проверки захвата трафика
- 7 HTTPS целей: Google, YouTube, Discord, GitHub, Cloudflare, IP API, 1.1.1.1
- 60-секундный цикл HTTP запросов с цветным выводом консоли
- Расположение: `TestNetworkApp\bin\Publish\TestNetworkApp.exe`

## Использование (CLI)

Примеры:

- По умолчанию + сохранить отчёт:  
  `ISP_Audit.exe --report isp_report.json`
- Явные цели и короткий JSON в stdout:  
  `ISP_Audit.exe --targets youtube.com,discord.com --json --report result.json`
- Отключить трассировку и увеличить таймауты:  
  `ISP_Audit.exe --no-trace --timeout 12 --verbose`

Флаги:

- `--targets <file|list>` список через запятую или путь к JSON/CSV
- `--report <path>` путь для JSON‑отчёта (по умолчанию `isp_report.json` в CWD)
- `--timeout <s>` таймаут в секундах (HTTP=12с, TCP/UDP=3с по умолчанию)
- `--ports <list>` список TCP‑портов (по умолчанию `80,443,8000-8020`)
- `--no-trace` отключить вызов системного `tracert`
- `--verbose` подробный лог в консоли
- `--json` вывести короткий JSON‑сводку в stdout
- `--help` показать справку

Цели по умолчанию: инфраструктура Star Citizen — портал и аккаунты (`*.robertsspaceindustries.com`), лаунчер, CDN и игровые шлюзы (`p4*-live.cloudimperiumgames.com`).
Предустановки (домены, TCP и UDP проверки) описаны в файле `star_citizen_targets.json`, который копируется рядом с исполняемым файлом; при необходимости обновите его вручную.

Примечание: при запуске с аргументами всегда используется CLI; без аргументов — открывается GUI.

## Архитектура Exe-сценария

### Компоненты

**TrafficAnalyzer.cs** (WinDivert FLOW + SOCKET + NETWORK layers):
- **Flow Layer (-1000)**: Событийный мониторинг успешных соединений (FLOW_ESTABLISHED) с привязкой к PID
- **Socket Layer (-1000)**: Перехват событий `connect()` (SOCKET_CONNECT) для детекции попыток связи с недоступными хостами
- **Network Layer (0)**: Анализ содержимого пакетов (DNS responses, TLS ClientHello) для обогащения данных
- **Fallback**: Использование IP Helper API (GetExtendedTcpTable) в режиме Bypass для предотвращения конфликтов
- DNS response parsing (UDP port 53) → IP→hostname маппинг
- TLS SNI extraction (TCP port 443 ClientHello) → hostname из HTTPS
- Reverse DNS fallback для IP без DNS/SNI данных
- Генерация GameProfile с TargetDefinition списком

**ProblemClassifier.cs**:
- Анализ TestResult[] → BlockageType классификация
- DNS_FILTERED, DNS_BOGUS, DPI, FIREWALL, ISP_BLOCK детекция
- Критичность проблем (Critical/Medium/Low)

**BypassStrategyPlanner.cs**:
- Генерация BypassProfile на основе классифицированных проблем
- DNS change recommendation (DoH providers)
- WinDivert rules (RST drop, TLS fragmentation, redirect rules)

**DnsFixApplicator.cs**:
- Тестирование DoH провайдеров: Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), AdGuard (94.140.14.14)
- Применение DNS через netsh (требует UAC elevation)
- Сохранение текущих настроек для реверта
- Автоматический rollback через FixHistory.json

**WinDivertBypassManager.cs**:
- Активация/деактивация WinDivert фильтрации
- TCP RST dropping (входящие/исходящие)
- TLS ClientHello fragmentation (на байтах 2-3 после TLS record header)
- Redirect rules из bypass_profile.json
- Безопасное отключение при закрытии приложения

### UI Components (WPF + MaterialDesignInXaml 5.1.0)

**MainWindow.xaml**:
- Сценарий выбор: RadioButton (Профиль/Хост/Exe-сценарий)
- Exe-scenario секция: ExePath TextBox + Browse Button + 3 Stage GroupBoxes
- Material Design Cards для проблем (Visibility.Collapsed по умолчанию)

**MainViewModel.cs** (MVVM):
- Observable properties: ExePath, Stage1/2/3Status, Stage1/2/3Complete
- Commands: BrowseExeCommand, AnalyzeTrafficCommand, DiagnoseCommand, ApplyBypassCommand, ViewStage1ResultsCommand
- Progress<TestProgress> для UI updates
- CancellationToken support

**CapturedTargetsWindow.xaml**:
- DataGrid с колонками: Host, Service, Critical
- Статистика: Total targets, Critical count, Test mode
- Save to JSON button
- Без MaterialDesign зависимостей (базовые WPF стили)

**Controls/**:
- ProgressStepper.xaml: пошаговый прогресс с номерами
- StatusDot.xaml: цветная индикация статуса (зелёный/красный/жёлтый)
- TestCard.xaml: карточка результата теста с Fix button

### Файлы конфигурации

**star_citizen_targets.json**:
```json
{
  "default_targets": [
    {"name": "RSI Portal", "host": "robertsspaceindustries.com", "service": "portal", "ports": [80, 443]},
    {"name": "Game Launcher", "host": "launcher.robertsspaceindustries.com", "service": "launcher", "ports": [80, 443]}
  ],
  "udp_probes": [
    {"name": "Vivox Voice", "host": "vdx5.vivox.com", "port": 443, "kind": "Raw", "expect_reply": false}
  ]
}
```

**Profiles/StarCitizen.json**:
```json
{
  "name": "Star Citizen",
  "testMode": "host",
  "targets": [
    {"name": "Portal", "host": "robertsspaceindustries.com", "critical": true, "service": "portal"},
    {"name": "Launcher", "host": "launcher.robertsspaceindustries.com", "critical": true, "service": "launcher"}
  ]
}
```

**bypass_profile.json**:
```json
{
  "dns_providers": [
    {"name": "Cloudflare", "ip": "1.1.1.1", "priority": 1},
    {"name": "Google", "ip": "8.8.8.8", "priority": 2}
  ],
  "windivert_rules": {
    "drop_rst": true,
    "fragment_tls": true,
    "fragment_position": 2
  },
  "redirect_rules": []
}
```

### Workflow

1. **GUI Initialization**:
   - MainWindow загружает AvailableProfiles
   - Binding к MainViewModel properties
   - Commands инициализируются в конструкторе

2. **Stage 1 Execution**:
   - User: Browse exe → ExePath property update
   - User: Click "Запустить анализ" → RunStage1AnalyzeTrafficAsync()
   - Check: IsAdministrator() → MessageBox if not admin
   - Process.Start(ExePath) → get PID
   - Task.Delay(8000) → wait for connection establishment
   - TrafficAnalyzer.AnalyzeProcessTrafficAsync(pid, 30s)
     - WinDivert.Open(NETWORK layer, Sniff)
     - UpdatePortToPidCache() every 2s
     - ProcessPacket() → DNS/SNI parsing → connections dictionary
     - EnrichWithHostnamesAsync() → DNS cache → SNI → Reverse DNS
     - BuildGameProfile() → group by hostname
   - Save profile to `Profiles/{exeName}_captured.json`
   - MessageBox: "Перейти к Stage 2?" → Yes → RunStage2DiagnoseAsync()

3. **Stage 2 Execution**:
   - Check: _capturedProfile != null → MessageBox if null
   - Create Config from _capturedProfile.Targets
   - Initialize TestResults from targets
   - AuditRunner.RunAsync(config, progress, cancellationToken)
   - ProblemClassifier.ClassifyProblems(testResults) → _detectedProblems
   - BypassStrategyPlanner.PlanBypassStrategy(problems, profile) → _plannedBypass
   - MessageBox: "Перейти к Stage 3?" → Yes → RunStage3ApplyBypassAsync()

4. **Stage 3 Execution**:
   - Check: _detectedProblems != null && _plannedBypass != null
   - If RequiresDnsChange(): DnsFixApplicator.ApplyDnsFixAsync()
     - Test DoH providers (1.1.1.1, 8.8.8.8, 9.9.9.9, 94.140.14.14)
     - Select fastest working provider
     - netsh interface ip set dns (requires UAC)
     - Save original DNS to FixHistory.json
   - If RequiresWinDivert(): WinDivertBypassManager.Enable()
     - Load bypass_profile.json
     - WinDivert.Open(NETWORK layer, no Sniff)
     - Apply rules: drop RST, fragment TLS, redirects
   - Process.Start(ExePath) with bypass active
   - User can disable bypass via GUI button

## Новые диагностические возможности

### Точная диагностика блокировок Star Citizen

Начиная с версии 2025-10-30, ISP_Audit включает специализированные тесты для выявления реальных причин блокировки игры Star Citizen:

**FirewallTest** - Windows блокировки:
- Проверка правил Windows Firewall для игровых портов (8000-8003, 64090-64094)
- Статус Windows Defender
- Детекция блокирующих правил для Star Citizen

**IspTest** - анализ провайдера:
- Определение ISP через внешний IP (ip-api.com)
- CGNAT детекция (диапазон 100.64.0.0/10)
- DPI проверка (модификация HTTP заголовков)
- DNS фильтрация провайдера

**RouterTest** - проблемы сетевого оборудования:
- UPnP доступность
- SIP ALG детекция (влияет на Vivox voice chat)
- Стабильность пинга до gateway
- QoS политики

**SoftwareTest** - конфликты ПО:
- Детекция антивирусов (Kaspersky, Avast, ESET, Norton и др.)
- Детекция VPN клиентов
- Hosts файл проверка (блокировка RSI доменов)
- Системный прокси проверка

**Расширенные проверки**:
- Vivox voice chat (viv.vivox.com:443)
- AWS игровые серверы (eu-central-1, eu-west-1, us-east-1, us-west-2)
- Игровые UDP порты (64090-64094)

### Умный вердикт playable

Программа оценивает играбельность Star Citizen на основе многофакторного анализа:

**YES** (игра работает):
- VPN активен И HTTPS работает
- Windows Firewall OK
- ISP OK (нет DPI/блокировок)
- TCP Portal доступен
- Хотя бы 1 AWS endpoint доступен

**MAYBE** (могут быть проблемы):
- CGNAT обнаружен
- Нет UPnP на роутере
- Антивирус обнаружен
- TCP Launcher частично доступен

**NO** (игра не запустится):
- Firewall блокирует порты 8000-8003
- ISP DPI активен
- TCP Portal недоступен
- Vivox недоступен
- Все AWS endpoints недоступны

### GUI индикаторы проблем

При обнаружении проблем отображаются информационные карточки с конкретными рекомендациями:

- **FirewallCard** - блокирующие правила Windows + как исправить
- **IspCard** - CGNAT, DPI, DNS фильтрация + советы по обходу (VPN)
- **RouterCard** - UPnP, SIP ALG, нестабильность + инструкции настройки
- **SoftwareCard** - конфликтующие антивирусы, VPN, прокси + решения

Карточки показываются только при реальных проблемах, чтобы не перегружать интерфейс.

## Формат отчёта (JSON)

Пример верхнего уровня:

``` 
{ 
  "run_at": "2025-10-24T15:00:00Z", 
  "cli": "--report report.json", 
  "ext_ip": "185.53.46.108", 
  "summary": { 
    "dns": "OK|WARN|DNS_FILTERED|DNS_BOGUS", 
    "tcp": "OK|FAIL|UNKNOWN", 
    "udp": "OK|FAIL|INFO|UNKNOWN", 
    "tls": "OK|SUSPECT|FAIL|UNKNOWN", 
    "rst_inject": "UNKNOWN",
    "firewall": "OK|BLOCKING|UNKNOWN",
    "isp_blocking": "OK|CGNAT|DPI|DNS_FILTERED|UNKNOWN",
    "router_issues": "OK|NO_UPNP|SIP_ALG|UNSTABLE|UNKNOWN",
    "software_conflicts": "OK|ANTIVIRUS|VPN|PROXY|UNKNOWN"
  }, 
  "firewall": {
    "windows_firewall_enabled": true,
    "blocked_ports": ["8000", "8001"],
    "windows_defender_active": true,
    "blocking_rules": ["Block Star Citizen"],
    "status": "BLOCKING"
  },
  "isp": {
    "isp": "Example ISP",
    "country": "RU",
    "city": "Moscow",
    "cgnat_detected": false,
    "dpi_detected": true,
    "dns_filtered": false,
    "known_problematic_isps": [],
    "status": "DPI"
  },
  "router": {
    "gateway_ip": "192.168.1.1",
    "upnp_enabled": false,
    "sip_alg_detected": false,
    "avg_ping_ms": 2.5,
    "max_ping_ms": 5.2,
    "packet_loss_percent": 0,
    "status": "NO_UPNP"
  },
  "software": {
    "antivirus_detected": ["Windows Defender"],
    "vpn_clients_detected": [],
    "proxy_enabled": false,
    "hosts_file_issues": false,
    "hosts_file_entries": [],
    "status": "OK"
  },
  "targets": { 
    "RSI Лаунчер": { 
      "host": "launcher.robertsspaceindustries.com", 
      "service": "Лаунчер", 
      "system_dns": ["23.215.0.138"], 
      "doh": ["23.215.0.140"], 
      "dns_status": "OK", 
      "tcp": [ 
        {"ip":"23.215.0.138","port":80,"open":true,"elapsed_ms":45}, 
        {"ip":"23.215.0.138","port":443,"open":true,"elapsed_ms":48} 
      ], 
      "http": [ 
        {"url":"https://launcher.robertsspaceindustries.com","success":true,"status":200,"serverHeader":"", "cert_cn":"*.robertsspaceindustries.com"} 
      ], 
      "traceroute": {"hops":[{"hop":1,"ip":"10.0.0.1","status":"TtlExpired"}]} 
    } 
  }, 
  "udp_tests": [ 
    { 
      "name": "Cloudflare DNS", 
      "service": "Базовая сеть", 
      "host": "1.1.1.1", 
      "port": 53, 
      "expect_reply": true, 
      "success": true, 
      "reply": true, 
      "rtt_ms": 12, 
      "reply_bytes": 128, 
      "note": "ответ получен", 
      "description": "Проверка UDP DNS",
      "certainty": "high"
    }, 
    { 
      "name": "Star Citizen EU шлюз", 
      "service": "Игровые сервера", 
      "host": "p4eu-live.cloudimperiumgames.com", 
      "port": 64090, 
      "expect_reply": false, 
      "success": true, 
      "reply": false, 
      "rtt_ms": 1, 
      "reply_bytes": 0, 
      "note": "пакет отправлен", 
      "description": "Отправка тестового пакета, ответ не ожидается",
      "certainty": "low"
    } 
  ] 
} 
``` 

## Правила определения статусов

- DNS:
  - `DNS_FILTERED` — системный DNS пуст, а DoH возвращает A‑записи.
  - `DNS_BOGUS` — системный DNS вернул 0.0.0.0/8, 127.0.0.0/8, 10/8, 172.16/12, 192.168/16.
  - `WARN` — множества системных и DoH‑адресов не пересекаются (возможно CDN/гео, но обратите внимание).
  - `OK` — остальные случаи.
- TCP: `OK`, если где‑то порт открыт; иначе `FAIL`.
- UDP: `OK`, если все тесты с ожидаемым ответом успешны; `FAIL`, если хотя бы один ожидаемый ответ не пришёл; `INFO`, если выполнялись только тесты без ожидания ответа (например, UDP-зонд к игровому шлюзу).
- TLS: `SUSPECT`, если 443 открыт, но HTTPS не проходит; `OK`, если есть 2xx/3xx; `FAIL`, если ни одного успеха.
- RST: `UNKNOWN` — эвристика по таймингам без pcap.

## Советы по устранению проблем

- `DNS_FILTERED / DNS_BOGUS`
  - Включите DoH/DoT (Chrome/Firefox/Windows 11), смените резолвер (1.1.1.1/8.8.8.8).
  - Возможные обходы: DoH/DoT, DNSCrypt, VPN, локальный резолвер (unbound) c TLS.
- `TCP = FAIL`
  - Проверьте локальный фаервол/антивирус/роутер/MTU, задержки DNS.
  - Обход: VPN/HTTPS‑прокси, смена сети/роутера.
- `UDP = FAIL`
  - Возможна блокировка UDP/QUIC. Используйте DoH/DoT вместо UDP‑DNS или VPN.
- `TLS = SUSPECT`
  - Возможна блокировка TLS/SNI. Обход: VPN, HTTPS‑прокси/HTTP2, ECH/ESNI (если доступно), временно зеркала по HTTP (без чувствительных данных).

## Соответствие текущей реализации

- GUI по умолчанию, современная верхняя панель (FlowLayoutPanel, AutoSize), русские подписи — есть.
- Прогресс по шагам, статус/цвета, прогресс‑бар, отмена выполнения — есть.
- Traceroute через системный `tracert`, потоковый вывод хопов, фикс кодировки — есть.
- UDP‑DNS на `1.1.1.1:53`, минимальный парсинг ответа — есть.
- DNS сравнение System vs DoH (Cloudflare), эвристика мусорных IP — есть.
- TCP‑порты по умолчанию 80/443 с повторной попыткой — есть.
- HTTP(S) запросы с SNI, чтение CN сертификата, таймауты — есть.
- JSON‑отчёт (summary + по целям) и человекочитаемые рекомендации — есть.
- Сборка single‑file win‑x64 + workflow GitHub Actions — есть.

## Ограничения и безопасность
- WinDivert требует прав администратора (kernel driver)
- Используется 3-слойная архитектура WinDivert (FLOW/SOCKET/NETWORK) для максимального покрытия
- В режиме Bypass включается гибридный режим (IP Helper вместо FLOW/SOCKET) для устранения конфликтов
- Port caching уменьшает overhead GetExtendedTcpTable (вызов каждые 2с вместо per-packet)ключения
- Port caching уменьшает overhead GetExtendedTcpTable (вызов каждые 2с вместо per-packet)
- DNS парсинг работает только для uncached queries (если DNS закэширован системой → не видим)
- SNI extraction работает только для TLS 1.0-1.3 ClientHello (не для encrypted SNI/ECH)
- Reverse DNS может возвращать технические CDN имена вместо оригинальных доменов
- Системный `tracert` используется для трассировки (OEM866 кодировка для русских хопов)
- По умолчанию ничего никуда не отправляется; отчёт хранится локально
- WinDivert bypass безопасно отключается при закрытии программы
- FixHistory.json хранит оригинальные DNS settings для rollback

## Системные требования

- **OS**: Windows 10/11 (x64)
- **.NET**: .NET 9 Runtime (включён в single-file exe)
- **Права**: Администратор требуется только для Exe-сценария и WinDivert bypass
- **Зависимости**:
  - WinDivert 2.2.0 (WinDivert.dll + WinDivert64.sys) — копируются в native/ и bin/Debug/
  - MaterialDesignInXaml 5.1.0 (NuGet package)
  - MaterialDesignColors 3.1.0 (NuGet package)
  - System.Text.Json (встроено в .NET 9)

## Известные проблемы

1. **ERROR_INVALID_PARAMETER (87)** при запуске WinDivert
   - Причина: SOCKET layer + Sniff flag требовали правильной комбинации флагов
   - Решение: используется `Sniff | RecvOnly` для SOCKET layer ✅

2. **"захвачено событий - 0"**
   - Причина: GetExtendedTcpTable вызов per-packet слишком медленный
   - Решение: port caching mechanism ✅

3. **"обнаружено целей 0"** несмотря на трафик
   - Причина: соединения установлены ДО запуска WinDivert (timing race)
   - Решение: Task.Delay(8000) перед началом захвата ✅
   - Альтернатива: увеличить delay до 15 секунд если приложение медленное

4. **DNS cache пустой (0 from DNS cache)**
   - Причина: DNS запросы закэшированы системой или уходят ДО WinDivert start
   - Workaround: очистить DNS cache (`ipconfig /flushdns`) перед Stage 1
   - Fallback: reverse DNS всё равно работает

5. **StaticResource MaterialDesignShadowDepth1 ошибка**
   - Причина: CapturedTargetsWindow использовала MaterialDesign ресурсы
   - Решение: заменено на прямой DropShadowEffect ✅

6. **Process блокирует сборку**
   - Причина: ISP_Audit.exe запущен и блокирует перезапись
   - Решение: `Stop-Process -Name "ISP_Audit" -Force` перед `dotnet build`

## Ограничения и безопасность

- Во время запуска не используются внешние бинарники, кроме системного `tracert` (если недоступен — шаг пропускается).
- Raw‑сокеты, pcap и пр. не используются в основном билде (не требуются права администратора).
- По умолчанию ничего никуда не отправляется; отчёт хранится локально. Внешняя загрузка отчётов — только по явному флагу (не реализовано) и с токеном.
- Модуль обхода на базе WinDivert включается вручную, требует запуска от имени администратора и безопасно отключается при закрытии программы.

## Обход блокировок (WinDivert)

### Возможности
- **TCP RST dropping**: отбрасывание входящих/исходящих RST пакетов
- **TLS ClientHello fragmentation**: разбиение TLS handshake на фрагменты (обход DPI)
- **Selective redirect**: переадресация трафика на альтернативные IP/порты
- **Process-specific filtering**: применение правил только к целевому процессу

### Конфигурация (bypass_profile.json)
```json
{
  "dns_providers": [
    {"name": "Cloudflare", "ip": "1.1.1.1", "priority": 1},
    {"name": "Google", "ip": "8.8.8.8", "priority": 2},
    {"name": "Quad9", "ip": "9.9.9.9", "priority": 3},
    {"name": "AdGuard", "ip": "94.140.14.14", "priority": 4}
  ],
  "windivert_rules": {
    "drop_rst_incoming": true,
    "drop_rst_outgoing": true,
    "fragment_tls": true,
    "fragment_position": 2,
    "fragment_delay_ms": 0
  },
  "redirect_rules": [
    {
      "original_ip": "blocked.example.com",
      "original_port": 443,
      "redirect_ip": "mirror.example.com",
      "redirect_port": 443,
      "enabled": false
    }
  ]
}
```

### Требования
- Права администратора (kernel driver WinDivert64.sys)
- WinDivert.dll (47KB) и WinDivert64.sys (90KB) в native/ или bin/Debug/
- WinDivert 2.2.0+ (более ранние версии несовместимы)

### Активация
1. **Автоматически** при Stage 3 (если обнаружены проблемы DPI/RST)
2. **Вручную** через GUI кнопку "Включить обход" (появляется после диагностики)
3. **CLI** через флаг `--enable-bypass` (планируется)

### Безопасность
- Bypass применяется ТОЛЬКО к целевому процессу (process PID filtering)
- Автоматическое отключение при закрытии ISP_Audit
- Не влияет на другие приложения/системный трафик
- Driver unload при выходе (WinDivertClose)

### Диагностика
- Статус в GUI: "WinDivert не активен" / "WinDivert активен (PID: 12345)"
- Лог активации: `[Bypass] WinDivert handle opened`, `[Bypass] Rules applied: RST drop, TLS fragment`
- Ошибки: `[Bypass] ERROR_ACCESS_DENIED (5)` → запустите от администратора

## Частые вопросы

**Q: Нужны ли права администратора?**  
A: Только для Exe-сценария (WinDivert kernel driver). Профильная диагностика работает без админ прав.

**Q: Почему Stage 1 захватывает 0 целей?**  
A: 
1. Приложение установило соединения ДО запуска WinDivert → увеличьте delay с 8 до 15 секунд
2. Приложение не делает сетевых запросов → используйте TestNetworkApp.exe для калибровки
3. GetExtendedTcpTable возвращает пустой список → проверьте что процесс запущен и активен

**Q: DNS cache всегда пустой (0 from DNS cache)**  
A: Системный DNS кэш может содержать записи → выполните `ipconfig /flushdns` перед Stage 1. Reverse DNS всё равно работает как fallback.

**Q: Hostname показывает технические CDN имена вместо оригинальных доменов**  
A: Это нормально для ISP диагностики. Технические имена (`prg03s12-in-f14.1e100.net`) показывают:
- Реальную инфраструктуру (Google CDN Prague)
- Конкретные серверы для диагностики блокировок
- Георасположение endpoints

**Q: ERROR_INVALID_PARAMETER (87) при запуске WinDivert**  
A: Старая проблема SOCKET layer + Sniff. Решено переходом на NETWORK layer. Если возникает — обновите WinDivert до 2.2.0+.

**Q: Кнопка "Просмотр результатов" выдаёт ошибку**  
A: Была проблема с MaterialDesign ресурсами в CapturedTargetsWindow. Исправлено заменой на базовые WPF стили. Пересоберите проект.

**Q: Process блокирует сборку (MSB3027)**  
A: ISP_Audit.exe запущен. Выполните `Stop-Process -Name "ISP_Audit" -Force` перед `dotnet build`.

**Q: Как проверить что WinDivert работает?**  
A: 
1. Запустите ISP_Audit от администратора
2. Выберите Exe-сценарий → TestNetworkApp.exe
3. Проверьте Output: должны быть сообщения `✓ Кэш обновлен: X TCP + Y UDP = Z портов`
4. Если кэш пустой → приложение не установило соединения за 8 секунд

**Q: Stage 2 говорит "профиль не найден"**  
A: 
1. Проверьте что Stage 1 завершился успешно (MessageBox "Захват завершён")
2. Проверьте что файл `Profiles/{exeName}_captured.json` существует
3. Если файл есть но Stage 2 не видит → баг в `_capturedProfile` assignment, сообщите issue

**Q: Как откатить DNS изменения?**  
A: 
1. GUI: кнопка "Откатить исправления" (появляется после применения fix)
2. Вручную: `netsh interface ip set dns "Ethernet" dhcp`
3. FixHistory.json хранит оригинальные настройки

**Q: Traceroute "висит"?**  
A: Трассировка может занять 30-60 секунд (timeout per hop). Прогресс отображается в лог. Можно прервать кнопкой "Остановить тест".
