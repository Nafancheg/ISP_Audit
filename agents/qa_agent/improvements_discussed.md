# Обсуждение улучшений тестов (Ангел vs Демон)

**Дата**: 2025-10-30  
**Участники**: User (Демон) + AI (Ангел)

---

## ТЕСТ 1: DnsTest - ДОГОВОРЁННОСТИ

### Проблемы (найденные Демоном):
1. ❌ **Cloudflare не связан с игрой** - DoH используется только для проверки подмены
2. ❌ **Cloudflare может быть заблокирован** провайдером
3. ❌ **Разные IP CDN** (99.84.91.103 vs 99.84.91.100) - это НОРМА, не подмена
4. ❌ **Плодим сущности** - зачем проверять DoH если достаточно System DNS?

### РЕШЕНИЕ:
**Упростить логику:**
```csharp
// Если System DNS пуст → провайдер блокирует
if (system_dns.Count == 0)
    return DnsStatus.DNS_FILTERED;

// Если System DNS вернул мусор (0.0.0.0, 127.x) → явная блокировка
if (system_dns.Any(ip => ip == "0.0.0.0" || ip.StartsWith("127.")))
    return DnsStatus.DNS_BOGUS;

// Если System DNS вернул нормальные адреса → OK
return DnsStatus.OK;
```

**DoH оставить только для информации** (показать пользователю "настоящий адрес"), но НЕ для логики.

---

### Рекомендация при DNS_FILTERED:

**НЕПРАВИЛЬНО (старое):**
```
Рекомендация: используй VPN или смени DNS
```

**ПРАВИЛЬНО (новое):**
```
DNS_FILTERED обнаружен
Провайдер блокирует DNS запросы

РЕШЕНИЕ:
[Кнопка: 🔧 ИСПРАВИТЬ DNS (1 клик)]

При нажатии:
1. Запросить права администратора (UAC)
2. Выполнить PowerShell:
   Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses ('1.1.1.1','8.8.8.8')
3. Показать "DNS изменён. Перезапустите тест."

Альтернатива (если нет прав админа):
Ссылка: https://www.howtogeek.com/765940/how-to-enable-dns-over-https-on-windows-11/

Если не помогло → блокировка глубже (DPI), нужен VPN.
```

**КЛЮЧЕВОЕ:** VPN - это **ПОСЛЕДНЕЕ** средство, не первое!

---

## Файлы для изменения:

### 1. Tests/DnsTest.cs
**Упростить логику** (убрать зависимость от DoH для определения статуса)

### 2. MainWindow.xaml
**Добавить кнопки "ИСПРАВИТЬ DNS" и "ВЕРНУТЬ DNS"** в карточку DNS_FILTERED

```xml
<!-- При DNS_FILTERED показывать кнопки -->
<StackPanel Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,12,0,0">
    <Button x:Name="FixDnsButton"
            Content="🔧 ИСПРАВИТЬ DNS (1 клик)"
            Click="FixDnsButton_Click"
            Background="#4CAF50"
            Foreground="White"
            Padding="12,8"
            FontSize="14"
            FontWeight="Bold"
            Margin="0,0,12,0"/>
    
    <Button x:Name="ResetDnsButton"
            Content="↩️ ВЕРНУТЬ КАК БЫЛО"
            Click="ResetDnsButton_Click"
            Background="#FF9800"
            Foreground="White"
            Padding="12,8"
            FontSize="14"
            FontWeight="Bold"
            Visibility="Collapsed"/>
</StackPanel>
```

**Логика:**
1. Изначально видна только кнопка "ИСПРАВИТЬ DNS"
2. После изменения DNS → показывается кнопка "ВЕРНУТЬ КАК БЫЛО"
3. После отката → кнопка "ВЕРНУТЬ" снова скрывается

### 3. MainWindow.xaml.cs
**Добавить методы `FixDnsButton_Click` и `ResetDnsButton_Click`**:

```csharp
// ПЕРЕД изменением сохранить оригинальные DNS
private List<string>? _originalDnsServers = null;
private string? _adapterName = null;

private async void FixDnsButton_Click(object sender, RoutedEventArgs e)
{
    try
    {
        // 1. Найти активный адаптер
        var adapter = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up 
                              && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);
        
        if (adapter == null)
        {
            MessageBox.Show("Активный адаптер не найден");
            return;
        }
        
        _adapterName = adapter.Name;
        
        // 2. СОХРАНИТЬ текущие DNS (для отката)
        var ipProps = adapter.GetIPProperties();
        _originalDnsServers = ipProps.DnsAddresses
            .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            .Select(ip => ip.ToString())
            .ToList();
        
        if (_originalDnsServers.Count == 0)
        {
            _originalDnsServers = new List<string> { "DHCP" }; // Автоматически
        }
        
        // 3. Запустить PowerShell для смены DNS
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-Command \"Set-DnsClientServerAddress -InterfaceAlias '{adapter.Name}' -ServerAddresses ('1.1.1.1','8.8.8.8')\"",
            Verb = "runas", // UAC prompt
            UseShellExecute = true
        };
        
        var process = Process.Start(psi);
        await process.WaitForExitAsync();
        
        if (process.ExitCode == 0)
        {
            MessageBox.Show(
                "DNS изменён на Cloudflare (1.1.1.1).\n\n" +
                "Перезапустите тест для проверки.\n\n" +
                "Для отката нажмите кнопку 'Вернуть DNS'.", 
                "Готово", MessageBoxButton.OK, MessageBoxImage.Information);
            
            // Показать кнопку "ВЕРНУТЬ DNS"
            ResetDnsButton.Visibility = Visibility.Visible;
        }
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}

private async void ResetDnsButton_Click(object sender, RoutedEventArgs e)
{
    if (_originalDnsServers == null || _adapterName == null)
    {
        MessageBox.Show("Нет сохранённых настроек для отката");
        return;
    }
    
    try
    {
        string command;
        
        if (_originalDnsServers.Contains("DHCP"))
        {
            // Вернуть на автоматическое получение (DHCP)
            command = $"-Command \"Set-DnsClientServerAddress -InterfaceAlias '{_adapterName}' -ResetServerAddresses\"";
        }
        else
        {
            // Вернуть оригинальные DNS
            var dnsString = string.Join("','", _originalDnsServers);
            command = $"-Command \"Set-DnsClientServerAddress -InterfaceAlias '{_adapterName}' -ServerAddresses ('{dnsString}')\"";
        }
        
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = command,
            Verb = "runas",
            UseShellExecute = true
        };
        
        var process = Process.Start(psi);
        await process.WaitForExitAsync();
        
        if (process.ExitCode == 0)
        {
            MessageBox.Show("DNS восстановлены в исходное состояние.", "Готово", MessageBoxButton.OK, MessageBoxImage.Information);
            ResetDnsButton.Visibility = Visibility.Collapsed;
            _originalDnsServers = null;
            _adapterName = null;
        }
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
```

---

## СТАТУС: ⏳ В ОБСУЖДЕНИИ

---

## ТЕСТ 2: TcpTest - ДОГОВОРЁННОСТИ

### Проблемы (найденные Демоном):
1. ❌ **Проверяем портал, а не игру** - robertsspaceindustries.com нужен только для регистрации
2. ❌ **Порты 8000-8003 на портале НЕ существуют** - это веб-сайт, а не игровой сервер
3. ❌ **НЕ проверяем launcher** - install.robertsspaceindustries.com (откуда патчи?)
4. ❌ **НЕ проверяем игровые серверы** - AWS endpoints (eu-central-1, us-east-1)
5. ❌ **НЕ проверяем Vivox** - voice chat (viv.vivox.com)
6. ❌ **Early-exit пропускает критичные порты** - если DNS пуст → TCP не проверяется

### РЕШЕНИЕ:

**Переделать star_citizen_targets.json:**

**УБРАТЬ:**
```json
{
  "name": "RSI Портал (Портал)",
  "host": "robertsspaceindustries.com",
  "service": "Портал"  // ← НЕ НУЖЕН ДЛЯ ИГРЫ!
}
```

**ДОБАВИТЬ:**
```json
{
  "name": "Launcher CDN",
  "host": "install.robertsspaceindustries.com",
  "service": "Launcher",
  "description": "Откуда скачиваются патчи и обновления",
  "tcp_ports_checked": [80, 443],
  "critical": true
},
{
  "name": "AWS EU Central (Game Servers)",
  "host": "ec2.eu-central-1.amazonaws.com",
  "service": "Game Servers",
  "description": "Игровые серверы EU региона",
  "tcp_ports_checked": [8000, 8001, 8002, 8003],
  "critical": true
},
{
  "name": "AWS US East (Game Servers)",
  "host": "ec2.us-east-1.amazonaws.com",
  "service": "Game Servers",
  "tcp_ports_checked": [8000, 8001, 8002, 8003],
  "critical": false
},
{
  "name": "Vivox Voice Chat",
  "host": "viv.vivox.com",
  "service": "Voice Chat",
  "description": "Голосовой чат в игре",
  "tcp_ports_checked": [443, 5060, 5061],
  "udp_ports_checked": [3478, 5060, 5061],
  "critical": true
}
```

**Логика critical:**
- `critical: true` → если недоступен → playable = "NO"
- `critical: false` → если недоступен → playable = "MAYBE" (можно играть на других регионах)

---

### Убрать Early-Exit для критичных целей

**ПРОБЛЕМА (AuditRunner.cs строки 67-82):**
```csharp
bool dnsCompleteFail = targetReport.dns_enabled &&
    targetReport.system_dns.Count == 0 &&
    targetReport.doh.Count == 0;

if (dnsCompleteFail)
{
    // Пропускаем TCP/HTTP/Trace
    targetReport.tcp_enabled = false;
    targetReport.http_enabled = false;
    targetReport.trace_enabled = false;
}
```

**ИСПРАВЛЕНИЕ:**
```csharp
bool dnsCompleteFail = targetReport.dns_enabled &&
    targetReport.system_dns.Count == 0 &&
    targetReport.doh.Count == 0;

if (dnsCompleteFail)
{
    // Если цель критична → всё равно проверяем TCP по известным IP
    if (def.critical)
    {
        // Пробуем известные IP (из кэша, hardcoded, или предыдущих запусков)
        var fallbackIPs = GetKnownIPsForHost(def.Host);
        if (fallbackIPs.Count > 0)
        {
            targetReport.system_dns = fallbackIPs;
            // Продолжаем TCP/HTTP тесты
        }
        else
        {
            // DNS не работает и нет известных IP → пропускаем
            targetReport.tcp_enabled = false;
            targetReport.http_enabled = false;
        }
    }
    else
    {
        // Некритичная цель → пропускаем
        targetReport.tcp_enabled = false;
        targetReport.http_enabled = false;
    }
}
```

---

### Файлы для изменения:

1. **star_citizen_targets.json** - переделать список целей (убрать портал, добавить launcher/AWS/Vivox)
2. **TargetModels.cs** - добавить поле `critical: bool`
3. **AuditRunner.cs** - убрать early-exit для критичных целей, добавить fallback IP
4. **ReportWriter.cs** - учитывать `critical` флаг при определении playable

---

## ФУНДАМЕНТАЛЬНОЕ ОТКРЫТИЕ: Универсальный инструмент! 🎯

### Проблема хардкода целей:
1. ❌ **Хардкод хостов** устаревает при изменении инфраструктуры
2. ❌ **Не отличаем provider block от geo-block** (AWS блокирует РФ vs провайдер блокирует AWS)
3. ❌ **Работает только для Star Citizen** - а что если пользователь играет в MSFS, Warzone, Battlefield?

### РЕШЕНИЕ: Два режима работы

---

## РЕЖИМ 1: Универсальный сниффер "Анализ игры" 🎮

**GUI:**
```
┌─────────────────────────────────────────────────┐
│  🎮 РЕЖИМ: Анализ приложения                    │
├─────────────────────────────────────────────────┤
│  Выберите EXE файл игры/приложения:             │
│  [📁 Выбрать...] или перетащите сюда           │
│                                                 │
│  Или введите хост вручную:                      │
│  [youtube.com          ] [+ Добавить]          │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ 🚀 Star Citizen (пресет)                │   │
│  │ ✈️  Microsoft Flight Simulator (пресет)  │   │
│  │ 🎯 Call of Duty: Warzone (пресет)       │   │
│  │ 📺 YouTube (пресет)                     │   │
│  │ 🎬 Netflix (пресет)                     │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
│  [🔍 НАЧАТЬ АНАЛИЗ ТРАФИКА]                    │
│                                                 │
│  Что делает:                                    │
│  1. Запускает выбранное приложение (или вы      │
│     запускаете вручную)                        │
│  2. Снифает трафик 60 секунд                   │
│  3. Находит все endpoints (IP:Port)            │
│  4. Классифицирует (CDN, Game, Voice, API)    │
│  5. ТЕСТИРУЕТ доступность каждого endpoint     │
│  6. Показывает ЧТО заблокировано              │
│  7. Даёт рекомендации (Fix DNS, VPN, etc)     │
└─────────────────────────────────────────────────┘
```

**Преимущества:**
- ✅ Работает для **любой** игры/приложения
- ✅ Нет хардкода - всегда актуальные адреса
- ✅ Показывает РЕАЛЬНЫЕ проблемы конкретного пользователя
- ✅ Может экспортировать профиль для других пользователей

**Файлы:**
- `Utils/TrafficSniffer.cs` - WinDivert sniffer
- `Utils/EndpointClassifier.cs` - классификация по портам/SNI
- `Utils/ProfileExporter.cs` - сохранить endpoints в JSON

---

## РЕЖИМ 2: Быстрый тест хоста 🌐

**GUI:**
```
┌─────────────────────────────────────────────────┐
│  🌐 РЕЖИМ: Быстрый тест хоста                   │
├─────────────────────────────────────────────────┤
│  Введите hostname или IP:                       │
│  [youtube.com          ]                        │
│                                                 │
│  Порты (опционально):                           │
│  [80, 443              ] (или оставить пусто)  │
│                                                 │
│  [🧪 ПРОТЕСТИРОВАТЬ]                            │
│                                                 │
│  Проверяет:                                     │
│  ✅ DNS резолвинг (System DNS vs DoH)          │
│  ✅ TCP доступность (указанные порты)          │
│  ✅ HTTPS (если порт 443)                      │
│  ✅ UDP (если указаны UDP порты)               │
│  ✅ Traceroute (путь до хоста)                 │
│                                                 │
│  Результат:                                     │
│  ✅ youtube.com → 142.250.185.46               │
│  ✅ TCP:443 → OK (24ms)                        │
│  ✅ HTTPS → OK (certificate valid)             │
│  ✅ Traceroute → 8 hops, no packet loss        │
│                                                 │
│  Вердикт: ✅ Доступно без проблем              │
└─────────────────────────────────────────────────┘
```

**Преимущества:**
- ✅ Быстрый тест "на коленке"
- ✅ Не требует запуска приложения
- ✅ Понятен любому пользователю
- ✅ Идеален для поддержки (скажи клиенту: "введи youtube.com и нажми тест")

---

## РЕЖИМ 3: Загрузка пресета 📋

**GUI:**
```
┌─────────────────────────────────────────────────┐
│  📋 РЕЖИМ: Загрузить профиль                    │
├─────────────────────────────────────────────────┤
│  Выберите профиль:                              │
│                                                 │
│  🚀 Star Citizen (встроенный)                  │
│     - Launcher CDN                             │
│     - AWS Game Servers (EU/US)                 │
│     - Vivox Voice Chat                         │
│     Обновлён: 2025-10-25                       │
│                                                 │
│  ✈️  Microsoft Flight Simulator (встроенный)   │
│     - Azure CDN                                │
│     - Azure Traffic Manager                    │
│     - Bing Maps API                            │
│     Обновлён: 2025-10-20                       │
│                                                 │
│  📁 Загрузить свой профиль (.json)             │
│                                                 │
│  🌍 Скачать с GitHub (community profiles)      │
│     - Star Citizen (актуальный)                │
│     - Call of Duty: Warzone                    │
│     - Battlefield 2042                         │
│     - PUBG                                     │
│     - Apex Legends                             │
│                                                 │
│  [📥 ЗАГРУЗИТЬ И ТЕСТИРОВАТЬ]                  │
└─────────────────────────────────────────────────┘
```

**Профиль формат:**
```json
{
  "name": "Star Citizen",
  "version": "3.21.0",
  "updated": "2025-10-25",
  "author": "community",
  "targets": [
    {
      "name": "Launcher CDN",
      "host": "install.robertsspaceindustries.com",
      "ips": ["151.101.2.3"], // fallback если DNS не работает
      "tcp_ports": [443],
      "critical": true,
      "type": "CDN"
    },
    {
      "name": "AWS Game Server (EU)",
      "ips": ["3.21.45.67", "3.21.45.68"],
      "tcp_ports": [8000, 8001, 8002, 8003],
      "critical": true,
      "type": "GameServer",
      "note": "May be geo-blocked outside EU"
    }
  ]
}
```

**Преимущества:**
- ✅ Community-driven обновления
- ✅ Не требует снифинга (если есть актуальный профиль)
- ✅ Можно тестировать ДО покупки игры ("купить или провайдер заблокирует?")
- ✅ GitHub Releases → автообновление профилей

---

## Итоговая архитектура:

```
ISP_Audit
├── Режим 1: Сниффер (универсальный)
│   └── Анализирует любой EXE → сохраняет профиль
│
├── Режим 2: Быстрый тест
│   └── Тестирует один хост/IP
│
└── Режим 3: Пресеты
    ├── Встроенные (Star Citizen, MSFS)
    └── Community (GitHub, import JSON)
```

**Файлы:**

1. **Utils/TrafficSniffer.cs** - WinDivert sniffer для Режима 1
2. **Utils/EndpointClassifier.cs** - классификация endpoints
3. **Utils/ProfileManager.cs** - загрузка/сохранение профилей
4. **Utils/GitHubProfileLoader.cs** - скачивание community profiles
5. **Config/BuiltinProfiles.cs** - встроенные пресеты (Star Citizen, MSFS)

**star_citizen_targets.json → превращается в пресет:**
- `Profiles/StarCitizen.json`
- `Profiles/MSFS.json`
- `Profiles/YouTube.json`

---

## Вопрос к тебе:

**Делаем универсальный инструмент?**

**ЗА:**
- ✅ Больше пользователей (не только Star Citizen игроки)
- ✅ Больше contributors (community profiles)
- ✅ Актуальность (сниффер всегда даёт свежие данные)
- ✅ Полезен для диагностики любого сервиса

**ПРОТИВ:**
- ❌ Сложнее в разработке
- ❌ Нужен UI редизайн (режимы работы)
- ❌ WinDivert требует прав админа
- ❌ **WinDivert не подписан → антивирусы орут** (Windows Defender, Kaspersky, etc)
  - Нужно либо подписывать драйвер (дорого, EV Certificate ~$300/год)
  - Либо инструкция "добавьте в исключения"
  - Либо альтернатива без драйвера

**Или оставляем Star Citizen-only?**

---

### Альтернативы WinDivert (без драйвера):

**1. Npcap/WinPcap** - тоже драйвер, та же проблема

**2. ETW (Event Tracing for Windows)** - встроенный в Windows
- ✅ Не требует драйвера
- ✅ Нет проблем с антивирусами
- ❌ Только метаданные (IP:Port), нет payload
- ❌ Сложнее в использовании
- ❌ **Работает ВЫШЕ сетевого стека** (Transport Layer)
  - Видит только **успешные** соединения после Windows Firewall
  - НЕ видит заблокированные пакеты/порты
  - НЕ видит low-level проблемы (RST injection, DPI)
- ⚠️ **Не подходит для диагностики блокировок!**

**3. Process Monitor (Procmon) подход**
- Парсим network connections через `netstat` или `Get-NetTCPConnection`
- ✅ Нет драйвера
- ❌ Видим только активные соединения (можем пропустить UDP)
- ❌ Не видим исторические данные

**4. Windows Firewall API**
- Логируем через встроенный Windows Firewall
- ✅ Нет драйвера
- ❌ Требует включения логирования
- ❌ Неудобно парсить логи

---

### ПРЕДЛАГАЕМОЕ РЕШЕНИЕ:

**ПРОБЛЕМА С ETW:**
ETW работает **ВЫШЕ сетевого стека** → не видит блокировки провайдера!

```
Приложение (Star Citizen)
    ↓
Socket API (connect, send, recv)
    ↓
[ETW здесь] ← Видит только успешные соединения!
    ↓
TCP/IP Stack (Windows)
    ↓
Network Driver
    ↓
[WinDivert здесь] ← Видит ВСЁ (даже блокированное)!
    ↓
Провайдер (DPI, RST injection)
    ↓
Интернет
```

**Вывод:** ETW бесполезен для детекции блокировок. Нужен WinDivert или аналог на уровне драйвера.

---

### РЕАЛЬНОЕ РЕШЕНИЕ:

**Вариант 1: WinDivert + инструкция для антивируса**

**ВАЖНО: Проверка подписи WinDivert**

Официальный WinDivert (https://github.com/basil00/WinDivert):
- ✅ **Драйвер (.sys) ПОДПИСАН** Microsoft-compatible сертификатом
- ✅ Windows принимает подпись без проблем
- ⚠️ **DLL не подписана** (но это не критично)
- ⚠️ **ISP_Audit.exe не подписан** (некоммерческий продукт, подписывайте сами если нужно)

**Что может ругаться:**
1. ⚠️ Антивирусы (Kaspersky, ESET, Avast) - детектят по поведению (packet interception)
2. ⚠️ Windows Defender SmartScreen - может показать предупреждение
3. ❌ Корпоративные антивирусы - могут блокировать kernel drivers по политике

**Решение для пользователей:**
- ✅ Добавить ISP_Audit в исключения антивируса
- ✅ При запуске SmartScreen → "Дополнительно" → "Выполнить в любом случае"
- ✅ Запускать от администратора (WinDivert требует)

**Disclaimer:**
```
⚠️ ISP_Audit использует WinDivert для анализа сетевых пакетов.
   Антивирус может показать предупреждение - это нормально.
   
   Добавьте программу в исключения или используйте на свой риск.
   Авторы не несут ответственности за конфликты с антивирусами.
   
   Исходный код открыт: github.com/Nafancheg/ISP_Audit
```

```
┌──────────────────────────────────────────────────┐
│  ⚠️  ПЕРВЫЙ ЗАПУСК                               │
├──────────────────────────────────────────────────┤
│  ISP_Audit использует WinDivert для анализа      │
│  сетевых пакетов. Антивирус может заблокировать. │
│                                                  │
│  Это НОРМАЛЬНО - мы анализируем сетевой трафик.  │
│                                                  │
│  📋 Если антивирус блокирует:                    │
│  1. Добавьте ISP_Audit в исключения              │
│  2. Или используйте на свой страх и риск         │
│                                                  │
│  ℹ️  Исходный код открыт на GitHub               │
│     github.com/Nafancheg/ISP_Audit               │
│                                                  │
│  ⚠️  Авторы не несут ответственности за          │
│     конфликты с антивирусами                     │
│                                                  │
│  [✅ ПОНЯТНО, ПРОДОЛЖИТЬ]  [❌ Выход]           │
└──────────────────────────────────────────────────┘
```

**Действия:**
- ✅ Показывать WARNING при первом запуске (один раз)
- ✅ README с инструкциями "Как добавить в исключения"
- ✅ Disclaimer в About: "Используйте на свой риск"
- ✅ GitHub badges: "Open Source", "WinDivert-based"
- ❌ НЕ подписываем (некоммерческий проект, не наша проблема)

---

**Вариант 2: Netstat подход (без deep inspection)**

**Упрощённая версия без WinDivert:**

1. Запускаем игру (пользователь сам)
2. Опрашиваем `Get-NetTCPConnection` каждые 2 секунды
3. Собираем endpoints которые игра РЕАЛЬНО использует
4. **Тестируем эти endpoints обычными тестами** (DNS, TCP connect, traceroute)

**Код:**
```csharp
var process = Process.GetProcessesByName("StarCitizen").FirstOrDefault();
if (process == null) return;

// PowerShell: Get-NetTCPConnection -OwningProcess PID
var psi = new ProcessStartInfo
{
    FileName = "powershell.exe",
    Arguments = $"-Command \"Get-NetTCPConnection -OwningProcess {process.Id} | Select RemoteAddress, RemotePort\"",
    RedirectStandardOutput = true
};

// Парсим вывод → получаем endpoints
// Затем тестируем их обычными методами (без WinDivert)
```

**Преимущества:**
- ✅ Нет драйвера
- ✅ Нет проблем с антивирусом
- ✅ Видим РЕАЛЬНЫЕ endpoints игры

**Недостатки:**
- ❌ Не видим **неудачные** попытки соединения
- ❌ Не видим UDP (нужен `Get-NetUDPEndpoint`)
- ❌ Видим только **активные** соединения (можем пропустить кратковременные)

**Но для нашей задачи ДОСТАТОЧНО:**
- Игра подключилась к серверу → мы видим endpoint → тестируем его
- Игра НЕ подключилась → тестируем хардкод endpoints (Launcher CDN, AWS, Vivox)

---

### ✅ ФИНАЛЬНОЕ РЕШЕНИЕ: WinDivert Sniffer

**Архитектура:**

```
ISP_Audit (универсальный инструмент)
│
├── Режим 1: 🔍 Анализ приложения (WinDivert)
│   ├── Выбор EXE или процесса
│   ├── Снифинг трафика 60-120 сек
│   ├── Классификация endpoints (CDN/Game/Voice/API)
│   ├── Тестирование каждого endpoint
│   └── Сохранение профиля
│
├── Режим 2: 🌐 Быстрый тест хоста
│   ├── Ввод hostname/IP
│   ├── DNS + TCP + HTTPS + Traceroute
│   └── Моментальный результат
│
└── Режим 3: 📋 Пресеты (community profiles)
    ├── Встроенные (Star Citizen, MSFS)
    ├── Загрузка с GitHub
    └── Импорт своего JSON
```

---

## Режим 1: Анализ приложения (детально)

### GUI Mock:
```
┌─────────────────────────────────────────────────────┐
│  🔍 АНАЛИЗ ПРИЛОЖЕНИЯ                                │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Выберите приложение:                                │
│  ┌──────────────────────────────────────────────┐   │
│  │ ⚪ Выбрать EXE файл                          │   │
│  │    [📁 Обзор...] или перетащите сюда         │   │
│  │                                              │   │
│  │ ⚪ Указать запущенный процесс                │   │
│  │    [StarCitizen.exe ▼] (автообнаружение)    │   │
│  │                                              │   │
│  │ ⚪ Ввести хост вручную (без снифинга)        │   │
│  │    [youtube.com              ]  [+]         │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
│  Или выберите пресет:                                │
│  ┌──────────────────────────────────────────────┐   │
│  │ 🚀 Star Citizen      ✈️  Microsoft Flight    │   │
│  │ 🎯 Call of Duty      🎮 Apex Legends         │   │
│  │ 📺 YouTube           🎬 Netflix              │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
│  Параметры снифинга:                                 │
│  Длительность: [60 ▼] секунд                        │
│  ☑ Автоматически запустить приложение               │
│  ☑ Классифицировать endpoints                       │
│  ☑ Протестировать после снифинга                    │
│                                                      │
│  [🔍 НАЧАТЬ АНАЛИЗ]                                 │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### Процесс снифинга:
```
┌─────────────────────────────────────────────────────┐
│  🔍 Анализ трафика: StarCitizen.exe                  │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Статус: Сбор данных... [███████░░░] 45/60 сек      │
│                                                      │
│  Обнаружено endpoints: 23                            │
│  ├─ CDN: 3                                          │
│  ├─ Game Servers: 12                                │
│  ├─ Voice Chat: 2                                   │
│  └─ Unknown: 6                                      │
│                                                      │
│  Последние обнаруженные:                             │
│  • 3.21.45.67:8000 (TCP, 234 пакетов, 1.2 MB)      │
│  • 3.21.45.67:8001 (TCP, 189 пакетов, 890 KB)      │
│  • 52.123.45.78:3478 (UDP, 456 пакетов, 234 KB)    │
│                                                      │
│  [⏸ ПАУЗА]  [⏹ ОСТАНОВИТЬ]                         │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### Результаты снифинга:
```
┌─────────────────────────────────────────────────────┐
│  ✅ Анализ завершён                                  │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Обнаружено 23 endpoints за 60 секунд                │
│                                                      │
│  📦 CDN (3):                                         │
│  ✅ install.robertsspaceindustries.com (151.101.2.3) │
│     TCP:443 - 1234 пакетов, 5.6 MB                  │
│                                                      │
│  🎮 Game Servers (12):                               │
│  ✅ 3.21.45.67:8000 - 234 пакетов, 1.2 MB           │
│  ✅ 3.21.45.67:8001 - 189 пакетов, 890 KB           │
│  ✅ 3.21.45.68:8000 - 456 пакетов, 2.3 MB           │
│  ... (показать ещё 9)                               │
│                                                      │
│  🎙️ Voice Chat (2):                                 │
│  ✅ 52.123.45.78:3478 (UDP STUN)                    │
│                                                      │
│  ❓ Unknown (6):                                     │
│  ⚠️  8.8.8.8:53 (DNS)                               │
│  ... (показать ещё 5)                               │
│                                                      │
│  [🧪 ПРОТЕСТИРОВАТЬ ВСЕ]  [💾 СОХРАНИТЬ ПРОФИЛЬ]   │
│  [📤 ЭКСПОРТ JSON]        [🔄 ПОВТОРИТЬ АНАЛИЗ]    │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

## Реализация

### Файлы для создания:

**1. Utils/TrafficSniffer.cs** - WinDivert wrapper
```csharp
public class TrafficSniffer
{
    public async Task<List<DiscoveredEndpoint>> SniffProcess(
        int processId, 
        int durationSeconds,
        IProgress<SniffProgress> progress)
    {
        // WinDivert фильтр: только пакеты от нашего процесса
        var filter = $"outbound and processId == {processId}";
        
        using var handle = WinDivertNative.Open(
            filter,
            WinDivertNative.Layer.Network,
            0,
            WinDivertNative.OpenFlags.Sniff);
        
        var endpoints = new ConcurrentDictionary<string, DiscoveredEndpoint>();
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(durationSeconds));
        
        while (!cts.Token.IsCancellationRequested)
        {
            var packet = new byte[WinDivertNative.MaxPacketSize];
            var addr = new WinDivertNative.Address();
            
            if (!WinDivertNative.WinDivertRecv(handle, packet, (uint)packet.Length, ref addr, out var readLen))
                continue;
            
            var (ip, port, protocol, sni) = ParsePacket(packet, (int)readLen);
            var key = $"{protocol}:{ip}:{port}";
            
            endpoints.AddOrUpdate(key, 
                _ => new DiscoveredEndpoint { IP = ip, Port = port, Protocol = protocol, SNI = sni },
                (_, existing) => { existing.PacketCount++; existing.BytesTransferred += readLen; return existing; });
            
            progress?.Report(new SniffProgress { 
                ElapsedSeconds = (durationSeconds - (int)cts.Token.GetRemainingTime().TotalSeconds),
                EndpointsFound = endpoints.Count 
            });
        }
        
        return endpoints.Values.ToList();
    }
}
```

**2. Utils/EndpointClassifier.cs** - классификация endpoints
```csharp
public enum EndpointType
{
    Unknown,
    CDN,           // Launcher/Update servers
    GameServer,    // Game traffic
    VoiceChat,     // Vivox/Teamspeak
    API,           // REST APIs
    Analytics,     // Telemetry
    DNS            // DNS queries
}

public class EndpointClassifier
{
    public EndpointType Classify(string ip, int port, string protocol, string? sni)
    {
        // CDN detection
        if (sni?.Contains("install.") == true || sni?.Contains("cdn.") == true)
            return EndpointType.CDN;
        
        // Game server ports
        if (port >= 8000 && port <= 8020)
            return EndpointType.GameServer;
        if (port >= 64090 && port <= 64094)
            return EndpointType.GameServer;
        
        // Voice chat
        if (port == 3478 || port == 5060 || port == 5061)
            return EndpointType.VoiceChat;
        
        // DNS
        if (port == 53)
            return EndpointType.DNS;
        
        // API (обычно HTTPS)
        if (port == 443 && sni?.Contains("api.") == true)
            return EndpointType.API;
        
        return EndpointType.Unknown;
    }
}
```

**3. Utils/ProfileManager.cs** - сохранение/загрузка профилей
```csharp
public class ProfileManager
{
    public void SaveProfile(string name, List<DiscoveredEndpoint> endpoints)
    {
        var profile = new GameProfile
        {
            Name = name,
            Version = "1.0",
            Updated = DateTime.UtcNow,
            Author = Environment.UserName,
            Targets = endpoints.Select(e => new ProfileTarget
            {
                Name = $"{e.Type} - {e.IP}:{e.Port}",
                IPs = new[] { e.IP },
                TcpPorts = e.Protocol == "TCP" ? new[] { e.Port } : null,
                UdpPorts = e.Protocol == "UDP" ? new[] { e.Port } : null,
                Critical = e.Type == EndpointType.GameServer || e.Type == EndpointType.CDN,
                Type = e.Type.ToString()
            }).ToList()
        };
        
        File.WriteAllText($"Profiles/{name}.json", JsonSerializer.Serialize(profile));
    }
}
```

**4. Wpf/SnifferWindow.xaml** - GUI для снифинга
```xml
<Window x:Class="IspAudit.Wpf.SnifferWindow"
        Title="Анализ приложения" Width="600" Height="500">
    <!-- GUI из мокапа выше -->
</Window>
```

---

## Интеграция с существующими тестами

После снифинга endpoints → тестируем их обычными тестами:
1. **DnsTest** - проверяем DNS резолвинг хостов
2. **TcpTest** - проверяем TCP connectivity к обнаруженным портам
3. **UdpTest** - проверяем UDP endpoints
4. **TracerouteTest** - маршрут до критичных endpoints

---

## Следующие шаги:

1. ✅ Создать `Utils/TrafficSniffer.cs`
2. ✅ Создать `Utils/EndpointClassifier.cs`
3. ✅ Создать `Utils/ProfileManager.cs`
4. ✅ Создать `Wpf/SnifferWindow.xaml` + code-behind
5. ✅ Интегрировать в MainWindow (кнопка "Анализ приложения")
6. ✅ Добавить пресеты (Star Citizen, MSFS, YouTube, Netflix)
7. ✅ README с инструкциями для антивирусов

Готов начать реализацию?

---

### Реализация ETW (рекомендуемая):

**Новый файл: `Utils/EtwNetworkSniffer.cs`**

```csharp
// Использует Microsoft-Windows-TCPIP ETW provider
// Не требует драйвера, работает из коробки!

public class EtwNetworkSniffer
{
    public async Task<List<DiscoveredEndpoint>> SniffWithEtw(
        string processName, 
        int durationSeconds = 60)
    {
        // 1. Найти PID процесса (например "StarCitizen.exe")
        var process = Process.GetProcessesByName(processName).FirstOrDefault();
        if (process == null)
            throw new Exception($"Процесс {processName} не найден");
        
        // 2. Подписаться на ETW events: TCP Connect, UDP Send
        using var session = new TraceEventSession("ISP_Audit_Sniffer");
        session.EnableProvider("Microsoft-Windows-TCPIP");
        
        var endpoints = new Dictionary<string, DiscoveredEndpoint>();
        
        session.Source.Dynamic.All += e =>
        {
            // Фильтруем только наш процесс
            if (e.ProcessID != process.Id)
                return;
            
            // Парсим TCP Connect / UDP Send events
            if (e.EventName == "TcpConnect" || e.EventName == "UdpSend")
            {
                var ip = e.PayloadByName("DestAddress").ToString();
                var port = (int)e.PayloadByName("DestPort");
                var protocol = e.EventName.StartsWith("Tcp") ? "TCP" : "UDP";
                
                var key = $"{protocol}:{ip}:{port}";
                if (!endpoints.ContainsKey(key))
                {
                    endpoints[key] = new DiscoveredEndpoint
                    {
                        IP = ip,
                        Port = port,
                        Protocol = protocol,
                        Type = ClassifyEndpoint(ip, port, protocol)
                    };
                }
                
                endpoints[key].PacketCount++;
            }
        };
        
        // 3. Собираем данные N секунд
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(durationSeconds));
        await Task.Run(() => session.Source.Process(), cts.Token);
        
        return endpoints.Values.ToList();
    }
}
```

**Nuget пакет:** `Microsoft.Diagnostics.Tracing.TraceEvent`

✅ **Преимущества ETW:**
- Встроено в Windows (Vista+)
- Не требует драйвера
- Не ругается антивирус
- Требует только админа (как и WinDivert)
- Достаточно для определения endpoints

❌ **Недостатки ETW:**
- Нет SNI из TLS handshake (но можно определить по портам)
- Нет payload (но нам и не нужен)
- Чуть сложнее код

---

### Итоговая стратегия:

**Режим 1 (рекомендуемый): ETW Sniffer**
- Кнопка: "🔍 АНАЛИЗИРОВАТЬ ТРАФИК"
- Под капотом: ETW (без драйвера)
- Работает из коробки

**Режим 2 (опциональный): WinDivert**
- Кнопка: "🔬 РАСШИРЕННЫЙ АНАЛИЗ"
- Warning: Требует драйвер, может ругаться антивирус
- Даёт больше данных (SNI, timing, payload size)

**Режим 3 (fallback): netstat**
- Автоматически если ETW не работает
- Просто опрос активных соединений

Что скажешь?

---

---

## 🎯 БАЗОВАЯ СТРАТЕГИЯ (приоритеты)

### ПРИОРИТЕТ 1: Вылечить DNS 🔥
**Проблема:** DNS - корень 80% проблем с доступностью
**Решение:**
1. ✅ Упростить DnsTest (убрать DoH из логики)
2. ✅ Добавить кнопку "FIX DNS" (1 клик → Cloudflare 1.1.1.1)
3. ✅ Добавить кнопку "ROLLBACK DNS" (вернуть как было)
4. ✅ Показывать понятные рекомендации (VPN - последнее средство!)

**Файлы:**
- `Tests/DnsTest.cs` - упростить
- `MainWindow.xaml` - добавить кнопки
- `MainWindow.xaml.cs` - реализовать Fix/Rollback

---

### ПРИОРИТЕТ 2: Убрать тесты "хрен пойми чего" 🗑️
**Проблема:** Тесты проверяют не то что нужно
**Решение:**
- ❌ **УБРАТЬ FirewallTest** - Windows Firewall НЕ блокирует игры (только провайдер блокирует)
- ❌ **УБРАТЬ IspTest** - что это вообще? Непонятный тест
- ❌ **УБРАТЬ RouterTest** - роутер НЕ блокирует игры (провайдер блокирует)
- ❌ **УБРАТЬ SoftwareTest** - проверка софта не относится к сети
- ✅ **ОСТАВИТЬ TcpTest** - но проверять ПРАВИЛЬНЫЕ endpoints (launcher/AWS/Vivox)
- ✅ **ОСТАВИТЬ UdpProbeRunner** - UDP порты критичны для игры
- ✅ **ОСТАВИТЬ TracerouteTest** - показывает где пакеты теряются
- ✅ **ОСТАВИТЬ RstHeuristic** - детектит RST injection от провайдера
- ⚠️ **HttpTest** - под вопросом (нужен только для DPI детекции TLS)

**Итого: 5 тестов убрать, 4-5 оставить**

---

### ПРИОРИТЕТ 3: Добавить снифер 🔍
**Проблема:** Хардкод хостов устаревает, не видим реальные проблемы
**Решение:**
- ✅ Добавить кнопку "АНАЛИЗ ПРИЛОЖЕНИЯ"
- ✅ WinDivert сниффер (60 сек → находит endpoints → тестирует их)
- ✅ Классификация endpoints (CDN, Game, Voice, API)
- ✅ Экспорт профиля (JSON для community)
- ✅ Disclaimer про антивирусы (open source, на свой риск)

**Файлы:**
- `Utils/TrafficSniffer.cs` - WinDivert wrapper
- `Utils/EndpointClassifier.cs` - классификация
- `Utils/ProfileManager.cs` - save/load profiles
- `Wpf/SnifferWindow.xaml` - GUI

---

## ПЛАН ДЕЙСТВИЙ (по приоритету):

### ШАГ 1: DNS Fix (быстро, критично) ⚡
**Время:** 2-3 часа
**Файлы:**
1. Упростить `Tests/DnsTest.cs`
2. Добавить кнопки в `MainWindow.xaml`
3. Реализовать `FixDnsButton_Click` в `MainWindow.xaml.cs`
4. Реализовать `ResetDnsButton_Click` в `MainWindow.xaml.cs`

**Результат:** Пользователь 1 кликом фиксит DNS → 80% проблем решены

---

### ШАГ 2: Зачистка мусора (быстро, упрощает код) 🗑️
**Время:** 1-2 часа
**Файлы:**
1. Удалить `Tests/FirewallTest.cs`
2. Удалить `Tests/IspTest.cs`
3. Удалить `Tests/RouterTest.cs`
4. Удалить `Tests/SoftwareTest.cs`
5. Убрать их из `AuditRunner.cs`
6. Убрать их из GUI

**Результат:** Код проще, тесты понятнее, нет "шума"

---

### ШАГ 3: Исправить TcpTest (критично) 🎯
**Время:** 2-3 часа
**Файлы:**
1. Переделать `star_citizen_targets.json` (убрать портал, добавить launcher/AWS/Vivox)
2. Добавить поле `critical: bool` в `TargetModels.cs`
3. Убрать early-exit для critical в `AuditRunner.cs`
4. Учитывать `critical` в `ReportWriter.cs` (playable verdict)

**Результат:** Тестируем ТО что нужно игре, а не портал

---

### ШАГ 4: Добавить сниффер (долго, но мощно) 🔍
**Время:** 8-10 часов
**Файлы:**
1. Создать `Utils/TrafficSniffer.cs`
2. Создать `Utils/EndpointClassifier.cs`
3. Создать `Utils/ProfileManager.cs`
4. Создать `Wpf/SnifferWindow.xaml` + code-behind
5. Интегрировать в `MainWindow` (кнопка "Анализ")
6. Добавить disclaimer про WinDivert/антивирусы

**Результат:** Универсальный инструмент для любой игры/приложения

---

## ОПЦИОНАЛЬНЫЕ УЛУЧШЕНИЯ (потом):

- 📋 Community profiles (GitHub releases)
- 🌐 Быстрый тест хоста (без снифинга)
- 🎮 Пресеты для популярных игр (MSFS, Warzone, etc)
- 🔬 Расширенный анализ (payload, timing)

---

## СТАТУС:

✅ **Обсуждено и утверждено:**
- DnsTest: упростить + Fix DNS button
- TcpTest: проверять game endpoints не portal
- Убрать: FirewallTest, IspTest, RouterTest, SoftwareTest
- Добавить: WinDivert сниффер

❌ **Ещё не обсудили:**
- HttpTest - нужен ли? (только для DPI детекции TLS?)
- UdpProbeRunner - порты правильные?
- TracerouteTest - маршрут к чему?
- RstHeuristic - работает ли?

**ВОПРОС:** Начинаем реализацию ШАГ 1 (DNS Fix) или сначала закончим обсуждение оставшихся тестов?

---

## 🚀 ГОТОВО К РЕАЛИЗАЦИИ

Все решения задокументированы в этом файле.
Следующий шаг: создать промпты для Coding Agent через многоагентскую схему.

**Команда для запуска:**
```powershell
# Из корня проекта
.\agents\new_task.ps1
```

Это создаст новую задачу в `agents/runs/` с промптами для всех агентов.

---

