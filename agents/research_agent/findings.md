# [RED] Research Agent: Findings — Переработка тестов по примеру PowerShell скриптов

**Дата исследования**: 2025-10-30  
**Задача**: Переработка текущих тестов для выявления РЕАЛЬНЫХ блокировок (firewall, ISP DPI, специфичные SC проблемы) вместо ложных срабатываний

---

## 1. Затронутые файлы и компоненты

### 1.1 Критические тестовые модули

**`Tests/DnsTest.cs`** — DNS резолвинг (System DNS vs DoH)
- ✓ VPN-aware (профиль `vpn`)
- ✗ НЕ проверяет ISP DNS фильтрацию (сравнение только с Cloudflare DoH)
- Требуется: добавить сравнение с Google DNS (8.8.8.8)

**`Tests/TcpTest.cs`** — TCP-подключение к портам 80/443/8000-8020
- ✗ НЕ различает причины блокировки (firewall vs ISP vs RST)
- Требуется: категоризация портов (Portal/Launcher/Game) + детекция типа блокировки

**`Tests/HttpTest.cs`** — HTTPS проверка + детекция блок-страниц
- ✓ VPN-aware (строже эвристика блок-страниц)
- ✓ Валидация TLS-сертификатов (CN mismatch)
- ✗ НЕ проверяет Vivox (voice chat) и AWS endpoints (игровые серверы)
- Требуется: добавить viv.vivox.com + AWS eu-central-1/eu-west-1/us-east-1/us-west-2

**`Tests/UdpProbeRunner.cs`** — UDP проверки (DNS + raw)
- ✗ НЕТ проверки игровых UDP портов (64090-64094)
- Требуется: добавить проверку игровых портов + Vivox UDP (3478)

### 1.2 Ядро системы

**`AuditRunner.cs`** — оркестратор тестов
- ✓ Early-exit при DNS FAIL
- ✗ НЕТ категоризации проблем (Firewall/ISP/Router/Software)
- Требуется: добавить новые тесты FirewallTest/IspTest/RouterTest/SoftwareTest

**`Output/ReportWriter.cs`** — формирование отчёта и вердикта
- ✓ Разделение TCP портов (Portal/Launcher)
- ✗ Вердикт `playable` НЕ учитывает firewall/ISP/router
- Требуется: переписать логику вердикта с учётом новых тестов

**`Utils/NetUtils.cs`** — сетевые утилиты
- ✓ VPN-детекция (Tunnel интерфейсы, названия)
- ✗ НЕТ методов для ISP/Router/Firewall проверок
- Требуется: CGNAT, Gateway ping, DNS servers, ISP info

### 1.3 GUI (WPF)

**`MainWindow.xaml.cs`** — интерфейс пользователя
- ✓ VPN-баннер (VpnInfoCard)
- ✓ Адаптивные таймауты при VPN
- ✗ НЕТ детализации по категориям проблем
- Требуется: карточки Firewall/ISP/Router/Software

**`Wpf/ServiceItemViewModel.cs`** — ViewModel сервисов
- ✓ Статусы Success/Warning/Error
- ✗ НЕТ разделения по типам проблем
- Требуется: поле ProblemCategory, метод SetBlocked()

### 1.4 Данные

**`star_citizen_targets.json`** — каталог целей SC
- Текущие: 5 целей (Portal, Accounts, API, CDN, Installer) + порты 80/443/8000-8020 + UDP DNS
- ✗ НЕТ Vivox, AWS endpoints, игровых UDP портов
- Требуется: добавить viv.vivox.com + AWS регионы + UDP 64090-64094 + Vivox UDP 3478

---

## 2. Текущая реализация — как работает сейчас

### 2.1 Архитектура тестов

**Последовательность выполнения:**
```
1. VPN Detection → Config.Profile = "vpn" or "normal"
2. Для каждой цели (5 шт):
   a) DnsTest: System DNS vs DoH (Cloudflare)
   b) TcpTest: порты 80/443/8000-8020 (параллельно, макс 10)
   c) HttpTest: HTTPS (/, www.*, /generate_204) + блок-страницы
   d) TracerouteTest: tracert (отключено по умолчанию)
3. UdpProbeRunner: DNS 1.1.1.1:53
4. RstHeuristic: 1.1.1.1:81 (отключено по умолчанию)
5. BuildSummary: агрегация + вердикт playable
```

**Проблемы:**
- Firewall блокировки НЕ детектируются → TCP FAIL, но причина неизвестна
- ISP DPI НЕ проверяется → HTTP SUSPECT, но причина неизвестна
- VPN режим: адаптация ТОЛЬКО в DnsTest/HttpTest, НО вердикт `playable` НЕ учитывает VPN

### 2.2 Логика вердикта (ReportWriter.BuildSummary)

**Текущий алгоритм:**
```
playable = NO:
  - tls == FAIL/BLOCK_PAGE/MITM_SUSPECT
  - dns == DNS_BOGUS
  - dns == DNS_FILTERED И profile != "vpn"
  - tcp_portal == FAIL

playable = MAYBE:
  - tls == SUSPECT
  - dns == WARN
  - tcp_portal == WARN

playable = YES:
  - tls == OK
  - tcp_portal != FAIL
  - dns != UNKNOWN
```

**Проблемы:**
- Если Windows Firewall блокирует порт 8000 → TCP FAIL → playable = MAYBE, НО должен быть NO (критично для лаунчера)
- Если VPN активен И работает (HTTPS OK) → playable = YES, НО если DNS/TCP WARN → playable = MAYBE (ложный негатив)
- Нет проверки Vivox/AWS → игра может НЕ работать, но playable = YES

### 2.3 VPN-обработка

**VPN-детекция** (`NetUtils.LikelyVpnActive()`):
- Проверяет NetworkInterface: Tunnel type, имена (vpn/wintun/wireguard/openvpn/tap/tun/ikev2)

**VPN-адаптация:**
- `Config.Profile`: "vpn" (GUI автоматически) или "normal" (CLI — вручную через --profile)
- `DnsTest`: в профиле "vpn" → WARN вместо DNS_FILTERED если System DNS пуст
- `HttpTest`: в профиле "vpn" → строже эвристика блок-страниц (только 451/403/rkn.gov.ru)
- `MainWindow`: таймауты увеличены (HTTP 12s, TCP 8s, UDP 4s) + баннер VpnInfoCard

**Проблема**: вердикт `playable` НЕ адаптируется под VPN → если VPN работает, но DNS WARN → playable = MAYBE (должен быть YES)

### 2.4 GUI — отображение результатов

**Баннеры:**
- `WarningCard` (жёлтый) — если playable != YES (список проблем + рекомендации)
- `SuccessCard` (зелёный) — если playable == YES
- `VpnInfoCard` (синий) — если VPN активен

**Проблемы:**
- Предупреждения НЕ категоризированы (firewall/ISP/router — всё в одном списке)
- Рекомендации слишком общие: "Проверьте фильтры/прокси" (не указана конкретная причина)

---

## 3. Риски и зависимости

### 3.1 Риски добавления новых тестов

**Риск 1: Требуются админ права**
- Windows Firewall правила (WMI: `MSFT_NetFirewallRule`) — требует админ
- Windows Defender (WMI: `MSFT_MpPreference`) — требует админ
- Hosts файл — ЧТЕНИЕ без админа, ЗАПИСЬ требует админ
- **Решение**: обернуть в try-catch, показать "Запустите от администратора для полной диагностики"

**Риск 2: Производительность**
- Firewall: чтение правил (~100-500ms)
- ISP: внешний API ip-api.com + DNS сравнение (~1-2s)
- Router: пинг gateway 20 раз (~2-4s)
- **Решение**: параллелизация Software/Firewall/Router/ISP (не блокируют основные тесты)

**Риск 3: Ложные срабатывания**
- Windows Firewall: правила могут быть неактивны или для других приложений
- DPI детекция: модификация заголовков может быть нормой для корпоративных прокси
- CGNAT: некоторые провайдеры используют диапазоны 100.x не для CGNAT
- **Решение**: многофакторная проверка + категоризация WARN vs FAIL

**Риск 4: Зависимость от внешних API**
- ip-api.com (ISP info) — rate limit 45 req/min, может быть недоступен
- ifconfig.co/ipify.org (external IP) — могут быть недоступны
- **Решение**: timeout 5s + fallback → если API недоступен, показать "ISP: неизвестен" (не критично)

### 3.2 Зависимости между тестами

**Зависимость 1: Firewall → TCP**
- Если Firewall блокирует порт 8000 → TCP FAIL
- Нужно запускать FirewallTest ДО TcpTest → чтобы указать причину "Windows Firewall блокирует порт 8000"

**Зависимость 2: ISP → DNS/HTTP**
- Если ISP фильтрует DNS → DnsTest = DNS_FILTERED
- Если ISP DPI блокирует HTTPS → HttpTest = SUSPECT
- Нужно запускать IspTest параллельно → корреляция результатов

**Зависимость 3: VPN → все тесты**
- VPN может туннелировать весь трафик (full tunnel) или только DNS (split tunnel)
- Нужно детектировать VPN routing (default route 0.0.0.0/0) → адаптация логики
- Full tunnel VPN → не проверять firewall/router (не релевантно)

### 3.3 Зависимости от .NET API

**Требуемые NuGet пакеты:**
- `System.Management` — для WMI (Windows Firewall, Defender) — ✅ добавить
- `System.Text.Json` — для JSON — ✅ уже используется
- `System.Net.Http` — для HTTP — ✅ уже используется

**Windows-специфичные API:**
- WMI (`System.Management`) — Windows Firewall, Defender
- Registry (`Microsoft.Win32.Registry`) — системный прокси, DNS настройки
- COM Interop (`UPnP.UPnPDeviceFinder`) — UPnP проверка
- Process (`System.Diagnostics.Process`) — детекция антивирусов
- ServiceController (`System.ServiceProcess`) — детекция служб

---

## 4. Рекомендации для Planning Agent

### 4.1 Приоритизация задач

**P0 — КРИТИЧНО (без них вердикт ложный):**
1. **Firewall Test** — Windows Firewall блокировки портов 8000-8003
2. **ISP DNS Filtering** — сравнение System DNS vs DoH vs Google DNS
3. **Vivox Check** — проверка viv.vivox.com:443 (voice chat)
4. **AWS Endpoints Check** — проверка eu-central-1/eu-west-1/us-east-1/us-west-2 (игровые серверы)
5. **Улучшение вердикта** — учёт firewall/ISP/VPN в `playable`

**P1 — ВАЖНО (улучшают диагностику):**
6. **ISP DPI Test** — детекция DPI модификации заголовков
7. **CGNAT Detection** — проверка диапазона 100.64.0.0/10
8. **Router UPnP Check** — проверка UPnP (COM объект `UPnP.UPnPDeviceFinder`)
9. **Software Detection** — детекция антивирусов, VPN клиентов, прокси
10. **UDP Game Ports** — проверка портов 64090-64094 (игровые)

**P2 — NICE-TO-HAVE:**
11. Router SIP ALG — проверка порта 3478/UDP для Vivox
12. Router QoS — проверка Windows QoS политик
13. Router Gateway Stability — 20 пингов до gateway
14. Hosts File Check — проверка записей для RSI доменов
15. System Proxy Check — проверка HKCU реестра

### 4.2 Архитектура новых тестов

**Предлагаемая структура файлов:**
```
Tests/
  DnsTest.cs (расширить: Google DNS, ISP фильтрация)
  TcpTest.cs (расширить: категоризация портов, детекция блокировки)
  HttpTest.cs (расширить: Vivox, AWS endpoints)
  UdpProbeRunner.cs (расширить: игровые порты 64090-64094)
  TracerouteTest.cs (оставить как есть)
  RstHeuristic.cs (заменить на DPI Test)
  
  FirewallTest.cs (новый) — Windows Firewall + Defender
  IspTest.cs (новый) — CGNAT + DPI + DNS фильтрация + ISP info
  RouterTest.cs (новый) — UPnP + SIP ALG + Gateway ping + QoS
  SoftwareTest.cs (новый) — антивирусы + VPN + прокси + hosts
```

**Новые модели данных:**
```csharp
// Output/FirewallTestResult.cs
public record FirewallTestResult(
    bool windowsFirewallEnabled,
    List<string> blockedPorts, // ["8000", "8001", "8002"]
    bool windowsDefenderActive,
    List<string> blockingRules // ["RuleName: blocks port 8000"]
);

// Output/IspTestResult.cs
public record IspTestResult(
    string? isp, string? country, string? city,
    bool cgnatDetected,
    bool dpiDetected,
    bool dnsFiltered,
    List<string> knownProblematicISPs // ["Rostelecom", "Beeline"]
);

// Output/RouterTestResult.cs
public record RouterTestResult(
    string? gatewayIp,
    bool upnpEnabled,
    bool sipAlgDetected,
    double avgPingMs,
    double maxPingMs,
    int packetLossPercent
);

// Output/SoftwareTestResult.cs
public record SoftwareTestResult(
    List<string> antivirusDetected, // ["Kaspersky", "Windows Defender"]
    List<string> vpnClientsDetected, // ["NordVPN", "ProtonVPN"]
    bool proxyEnabled,
    bool hostsFileIssues
);
```

**Интеграция в `RunReport` и `Summary`:**
```csharp
public class RunReport
{
    // ... existing fields ...
    public FirewallTestResult? firewall { get; set; }
    public IspTestResult? isp { get; set; }
    public RouterTestResult? router { get; set; }
    public SoftwareTestResult? software { get; set; }
}

public class Summary
{
    // ... existing fields ...
    public string firewall { get; set; } = "UNKNOWN"; // OK / BLOCKING / UNKNOWN
    public string isp_blocking { get; set; } = "UNKNOWN"; // OK / DNS_FILTERED / DPI / CGNAT / UNKNOWN
    public string router_issues { get; set; } = "UNKNOWN"; // OK / NO_UPNP / SIP_ALG / UNSTABLE / UNKNOWN
    public string software_conflicts { get; set; } = "UNKNOWN"; // OK / ANTIVIRUS / VPN / PROXY / HOSTS / UNKNOWN
}
```

### 4.3 Порядок выполнения тестов

**Предлагаемая последовательность:**
```
1. System Info
   - VPN Detection (NetUtils.LikelyVpnActive)
   - External IP (NetUtils.TryGetExternalIpAsync)

2. Параллельный блок (System-level)
   a) Software Detection (антивирусы, VPN клиенты, прокси, hosts)
   b) Firewall Check (Windows Firewall, Defender)
   c) Router Check (gateway ping, UPnP)
   d) ISP Check (ISP info, CGNAT, DNS фильтрация) — требует external IP

3. Per-Target тесты (последовательно для каждой цели)
   - DNS Test (System DNS vs DoH vs Google DNS)
   - TCP Test (порты 80/443/8000-8020)
   - HTTP Test (HTTPS + Vivox + AWS endpoints)

4. UDP Test (игровые порты 64090-64094)

5. Traceroute (опционально, отключено по умолчанию)

6. BuildSummary (агрегация + вердикт playable)
```

**Параллелизация:**
- Software/Firewall/Router/ISP — параллельно (не зависят друг от друга)
- DNS/TCP/HTTP — последовательно per-target (DNS → TCP → HTTP)

### 4.4 GUI изменения

**Новые карточки (MaterialDesignCard):**
- `FirewallCard` — если firewall == BLOCKING:
  ```
  🛡️ Windows Firewall блокирует порты
  • Порт 8000 (Launcher)
  • Порт 8001 (Launcher)
  Рекомендация: Откройте порты 8000-8003 в Windows Firewall
  ```

- `IspCard` — если isp_blocking == DPI/CGNAT/DNS_FILTERED:
  ```
  🌐 Провайдер блокирует игровые сервисы
  • Провайдер: Rostelecom (Russia)
  • DPI обнаружен (Deep Packet Inspection)
  Рекомендация: Используйте VPN или bypass режим
  ```

- `RouterCard` — если router_issues == NO_UPNP/SIP_ALG/UNSTABLE:
  ```
  📡 Проблемы с роутером
  • UPnP отключен
  • Нестабильное соединение (макс пинг: 250ms)
  Рекомендация: Включите UPnP в настройках роутера
  ```

- `SoftwareCard` — если software_conflicts == ANTIVIRUS/VPN/PROXY:
  ```
  💾 Конфликты программного обеспечения
  • Обнаружен: Kaspersky Antivirus
  • Hosts файл содержит записи для RSI доменов
  Рекомендация: Добавьте Star Citizen в исключения антивируса
  ```

**Обновление `TestProgress`:**
```csharp
public enum TestKind
{
    DNS, TCP, HTTP, UDP, TRACEROUTE, RST,
    FIREWALL, ISP, ROUTER, SOFTWARE // новые
}
```

### 4.5 Новый алгоритм вердикта

**Логика `playable` с учётом новых тестов:**
```csharp
playable = NO:
  - firewall == BLOCKING И блокирует порты 8000-8003
  - isp_blocking == DPI И tls == SUSPECT
  - tcp_portal == FAIL (порты 80/443 закрыты)
  - dns == DNS_BOGUS
  - Vivox недоступен (viv.vivox.com:443 FAIL)
  - AWS endpoints недоступны (все 4 региона FAIL)

playable = MAYBE:
  - isp_blocking == CGNAT (voice chat может не работать)
  - router_issues == NO_UPNP (P2P может не работать)
  - software_conflicts == ANTIVIRUS (может блокировать)
  - tcp_launcher == WARN (частично доступен)
  - Vivox частично доступен (1-2 региона недоступны)

playable = YES:
  - VPN активен И tls == OK (даже если DNS/TCP WARN)
  - firewall == OK И isp_blocking == OK И tcp_portal == OK И tls == OK
  - Vivox доступен И хотя бы 1 AWS регион доступен
```

### 4.6 .NET API для портирования PowerShell команд

**Windows Firewall:**
```csharp
// Вариант 1: WMI (требует NuGet: System.Management + админ)
using System.Management;
var scope = new ManagementScope(@"root\StandardCimv2");
var query = new ObjectQuery("SELECT * FROM MSFT_NetFirewallRule WHERE Enabled = TRUE");
var searcher = new ManagementObjectSearcher(scope, query);
foreach (ManagementObject rule in searcher.Get())
{
    string name = rule["DisplayName"]?.ToString();
    string action = rule["Action"]?.ToString(); // "Block" or "Allow"
}

// Вариант 2: netsh (парсинг вывода)
var process = Process.Start(new ProcessStartInfo
{
    FileName = "netsh",
    Arguments = "advfirewall firewall show rule name=all",
    RedirectStandardOutput = true,
    UseShellExecute = false
});
string output = process.StandardOutput.ReadToEnd();
// Парсинг output для поиска блокирующих правил
```

**Windows Defender:**
```csharp
// Вариант 1: WMI (требует админ)
var scope = new ManagementScope(@"root\Microsoft\Windows\Defender");
var query = new ObjectQuery("SELECT * FROM MSFT_MpPreference");
// ...

// Вариант 2: Реестр (не требует админ)
using Microsoft.Win32;
var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");
if (key != null)
{
    var exclusions = key.GetValueNames();
    // Проверить наличие "C:\Program Files\Roberts Space Industries"
}
```

**Network Adapters:**
```csharp
using System.Net.NetworkInformation;
var adapters = NetworkInterface.GetAllNetworkInterfaces();
foreach (var adapter in adapters)
{
    if (adapter.OperationalStatus == OperationalStatus.Up)
    {
        string name = adapter.Name;
        string desc = adapter.Description;
        var type = adapter.NetworkInterfaceType; // Tunnel для VPN
    }
}
```

**Processes/Services:**
```csharp
using System.Diagnostics;
using System.ServiceProcess;

// Процессы
var processes = Process.GetProcesses();
foreach (var proc in processes)
{
    if (proc.ProcessName.Contains("avp", StringComparison.OrdinalIgnoreCase))
        // Kaspersky обнаружен
}

// Службы
var services = ServiceController.GetServices();
foreach (var svc in services)
{
    if (svc.ServiceName == "nordvpn" && svc.Status == ServiceControllerStatus.Running)
        // NordVPN активен
}
```

**Hosts File:**
```csharp
string hostsPath = Environment.GetFolderPath(Environment.SpecialFolder.System) + @"\drivers\etc\hosts";
if (File.Exists(hostsPath))
{
    var lines = File.ReadAllLines(hostsPath);
    var suspicious = lines.Where(line => 
        !line.StartsWith("#") &&
        (line.Contains("robertsspaceindustries") || line.Contains("cloudimperiumgames"))
    );
}
```

**Registry (System Proxy):**
```csharp
using Microsoft.Win32;
var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
if (key != null)
{
    int proxyEnable = (int)(key.GetValue("ProxyEnable") ?? 0);
    string proxyServer = key.GetValue("ProxyServer")?.ToString();
    if (proxyEnable == 1) // Прокси включен
}
```

**UPnP:**
```csharp
// COM Interop
Type upnpFinderType = Type.GetTypeFromProgID("UPnP.UPnPDeviceFinder");
if (upnpFinderType != null)
{
    dynamic finder = Activator.CreateInstance(upnpFinderType);
    dynamic devices = finder.FindByType("urn:schemas-upnp-org:device:InternetGatewayDevice:1", 0);
    int count = devices.Count; // Количество UPnP устройств
}
```

### 4.7 Тестирование

**Тестовые сценарии (8 шт):**
1. **Без VPN, всё работает**
   - Ожидаемый результат: `playable = YES`, нет предупреждений

2. **Без VPN, Windows Firewall блокирует порт 8000**
   - Ожидаемый результат: `playable = NO`, "Windows Firewall блокирует порт 8000"

3. **Без VPN, ISP блокирует HTTPS (DPI)**
   - Ожидаемый результат: `playable = NO`, "Провайдер блокирует HTTPS (DPI)"

4. **С VPN (full tunnel), всё работает**
   - Ожидаемый результат: `playable = YES`, баннер "VPN активен"

5. **С VPN (split tunnel), VPN не туннелирует игровые порты**
   - Ожидаемый результат: `playable = MAYBE`, "VPN не туннелирует порты 8000-8020"

6. **CGNAT провайдер**
   - Ожидаемый результат: `playable = MAYBE`, "Провайдер использует CGNAT — voice chat может не работать"

7. **Vivox недоступен**
   - Ожидаемый результат: `playable = MAYBE`, "Voice chat (Vivox) недоступен"

8. **AWS endpoints недоступны (все 4 региона)**
   - Ожидаемый результат: `playable = NO`, "Игровые серверы (AWS) недоступны"

**Unit тесты (моки):**
- `FirewallTest`: мок WMI результатов для Windows Firewall правил
- `IspTest`: мок ip-api.com JSON ответов (ISP, country, CGNAT)
- `RouterTest`: мок NetworkInterface для gateway IP
- `SoftwareTest`: мок Process.GetProcesses() для детекции антивирусов

### 4.8 Оценка сложности и времени

**Оценка времени (для продвинутой модели):**

**P0 задачи (критичные):**
1. Firewall Test: 2-3 часа (WMI интеграция + парсинг правил)
2. ISP DNS Filtering: 1-2 часа (добавить Google DNS в DnsTest)
3. Vivox Check: 1 час (добавить цель в HttpTest)
4. AWS Endpoints Check: 1-2 часа (добавить 4 цели в star_citizen_targets.json + HttpTest)
5. Улучшение вердикта: 2-3 часа (переписать BuildSummary с учётом новых тестов)

**P1 задачи (важные):**
6. ISP DPI Test: 2-3 часа (детекция модификации заголовков + CGNAT)
7. Router UPnP Check: 2-3 часа (COM Interop + gateway ping)
8. Software Detection: 2-3 часа (детекция процессов/служб + hosts + прокси)
9. UDP Game Ports: 1-2 часа (добавить 5 портов в UdpProbeRunner)

**GUI изменения:**
10. Новые карточки (Firewall/ISP/Router/Software): 3-4 часа (XAML + ViewModel)
11. Обновление прогресса (новые TestKind): 1-2 часа

**Тестирование:**
12. Unit тесты: 2-3 часа
13. Интеграционные тесты (8 сценариев): 2-3 часа

**Итого:** 22-34 часа (3-4 дня для продвинутой модели)

### 4.9 NuGet пакеты и зависимости

**Требуемые NuGet пакеты:**
```xml
<PackageReference Include="System.Management" Version="9.0.0" />
```

**Опциональные:** нет (все остальные API — в стандартной библиотеке .NET)

---

## Итого: Ключевые выводы

### Текущие проблемы:
1. ✗ Вердикт `playable` НЕ учитывает firewall/ISP/router → ложные срабатывания
2. ✗ VPN-режим адаптирован ТОЛЬКО в DNS/HTTP, НО вердикт НЕ адаптирован
3. ✗ НЕТ проверки Vivox (voice chat) и AWS endpoints (игровые серверы)
4. ✗ НЕТ категоризации проблем (Firewall/ISP/Router/Software) → пользователь не понимает причину

### Решения:
1. ✓ Добавить 4 новых теста (Firewall/ISP/Router/Software)
2. ✓ Расширить существующие тесты (DNS: Google DNS, HTTP: Vivox+AWS, UDP: игровые порты)
3. ✓ Переписать логику вердикта с учётом firewall/ISP/VPN/router
4. ✓ Добавить 4 новые карточки в GUI для категоризированных проблем
5. ✓ Использовать .NET API (System.Management/Registry/Process/NetworkInterface)

### Приоритеты:
- **P0** (критично): Firewall Test, ISP DNS Filtering, Vivox, AWS Endpoints, улучшение вердикта
- **P1** (важно): ISP DPI, Router UPnP, Software Detection, UDP Game Ports
- **P2** (nice-to-have): Router SIP ALG/QoS/Stability, Hosts File, System Proxy

### Оценка времени:
- **P0**: 8-11 часов
- **P1**: 7-11 часов
- **GUI**: 4-6 часов
- **Тестирование**: 4-6 часов
- **Итого**: 22-34 часа (3-4 дня)

**Готово для Planning Agent!**
