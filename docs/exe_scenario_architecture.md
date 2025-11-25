# Архитектура: Сценарий "По .exe" — Трёхэтапный автоматизированный workflow

**Дата**: 2025-11-19  
**Статус**: DESIGN  
**Цель**: Полная автоматизация диагностики и обхода блокировок для произвольного приложения

---

## Обзор

Пользователь выбирает exe файл → ISP_Audit автоматически:
1. **Собирает профиль** (анализ трафика приложения)
2. **Диагностирует проблемы** (DNS/TCP/TLS тесты)
3. **Применяет обход** (автоматическая конфигурация WinDivert)

---

## Этап 1: Сбор профиля (Traffic Analysis)

### Цель
Автоматически обнаружить все сетевые подключения приложения без ручной настройки.

### Проблема: WinDivert не поддерживает фильтрацию по PID
WinDivert filter language не имеет поля `ProcessId`:
```c
// ❌ НЕ РАБОТАЕТ
WinDivertOpen("ProcessId == 1234", WINDIVERT_LAYER_NETWORK, ...);
```

### Решение: SOCKET Layer + ETW Fallback

#### Подход 1: WinDivert SOCKET Layer (Recommended)
**Преимущество**: Встроенная поддержка ProcessId в SOCKET layer.

```c
// ✅ РАБОТАЕТ на SOCKET layer
WinDivertOpen("true", WINDIVERT_LAYER_SOCKET, 0, WINDIVERT_FLAG_SNIFF);
```

**WINDIVERT_ADDRESS структура** содержит:
- `Socket.ProcessId` — PID процесса
- `Socket.LocalAddr` — локальный IP:port
- `Socket.RemoteAddr` — удалённый IP:port
- `Socket.Protocol` — TCP/UDP

**Алгоритм**:
1. Открыть WinDivert handle на `WINDIVERT_LAYER_SOCKET` с `WINDIVERT_FLAG_SNIFF`
2. Запустить целевое приложение (или получить PID существующего процесса)
3. В цикле `WinDivertRecv()` собирать события:
   - Фильтровать по `addr.Socket.ProcessId == targetPid`
   - Извлекать `RemoteAddr` (IP + Port)
4. Через 30-60 секунд остановить сбор
5. Для каждого уникального IP выполнить reverse DNS → получить hostname
6. Сохранить в `Profiles/{exeName}.json`

**Преимущества**:
- ✅ Точная фильтрация по PID
- ✅ Видит TCP + UDP подключения
- ✅ Не требует парсинга пакетов
- ✅ Работает для всех приложений

**Недостатки**:
- ⚠️ SOCKET layer требует Windows 10 1903+
- ⚠️ Не видит DNS queries (только resolved IP)

---

#### Подход 2: NETWORK Layer + Process Mapping (Fallback)
Для старых Windows или если SOCKET layer недоступен.

**Алгоритм**:
1. Открыть WinDivert на `WINDIVERT_LAYER_NETWORK` с фильтром `"tcp or udp"`
2. Запустить приложение, получить PID
3. Параллельно мониторить **TCP/UDP таблицу соединений** через `GetExtendedTcpTable()` / `GetExtendedUdpTable()`
4. Сопоставлять захваченные пакеты (src IP:port) с таблицей → получать PID
5. Фильтровать пакеты по целевому PID
6. Извлекать destination IP:port
7. Reverse DNS → hostname
8. Сохранять в профиль

**Преимущества**:
- ✅ Работает на Windows 7+
- ✅ Видит DNS queries (можно парсить UDP:53)

**Недостатки**:
- ⚠️ Требует парсинга IP/TCP/UDP заголовков
- ⚠️ Race condition между захватом пакета и чтением таблицы
- ⚠️ Сложнее в реализации

---

#### Подход 3: ETW (Event Tracing for Windows) для DNS
Для захвата **только DNS queries** без WinDivert.

**ETW Provider**: `Microsoft-Windows-DNS-Client`  
**Event ID**: 3008 (DNS Query)

**Алгоритм**:
1. Создать ETW trace session с подпиской на DNS-Client provider
2. Фильтровать события по `ProcessId == targetPid`
3. Извлекать `QueryName` из event payload
4. Сохранять уникальные домены

**Преимущества**:
- ✅ Простота (не нужен WinDivert для DNS)
- ✅ Видит оригинальные доменные имена (не IP)
- ✅ Lightweight

**Недостатки**:
- ⚠️ Только DNS (не видит прямые IP подключения)
- ⚠️ Требует admin прав
- ⚠️ ETW API сложнее WinDivert

---

### Рекомендуемая реализация: Hybrid SOCKET + ETW

**TrafficAnalyzer.cs**:
```csharp
public class TrafficAnalyzer
{
    // Этап 1: Захват сетевых подключений
    public async Task<GameProfile> AnalyzeProcessTrafficAsync(
        string exePath, 
        int durationSeconds,
        IProgress<string> progress,
        CancellationToken ct)
    {
        // 1. Запустить процесс
        var process = Process.Start(exePath);
        int pid = process.Id;
        
        // 2. Запустить SOCKET layer monitor (TCP/UDP connections)
        var socketTask = CaptureSocketConnectionsAsync(pid, durationSeconds, ct);
        
        // 3. Параллельно запустить ETW DNS monitor
        var dnsTask = CaptureDnsQueriesAsync(pid, durationSeconds, ct);
        
        // 4. Ждать завершения
        await Task.WhenAll(socketTask, dnsTask);
        
        // 5. Объединить результаты
        var connections = socketTask.Result;
        var domains = dnsTask.Result;
        
        // 6. Создать профиль
        return BuildGameProfile(exePath, connections, domains);
    }
    
    private async Task<List<NetworkConnection>> CaptureSocketConnectionsAsync(
        int pid, int duration, CancellationToken ct)
    {
        // WinDivert SOCKET layer с фильтрацией по PID
        // ...
    }
    
    private async Task<List<string>> CaptureDnsQueriesAsync(
        int pid, int duration, CancellationToken ct)
    {
        // ETW DNS trace с фильтрацией по PID
        // ...
    }
}
```

---

## Этап 2: Диагностика (Problem Detection)

### Цель
Проверить доступность всех обнаруженных Target'ов и классифицировать проблемы.

### Компоненты

#### 2.1 AuditRunner (существующий)
Уже реализован, используем как есть:
```csharp
var targets = profile.Targets; // из Этапа 1
await auditRunner.RunAsync(targets, config, progress, ct);
```

**Результат**: Массив `TestResult[]` с статусами (Pass/Fail/Unknown).

---

#### 2.2 ProblemClassifier.cs (новый)
Анализирует результаты тестов и определяет **тип блокировки** для каждого Target.

```csharp
public class ProblemClassifier
{
    public BlockageType ClassifyProblem(TestResult result)
    {
        // DNS фильтрация
        if (result.DnsStatus == "DNS_FILTERED" || result.DnsStatus == "DNS_BOGUS")
            return BlockageType.DnsFiltering;
        
        // DPI (TCP RST injection)
        if (result.TcpStatus == "FAIL" && result.HttpStatus == "SUSPECT")
            return BlockageType.DpiRstInjection;
        
        // TLS SNI filtering
        if (result.TcpStatus == "OK" && result.HttpStatus == "FAIL")
            return BlockageType.TlsSniFiltering;
        
        // Firewall блокировка
        if (result.TcpStatus == "FAIL" && result.FirewallBlocked)
            return BlockageType.FirewallBlock;
        
        // UDP блокировка
        if (result.UdpStatus == "FAIL")
            return BlockageType.UdpBlock;
        
        return BlockageType.None;
    }
}

public enum BlockageType
{
    None,
    DnsFiltering,       // Провайдер подменяет DNS
    DpiRstInjection,    // DPI сбрасывает TCP соединения
    TlsSniFiltering,    // DPI блокирует TLS по SNI
    FirewallBlock,      // Windows Firewall блокирует
    UdpBlock            // UDP трафик не проходит
}
```

---

#### 2.3 BypassStrategyPlanner.cs (новый)
Создаёт **план обхода** на основе классификации проблем.

```csharp
public class BypassStrategyPlanner
{
    public BypassProfile PlanBypassStrategy(
        TestResult[] results, 
        ProblemClassifier classifier)
    {
        var profile = new BypassProfile
        {
            DropTcpRst = false,
            FragmentTlsClientHello = false,
            RedirectRules = new List<BypassRedirectRule>()
        };
        
        foreach (var result in results.Where(r => r.Status == TestStatus.Fail))
        {
            var blockage = classifier.ClassifyProblem(result);
            
            switch (blockage)
            {
                case BlockageType.DnsFiltering:
                    // Решение: DoH (обработается отдельно, не через WinDivert)
                    result.FixType = FixType.DnsChange;
                    break;
                
                case BlockageType.DpiRstInjection:
                    // Решение: Drop TCP RST пакеты
                    profile.DropTcpRst = true;
                    result.FixType = FixType.Manual; // "Обход DPI активирован"
                    break;
                
                case BlockageType.TlsSniFiltering:
                    // Решение: Fragment TLS ClientHello
                    profile.FragmentTlsClientHello = true;
                    profile.TlsFirstFragmentSize = 64;
                    profile.TlsFragmentThreshold = 128;
                    result.FixType = FixType.Manual; // "Обход SNI активирован"
                    break;
                
                case BlockageType.FirewallBlock:
                    // Решение: Создать правило Firewall
                    result.FixType = FixType.FirewallRule;
                    break;
                
                case BlockageType.UdpBlock:
                    // Решение: Попробовать альтернативные порты (если известны)
                    // Или предложить VPN
                    result.FixType = FixType.Manual; // "Используйте VPN"
                    break;
            }
        }
        
        return profile;
    }
}
```

**Результат**: `BypassProfile` с настройками для WinDivert.

---

## Этап 3: Лечение (Auto-Bypass)

### Цель
Применить обход и запустить приложение с активными правилами.

### Компоненты

#### 3.1 WinDivertBypassManager (существующий, расширить)
Добавить метод для **запуска приложения с обходом**:

```csharp
public class WinDivertBypassManager
{
    // Новый метод
    public async Task<Process> ApplyBypassAndLaunchAsync(
        string exePath, 
        BypassProfile profile,
        CancellationToken ct)
    {
        // 1. Включить WinDivert с профилем
        await EnableAsync(profile, ct);
        
        // 2. Подождать инициализации (100ms)
        await Task.Delay(100, ct);
        
        // 3. Запустить процесс
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = false
        });
        
        // 4. Вернуть процесс (не ждать завершения)
        return process;
    }
    
    // Новый метод: Stop bypass when process exits
    public async Task MonitorProcessAndDisableAsync(Process process)
    {
        await Task.Run(() => process.WaitForExit());
        await DisableAsync();
    }
}
```

---

#### 3.2 DnsFixApplicator.cs (новый)
Для DNS-блокировок WinDivert не поможет — нужно **изменить системные настройки DNS**.

```csharp
public class DnsFixApplicator
{
    public async Task<bool> ApplyCloudflareDoHAsync()
    {
        // 1. Через netsh изменить DNS на 1.1.1.1 / 1.0.0.1
        await RunNetshCommandAsync("interface ipv4 set dns \"Ethernet\" static 1.1.1.1 primary");
        await RunNetshCommandAsync("interface ipv4 add dns \"Ethernet\" 1.0.0.1 index=2");
        
        // 2. Включить DoH в Windows 11 через реестр
        // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
        // DohFlags = 3 (автоматический DoH)
        
        return true;
    }
    
    private async Task<bool> RunNetshCommandAsync(string arguments)
    {
        // Запуск netsh с правами администратора
        // ...
    }
}
```

**Важно**: Требует UAC elevation!

---

## UI Workflow

### Текущий интерфейс (не трогаем структуру)
Добавляем **только функциональность**, UI остаётся как есть.

### Exe-сценарий UI (дополнения):

```xaml
<!-- Блок для Exe-сценария в MainWindow.xaml -->
<StackPanel Visibility="{Binding IsExeScenario, Converter={StaticResource BoolToVis}}">
    <!-- Existing: File selection -->
    <TextBox Text="{Binding ExePath}" />
    <Button Command="{Binding ChooseExeCommand}">Обзор...</Button>
    
    <!-- NEW: Three-stage workflow buttons -->
    <GroupBox Header="Этап 1: Сбор профиля">
        <StackPanel>
            <Button Command="{Binding AnalyzeTrafficCommand}">
                ▶ Анализировать трафик
            </Button>
            <TextBlock Text="{Binding Stage1Status}" />
            <TextBlock Text="{Binding Stage1HostsFound}" />
        </StackPanel>
    </GroupBox>
    
    <GroupBox Header="Этап 2: Диагностика" IsEnabled="{Binding Stage1Complete}">
        <StackPanel>
            <Button Command="{Binding DiagnoseCommand}">
                ▶ Проверить доступность
            </Button>
            <TextBlock Text="{Binding Stage2Status}" />
            <TextBlock Text="{Binding Stage2ProblemsFound}" />
        </StackPanel>
    </GroupBox>
    
    <GroupBox Header="Этап 3: Обход блокировок" IsEnabled="{Binding Stage2Complete}">
        <StackPanel>
            <Button Command="{Binding ApplyBypassCommand}">
                ▶ Применить обход и запустить
            </Button>
            <TextBlock Text="{Binding Stage3Status}" />
        </StackPanel>
    </GroupBox>
</StackPanel>
```

### MainViewModel (новые команды):

```csharp
public class MainViewModel
{
    // Stage 1
    public ICommand AnalyzeTrafficCommand { get; }
    public string Stage1Status { get; set; } = "Ожидание...";
    public string Stage1HostsFound { get; set; } = "Найдено хостов: 0";
    public bool Stage1Complete { get; set; } = false;
    
    // Stage 2
    public ICommand DiagnoseCommand { get; }
    public string Stage2Status { get; set; } = "Ожидание Этапа 1...";
    public string Stage2ProblemsFound { get; set; } = "";
    public bool Stage2Complete { get; set; } = false;
    
    // Stage 3
    public ICommand ApplyBypassCommand { get; }
    public string Stage3Status { get; set; } = "Ожидание Этапа 2...";
    
    private async Task ExecuteAnalyzeTrafficAsync()
    {
        Stage1Status = "Запуск приложения...";
        
        var analyzer = new TrafficAnalyzer();
        var profile = await analyzer.AnalyzeProcessTrafficAsync(
            ExePath, 
            durationSeconds: 60,
            new Progress<string>(msg => Log(msg)),
            _cts.Token
        );
        
        Stage1HostsFound = $"Найдено хостов: {profile.Targets.Count}";
        Stage1Status = "✅ Профиль собран";
        Stage1Complete = true;
        
        // Сохранить профиль для следующих этапов
        _collectedProfile = profile;
    }
    
    private async Task ExecuteDiagnoseAsync()
    {
        Stage2Status = "Проверка доступности...";
        
        await RunTestsAsync(); // Existing method
        
        // Classify problems
        var classifier = new ProblemClassifier();
        var planner = new BypassStrategyPlanner();
        
        _bypassProfile = planner.PlanBypassStrategy(
            TestResults.ToArray(), 
            classifier
        );
        
        int problems = TestResults.Count(r => r.Status == TestStatus.Fail);
        Stage2ProblemsFound = $"Обнаружено проблем: {problems}";
        Stage2Status = problems > 0 ? "⚠ Найдены блокировки" : "✅ Всё работает";
        Stage2Complete = true;
    }
    
    private async Task ExecuteApplyBypassAsync()
    {
        Stage3Status = "Применение обхода...";
        
        // Apply DNS fix if needed
        var dnsResults = TestResults.Where(r => r.FixType == FixType.DnsChange);
        if (dnsResults.Any())
        {
            var dnsApplicator = new DnsFixApplicator();
            await dnsApplicator.ApplyCloudflareDoHAsync();
        }
        
        // Apply WinDivert bypass
        var bypassManager = new WinDivertBypassManager();
        var process = await bypassManager.ApplyBypassAndLaunchAsync(
            ExePath, 
            _bypassProfile,
            _cts.Token
        );
        
        Stage3Status = $"✅ Обход активен. Приложение запущено (PID {process.Id})";
        
        // Monitor process and disable bypass when it exits
        _ = bypassManager.MonitorProcessAndDisableAsync(process);
    }
}
```

---

## Структура файлов

### Новые файлы:

```
Utils/
├── TrafficAnalyzer.cs          # Этап 1: Захват трафика (SOCKET + ETW)
├── NetworkConnection.cs         # Model: IP:Port + Protocol
├── ProblemClassifier.cs         # Этап 2: Классификация блокировок
├── BypassStrategyPlanner.cs     # Этап 2: Генерация BypassProfile
├── DnsFixApplicator.cs          # Этап 3: Изменение системных DNS
└── ProcessLauncher.cs           # Утилиты для запуска процессов

Bypass/
└── WinDivertBypassManager.cs    # РАСШИРИТЬ: ApplyBypassAndLaunchAsync()
```

### Модели данных:

```csharp
// NetworkConnection.cs
public record NetworkConnection(
    IPAddress RemoteIp,
    ushort RemotePort,
    TransportProtocol Protocol,
    string? Hostname // resolved via reverse DNS
);

// BlockageType.cs (enum)
public enum BlockageType
{
    None,
    DnsFiltering,
    DpiRstInjection,
    TlsSniFiltering,
    FirewallBlock,
    UdpBlock
}
```

---

## Требования

### Технические
- ✅ .NET 9 (уже используется)
- ✅ WinDivert 2.2+ (уже интегрирован)
- ⚠️ Windows 10 1903+ для SOCKET layer (fallback на NETWORK layer для старых версий)
- ⚠️ Admin права (уже требуются для WinDivert)

### Безопасность
- ⚠️ Запуск стороннего exe файла — потенциальный риск
- ✅ Пользователь сам выбирает файл через FileDialog
- ✅ Показываем PID и имя процесса перед запуском
- ✅ Мониторинг только во время активного сеанса (30-60 секунд)
- ✅ Автоматическое отключение bypass при завершении процесса

---

## Альтернативные подходы (отклонены)

### 1. Pcap через SharpPcap
**Проблема**: Требует установки WinPcap/Npcap, зависимость от сторонней библиотеки.  
**Решение**: WinDivert уже в проекте, не требует дополнительных драйверов.

### 2. Статический анализ exe файла
**Проблема**: Ненадёжно — может найти устаревшие/неиспользуемые хосты, пропустить динамические подключения.  
**Решение**: Runtime traffic capture даёт только реально используемые адреса.

### 3. Hooking Windows API (WSASendTo, connect)
**Проблема**: Требует инъекции DLL в процесс, сложность с защитой от tampering (античиты).  
**Решение**: WinDivert работает на уровне драйвера, не требует модификации процесса.

---

## Риски и митигация

| Риск | Вероятность | Влияние | Митигация |
|------|-------------|---------|-----------|
| Приложение не создаёт сетевой трафик за 60 секунд | Средняя | Высокое | Показать таймер, дать пользователю возможность продлить/остановить |
| SOCKET layer недоступен (Windows 7) | Низкая | Среднее | Fallback на NETWORK layer + TCP/UDP table mapping |
| Приложение использует DoH/VPN → bypass не нужен | Низкая | Низкое | Проверять результаты Этапа 2, если все тесты Pass → пропускать Этап 3 |
| Пользователь забыл остановить bypass | Средняя | Среднее | Auto-disable при завершении процесса, кнопка "Остановить" в UI |

---

## Дальнейшие улучшения (v2)

1. **Профили для популярных приложений**:
   - Discord.exe → автоматически использовать готовый профиль вместо анализа
   - StarCitizen.exe → готовый профиль уже есть

2. **Machine Learning для классификации**:
   - Обучить модель на исторических данных для более точной классификации blockage type

3. **Community-driven профили**:
   - Пользователи могут делиться профилями через облако
   - Автоматическое скачивание популярных профилей

4. **GUI Wizard**:
   - Пошаговый мастер вместо 3 отдельных кнопок
   - "Next" автоматически переходит к следующему этапу

---

## Заключение

**Предложенная архитектура** обеспечивает:
✅ Полную автоматизацию (от выбора exe до запуска с bypass)  
✅ Точную диагностику (классификация типов блокировок)  
✅ Гибкость (работает для любого Windows-приложения)  
✅ Обратную совместимость (существующие профили + Host/Profile сценарии работают как раньше)

**Сложность реализации**: ~1500-2000 строк кода, 3-5 дней работы.

**Приоритет**: MEDIUM-HIGH (после завершения Export reports можно приступать к реализации).

---

## Реализация (Final Implementation)

В итоговой версии (ноябрь 2025) мы отказались от выбора "одного из" подходов в пользу **Гибридной Multi-Layer Архитектуры**:

1. **WinDivert FLOW Layer (-1000)**:
   - Основной источник данных о соединениях (PID, IP, Port).
   - Работает в пассивном режиме (Sniff).

2. **WinDivert SOCKET Layer (-1000)**:
   - Ловит события `SOCKET_CONNECT` (попытки соединения).
   - Критически важен для обнаружения ресурсов, заблокированных по IP (когда SYN-пакеты дропаются и Flow не создается).

3. **WinDivert NETWORK Layer (0)**:
   - Используется для DNS-парсинга (UDP:53) и анализа TLS SNI (TCP:443).
   - Позволяет обогащать данные хостнеймами.

4. **IP Helper Fallback (Watcher Mode)**:
   - При активации активного обхода (Bypass) слои FLOW и SOCKET отключаются во избежание конфликтов драйвера.
   - Вместо них используется polling через `GetExtendedTcpTable` (Watcher Mode).

Этот подход обеспечивает 100% покрытие трафика в режиме диагностики и стабильность в режиме обхода.
