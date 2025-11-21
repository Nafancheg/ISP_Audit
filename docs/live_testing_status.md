# Live Testing Pipeline - Статус Реализации

## ✅ Завершено

### Архитектура (Feature Branch: `feature/live-testing-pipeline`)

```
Sniffer (TrafficAnalyzer) → Channel → Tester → Channel → Classifier → Channel → UI/Bypass
                              ↓                    ↓                      ↓
                        HostDiscovered        HostTested            HostBlocked
                                                                        ↓
                                                              WinDivertBypassManager
```

### Компоненты

#### 1. LiveTestingPipeline.cs (470+ строк)
- **Каналы**: `Channel<HostDiscovered>`, `Channel<HostTested>`, `Channel<HostBlocked>`
- **3 независимых worker'а**: TesterWorker, ClassifierWorker, UiWorker
- **Fire-and-forget**: Не блокирует sniffer при тестировании
- **WinDivert интеграция**: Автоматическое применение bypass (если admin права)

#### 2. TestHostAsync() - Быстрое тестирование
```csharp
// 1. Reverse DNS (GetHostEntryAsync)
// 2. TCP connect (таймаут 3с)
// 3. TLS handshake (только HTTPS с hostname)
```

**Результат**: `HostTested` с полями:
- `DnsOk`, `TcpOk`, `TlsOk`
- `DnsStatus` (OK/DNS_FILTERED)
- `Hostname` (reverse DNS)
- `TcpLatencyMs`
- `BlockageType` (TCP_RST/TLS_DPI/TCP_TIMEOUT/TLS_TIMEOUT/PORT_CLOSED)

#### 3. ClassifyBlockage() - Классификация блокировок
| Симптомы | Диагноз | Стратегия | Действие |
|----------|---------|-----------|----------|
| DNS_FILTERED/DNS_BOGUS | DNS блокировка | `DOH` | Использовать DNS over HTTPS |
| TCP RST после connect | TCP RST injection | `DROP_RST` | Блокировать RST пакеты (WinDivert) |
| TLS timeout + TCP OK | DPI на TLS | `TLS_FRAGMENT` | Фрагментация ClientHello |
| TCP timeout | Firewall/Route block | `PROXY` | Проксирование |
| Port closed | Не блокировка | `NONE` | Игнорировать |

#### 4. UiWorker - Вывод результатов
```
✓ example.com:443 (12ms)
❌ blocked.com:443 (156ms) | DNS:✓ TCP:✓ TLS:✗ | TLS_DPI
   → Стратегия: TLS_FRAGMENT
   → Применяю bypass для blocked.com...
```

#### 5. Интеграция с TrafficAnalyzer
- Параметр `enableLiveTesting` в `AnalyzeProcessTrafficAsync()`
- При обнаружении нового хоста: `pipeline.EnqueueHostAsync(discovered)`
- `RunFlowMonitor()` принимает `LiveTestingPipeline? pipeline`

### Сборка
✅ `dotnet build` успешна, все тесты компилируются

### 5. ApplyBypassAsync() - ✅ ПОЛНОСТЬЮ РЕАЛИЗОВАНО
**Статус**: Интегрировано с WinDivertBypassManager

**Реализация**:
```csharp
private async Task ApplyBypassAsync(HostBlocked blocked, CancellationToken ct)
{
    switch (blocked.BypassStrategy)
    {
        case "DROP_RST":
            await _bypassManager.ApplyBypassStrategyAsync("DROP_RST", ip, port);
            // WinDivert filter: outbound and tcp.Rst == 1
            break;
            
        case "TLS_FRAGMENT":
            await _bypassManager.ApplyBypassStrategyAsync("TLS_FRAGMENT", ip, port);
            // WinDivert filter: outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0
            // Параметры: FirstFragmentSize=64, Threshold=128
            break;
    }
}
```

**WinDivertBypassManager API (новые методы)**:
- `EnableTlsFragmentationAsync(ip, port)` - TLS fragmentation для HTTPS
- `EnableRstBlockingAsync()` - блокировка TCP RST пакетов
- `ApplyBypassStrategyAsync(strategy, ip, port)` - универсальный метод

**Особенности**:
- `EnableAutoBypass=true` по умолчанию (автоматическое применение)
- Проверка admin прав (WinDivert требует администратора)
- Bypass активен пока LiveTestingPipeline жив
- Graceful degradation: без admin - только логи рекомендаций
- Автоматическое отключение при `Dispose()`

## ⏳ В Разработке

### 1. DNS Resolution в TestHostAsync ⚠️ **КРИТИЧНО - ПРИОРИТЕТ 0**
**Статус**: Только reverse DNS, прямой резолв не реализован
**Проблема**: Reverse DNS недостаточен для детекции DNS poisoning/hijacking

**План реализации**:
```csharp
// Последовательность проверки DNS:
async Task<DnsTestResult> TestDnsAsync(string host)
{
    // 1. System DNS резолв → получить официальный IP
    var systemIps = await Dns.GetHostAddressesAsync(host);
    
    // 2. Сравнить с IP из трафика
    bool ipMismatch = !systemIps.Contains(trafficIp);
    
    // 3. Если не совпадают → DoH запрос для верификации
    if (ipMismatch) {
        var dohIps = await QueryDoHAsync(host); // cloudflare-dns.com
        
        // 4. Детекция DNS poisoning
        if (dohIps.Contains(trafficIp) && !systemIps.Contains(trafficIp))
            return DNS_HIJACKED; // System DNS возвращает поддельный IP
    }
    
    return OK;
}
```

**Требования**:
- Добавить System DNS резолв для сравнения с IP из трафика
- DoH клиент (cloudflare-dns.com, dns.google) для верификации
- Детекция DNS poisoning: System DNS ≠ DoH результат
- Если System DNS → bypass IP (198.18.x.x) → `DNS_BYPASS`
- Если System DNS → bogus IP (0.0.0.0, 127.x) → `DNS_BOGUS`

### 2. GUI Интеграция
**Статус**: Только console `IProgress<string>`

**План**:
- `MainViewModel` должен получать `HostTested`/`HostBlocked` события
- Таблица live результатов в `MainWindow.xaml`
- Кнопка "Применить bypass" для выбранных хостов
- Статистика: успешные/заблокированные/bypassed

### 3. Тестирование с FsHud
**План**:
1. Удалить все правила из Podkop роутера
2. Запустить FsHud → приложение не загрузится (CloudFront CDN заблокирован)
3. ISP_Audit → "Приложение" → FsHud.exe → включить "Live Testing"
4. Захват трафика → pipeline тестирует каждый хост
5. Детектирует блокировки (ожидается `dp0wn1kjwhg75.cloudfront.net` → TLS_DPI)
6. Применяет TLS_FRAGMENT bypass
7. FsHud работает без ручной настройки роутера

## ❌ Не Реализовано

### 1. Persistence Bypass Правил
- Текущие WinDivert bypass работают только пока процесс ISP_Audit.exe активен
- После закрытия bypass исчезает
- Нужно: сохранение правил, автозапуск службы, или интеграция с Windows Firewall

### 2. Мульти-Процесс Сниффер
- Сейчас: 1 приложение = 1 pipeline instance
- Нужно: одновременный захват нескольких приложений с общим bypass manager

### 3. Bypass Strategy Refinement
- Сейчас: фиксированные стратегии (DROP_RST, TLS_FRAGMENT)
- Нужно: параметры из `docs/bypass_strategy_todo.md`:
  - `--dpi-desync-repeats=6`
  - `--dpi-desync-autottl=2`
  - `--dpi-desync-fooling=badseq`
  - Тестирование эффективности каждой стратегии

### 4. DoH Integration
- DoH клиент для обхода DNS блокировок
- Текущая реализация DNS test использует System DNS
- Нужно: встроенный DoH resolver (cloudflare-dns.com, dns.google)

## 🔍 Следующие Шаги

### Приоритет 0: 🔥 КРИТИЧНЫЕ БАГИ
1. **Исправить WinDivert Priority**
   - Изменить TLS fragmenter priority: `-1` → `1000`
   - Тестирование: запустить от администратора, проверить отсутствие error 87
   - Верификация: bypass должен активироваться для HTTPS хостов

2. **Bounded Channels + Deduplication**
   - Ограничить размер очереди (1000 элементов)
   - Кэш протестированных хостов (TTL 5 минут)
   - Предотвращение memory leak при burst трафике

### Приоритет 1: DNS Resolution (КРИТИЧНО)
1. **Реализовать полную DNS проверку**
   - System DNS резолв
   - DoH клиент (cloudflare-dns.com, dns.google)
   - Сравнение результатов для детекции DNS hijacking
   - Статусы: `DNS_HIJACKED`, `DNS_POISONED`, `DNS_BYPASS`

2. **Параллельное тестирование**
   - DNS + TCP одновременно (`Task.WhenAll`)
   - TLS только если TCP успешен
   - Сокращение времени тестирования с ~6с до ~3с

### Приоритет 2: Оптимизация Performance
1. **Адаптивные таймауты**
   - Базовый: 3с
   - Адаптивный: `baseTimeout + avgLatency * 2`
   - VPN detection: увеличенные таймауты

2. **TLS Hostname Fallback**
   - SNI parsing из WinDivert captured packets
   - HTTP Host header кэш
   - IP-based TLS (последний вариант)

### Приоритет 3: ApplyBypassAsync Testing
1. `DROP_RST` → WinDivert filter для блокировки RST пакетов
2. `TLS_FRAGMENT` → проверка работы после исправления priority
3. Тестирование на простых случаях (заблокированный Discord/YouTube)

### Приоритет 4: GUI Live Results
1. Observable collection в MainViewModel
2. DataGrid в MainWindow с колонками:
   - Хост, Порт, DNS, TCP, TLS, Latency, Blockage Type, Strategy, Status
3. Context menu: "Применить bypass", "Игнорировать"

### Приоритет 5: FsHud Testing
1. Чистый эксперимент (без Podkop)
2. Захват с `enableLiveTesting = true`
3. Верификация детекции CloudFront блокировки
4. Применение bypass → проверка работы FsHud

### Приоритет 6: Документация
1. Обновить README.md с секцией "Live Testing"
2. Скриншоты GUI с live результатами
3. Примеры bypass правил для типичных блокировок

## 📊 Метрики

- **Строк кода**: LiveTestingPipeline.cs (470+), WinDivertBypassManager.cs (+100 новых методов), TrafficAnalyzer.cs (~50)
- **Коммитов**: 7 (architecture + implementation + WinDivert integration + auto-bypass + docs)
- **Типов блокировок**: 5 (TCP_RST, TLS_DPI, TCP_TIMEOUT, TLS_TIMEOUT, PORT_CLOSED)
- **Bypass стратегий**: 4 + 2 (DOH, DROP_RST, TLS_FRAGMENT, PROXY + NONE, UNKNOWN)
- **WinDivert API методы**: 3 новых (EnableTlsFragmentationAsync, EnableRstBlockingAsync, ApplyBypassStrategyAsync)
- **Время тестирования**: ~3с на хост (TCP timeout + TLS timeout)

## 🐛 Известные Проблемы

### Критические (требуют исправления)

1. **❌ WinDivert Error 87 НЕ РЕШЁН**
   - **Причина**: Priority `-1` НИЖЕ Flow layer (0), пакеты никогда не достигают TLS fragmenter
   - **Документация**: "Higher `priority` values represent **higher priorities**"
   - **Решение**: Изменить priority с `-1` на `+1000` (выше Flow layer)
   ```csharp
   // НЕПРАВИЛЬНО (текущий код):
   _tlsHandle = WinDivertNative.Open(..., priority: -1, ...);  // -1 < 0 → ниже приоритет
   
   // ПРАВИЛЬНО:
   _tlsHandle = WinDivertNative.Open(..., priority: 1000, ...);  // 1000 > 0 → выше приоритет
   ```

2. **Memory leak риск - Unbounded Channels**
   - **Проблема**: Burst трафик + unbounded queue = потенциальный OOM
   - **Решение**: Bounded channels с back-pressure
   ```csharp
   // НЕПРАВИЛЬНО (текущий код):
   _snifferQueue = Channel.CreateUnbounded<HostDiscovered>(...);
   
   // ПРАВИЛЬНО:
   _snifferQueue = Channel.CreateBounded<HostDiscovered>(
       new BoundedChannelOptions(1000) { 
           FullMode = BoundedChannelFullMode.Wait,
           SingleReader = true 
       });
   ```

3. **Дедупликация хостов отсутствует**
   - **Проблема**: Один хост тестируется многократно при повторных соединениях
   - **Решение**: Кэш протестированных хостов (TTL 5 минут)
   ```csharp
   private ConcurrentDictionary<(IPAddress, int), DateTime> _testedHosts;
   
   // Перед тестированием:
   if (_testedHosts.TryGetValue((ip, port), out var lastTest) 
       && DateTime.UtcNow - lastTest < TimeSpan.FromMinutes(5))
       return; // Skip duplicate test
   ```

### Средние (требуют оптимизации)

4. **Timeout агрессивен**: 3с может быть мало для медленных соединений
   - **Решение**: Адаптивные таймауты на основе latency
   ```csharp
   var baseTimeout = TimeSpan.FromSeconds(3);
   var adaptiveTimeout = baseTimeout + TimeSpan.FromMilliseconds(avgLatency * 2);
   ```

5. **Последовательное тестирование медленное**
   - **Проблема**: DNS → TCP → TLS выполняются последовательно
   - **Решение**: Параллельное тестирование DNS + TCP
   ```csharp
   var dnsTask = TestDnsAsync(host);
   var tcpTask = TestTcpAsync(host, port);
   await Task.WhenAll(dnsTask, tcpTask);
   
   // TLS только если TCP успешен
   if (tcpTask.Result.Success)
       await TestTlsAsync(host, port);
   ```

6. **Reverse DNS может блокироваться**: Если ISP блокирует PTR запросы

7. **TLS без hostname fallback**
   - **Проблема**: Если reverse DNS failed, TLS handshake невозможен
   - **Решение**: Fallback механизмы
   ```csharp
   // 1. SNI из перехваченного TLS handshake (WinDivert parsing)
   // 2. HTTP Host header (если был HTTP трафик перед HTTPS)
   // 3. IP-based TLS (редко работает, но попробовать)
   ```

### Низкие (косметические)

8. **False positives**: PORT_CLOSED детектируется как блокировка (исправлено в ClassifyBlockage → NONE)

## 📝 Технические Детали

### Channel Configuration
```csharp
_snifferQueue = Channel.CreateUnbounded<HostDiscovered>(
    new UnboundedChannelOptions { SingleReader = true });
```
- **SingleReader**: Только 1 TesterWorker читает из sniffer queue
- **Unbounded**: Не ограничиваем размер очереди (может быть проблема при burst трафике)

### Fire-and-Forget Pattern
```csharp
_ = pipeline.EnqueueHostAsync(discovered); // Не ждем завершения
```
- Sniffer не блокируется на тестировании
- Task продолжается в фоне
- Результаты появляются асинхронно через IProgress

### ConfigureAwait(false)
Все async операции используют `.ConfigureAwait(false)` для:
- Избежания deadlock'ов в GUI контексте
- Производительности (не нужен SynchronizationContext)

---

## 🚀 Предложения по Улучшению

### 1. Bypass Strategy Learning (ML подход)
```csharp
public class BypassStrategyOptimizer
{
    // Запоминать какие стратегии работают для каких хостов
    private Dictionary<string, (string strategy, int successRate)> _learningCache;
    
    // Автоматически пробовать разные стратегии и выбирать лучшую
    public async Task<string> FindOptimalStrategyAsync(string host, int port)
    {
        var strategies = new[] { "DROP_RST", "TLS_FRAGMENT", "TTL_TRICK" };
        
        // Тестировать параллельно с разными параметрами:
        // - TLS_FRAGMENT: FirstFragmentSize = 32/64/128
        // - TTL_TRICK: TTL = 1-5 (для обхода DPI на промежуточных хопах)
        // - DROP_RST: bidirectional vs outbound only
        
        // Выбирать стратегию с лучшим success rate
        return _learningCache.GetOrAdd(host, () => TestAllStrategies(host, port));
    }
}
```

**Преимущества**:
- Автоматическая адаптация к ISP методам блокировки
- Снижение false negatives (когда bypass не помогает)
- История эффективности стратегий для каждого хоста

### 2. Pipeline Метрики и Мониторинг
```csharp
public class PipelineMetrics
{
    public int HostsDiscovered { get; set; }
    public int TestsCompleted { get; set; }
    public int BlockagesDetected { get; set; }
    public Dictionary<string, int> BlockageTypes { get; set; }  // TCP_RST: 15, TLS_DPI: 8, ...
    public double AverageTestLatency { get; set; }
    public int BypassesApplied { get; set; }
    public int BypassSuccessRate { get; set; }  // Успешность bypass (%)
    
    // Real-time экспорт в UI или логи
    public void ExportMetrics(IProgress<string> progress)
    {
        progress.Report($"📊 Обнаружено: {HostsDiscovered} | Протестировано: {TestsCompleted}");
        progress.Report($"🚫 Заблокировано: {BlockagesDetected} | Bypass: {BypassesApplied} ({BypassSuccessRate}%)");
    }
}
```

**Отображение в GUI**:
- Real-time счётчики в StatusBar
- График блокировок по времени
- Топ заблокированных доменов

### 3. Persistence через Windows Service
```csharp
// Вместо временных WinDivert правил (живут пока ISP_Audit.exe запущен):
public class IspAuditService : ServiceBase
{
    // Windows служба для persistent bypass rules
    // Автозапуск при загрузке системы
    // RESTful API для управления из GUI
    
    protected override void OnStart(string[] args)
    {
        // Загрузить bypass правила из registry/config
        var rules = LoadPersistedRules();
        foreach (var rule in rules)
            _bypassManager.ApplyBypassStrategyAsync(rule.Strategy, rule.Ip, rule.Port);
    }
    
    // HTTP API для GUI клиента:
    // POST /api/bypass/add { "host": "example.com", "strategy": "TLS_FRAGMENT" }
    // DELETE /api/bypass/remove { "host": "example.com" }
    // GET /api/bypass/status → список активных bypass правил
}
```

**Преимущества**:
- Bypass работает после перезагрузки
- Централизованное управление для всех приложений
- GUI может подключаться к службе (IPC/REST)

**Альтернатива**: Интеграция с Windows Firewall через netsh/WFP API

### 4. SNI Parsing для TLS Hostname Detection
```csharp
// Если reverse DNS failed, извлечь hostname из TLS ClientHello SNI extension
public static string? ExtractSniFromPacket(byte[] packet)
{
    // WinDivert captured TLS packet → parse SNI extension
    // TLS record (1 byte type, 2 bytes version, 2 bytes length)
    // Handshake (1 byte type = 0x01 для ClientHello)
    // Extensions → SNI (type 0x0000)
    
    return ParseTlsSni(packet);  // Возвращает hostname из SNI
}
```

**Использование**:
```csharp
// В TestHostAsync():
if (string.IsNullOrEmpty(hostname)) {
    // Fallback 1: Проверить кэш SNI из WinDivert captures
    hostname = _sniCache.GetValueOrDefault(ip);
    
    // Fallback 2: HTTP Host header (если был HTTP до HTTPS redirect)
    hostname ??= _httpHostCache.GetValueOrDefault(ip);
}
```

---

**Дата**: 22 ноября 2025  
**Ветка**: `feature/live-testing-pipeline`  
**Статус**: ⚠️ Core реализация завершена, **КРИТИЧНЫЕ БАГИ требуют исправления** (WinDivert priority, memory leak)
