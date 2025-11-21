# Live Testing Pipeline - Статус Реализации

## ✅ Завершено

### Архитектура (Feature Branch: `feature/live-testing-pipeline`)

```
Sniffer (TrafficAnalyzer) → Channel → Tester → Channel → Classifier → Channel → UI/Bypass
                              ↓                    ↓                      ↓
                        HostDiscovered        HostTested            HostBlocked
```

### Компоненты

#### 1. LiveTestingPipeline.cs (398 строк)
- **Каналы**: `Channel<HostDiscovered>`, `Channel<HostTested>`, `Channel<HostBlocked>`
- **3 независимых worker'а**: TesterWorker, ClassifierWorker, UiWorker
- **Fire-and-forget**: Не блокирует sniffer при тестировании

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

## ⏳ В Разработке

### 1. ApplyBypassAsync() - Автоматическое применение bypass
**Статус**: Заглушка, требует реализации

**План**:
```csharp
private async Task ApplyBypassAsync(HostBlocked blocked, CancellationToken ct)
{
    switch (blocked.BypassStrategy)
    {
        case "DROP_RST":
            // WinDivert: drop TCP RST packets для host.RemoteIp:RemotePort
            // Фильтр: tcp.Rst and ip.DstAddr == X.X.X.X and tcp.DstPort == YYYY
            break;
            
        case "TLS_FRAGMENT":
            // WinDivert: фрагментация TLS ClientHello
            // Параметры из docs/bypass_strategy_todo.md:
            // --dpi-desync-split-pos=1-3 --dpi-desync=multisplit
            break;
            
        case "DOH":
            // Перенаправление DNS запросов на DoH (1.1.1.1, 8.8.8.8)
            // Может потребовать netsh (UAC) или hosts файл
            break;
    }
}
```

**Зависимости**:
- `WinDivertBypassManager` - существует, но API нужно адаптировать для динамических правил
- `BypassProfile` - текущая структура статична (из JSON), нужна динамическая генерация

### 2. DNS Resolution в TestHostAsync
**Статус**: Только reverse DNS, прямой резолв не реализован

**План**:
- Добавить System DNS резолв для сравнения с IP из трафика
- DoH запрос (cloudflare-dns.com) для детекции DNS_FILTERED
- Если System DNS → bypass IP (198.18.x.x) → `DNS_BYPASS`
- Если System DNS → bogus IP (0.0.0.0, 127.x) → `DNS_BOGUS`

### 3. GUI Интеграция
**Статус**: Только console `IProgress<string>`

**План**:
- `MainViewModel` должен получать `HostTested`/`HostBlocked` события
- Таблица live результатов в `MainWindow.xaml`
- Кнопка "Применить bypass" для выбранных хостов
- Статистика: успешные/заблокированные/bypassed

### 4. Тестирование с FsHud
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

### Приоритет 1: Реализовать ApplyBypassAsync
1. `DROP_RST` → WinDivert filter для блокировки RST пакетов
2. `TLS_FRAGMENT` → интеграция с WinDivertBypassManager
3. Тестирование на простых случаях (заблокированный Discord/YouTube)

### Приоритет 2: GUI Live Results
1. Observable collection в MainViewModel
2. DataGrid в MainWindow с колонками:
   - Хост, Порт, DNS, TCP, TLS, Latency, Blockage Type, Strategy, Status
3. Context menu: "Применить bypass", "Игнорировать"

### Приоритет 3: FsHud Testing
1. Чистый эксперимент (без Podkop)
2. Захват с `enableLiveTesting = true`
3. Верификация детекции CloudFront блокировки
4. Применение bypass → проверка работы FsHud

### Приоритет 4: Документация
1. Обновить README.md с секцией "Live Testing"
2. Скриншоты GUI с live результатами
3. Примеры bypass правил для типичных блокировок

## 📊 Метрики

- **Строк кода**: LiveTestingPipeline.cs (398), TrafficAnalyzer.cs изменения (~50)
- **Коммиты**: 2 (architecture + implementation)
- **Типов блокировок**: 5 (TCP_RST, TLS_DPI, TCP_TIMEOUT, TLS_TIMEOUT, PORT_CLOSED)
- **Bypass стратегий**: 4 + 2 (DOH, DROP_RST, TLS_FRAGMENT, PROXY + NONE, UNKNOWN)
- **Время тестирования**: ~3с на хост (TCP timeout + TLS timeout)

## 🐛 Известные Проблемы

1. **Timeout агрессивен**: 3с может быть мало для медленных соединений
2. **Reverse DNS может блокироваться**: Если ISP блокирует PTR запросы
3. **TLS без hostname**: Если reverse DNS не вернул hostname, TLS handshake невозможен
4. **False positives**: PORT_CLOSED детектируется как блокировка (исправлено в ClassifyBlockage → NONE)

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

**Дата**: 2024 (текущая)  
**Ветка**: `feature/live-testing-pipeline`  
**Статус**: ✅ Core реализация завершена, GUI интеграция и bypass application в процессе
