# Dual Layer подход: Network + Flow (WinDivert)

## Суть

Решаем проблему атрибуции трафика (какому процессу принадлежит пакет) без тяжелого поллинга системы и без пропуска короткоживущих соединений.

Используем возможности WinDivert на 100%:
1. **Layer.Flow**: Получаем события создания соединений (содержат **PID** процесса).
2. **Layer.Network**: Захватываем сами пакеты (данные).

## Проблема текущих подходов

1. **Polling (GetExtendedTcpTable)**: Раз в N секунд. Пропускает соединения, которые жили меньше N секунд (DNS, быстрые HTTP редиректы).
2. **Network-only**: Видим пакеты, но не знаем PID (особенно для UDP).

## Алгоритм (Dual Layer)

Запускаем **два** параллельных потока чтения WinDivert в режиме `Sniff` (только чтение).

### Поток 1: Flow Monitor (Layer.Flow)
Слушает события сетевого стека.
- Фильтр: `outbound and !loopback`
- При событии `FLOW_ESTABLISHED`:
  - Извлекаем: `ProcessId`, `LocalPort`, `RemoteIp`, `RemotePort`, `Protocol`.
  - Сохраняем в `FlowMap`: `(LocalPort, Protocol) -> ProcessId`.
  - *Опционально*: Можно хранить полный 5-tuple для точности, но обычно LocalPort достаточно.

### Поток 2: Packet Capture (Layer.Network)
Слушает сырые пакеты.
- Фильтр: `outbound and !loopback` (тот же, что и для Flow)
- При получении пакета:
  - Парсим заголовки (IP, TCP/UDP).
  - Сохраняем в `PacketBuffer`: `Timestamp`, `Size`, `LocalPort`, `RemoteIp`, `RemotePort`, `Protocol`.
  - **Оптимизация**: Не храним payload, только заголовки (первые 64-128 байт).

### Финал (Correlation)
После завершения захвата (30 сек):
1. Останавливаем оба потока.
2. Фильтруем `PacketBuffer`:
   - Оставляем только те пакеты, чей `LocalPort` в `FlowMap` соответствует `TargetPid`.

## Структуры данных

```csharp
// Карта потоков: Порт -> PID
// ConcurrentDictionary для потокобезопасности
ConcurrentDictionary<(ushort Port, byte Proto), int> FlowMap;

// Легковесный пакет
struct PacketHeader
{
    DateTime Timestamp;
    ushort LocalPort;
    string RemoteIp;
    ushort RemotePort;
    bool IsTcp;
    int TotalSize;
    // byte[] HeaderBytes; // Опционально, если нужен глубокий анализ
}

ConcurrentBag<PacketHeader> PacketBuffer;
```

## WinDivert Фильтр

Используем менее агрессивный фильтр для частных сетей, чтобы не отсечь VPN-трафик или Double-NAT провайдеров.

```csharp
// Базовый фильтр для обоих слоев
var filter = "outbound and !loopback and (tcp or udp)";
```

## Реализация (Псевдокод)

```csharp
// Запуск
var flowTask = Task.Run(() => {
    using var handle = WinDivert.Open(filter, Layer.Flow, 0, OpenFlags.Sniff);
    while (!token.IsCancellationRequested) {
        var addr = WinDivert.Recv();
        if (addr.Event == FLOW_ESTABLISHED) {
            // WinDivert сообщает PID процесса, открывшего сокет!
            FlowMap.TryAdd((addr.Socket.LocalPort, addr.Socket.Protocol), addr.Socket.ProcessId);
        }
    }
});

var netTask = Task.Run(() => {
    using var handle = WinDivert.Open(filter, Layer.Network, 0, OpenFlags.Sniff);
    while (!token.IsCancellationRequested) {
        var packet = WinDivert.Recv();
        // Быстрый парсинг заголовков
        var header = ParseHeader(packet);
        PacketBuffer.Add(header);
    }
});

// Ждем 30 секунд или завершения процесса...
await Task.Delay(30000);

// Анализ
var targetPackets = PacketBuffer
    .Where(p => FlowMap.TryGetValue((p.LocalPort, p.Proto), out int pid) && pid == TargetPid)
    .GroupBy(...)
    .ToList();
```

## Преимущества

| Критерий | Polling (Старый) | Dual Layer (Новый) |
|----------|------------------|--------------------|
| **Точность PID** | Эвристическая (можем не успеть) | **100% (от драйвера)** |
| **Короткие соединения** | Пропускаем (< 5 сек) | **Ловим все** (даже 1 мс) |
| **Нагрузка CPU** | Скачки каждые 5 сек | Равномерная, низкая |
| **Сложность** | Таймеры, синхронизация | Event-driven, чище |

## Оптимизации ресурсов

1. **Truncate Payload**:
   Нам не нужно содержимое пакетов для аудита блокировок (нам важен факт соединения, TCP Flags, Retransmissions).
   Храним только метаданные. Это позволяет держать буфер на 100,000+ пакетов в памяти (100k * 64 bytes ≈ 6 MB).

2. **Flow Map Cleanup**:
   Если процесс долго работает, FlowMap может разрастись. Но для сессии в 30-60 секунд это неактуально.

## Сценарии использования

### 1. Exe Mode (Запуск через нас)
1. Запускаем мониторинг (Flow + Network).
2. Запускаем процесс `Process.Start()`.
3. Гарантированно ловим **первый SYN пакет**, так как мониторинг уже активен.
4. Ловим все DNS запросы процесса.

### 2. Pid Mode (Attach к запущенному)
1. Процесс уже работает.
2. Запускаем мониторинг.
3. `Layer.Flow` сообщит о **новых** соединениях.
4. **Важно**: Для уже открытых соединений событие `FLOW_ESTABLISHED` могло пройти раньше.
   *Решение*: В начале работы один раз вызвать `GetExtendedTcpTable`, чтобы заполнить `FlowMap` уже существующими соединениями. Далее полагаться на `Layer.Flow`.

## Итоговая рекомендация

Перейти на **Dual Layer** архитектуру. Она устраняет главную уязвимость гибридного подхода (слепота к коротким соединениям) и использует нативные возможности WinDivert, которые мы уже подключили в проект.
