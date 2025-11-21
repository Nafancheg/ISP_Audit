# Диагностика "пустого" снифа

## Проблема

**Симптомы:**
```
[Stage1] Старт Flow-only захвата трафика PID=11456
[Stage1] Процесс: 'FsHud', найдено 1 экземпляров (PIDs: 11456)
[Stage1] ✓ WinDivert Flow layer открыт успешно
[Stage1] ✓ DNS sniffer запущен
... тишина ...
```

Приложение запущено, WinDivert активен, но **соединений нет**.

## Причины

### 1. Приложение ждет действий пользователя
**Пример:** Окно логина, кнопка "Start", меню настроек

**Решение для пользователя:**
- Выполнить действия в приложении (ввести логин, нажать кнопку)
- Подождать 10-30 секунд (lazy initialization)

### 2. Launcher pattern (дочерние процессы)
**Пример:** `FsHud.exe` запускает `FsHudCore.exe` или `FsHud_Game.exe`

**Текущее решение:** PID Updater отслеживает новые процессы с тем же именем
**Проблема:** Если дочерний процесс имеет ДРУГОЕ имя — не захватим

**Улучшение:**
```csharp
// Отслеживать все дочерние процессы (по Parent PID)
var childProcesses = GetChildProcesses(targetPid);
targetPids.UnionWith(childProcesses);
```

### 3. Приложение уже подключено (кэшированные соединения)
**Пример:** Переподключение после обрыва — используется старое keep-alive соединение

**Решение:** Захват ESTABLISHED соединений процесса через netstat/API:
```csharp
// Получить активные соединения процесса БЕЗ WinDivert
var existingConnections = NetUtils.GetProcessConnections(targetPid);
if (existingConnections.Any()) {
    progress?.Report($"Обнаружено {existingConnections.Count} активных соединений");
    // Добавить их в GameProfile
}
```

### 4. Блокировка мешает подключению
**Пример:** DNS блокировка → приложение не может резолвить домен → не пытается подключиться

**Признаки:**
- Приложение показывает ошибку (но не в консоль)
- Окно "зависло" или показывает спиннер
- В Event Viewer есть network errors

**Решение:** Мониторить состояние процесса:
```csharp
// Проверять CPU/Network usage процесса
if (process.TotalProcessorTime == 0 && captureTime > 5sec) {
    progress?.Report("⚠️ Процесс не активен (CPU=0%)");
}
```

### 5. Процесс крашится/закрывается
**Пример:** Приложение не может найти конфиг → выходит сразу

**Решение:** Мониторить `process.HasExited`:
```csharp
if (process.HasExited) {
    progress?.Report($"⚠️ Процесс завершился (ExitCode={process.ExitCode})");
    return GameProfile.Empty;
}
```

## Что добавить в UI

### Stage1Status сообщения

**Вместо тишины показывать:**

```
[0-5 сек] "Захват активен, ожидаем первое соединение..."

[5-10 сек, 0 соединений]
"⚠️ Соединения не обнаружены. Возможные причины:
 • Приложение ожидает действий пользователя
 • Выполните действие в приложении (логин, старт игры)
 • Проверьте что приложение активно"

[10-30 сек, 0 соединений]
"⚠️ Долгое ожидание без соединений.
 • Проверьте Event Viewer на ошибки
 • Возможно приложение не может подключиться
 • Попробуйте запустить приложение вручную и проверить что оно работает"

[30+ сек, 0 соединений]
"❌ Соединения так и не появились.
 Рекомендации:
 1. Остановить захват (кнопка 'Стоп')
 2. Проверить что приложение работает без ISP_Audit
 3. Попробовать другое приложение для теста"
```

### Периодические обновления

**Каждые 5 секунд:**
```csharp
var elapsed = DateTime.Now - captureStartTime;
if (connections.Count == 0 && elapsed.TotalSeconds % 5 == 0) {
    progress?.Report($"Захват активен ({elapsed.TotalSeconds}с), соединений: 0");
    
    // Проверить состояние процесса
    if (!process.HasExited) {
        var cpuUsage = GetProcessCpuUsage(process);
        progress?.Report($"  Процесс активен: CPU={cpuUsage:F1}%");
    } else {
        progress?.Report($"  ⚠️ Процесс завершился!");
        cts.Cancel();
    }
}
```

## Автоматическая диагностика

### Добавить в TrafficAnalyzer.cs

```csharp
// После старта захвата
var diagnosticTimer = new Timer(_ => {
    if (connections.Count == 0) {
        var elapsed = DateTime.Now - startTime;
        
        // Проверка 1: Процесс жив?
        if (process.HasExited) {
            progress?.Report($"⚠️ Процесс завершился (ExitCode={process.ExitCode})");
            cts.Cancel();
            return;
        }
        
        // Проверка 2: Есть активные соединения через netstat?
        var existingConnections = NetUtils.GetProcessConnections(targetPid);
        if (existingConnections.Any()) {
            progress?.Report($"ℹ️ Обнаружено {existingConnections.Count} активных соединений (pre-existing)");
            // Добавить их в results
            foreach (var conn in existingConnections) {
                connections.TryAdd(conn.Key, conn.Value);
            }
        }
        
        // Проверка 3: Дочерние процессы?
        var childPids = GetChildProcesses(targetPid);
        if (childPids.Any(pid => !targetPids.Contains(pid))) {
            progress?.Report($"ℹ️ Обнаружены дочерние процессы: {string.Join(", ", childPids)}");
            targetPids.UnionWith(childPids);
        }
        
        // Проверка 4: Предупреждение
        if (elapsed.TotalSeconds >= 10) {
            progress?.Report($"⚠️ {elapsed.TotalSeconds}с без соединений. Проверьте активность приложения.");
        }
    }
}, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
```

## Реализация GetProcessConnections

**Файл:** `Utils/NetUtils.cs`

```csharp
using System.Net.NetworkInformation;

public static List<ConnectionInfo> GetProcessConnections(int pid) {
    var connections = new List<ConnectionInfo>();
    
    // TCP connections
    var tcpTable = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
    foreach (var conn in tcpTable) {
        // Windows API для получения PID соединения (требует P/Invoke)
        var connPid = GetConnectionPid(conn);
        if (connPid == pid && conn.State == TcpState.Established) {
            connections.Add(new ConnectionInfo {
                RemoteIp = conn.RemoteEndPoint.Address.ToString(),
                RemotePort = conn.RemoteEndPoint.Port,
                Protocol = "TCP"
            });
        }
    }
    
    // UDP connections (аналогично через GetActiveUdpListeners)
    
    return connections;
}

// P/Invoke для GetExtendedTcpTable (получить PID соединения)
[DllImport("iphlpapi.dll", SetLastError = true)]
private static extern uint GetExtendedTcpTable(...);
```

## План реализации

### Приоритет 1: Периодический статус (5 мин)
**Файл:** `Utils/TrafficAnalyzer.cs`
- Добавить таймер каждые 5 секунд
- Выводить статус: "Захват активен (15с), соединений: 0"
- Проверять `process.HasExited`

### Приоритет 2: Поиск pre-existing соединений (15 мин)
**Файл:** `Utils/NetUtils.cs`
- Реализовать `GetProcessConnections(pid)` через `IPGlobalProperties`
- Добавить P/Invoke для `GetExtendedTcpTable` (получить PID)
- Интегрировать в `TrafficAnalyzer` при старте

### Приоритет 3: Умные подсказки в UI (10 мин)
**Файл:** `ViewModels/MainViewModel.cs`
- Показывать разные сообщения в зависимости от времени без соединений:
  - 0-5с: "Ожидаем соединения..."
  - 5-10с: "Выполните действие в приложении"
  - 10-30с: "Проверьте что приложение работает"
  - 30+с: "Рекомендуется остановить и проверить вручную"

### Приоритет 4: Поиск дочерних процессов (опционально)
**Файл:** `Utils/ProcessUtils.cs`
- Реализовать `GetChildProcesses(parentPid)` через WMI/P/Invoke
- Добавить в PID updater логику

## Тестирование

**Сценарий 1: Приложение без сети**
- Запустить Notepad.exe → должно показать "0 соединений, процесс активен"

**Сценарий 2: Launcher pattern**
- Запустить Steam (launcher для игр) → должно захватить дочерние процессы

**Сценарий 3: Блокировка DNS**
- Запустить приложение с заблокированным DNS → показать "процесс активен, но соединений нет"

**Сценарий 4: Pre-existing connections**
- Запустить Chrome → открыть вкладку → запустить сниф → должно найти активные TCP соединения
