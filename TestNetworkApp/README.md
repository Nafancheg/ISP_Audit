# Тестовое приложение для калибровки ISP_Audit

## TestNetworkApp.exe

**Назначение**: Эталонное приложение для тестирования и калибровки Traffic Analyzer в ISP_Audit.

### Что делает:
- Устанавливает HTTP/HTTPS соединения к 7 известным адресам
- Работает 60 секунд (или до нажатия клавиши)
- Показывает статус каждого запроса в реальном времени
- Выводит PID процесса для отладки

### Целевые адреса:
1. **google.com** (443) - HTTPS
2. **youtube.com** (443) - HTTPS
3. **discord.com** (443) - HTTPS
4. **github.com** (443) - HTTPS
5. **api.ipify.org** (443) - IP check API
6. **cloudflare.com** (443) - HTTPS
7. **1.1.1.1** (443) - Cloudflare DNS over HTTPS

---

## Инструкция по тестированию

### 1. Сборка

```powershell
cd TestNetworkApp
dotnet publish -c Release -r win-x64 --self-contained false -o bin/Publish
```

Результат: `TestNetworkApp\bin\Publish\TestNetworkApp.exe`

### 2. Ручной тест (проверка работоспособности)

```powershell
.\TestNetworkApp\bin\Publish\TestNetworkApp.exe
```

Ожидаемый вывод:
```
=== ISP_Audit Test Network Application ===
PID: 12345
Запуск тестовых сетевых запросов...

Старт цикла запросов (60 секунд)...

[12:34:56] Google          -> 200 OK
[12:34:57] YouTube         -> 200 OK
[12:34:58] Discord         -> 200 OK
...
```

### 3. Тестирование ISP_Audit Stage 1

#### 3.1. Запустите ISP_Audit от администратора

```powershell
Start-Process "bin\Debug\net9.0-windows\ISP_Audit.exe" -Verb RunAs
```

#### 3.2. В ISP_Audit GUI:
1. **Browse** → выберите `TestNetworkApp\bin\Publish\TestNetworkApp.exe`
2. **Stage 1: Анализ трафика** → нажмите "Запустить анализ"
3. Ожидайте 30 секунд (приложение запустится автоматически)

#### 3.3. Ожидаемый результат:

**Stage 1 Status:**
```
Завершено: обнаружено 7 целей
```

**Output окно (логи):**
```
[Stage1] Process started: EXE=TestNetworkApp.exe, PID=12345
[Stage1] WinDivert NETWORK layer активирован
[Stage1] Захвачено событий: 100
[Stage1] Захвачено событий: 200
[Stage1] SUCCESS: 7 unique hosts captured
[Stage1]   → google.com (web)
[Stage1]   → youtube.com (web)
[Stage1]   → discord.com (web)
[Stage1]   → github.com (web)
[Stage1]   → api.ipify.org (web)
[Stage1]   → cloudflare.com (web)
[Stage1]   → 1.1.1.1 (web)
```

---

## Диагностика проблем

### "Захват завершен: 0 событий"

**Причины:**
1. ISP_Audit **НЕ запущен от администратора**
   - Решение: `Start-Process ISP_Audit.exe -Verb RunAs`

2. WinDivert не установлен или устарел
   - Проверка: `Get-Item native\WinDivert.dll | Select-Object Length`
   - Ожидается: **47104 байт** (версия 2.2.0)

3. TestNetworkApp не установил соединения
   - Проверка: запустите TestNetworkApp.exe вручную, убедитесь что запросы проходят (зеленый текст)

4. GetExtendedTcpTable не видит соединения
   - Возможно, соединения слишком быстрые
   - Увеличьте capture timeout до 60 секунд

### "ERROR 87 (ERROR_INVALID_PARAMETER)"

**Причины:**
1. WinDivert фильтр неверный
   - Текущий: `"outbound and (tcp or udp)"`
   - Это стандартный фильтр для NETWORK layer

2. WinDivert версия несовместима
   - Проверьте: должна быть **2.2.0**

### "ERROR 5 (Access Denied)"

**Решение:** Запустите ISP_Audit от администратора!

---

## Расширенное тестирование

### Увеличение времени захвата

Измените в `MainViewModel.cs`:

```csharp
TimeSpan.FromSeconds(30) → TimeSpan.FromSeconds(60)
```

### Добавление UDP трафика

TestNetworkApp использует только TCP (HTTPS). Для тестирования UDP:

```csharp
// Добавить в Program.cs
using var udpClient = new UdpClient();
udpClient.Send(new byte[] { 0x00 }, 1, "8.8.8.8", 53); // DNS query
```

### Проверка дочерних процессов

Если TestNetworkApp запускает дочерний процесс:

1. Найдите дочерний PID через Process Explorer
2. Измените MainViewModel для мониторинга дочерних процессов

---

## Файлы

- `TestNetworkApp\Program.cs` - исходный код
- `TestNetworkApp\bin\Publish\TestNetworkApp.exe` - готовый exe (147KB)
- `test_calibration.ps1` - скрипт автоматического тестирования (WIP)

---

## Следующие шаги

После успешной калибровки Stage 1:

1. **Stage 2: Классификация проблем**
   - Проверьте, что ProblemClassifier правильно анализирует захваченный профиль

2. **Stage 3: Применение обхода**
   - Протестируйте DNS fix
   - Протестируйте WinDivert bypass rules

3. **End-to-end тест**
   - Весь workflow от Stage 1 до Stage 3

