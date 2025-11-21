# План тестирования FsHud с Live Testing Pipeline

## Цель
Проверить работоспособность live testing pipeline на реальном приложении FsHud.exe, которое не загружается из-за ISP блокировок CloudFront CDN и других ресурсов.

## Подготовка

### 1. Чистый эксперимент (без Podkop)
```powershell
# На роутере Podkop:
# 1. Войти в Web UI (обычно 192.168.1.1)
# 2. Открыть раздел "Bypass Rules" или "DNS Override"
# 3. Удалить ВСЕ правила для следующих доменов:
#    - auth.fshud.com
#    - challenges.cloudflare.com
#    - edge.microsoft.com
#    - dp0wn1kjwhg75.cloudfront.net
#    - все остальные FsHud-related домены
# 4. Сохранить и перезагрузить правила
# 5. Проверить: ping challenges.cloudflare.com НЕ должен вернуть 198.18.x.x
```

### 2. Компиляция ISP_Audit
```powershell
cd C:\Users\nafan\Documents\ISP_Audit
git checkout feature/live-testing-pipeline
dotnet build -c Debug

# Или Release с single-file:
dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true -o ./publish
```

### 3. Проверка прав администратора
```powershell
# ISP_Audit требует admin для WinDivert
# Запускать из PowerShell с правами администратора:
Start-Process powershell -Verb RunAs
cd C:\Users\nafan\Documents\ISP_Audit\bin\Debug\net9.0-windows
```

## Тестовый Сценарий

### Этап 1: Верификация блокировок
**Ожидаемый результат**: FsHud не загрузится из-за ISP блокировок

```powershell
# 1. Запустить FsHud.exe вручную (не через ISP_Audit)
Start-Process "C:\Path\To\FsHud.exe"

# 2. Ожидаемое поведение:
# - Окно приложения открывается
# - Белый экран или "Loading..."
# - Контент не загружается (CloudFront заблокирован)
# - Возможно сообщение об ошибке сети

# 3. Закрыть FsHud.exe
Stop-Process -Name "FsHud" -Force
```

### Этап 2: Захват трафика с Live Testing
**Ожидаемый результат**: ISP_Audit обнаружит блокировки в реальном времени

```powershell
# 1. Запустить ISP_Audit от имени администратора
.\ISP_Audit.exe

# 2. В GUI:
# - Выбрать сценарий: "Приложение"
# - Путь к приложению: C:\Path\To\FsHud.exe
# - ✅ Включить живое тестирование
# - ✅ Тестировать до ручной отмены (для детального захвата)
# - Нажать "Запустить и захватить трафик"

# 3. Наблюдать вывод в Stage1Status:
# - "Захват активен (10с), соединений: 5"
# - "Обнаружен новый хост: dp0wn1kjwhg75.cloudfront.net (18.244.147.46:443)"
# - "[TESTER] Тестирую 18.244.147.46:443..."
# - "❌ dp0wn1kjwhg75.cloudfront.net:443 (156ms) | DNS:✓ TCP:✓ TLS:✗ | TLS_DPI"
# - "[BYPASS] Применяю TLS_FRAGMENT для dp0wn1kjwhg75.cloudfront.net..."
# - "✓ TLS_FRAGMENT bypass готов для dp0wn1kjwhg75.cloudfront.net (требуется admin)"

# 4. Дождаться захвата всех хостов (30-60 секунд)
# 5. Нажать "Остановить захват" (если включен continuous mode)
```

### Этап 3: Анализ результатов
**Файл**: `docs/fshud_live_testing_results.md`

**Ожидаемые детекции**:
| Хост | IP | Порт | DNS | TCP | TLS | Blockage Type | Strategy |
|------|----|----|-----|-----|-----|---------------|----------|
| dp0wn1kjwhg75.cloudfront.net | 18.244.147.x | 443 | ✓ | ✓ | ✗ | TLS_DPI | TLS_FRAGMENT |
| auth.fshud.com | ? | 443 | ✓ | ✓ | ? | ? | ? |
| challenges.cloudflare.com | 104.18.x.x | 443 | ✓ | ✓ | ✓ | OK | NONE |

**Интерпретация**:
- `TLS_DPI` на CloudFront → ISP блокирует TLS handshake → требуется фрагментация ClientHello
- `OK` на cloudflare.com → Cloudflare доступен, проблема специфична для CDN
- Если `DNS_FILTERED` → ISP блокирует DNS резолв → требуется DoH

### Этап 4: Применение Bypass (Manual)
**Текущее ограничение**: `ApplyBypassAsync()` только логирует рекомендации, реальное применение требует доработки WinDivertBypassManager.

**Workaround до full implementation**:
```powershell
# Создать bypass_profile.json с CloudFront правилами:
@"
{
  "dropTcpRst": false,
  "fragmentTlsClientHello": true,
  "tlsFirstFragmentSize": 64,
  "tlsFragmentThreshold": 128,
  "redirectRules": []
}
"@ | Out-File -Encoding UTF8 bypass_profile.json

# Перезапустить ISP_Audit → захват с bypass активным
# Или использовать существующий WinDivert bypass для FsHud
```

### Этап 5: Верификация Fix
```powershell
# 1. С активным bypass (через ISP_Audit или вручную):
# Запустить FsHud.exe → UI должен загрузиться

# 2. Проверить логи ISP_Audit:
# - "✓ dp0wn1kjwhg75.cloudfront.net:443 (25ms)" (TLS OK)
# - Все хосты должны быть зелеными

# 3. FsHud должен отображать:
# - Карты, маршруты, профили пользователя
# - Без "Loading..." застревания
# - Без ошибок сети
```

## Ожидаемые Проблемы и Решения

### Проблема 1: "pipeline не инициализирован"
**Причина**: `enableLiveTesting = false` или ошибка при создании pipeline

**Решение**:
```csharp
// В MainViewModel.cs проверить:
EnableLiveTesting = true; // Должно быть true по умолчанию

// В TrafficAnalyzer.cs проверить логи:
Log("[LIVE-TESTING] Pipeline initialized with auto-bypass: {_config.EnableAutoBypass}");
```

### Проблема 2: Reverse DNS timeout
**Причина**: ISP может блокировать PTR запросы

**Решение**:
```csharp
// В TestHostAsync() уменьшить таймаут reverse DNS:
var dnsTask = Dns.GetHostEntryAsync(ip.ToString());
var timeout = Task.Delay(1000); // 1 секунда вместо 3
if (await Task.WhenAny(dnsTask, timeout) == timeout)
    hostname = null; // Пропустить reverse DNS
```

### Проблема 3: False positive TLS_DPI
**Причина**: TLS timeout может быть из-за медленного соединения, не DPI

**Решение**:
```csharp
// Проверить latency: если TCP > 2000ms → вероятно не DPI
if (tested.BlockageType == "TLS_TIMEOUT" && tested.TcpLatencyMs > 2000) {
    strategy = "SLOW_CONNECTION"; // Не bypass, просто медленно
}
```

### Проблема 4: WinDivert не применяется автоматически
**Статус**: Известное ограничение, `ApplyBypassAsync()` в текущей реализации только логирует

**TODO (Приоритет 1)**:
1. Расширить `WinDivertBypassManager` для динамических правил (не только из профиля)
2. Добавить метод `AddDynamicRule(ip, port, strategy)`
3. Вызывать из `ApplyBypassAsync()`:
   ```csharp
   var manager = new WinDivertBypassManager();
   await manager.EnableAsync(tlsProfile);
   // Bypass активен, пока ISP_Audit работает
   ```

## Метрики Успеха

### Минимальный успех (MVP):
- ✅ Live testing обнаруживает хотя бы 1 блокировку (TLS_DPI на CloudFront)
- ✅ Классификация корректна (не false positive)
- ✅ Логи содержат детальную информацию (DNS/TCP/TLS статусы)

### Полный успех:
- ✅ Все заблокированные хосты обнаружены
- ✅ Bypass применяется автоматически (после доработки ApplyBypassAsync)
- ✅ FsHud загружается успешно с активным bypass
- ✅ Без ложных срабатываний (OK хосты не помечены как заблокированные)

### Расширенный успех:
- ✅ Работа с другими приложениями (Discord, Telegram, YouTube в браузере)
- ✅ Persistence bypass правил (сохранение между перезапусками)
- ✅ GUI таблица с live результатами (DataGrid)
- ✅ Кнопка "Применить bypass" для выбранных хостов

## Следующие Шаги

### После успешного теста:
1. **Документировать результаты** → `docs/fshud_live_testing_results.md`
2. **Merge в main** → создать PR из feature/live-testing-pipeline
3. **Release notes** → обновить README.md с секцией "Live Testing"
4. **Скриншоты** → захватить UI с live результатами

### Приоритет разработки:
1. **HIGH**: Полная реализация `ApplyBypassAsync()` с WinDivert
2. **MEDIUM**: GUI таблица для live результатов
3. **MEDIUM**: Persistence bypass правил (сохранение в JSON)
4. **LOW**: Тестирование на других приложениях (Discord, Steam)

---

**Дата плана**: 22 ноября 2025  
**Статус**: Готов к выполнению  
**Ответственный**: Developer (ты)  
**Длительность теста**: ~30 минут
