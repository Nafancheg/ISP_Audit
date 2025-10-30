# [BLUE] Planning Agent: Детальный план — Переработка тестов

**Дата планирования**: 2025-10-30  
**Основание**: agents/research_agent/findings.md  
**Цель**: Внедрение тестов для выявления РЕАЛЬНЫХ блокировок (firewall, ISP DPI, специфичные SC проблемы)

---

## Подзадача 1: Добавление NuGet зависимостей и подготовка инфраструктуры

**Файлы:**
- `ISP_Audit.csproj`

**Описание:**
Добавить NuGet пакет `System.Management` версии 9.0.0 для работы с WMI (Windows Firewall, Defender). Убедиться, что проект компилируется без ошибок.

**Код:**
```xml
<!-- В секцию <ItemGroup> добавить: -->
<PackageReference Include="System.Management" Version="9.0.0" />
```

**Зависимости:** нет

**Риски:** 
Минимальные, пакет стабильный и официальный

---

## Подзадача 2: Создание моделей данных для новых тестов

**Файлы:**
- `Output/FirewallTestResult.cs` (новый)
- `Output/IspTestResult.cs` (новый)
- `Output/RouterTestResult.cs` (новый)
- `Output/SoftwareTestResult.cs` (новый)

**Описание:**
Создать record классы для результатов новых тестов. Каждый record содержит данные диагностики и статус (OK/BLOCKING/UNKNOWN и т.д.).

**FirewallTestResult.cs:**
```csharp
namespace ISP_Audit.Output;

public record FirewallTestResult(
    bool WindowsFirewallEnabled,
    List<string> BlockedPorts,
    bool WindowsDefenderActive,
    List<string> BlockingRules,
    string Status
);
```

**IspTestResult.cs:**
```csharp
namespace ISP_Audit.Output;

public record IspTestResult(
    string? Isp,
    string? Country,
    string? City,
    bool CgnatDetected,
    bool DpiDetected,
    bool DnsFiltered,
    List<string> KnownProblematicISPs,
    string Status
);
```

**RouterTestResult.cs:**
```csharp
namespace ISP_Audit.Output;

public record RouterTestResult(
    string? GatewayIp,
    bool UpnpEnabled,
    bool SipAlgDetected,
    double AvgPingMs,
    double MaxPingMs,
    int PacketLossPercent,
    string Status
);
```

**SoftwareTestResult.cs:**
```csharp
namespace ISP_Audit.Output;

public record SoftwareTestResult(
    List<string> AntivirusDetected,
    List<string> VpnClientsDetected,
    bool ProxyEnabled,
    bool HostsFileIssues,
    List<string> HostsFileEntries,
    string Status
);
```

**Зависимости:** нет

**Риски:** нет

---

## Подзадача 3: Обновление моделей RunReport и Summary

**Файлы:**
- `Output/ReportWriter.cs`

**Описание:**
Добавить поля для новых тестов в классы `RunReport` и `Summary`.

**В класс RunReport добавить:**
```csharp
public FirewallTestResult? firewall { get; set; }
public IspTestResult? isp { get; set; }
public RouterTestResult? router { get; set; }
public SoftwareTestResult? software { get; set; }
```

**В класс Summary добавить:**
```csharp
public string firewall { get; set; } = "UNKNOWN";
public string isp_blocking { get; set; } = "UNKNOWN";
public string router_issues { get; set; } = "UNKNOWN";
public string software_conflicts { get; set; } = "UNKNOWN";
```

**Зависимости:** после подзадачи 2

**Риски:** нет

---

## Подзадача 4: Реализация FirewallTest.cs

**Файлы:**
- `Tests/FirewallTest.cs` (новый)

**Описание:**
Создать класс `FirewallTest` с методом `RunAsync()`. Проверяет Windows Firewall через WMI, ищет блокирующие правила для портов 80, 443, 8000-8020, проверяет Windows Defender.

**Функциональность:**
1. Проверить включен ли Windows Firewall (WMI или netsh)
2. Получить список блокирующих правил для игровых портов
3. Проверить статус Windows Defender
4. Проверить есть ли Star Citizen в исключениях Defender
5. Вернуть FirewallTestResult с детальной информацией

**Обработка ошибок:**
Если нет админ прав → Status = "UNKNOWN", пустые списки

**Зависимости:** после подзадачи 2

**Риски:**
Требуются админ права для полной диагностики. WMI может быть недоступен на некоторых системах. Решение: обернуть в try-catch, показать предупреждение.

---

## Подзадача 5: Реализация IspTest.cs

**Файлы:**
- `Tests/IspTest.cs` (новый)

**Описание:**
Создать класс `IspTest` с методом `RunAsync()`. Получает ISP информацию через API (ip-api.com), проверяет CGNAT, DNS фильтрацию, DPI.

**Функциональность:**
1. Получить ISP информацию через API (ip-api.com или fallback ipify.org)
2. Проверить CGNAT (диапазон 100.64.0.0/10)
3. Проверить DNS фильтрацию (сравнение System DNS vs DoH vs Google 8.8.8.8)
4. Проверить DPI (модификация HTTP заголовков)
5. Проверить ISP в списке проблемных (Rostelecom, Beeline, МТС)

**Зависимости:** после подзадачи 2

**Риски:**
API ip-api.com может быть недоступен (rate limit 45 req/min). Решение: timeout 5s + fallback на ipify.org.

---

## Подзадача 6: Реализация RouterTest.cs

**Файлы:**
- `Tests/RouterTest.cs` (новый)

**Описание:**
Создать класс `RouterTest` с методом `RunAsync()`. Получает IP шлюза, пингует его 20 раз, проверяет UPnP через COM Interop.

**Функциональность:**
1. Получить IP адрес шлюза (default gateway)
2. Пинговать шлюз 20 раз → avg/max ping + packet loss
3. Проверить UPnP через COM Interop (UPnP.UPnPDeviceFinder)
4. Проверить SIP ALG (UDP 3478 для Vivox)

**Зависимости:** после подзадачи 2

**Риски:**
UPnP COM может быть недоступен на некоторых системах. Пинг может быть заблокирован firewall. Решение: обернуть в try-catch.

---

## Подзадача 7: Реализация SoftwareTest.cs

**Файлы:**
- `Tests/SoftwareTest.cs` (новый)

**Описание:**
Создать класс `SoftwareTest` с методом `RunAsync()`. Детектирует антивирусы, VPN клиенты, проверяет системный прокси и hosts файл.

**Функциональность:**
1. Детекция антивирусов (по процессам и службам)
2. Детекция VPN клиентов (NordVPN, ProtonVPN, ExpressVPN и др.)
3. Проверка системного прокси (реестр HKCU)
4. Проверка hosts файла на записи для RSI доменов

**Зависимости:** после подзадачи 2

**Риски:**
Hosts файл может требовать админ права для чтения (обычно нет). Детекция антивирусов может давать false positives. Решение: обернуть в try-catch.

---

## Подзадача 8: Расширение DnsTest — добавление Google DNS

**Файлы:**
- `Tests/DnsTest.cs`

**Описание:**
Добавить проверку DNS через Google DNS (8.8.8.8) в дополнение к Cloudflare DoH. Сравнивать результаты: System DNS vs DoH vs Google DNS. Если System DNS отличается от обоих → DNS_FILTERED.

**Изменения:**
1. Добавить метод `QueryGoogleDnsAsync(string hostname)`
2. Сравнивать результаты трех источников
3. Обновить логику детекции DNS фильтрации

**Зависимости:** нет

**Риски:**
Google DNS может быть недоступен. Решение: timeout 3s + fallback только на DoH.

---

## Подзадача 9: Расширение HttpTest — добавление Vivox и AWS endpoints

**Файлы:**
- `Tests/HttpTest.cs`
- `star_citizen_targets.json`

**Описание:**
Добавить проверку Vivox (voice chat) и AWS endpoints (игровые серверы) в каталог целей.

**star_citizen_targets.json — добавить:**
- vivox: viv.vivox.com (voice chat)
- aws_eu_central: s3.eu-central-1.amazonaws.com
- aws_eu_west: s3.eu-west-1.amazonaws.com
- aws_us_east: s3.us-east-1.amazonaws.com
- aws_us_west: s3.us-west-2.amazonaws.com

HttpTest.cs автоматически обработает новые цели.

**Зависимости:** нет

**Риски:**
AWS endpoints могут быть недоступны (не критично, если хотя бы 1 работает).

---

## Подзадача 10: Расширение UdpProbeRunner — добавление игровых UDP портов

**Файлы:**
- `Tests/UdpProbeRunner.cs`

**Описание:**
Добавить проверку игровых UDP портов (64090-64094) и Vivox UDP (3478).

**Изменения:**
Расширить список целей UdpTargets, добавив игровые порты и Vivox STUN порт.

**Зависимости:** нет

**Риски:**
Игровые серверы могут не отвечать на произвольные UDP пакеты. Решение: считать успехом если НЕ ICMP Unreachable.

---

## Подзадача 11: Интеграция новых тестов в AuditRunner

**Файлы:**
- `AuditRunner.cs`
- `Tests/TestProgress.cs`

**Описание:**
Добавить вызовы новых тестов в метод `RunAuditAsync()`. Добавить новые типы тестов в enum `TestKind` (FIREWALL, ISP, ROUTER, SOFTWARE).

**Изменения:**
После VPN детекции, перед циклом по целям добавить вызовы SoftwareTest, FirewallTest, RouterTest, IspTest.

**Зависимости:** после подзадач 4, 5, 6, 7

**Риски:** нет

---

## Подзадача 12: Переработка логики вердикта в ReportWriter

**Файлы:**
- `Output/ReportWriter.cs`

**Описание:**
Переписать метод `BuildSummary()` с учётом новых тестов. Новая логика playable учитывает firewall блокировки, ISP DPI, VPN режим, Vivox и AWS доступность.

**Новая логика playable:**
- NO: firewall блокирует 8000-8003, ISP DPI активен, TCP Portal недоступен, Vivox недоступен, все AWS endpoints недоступны
- MAYBE: CGNAT, нет UPnP, антивирус обнаружен, TCP Launcher частично доступен
- YES: VPN активен И HTTPS работает, firewall OK, ISP OK, TCP Portal OK

**Зависимости:** после подзадачи 11

**Риски:**
Логика может быть слишком строгой/мягкой. Решение: тестирование на 8 сценариях + корректировка.

---

## Подзадача 13: Обновление GUI — добавление новых карточек

**Файлы:**
- `MainWindow.xaml`
- `MainWindow.xaml.cs`

**Описание:**
Добавить 4 новые информационные карточки (MaterialDesignCard) для отображения результатов: FirewallCard, IspCard, RouterCard, SoftwareCard. Каждая карточка показывается только при наличии проблем и содержит детали + рекомендации.

**Зависимости:** после подзадачи 12

**Риски:** нет

---

## Подзадача 14: Обновление TestProgress для новых тестов

**Файлы:**
- `Tests/TestProgress.cs`
- `MainWindow.xaml.cs`

**Описание:**
Добавить новые типы тестов в enum `TestKind` (FIREWALL, ISP, ROUTER, SOFTWARE). Обновить GUI прогресс-бар для отображения статуса новых тестов.

**Зависимости:** после подзадачи 11

**Риски:** нет

---

## Подзадача 15: Тестирование — Unit тесты

**Файлы:**
- `Tests/FirewallTest.cs`
- `Tests/IspTest.cs`
- `Tests/RouterTest.cs`
- `Tests/SoftwareTest.cs`

**Описание:**
Добавить unit тесты для новых классов. Использовать моки для WMI, API, NetworkInterface, Process.

**Зависимости:** после подзадачи 11

**Риски:**
Моки WMI/COM могут быть сложными. Решение: упрощенные unit тесты + полагаться на интеграционное тестирование.

---

## Подзадача 16: Интеграционное тестирование — 8 сценариев

**Файлы:**
- `AuditRunner.cs`
- `Output/ReportWriter.cs`

**Описание:**
Протестировать 8 сценариев: без VPN всё работает, Firewall блокирует 8000, ISP DPI, VPN full tunnel, VPN split tunnel, CGNAT, Vivox недоступен, AWS endpoints недоступны.

**Процесс:**
Запустить ISP_Audit в каждом сценарии, проверить вердикт playable и отображение карточек в GUI. Записать результаты в agents/qa_agent/test_report.md.

**Зависимости:** после подзадачи 13

**Риски:**
Некоторые сценарии сложно воспроизвести (DPI, CGNAT). Решение: использовать моки или реальные тестовые окружения.

---

## Подзадача 17: Документация и финализация

**Файлы:**
- `README.md`
- `agents/delivery_agent/changelog.md`

**Описание:**
Обновить README.md с описанием новых возможностей диагностики. Создать changelog.md с перечислением всех изменений.

**Зависимости:** после подзадачи 16

**Риски:** нет

---

## Итого

### Количество подзадач: 17

### Порядок выполнения:
1. **Подзадача 1** (NuGet) — первая (независимая)
2. **Подзадачи 2-3** (модели данных) — параллельно после 1
3. **Подзадачи 4-7** (новые тесты) — параллельно после 2
4. **Подзадачи 8-10** (расширение тестов) — параллельно (независимы)
5. **Подзадача 11** (интеграция в AuditRunner) — после 4-7
6. **Подзадача 12** (логика вердикта) — после 11
7. **Подзадача 13** (GUI карточки) — после 12
8. **Подзадача 14** (TestProgress) — после 11
9. **Подзадача 15** (Unit тесты) — после 11 (параллельно с 12-14)
10. **Подзадача 16** (интеграционные тесты) — после 13
11. **Подзадача 17** (документация) — последняя (после 16)

### Критический путь:
```
1 → 2 → 4-7 → 11 → 12 → 13 → 16 → 17
```

### Можно выполнять параллельно:
- **Группа A:** Подзадачи 4, 5, 6, 7 (новые тесты)
- **Группа B:** Подзадачи 8, 9, 10 (расширение тестов)
- **Группа C:** Подзадачи 13, 14, 15 (GUI + TestProgress + Unit тесты)

### Основные риски:

**1. Требование админ прав**
- Затронуто: FirewallTest (WMI), Windows Defender
- Воздействие: Тест вернет Status = "UNKNOWN" без админ прав
- Митигация: Обернуть в try-catch, показать предупреждение в GUI

**2. Зависимость от внешних API**
- Затронуто: IspTest (ip-api.com)
- Воздействие: Если API недоступен → ISP info неизвестен
- Митигация: Timeout 5s + fallback на ipify.org или ifconfig.co

**3. Ложные срабатывания**
- Затронуто: DPI детекция, CGNAT детекция, антивирусы
- Воздействие: Пользователь может получить MAYBE вместо YES
- Митигация: Многофакторная проверка, категоризация WARN vs FAIL

**4. Производительность**
- Затронуто: Firewall (WMI), Router (20 пингов), ISP (API)
- Воздействие: Увеличение времени тестирования на 5-10 секунд
- Митигация: Параллелизация Software/Firewall/Router/ISP

**5. Кросс-платформенность**
- Затронуто: Все новые тесты (WMI, COM, Registry — Windows-only)
- Воздействие: Код не будет работать на Linux/macOS
- Митигация: НЕ критично (Star Citizen — Windows-only)

**6. Изменение логики вердикта**
- Затронуто: Подзадача 12 (ReportWriter)
- Воздействие: Может сломать существующие ожидания пользователей
- Митигация: Тщательное тестирование на 8 сценариях

### Оценка времени (для продвинутой модели):
- P0 задачи (критичные): 8-11 часов
- P1 задачи (важные): 7-11 часов
- GUI изменения: 4-6 часов
- Тестирование: 4-6 часов
- Документация: 1-2 часа

**Итого:** 24-36 часов (3-4 дня для продвинутой модели)

---

**План готов к передаче Coding Agent!**
