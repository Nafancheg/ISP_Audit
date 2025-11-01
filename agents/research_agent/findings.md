# Research Agent Findings

**Дата**: 2025-10-31

---

## Затронутые файлы

### Конфигурация целей
- `star_citizen_targets.json` — текущие цели (порталы вместо серверов)
- `TargetModels.cs` — структуры данных (нет поля Critical)
- `TargetCatalog.cs` — загрузка targets.json
- `TargetServiceProfiles.cs` — маппинг сервисов → порты
- `Config.cs` — глобальные настройки (нет поддержки Profiles/)

### Тестирование
- `AuditRunner.cs` — движок тестов (early-exit пропускает критичные цели)
- `Tests/DnsTest.cs` — 3 источника DNS (System, DoH, Google)
- `Output/ReportWriter.cs` — вердикт playable (не использует Critical)
- `Utils/NetUtils.cs` — утилиты DNS

### GUI
- `MainWindow.xaml` — разметка (нет кнопок DNS Fix)
- `MainWindow.xaml.cs` — логика (нет FixDnsButton_Click)

---

## ЧАСТЬ 1: Текущие цели и профили

### Что тестируется сейчас

**Домены** (star_citizen_targets.json):
- ❌ `robertsspaceindustries.com` — портал (НЕ нужен для игры)
- ❌ `accounts.`, `api.`, `cdn.` — порталы
- ✅ `install.robertsspaceindustries.com` — launcher (НУЖЕН)
- ❌ `s3.*.amazonaws.com` — S3 CDN (игра на EC2!)
- ✅ `viv.vivox.com` — voice chat

**Порты**:
- TCP: 80, 443, 8000-8020
- UDP: 53, 3478, 64090-64094

**ПРОБЛЕМА**: порты 8000-8020 применяются КО ВСЕМ целям (включая порталы)

### Структура данных

**TargetDefinition** (TargetModels.cs):
```
Name, Host, Service
```
- ❌ НЕТ поля `Critical`
- ❌ НЕТ поля `FallbackIp`

**Загрузка**: TargetCatalog.cs → Config.cs → Program.cs
- ❌ НЕТ поддержки `Profiles/` папки

### Early-exit проблема

**AuditRunner.cs** (строка ~88):
```
if (DNS пуст) → пропустить TCP/HTTP/Trace
```
**ПРОБЛЕМА**: критичные цели должны тестироваться ВСЕГДА (с fallback IP)

### Вердикт playable

**ReportWriter.cs**:
- Анализирует статусы Firewall, ISP, Router, Software
- Проверяет tcp_portal (80/443), tcp_launcher (8000-8020)
- ❌ НЕ использует поле Critical (его нет)

---

## ЧАСТЬ 2: DNS логика

### Текущая реализация

**DnsTest.cs**:
- 3 источника: System DNS, Cloudflare DoH, Google DNS
- Сравнивает результаты → определяет статус
- VPN-aware логика (смягчает критерии)

**Статусы**:
- `DNS_FILTERED` — System DNS пуст, DoH работает
- `DNS_BOGUS` — System DNS вернул мусор (0.0.0.0, 127.x)
- `WARN` — несовпадение адресов
- `OK` — всё совпадает

**ПРОБЛЕМА**: DoH и Google используются в ЛОГИКЕ (должны быть только для информации)

### GUI

**MainWindow.xaml**:
- ❌ НЕТ кнопок "ИСПРАВИТЬ DNS" / "ВЕРНУТЬ DNS"
- ❌ НЕТ TextBox для ручного ввода хоста
- ❌ НЕТ TextBox для EXE файла

**MainWindow.xaml.cs**:
- ❌ НЕТ методов FixDnsButton_Click, ResetDnsButton_Click

---

## Риски и зависимости

### Что может сломаться при переходе на профили?

1. **Обратная совместимость**: `star_citizen_targets.json` используется в `TargetCatalog.cs`, `Program.cs`, `MainWindow.xaml.cs`
2. **Зависимости**: `Config.cs` использует `TargetCatalog.CreateDefaultTargetMap()`
3. **GUI изменения**: нужно добавить TextBlock для показа активного профиля

### Нужно ли менять GUI для поддержки профилей?

**ДА**, минимальные изменения:
1. Показать активный профиль → TextBlock "Профиль: Star Citizen"
2. Добавить неактивные поля (disabled): "Тест хоста", "EXE файл"

### Какие файлы зависят от структуры целей?

1. **TargetCatalog.cs** — загружает `star_citizen_targets.json`
---

## Риски

- **DNS изменение**: требуется проверка доступности DoH провайдеров (HTTPS запрос)
- **Netsh**: требует права админа (но НЕ reboot)
- **Профили**: загрузка JSON из `Profiles/` — нужна обработка ошибок
- **Critical поле**: изменение логики early-exit в AuditRunner может сломать вердикт playable
- **Обратная совместимость**: `star_citizen_targets.json` (корень) vs `Profiles/StarCitizen.json`

---

## Рекомендации Planning Agent

1. **Сначала структуры** (Part 1, 7 подзадач):
   - Добавить Critical/FallbackIp в TargetDefinition
   - Создать GameProfile
   - Создать Profiles/StarCitizen.json с правильными целями (install., ec2., viv.)
   - Обновить TargetCatalog для загрузки из Profiles/
   - Исправить AuditRunner (early-exit для Critical целей)
   - Обновить ReportWriter (использовать Critical поле)
   - Добавить GUI поля (профиль, тест хоста, EXE)

2. **Потом DNS** (Part 2, 3 подзадачи):
   - Создать DnsAvailabilityCheck (HTTPS запрос к DoH endpoint)
   - Добавить кнопки в MainWindow.xaml ("ИСПРАВИТЬ DNS", "ВЕРНУТЬ DNS")
   - Реализовать обработчики в MainWindow.xaml.cs (netsh apply/revert)

3. **Тестирование**:
   - Проверить загрузку Profiles/StarCitizen.json
   - Проверить early-exit с Critical целями
   - Проверить DnsAvailabilityCheck (3 провайдера)
   - Проверить netsh apply/revert (с админ правами)

---

**Файлы для изменения**:
- `TargetModels.cs` — добавить Critical, FallbackIp, GameProfile
- `Profiles/StarCitizen.json` — NEW
- `TargetCatalog.cs` — загрузка из Profiles/
- `AuditRunner.cs` — early-exit логика
- `ReportWriter.cs` — вердикт с Critical
- `Tests/DnsTest.cs` — availability check
- `MainWindow.xaml` — кнопки DNS + поля профиля
- `MainWindow.xaml.cs` — обработчики кнопок
- `GuiProfileStorage.cs` — поддержка Profiles/

---

**Дата завершения**: 2025-01-31  
**Статус**: ✅ Завершено
