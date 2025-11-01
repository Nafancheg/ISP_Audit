# Исправление архитектурных проблем ISP_Audit

Дата: 2025-10-30
ID: 20251030-171114-arch-fix

## Контекст

QA Agent обнаружил 4 критические проблемы. После детального Angel vs Demon review обнаружены ФУНДАМЕНТАЛЬНЫЕ проблемы:

**ПРОБЛЕМА #1: Тестируем портал вместо игры**
- `star_citizen_targets.json` проверяет `robertsspaceindustries.com` (портал для регистрации)
- Портал НЕ нужен для игры (используется 1 раз при регистрации)
- НЕ проверяем критичные сервисы: Launcher CDN, AWS game servers, Vivox voice chat

**ПРОБЛЕМА #2: DNS - корень 80% проблем**
- `DnsTest.cs` слишком сложный (DoH comparison даёт false positives из-за CDN)
- Нет кнопки "FIX DNS" (пользователю нужно самому искать как сменить DNS)
- VPN рекомендуется ПЕРВЫМ средством (должен быть ПОСЛЕДНИМ)

**ПРОБЛЕМА #3: Бесполезные тесты**
- `FirewallTest.cs`, `IspTest.cs`, `RouterTest.cs`, `SoftwareTest.cs` - проверяют не то

**ПРОБЛЕМА #4: Хардкод endpoints устаревает**
- Star Citizen меняет инфраструктуру → targets.json становится неактуальным
- Нужен WinDivert сниффер для автообнаружения endpoints

**Бизнес-ценность**: Инструмент должен РЕАЛЬНО помогать игрокам Star Citizen диагностировать сетевые проблемы.

## Цель и результат

### ШАГ 1: DNS Fix (ПРИОРИТЕТ 1, 2-3 часа)
1. Упростить `DnsTest.cs` (System DNS empty = DNS_FILTERED, DoH только для display)
2. Добавить кнопки "🔧 FIX DNS" и "↩️ ROLLBACK DNS" в GUI
3. Fix DNS работает 1 кликом (PowerShell → Cloudflare 1.1.1.1)
4. VPN рекомендуется ПОСЛЕДНИМ средством

### ШАГ 2: Удаление бесполезных тестов (ПРИОРИТЕТ 2, 1-2 часа)
1. Удалить: `FirewallTest.cs`, `IspTest.cs`, `RouterTest.cs`, `SoftwareTest.cs`
2. Убрать из `AuditRunner.cs` и GUI

### ШАГ 3: Исправление TcpTest (ПРИОРИТЕТ 3, 2-3 часа)
1. Переделать `star_citizen_targets.json`:
   - Убрать `robertsspaceindustries.com` (портал)
   - Добавить `install.robertsspaceindustries.com` (Launcher CDN)
   - Добавить AWS game servers, Vivox voice chat
2. Добавить `critical: bool` в `TargetModels.cs`
3. Убрать early-exit для critical в `AuditRunner.cs` (fallback IPs)
4. Учитывать `critical` в `ReportWriter.cs` (verdict)

### ШАГ 4: WinDivert сниффер (ПРИОРИТЕТ 4, 8-10 часов)
1. Создать `Utils/TrafficSniffer.cs` (WinDivert wrapper)
2. Создать `Utils/EndpointClassifier.cs` (CDN/Game/Voice/API)
3. Создать `Utils/ProfileManager.cs` (save/load JSON profiles)
4. Создать `Wpf/SnifferWindow.xaml` (GUI "Анализ приложения")
5. Интегрировать в `MainWindow`
6. Disclaimer о WinDivert/антивирусах

### Критерии приёмки:
- `dotnet build` успешен
- GUI запускается без ошибок
- Кнопка "FIX DNS" работает (UAC, меняет DNS на 1.1.1.1)
- Кнопка "ROLLBACK DNS" восстанавливает оригинальные DNS
- Тесты проверяют launcher/AWS/Vivox (НЕ портал)
- Удалённые тесты не запускаются
- Сниффер находит endpoints запущенного процесса
- Нет регрессий (UdpProbeRunner, TracerouteTest, RstHeuristic работают)

## Объём и ограничения

### В scope:
- Упрощение DnsTest (логика + GUI кнопки)
- Удаление 4 бесполезных тестов
- Переделка targets.json (убрать портал, добавить игровые сервисы)
- Добавление critical флага и fallback IPs
- WinDivert сниффер (универсальный инструмент)

### Вне scope:
- HttpTest review (оставить как есть)
- Community profiles / GitHub integration (будущее)
- Пресеты для других игр (будущее)
- Code signing сертификат (некоммерческий проект)

### Ограничения:
- **Технологии**: .NET 9.0, WPF, MaterialDesign, WinDivert 2.x
- **Async/await**: Все операции асинхронные с CancellationToken
- **Обратная совместимость**: НЕ требуется (breaking changes)
- **WinDivert**: Требует админа, антивирусы могут ругаться
- **Время**: ~13-18 часов

### Риски:
1. WinDivert и антивирусы → Disclaimer + README
2. PowerShell UAC prompt → Обработка ошибок + fallback
3. AWS endpoints geo-block → `critical: false` для не-EU
4. Launcher CDN адреса меняются → Fallback IPs + сниффер

### Оценка: LARGE (13-18 часов)

## Артефакты
- Исследование: research.md
- План: plan.md
- Реализация: implementation.md
- Ревью: review.md
- Тест-план: qa_test_plan.md
- Тест-отчёт: qa_report.md
- Changelog: changelog.md
- Решения: ../../qa_agent/improvements_discussed.md (107K tokens, УЖЕ СУЩЕСТВУЕТ)

## Детальный источник требований

**ВСЕ технические детали** задокументированы в:
📄 `agents/qa_agent/improvements_discussed.md`

Этот файл содержит:
- Angel vs Demon debate (полная транскрипция)
- Все договорённости по DnsTest (код Fix/Rollback кнопок)
- Все договорённости по TcpTest (targets.json структура)
- WinDivert сniffer архитектура (TrafficSniffer.cs, EndpointClassifier.cs, ProfileManager.cs)
- Приоритеты (ШАГ 1-4 с временными оценками)

**Агенты должны читать этот файл!**
