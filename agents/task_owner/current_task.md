# [PURPLE] Task Owner: Переработка тестов по примеру PowerShell скриптов

**Дата**: 2025-10-30
**Приоритет**: ВЫСОКИЙ
**Статус**: TODO

## Проблема

**Краткое описание**:
Текущие тесты (DNS, HTTP, TCP, UDP, Traceroute) не дают реального ответа - работает ли игра Star Citizen. При включенном VPN тесты показывают "неиграбельно", хотя игра реально работает нормально. Тесты не выявляют реальные проблемы (firewall, ISP блокировки, специфичные SC порты).

**Как проявляется**:
```
1. Пользователь включает VPN (работающий)
2. Запускает ISP_Audit
3. Тесты показывают проблемы/красные индикаторы
4. НО Star Citizen запускается и работает
5. Вердикт программы = "NOT_PLAYABLE" (ложь!)
6. Реальные проблемы НЕ выявляются:
   - Windows Firewall блокировки портов 8000-8003
   - ISP фильтрация (DPI, CGNAT)
   - Закрытые игровые порты на роутере
   - Блокировка Vivox (voice chat)
```

**Контекст**:
- Кто столкнётся: игроки Star Citizen
- Критичность: **HIGH** - программа дает ложные результаты

**Референсы**:
Два PowerShell скрипта демонстрируют правильную диагностику:
- `StarCitizen_NetworkDiag.ps1` - комплексная диагностика (DNS, задержки, AWS регионы, порты)
- `StarCitizen_DeepDiagnostics.ps1` - глубокий анализ блокировок (firewall, ISP, router, software)

---

## Анализ PowerShell скриптов (референсы)

### StarCitizen_NetworkDiag.ps1 содержит:
1. **Системные требования** - проверка ОС, RAM, GPU
2. **Конфигурация сети** - TCP Auto-Tuning, RSS, Jumbo Frames  
3. **DNS производительность** - сравнение Google/Cloudflare/Quad9/OpenDNS (5 попыток каждый)
4. **Маршрутизация провайдера** - traceroute, определение ISP через IP-API, CGNAT проверка, NAT тип (STUN)
5. **Задержка до игровых серверов** - пинг AWS регионов (EU, US East/West, APAC) по 10 попыток
6. **Пропускная способность** - загрузка 10MB файла с cloudflare
7. **Игровые порты** - TCP 80/443/8000-8003, UDP 64090-64094
8. **Windows оптимизации** - Game Mode, Nagle's Algorithm, Windows Defender исключения

### StarCitizen_DeepDiagnostics.ps1 содержит (КРИТИЧНО):
1. **Windows Firewall анализ** - блокирующие правила для SC портов, профили firewall, Windows Defender
2. **Стороннее ПО** - детекция антивирусов (Kaspersky/Avast/ESET/Norton), VPN клиентов, сетевых оптимизаторов, прокси
3. **Hosts файл** - проверка подозрительных записей для RSI доменов
4. **Системный прокси** - проверка настроек прокси, переменных окружения HTTP_PROXY/HTTPS_PROXY
5. **ISP блокировки**:
   - Определение провайдера через внешний IP (ipify + ip-api)
   - CGNAT детекция (диапазон 100.64.0.0/10)
   - DPI (Deep Packet Inspection) - модификация заголовков, фрагментация, throttling игровых портов
   - DNS фильтрация ISP - сравнение резолва через ISP DNS vs Google DNS
6. **Роутер проблемы**:
   - Стабильность пинга до gateway (20 попыток)
   - UPnP проверка
   - SIP ALG (влияет на voice chat)
   - QoS политики
7. **Star Citizen специфика**:
   - EasyAntiCheat установка/версия
   - AWS endpoints (eu-central-1, eu-west-1, us-east-1, us-west-2) - HTTPS доступность
   - Vivox voice chat (viv.vivox.com:443)
8. **Итоговый вердикт** - категоризация блокировок:
   - Firewall (Windows + Defender)
   - ISP (CGNAT, DPI, DNS фильтрация)
   - Router (UPnP, SIP ALG, QoS)
   - Software (антивирусы, VPN, прокси)
   - DNS (провайдерские проблемы)
   - System (общесистемные настройки)
9. **Рекомендации** - автоматические исправления (если запущено с `-FixIssues`)

---

## Желаемый результат (Definition of Done)

После выполнения:
1. **Firewall тесты** (из DeepDiagnostics):
   - Проверка Windows Firewall правил для портов 8000-8003, 64090-64094
   - Проверка Windows Defender блокировок
   - Детекция блокирующих правил для Star Citizen
2. **ISP анализ** (из DeepDiagnostics):
   - Определение провайдера через внешний IP
   - CGNAT детекция
   - DPI проверка (модификация заголовков, throttling портов)
   - DNS фильтрация провайдера (сравнение System DNS vs DoH)
3. **Router тесты** (из DeepDiagnostics):
   - Проверка UPnP доступности
   - SIP ALG детекция
   - QoS политики
   - Стабильность пинга до gateway
4. **Software проверки** (из DeepDiagnostics):
   - Детекция антивирусов (Kaspersky, Avast, ESET, Norton, McAfee, Bitdefender)
   - Детекция VPN клиентов (и адаптация логики тестов!)
   - Hosts файл проверка
   - Системный прокси проверка
5. **Star Citizen специфика** (из обоих скриптов):
   - AWS регионы (eu-central-1, eu-west-1, us-east-1, us-west-2) пинг + HTTPS
   - Vivox voice chat (viv.vivox.com:443)
   - EasyAntiCheat проверка
   - Игровые порты TCP 8000-8003, UDP 64090-64094
6. **Умный вердикт**:
   - Категоризация проблем (Firewall/ISP/Router/Software/DNS/System)
   - Приоритизация проблем (критичные vs предупреждения)
   - Понятные рекомендации для пользователя
   - VPN-aware: если VPN активен и работает → игра скорее всего PLAYABLE

Критерии приёмки:
- ✅ С VPN программа НЕ показывает ложные "NOT_PLAYABLE" если игра работает
- ✅ Выявляются РЕАЛЬНЫЕ блокировки: Windows Firewall правила, ISP DPI, закрытые порты
- ✅ Вердикт основан на категоризированных проблемах (не просто "DNS failed")
- ✅ Понятные сообщения: "Windows Firewall блокирует порт 8000" вместо "TCP Test Failed"
- ✅ Детекция VPN и адаптация логики (не считать VPN за проблему)
- ✅ Нет регрессий: текущие тесты (DNS/HTTP/TCP/UDP/Traceroute) продолжают работать

---

## Ограничения

**Технические**:
- .NET 9, WPF + MaterialDesign
- Async/await + CancellationToken
- Обратная совместимость: **НЕТ** (можно менять логику тестов)

**Что НЕ делать**:
- НЕ удалять существующие тесты полностью (DNS/HTTP/TCP/UDP/Traceroute) - дополнять и модифицировать
- НЕ менять GUI кардинально (только добавить новые статусы/индикаторы)
- НЕ добавлять зависимости от PowerShell (всё в C#)
- НЕ трогать bypass-логику (WinDivert)

**Оценка**: **LARGE** (10+ подзадач)

**Рекомендуемые модели по размеру**:
- Research/Planning: продвинутая модель (GPT-4, Claude Opus) - нужно глубокое понимание сетевой диагностики
- Coding: стандартная модель (GPT-4o, Claude Sonnet) - сложная логика

---

## Рекомендации для Research Agent

**Приоритетные вопросы для исследования:**

1. **Анализ PowerShell скриптов**:
   - Какие КОНКРЕТНО проверки делают скрипты?
   - Какие .NET API/классы использовать для портирования? (Get-NetFirewallRule → System.Management, Get-NetAdapter → NetworkInterface)
   - Как детектировать CGNAT (проверка диапазона 100.64.0.0/10)?
   - Как проверить DPI (модификация заголовков HTTP)?

2. **Текущая архитектура тестов**:
   - Tests/DnsTest.cs, HttpTest.cs, TcpTest.cs, UdpProbeRunner.cs, TracerouteTest.cs
   - Как интегрировать новые проверки? (новые классы FirewallTest.cs, IspTest.cs, RouterTest.cs?)
   - Где хранить результаты? (расширить UdpProbeResult.cs?)

3. **VPN детекция**:
   - Utils/NetUtils.cs - есть ли уже методы?
   - Как детектировать VPN? (interface names, DNS servers, routes)

4. **Вердикт логика**:
   - AuditRunner.cs - как сейчас формируется итоговый вердикт?
   - Как категоризировать проблемы (Firewall/ISP/Router/Software)?
   - Где хранить рекомендации для пользователя?

5. **GUI интеграция**:
   - MainWindow.xaml.cs, ServiceItemViewModel.cs - как показывать новые статусы?
   - Нужны ли новые иконки/цвета для категорий проблем?

---

## Статус агентов

### [1] [RED] Research Agent - TODO  
### [2] [BLUE] Planning Agent - TODO
### [3] [GREEN] Coding Agent - TODO
### [4] [YELLOW] QA Agent - TODO
### [5] [CYAN] Delivery Agent - TODO

