# ISP_Audit TODO List

**Дата создания:** 20 ноября 2025 г.  
**Ветка:** feature/wpf-new-migration  
**Последний коммит:** a0830a8 (Exe-scenario Stage 1-3 implementation + DNS/SNI parsing)

---

## 🟢 Завершённые задачи

### WinDivert Integration & Traffic Analysis
- [x] **ERROR_INVALID_PARAMETER (87) fix** - Переход с SOCKET на NETWORK layer для совместимости с Sniff флагом
- [x] **Port caching mechanism** - ConcurrentDictionary с обновлением каждые 2 секунды вместо per-packet GetExtendedTcpTable
- [x] **DNS packet parsing** - Парсинг UDP port 53 ответов для DNS A records с поддержкой compression pointers
- [x] **TLS SNI extraction** - Извлечение Server Name Indication из TCP port 443 ClientHello для оригинальных hostname
- [x] **Hybrid hostname resolution** - Приоритет: DNS cache → SNI cache → Reverse DNS (технические CDN имена)
- [x] **Diagnostic logging** - 14 progress messages с emoji индикаторами для отладки захвата трафика
- [x] **8-second connection delay** - Увеличение задержки с 5 до 8 секунд для установки соединений
- [x] **Force initial cache update** - Принудительное обновление кэша за -10 секунд до запуска WinDivert

### GUI Workflow (Stage 1-3)
- [x] **BrowseExeCommand** - OpenFileDialog для выбора .exe файла с фильтром "*.exe"
- [x] **AnalyzeTrafficCommand** - Stage 1 запуск процесса + WinDivert capture + сохранение профиля
- [x] **ViewStage1ResultsCommand** - Открытие CapturedTargetsWindow с DataGrid результатов
- [x] **DiagnoseCommand** - Stage 2 переработан для использования _capturedProfile напрямую (не через RunAuditAsync)
- [x] **ApplyBypassCommand** - Stage 3 DnsFixApplicator + WinDivertBypassManager интеграция
- [x] **MessageBox workflow** - Уведомления между Stage 1→2→3 с предложением продолжить
- [x] **CapturedTargetsWindow** - Удаление MaterialDesign зависимостей, замена на DropShadowEffect
- [x] **Stage 2 null check** - MessageBox "Профиль не найден" если _capturedProfile == null

### TestNetworkApp Calibration Tool
- [x] **.NET 9 console app** - 115 строк, 7 HTTPS целей (Google/YouTube/Discord/GitHub/Cloudflare/IP API/1.1.1.1)
- [x] **60-second HTTP loop** - HttpClient с цветными console output индикаторами
- [x] **Single-file publish** - 147KB exe в TestNetworkApp/bin/Release/net9.0/win-x64/publish/

### Documentation
- [x] **README.md header** - Добавлен Exe-сценарий overview, Stage 1-3 описания
- [x] **README.md GUI usage** - Разделение на "Профильная диагностика" и "Exe-сценарий" секции
- [x] **README.md architecture** - Новая секция "Архитектура Exe-сценария" (~150 строк)
- [x] **README.md system requirements** - Системные требования + зависимости
- [x] **README.md known issues** - 6 известных проблем с решениями (ERROR 87, "0 событий", "0 целей", DNS cache, StaticResource, Process blocks build)
- [x] **README.md WinDivert section** - Расширение с конфигурацией, активацией, безопасностью, диагностикой
- [x] **README.md FAQ** - Обновлённые частые вопросы с актуальными решениями

---

## 🔴 Критичные задачи (Priority 1)

### End-to-End Testing
- [ ] **Full Exe-scenario workflow test**
  - Шаги:
    1. Stop all ISP_Audit processes: `Stop-Process -Name "ISP_Audit" -Force`
    2. Launch as ADMIN: `Start-Process ISP_Audit.exe -Verb RunAs`
    3. Выбрать Exe-сценарий → Browse → TestNetworkApp.exe
    4. Нажать "Stage 1: Analyze Traffic" → ждать 30 секунд
    5. Проверить Output: `✓ Кэш обновлен: 7 TCP + 0 UDP = 7 портов`
    6. Проверить: `Пакетов: 500+, совпало PID: 50+, соединений: 7`
    7. Проверить: `✓ Hostname resolved: 7/7 (X from DNS cache, Y from SNI, Z from reverse DNS)`
    8. MessageBox "Захват завершён. Перейти к Stage 2?" → Yes
    9. Stage 2 выполняется без "профиль не найден"
    10. MessageBox "Обнаружены проблемы. Перейти к Stage 3?" → Yes
    11. UAC dialog для netsh → разрешить
    12. Проверить GUI status: "WinDivert активен (PID: 12345)"
  - **Acceptance criteria**:
    - Все 7 целей захвачены в JSON
    - CapturedTargetsWindow открывается без ошибок
    - Stage 2 использует _capturedProfile (не требует scenario selection)
    - DNS fix применяется (netsh успешен)
    - WinDivert bypass активируется (GUI status меняется)

- [ ] **DNS cache effectiveness validation**
  - Выполнить: `ipconfig /flushdns` перед тестом
  - Проверить logs: соотношение DNS cache / SNI / Reverse DNS
  - **Expected**: 50-70% DNS cache, 20-30% SNI, 10-20% Reverse DNS
  - **If DNS cache = 0%**:
    - Причина: DNS запросы произошли до запуска WinDivert
    - Решение: Увеличить delay с 8 до 15 секунд
    - Добавить diagnostic logging в TryParseDnsResponse
  - **If SNI extraction = 0%**:
    - Причина: TLS packets не захватываются или парсинг ломается
    - Решение: Добавить logging в TryExtractSniFromTls с hex dump первых 20 байт
    - Проверить: TLS версия (должна быть 0x0301-0x0303), Content Type (0x16)

- [ ] **CapturedTargetsWindow hostname display**
  - Проверить: JSON содержит mix оригинальных доменов + CDN имён
  - Ожидаемые примеры:
    - `youtube.com` (от DNS cache)
    - `www.google.com` (от SNI)
    - `prg03s12-in-f14.1e100.net` (от Reverse DNS)
  - Если только CDN имена → DNS/SNI парсинг не работает, проверить logs

---

## 🟠 Важные задачи (Priority 2)

### Stage 2 & 3 Validation
- [ ] **ProblemClassifier logic check**
  - Проверить: DNS_FILTERED обнаруживается (DoH возвращает адреса, system DNS пустой/bogus)
  - Проверить: DPI обнаруживается (RST injection timing heuristic)
  - Проверить: FIREWALL обнаруживается (Windows Firewall rules блокируют порты)
  - Проверить: CGNAT обнаруживается (100.64.0.0/10 в GetExtendedTcpTable)
  - Добавить unit tests для classify_problems() с mock data

- [ ] **BypassStrategyPlanner profile generation**
  - Проверить: bypass_profile.json генерируется правильно
  - Проверить: dns_providers содержит 4 DoH провайдера (Cloudflare/Google/Quad9/AdGuard)
  - Проверить: windivert_rules содержит drop_rst_incoming=true, fragment_tls=true
  - Проверить: redirect_rules пустой (не используется для DNS проблем)
  - Проверить: Если DPI обнаружен → fragment_position=2, fragment_size=2

- [ ] **DnsFixApplicator DoH testing**
  - Проверить: Все 4 провайдера тестируются параллельно
  - Проверить: Выбирается самый быстрый (min response time)
  - Проверить: Fallback если все провайдеры недоступны (показать MessageBox с ошибкой)
  - Проверить: FixHistory.json сохраняет оригинальные DNS
  - Проверить: Rollback восстанавливает original DNS через netsh

- [ ] **WinDivertBypassManager activation**
  - Проверить: GUI status меняется с "не активен" на "активен (PID: X)"
  - Проверить: Logs содержат `[Bypass] WinDivert handle opened`, `[Bypass] Rules applied`
  - Проверить: TCP RST пакеты дропаются (проверить через Wireshark)
  - Проверить: TLS ClientHello фрагментируется (первый пакет 2 байта, остальное в следующем)
  - Проверить: Bypass останавливается при закрытии приложения (driver unload)

---

## 🟡 Средний приоритет (Priority 3)

### Edge Cases & Error Handling
- [ ] **UAC elevation handling**
  - Добавить: Try-catch вокруг netsh команд
  - Если UAC cancelled → показать MessageBox "Требуются admin права для изменения DNS"
  - Добавить: Проверку `IsAdministrator()` перед Stage 3 с предупреждением

- [ ] **Process crash during capture**
  - Добавить: Try-finally в CaptureLoop для гарантированного WinDivert.Close()
  - Добавить: Exception handling для Process.Start() с MessageBox "Не удалось запустить {exePath}"
  - Добавить: Timeout для Process (если зависает > 2 минуты → Kill())

- [ ] **Empty capture results**
  - Если connections.Count == 0 после 30 секунд:
    - MessageBox: "Приложение не установило сетевых соединений. Увеличьте delay или используйте другое приложение."
    - Не создавать JSON файл
    - Не предлагать Stage 2
  - Если connections.Count < 3:
    - MessageBox: "Захвачено мало целей ({count}). Возможно приложение не активно. Продолжить?"

- [ ] **Disable buttons during processing**
  - Проверить: IsRunning = true блокирует все команды
  - Добавить: CommandManager.InvalidateRequerySuggested() после изменения IsRunning
  - Проверить: "Остановить тест" кнопка активна только когда IsRunning = true

- [ ] **Reset button implementation**
  - Добавить: `ResetExeScenarioCommand` для очистки Stage 1-3 state
  - Логика:
    - _capturedProfile = null
    - _exePath = null
    - Stage1Complete = Stage2Complete = Stage3Complete = false
    - TestResults.Clear()
    - Status = "Готов к новому анализу"
  - UI: Кнопка "Сбросить" появляется после Stage 1/2/3

---

## 🟢 Желательные улучшения (Priority 4)

### Performance & UX
- [ ] **Progress indicator for Stage 1**
  - Заменить: Indeterminate ProgressBar на Determinate
  - Показывать: "Захвачено {count} соединений..." каждые 2 секунды
  - Показывать: "Обработано {processed}/{total} пакетов"

- [ ] **Increase delay for slow apps**
  - Добавить: NumericUpDown в GUI для ручной настройки delay (default 8s)
  - Диапазон: 5-60 секунд
  - Сохранять: В Config.json для следующих запусков

- [ ] **Multi-profile support**
  - Добавить: ListBox с историей захваченных профилей (из Profiles/*.json)
  - Кнопка: "Загрузить предыдущий профиль" → пропустить Stage 1, сразу к Stage 2
  - Сортировка: По дате модификации файла

- [ ] **Export captured profile**
  - Кнопка: "Экспорт профиля" → SaveFileDialog
  - Форматы: JSON (текущий), CSV (для Excel), HTML (для браузера)
  - CSV содержит: Host, Port, Protocol, Hostname, BytesSent, BytesReceived

---

## 🔵 Дополнительное тестирование (Priority 5)

### Real-World Scenarios
- [ ] **Star Citizen full test**
  - Запустить: Exe-scenario с RSI Launcher.exe
  - Проверить: Захвачены ли Vivox серверы (vdx5.vivox.com:443 UDP)
  - Проверить: Захвачены ли game servers (p4*-live.cloudimperiumgames.com UDP 64090-64094)
  - Сравнить: Exe-scenario JSON vs star_citizen_targets.json (должны совпадать критичные цели)
  - Проверить: Stage 2 обнаруживает DNS filtering (если RSI DNS блокируется провайдером)

- [ ] **Discord test**
  - Запустить: Exe-scenario с Discord.exe
  - Проверить: Захвачены voice servers (discord.gg, discord.com)
  - Проверить: UDP voice ports (50000-65535 range)

- [ ] **Browser test (Chrome/Firefox)**
  - Запустить: Exe-scenario с chrome.exe
  - Открыть: 10 вкладок с разными сайтами
  - Проверить: DNS cache hit rate (должен быть высокий, т.к. DNS queries перед HTTPS)
  - Проверить: SNI extraction (должно быть 100%, все сайты HTTPS)

- [ ] **VPN scenario test**
  - Запустить: VPN (OpenVPN/WireGuard) перед Exe-scenario
  - Проверить: NetUtils.LikelyVpnActive() возвращает true
  - Проверить: Adaptive timeouts применяются (HttpTimeout=12, TcpTimeout=8)
  - Проверить: Не появляются false positives для DNS_FILTERED

---

## 🛠️ Технический долг

### Code Quality
- [ ] **Utils/TrafficAnalyzer.cs refactoring**
  - Разделить: 744 строки → TrafficCapture.cs (WinDivert), PacketParser.cs (DNS/SNI), HostnameResolver.cs (enrichment)
  - Вынести: Magic numbers в константы (DNS_PORT=53, HTTPS_PORT=443, TLS_HANDSHAKE=0x16)
  - Добавить: XML documentation comments для публичных методов

- [ ] **ViewModels/MainViewModel.cs cleanup**
  - 1547 строк слишком много → разделить на MainViewModel (общее) + ExeScenarioViewModel (Stage 1-3)
  - Вынести: Stage 1-3 логику в отдельные классы (Stage1Analyzer, Stage2Diagnostician, Stage3Applicator)
  - Улучшить: Error handling с Try-catch блоками вокруг всех async операций

- [ ] **Null safety improvements**
  - Включить: `<Nullable>enable</Nullable>` в ISP_Audit.csproj
  - Исправить: 47 nullable warnings по всему коду
  - Добавить: Null checks с `ArgumentNullException.ThrowIfNull()` (.NET 9)

### Testing Infrastructure
- [ ] **Unit tests для TrafficAnalyzer**
  - Тесты для: TryParseDnsResponse с mock DNS packets
  - Тесты для: TryExtractSniFromTls с mock TLS ClientHello
  - Тесты для: ReadDnsName с compression pointers (0xC0 cases)
  - Используть: xUnit + FluentAssertions

- [ ] **Integration tests для Exe-scenario**
  - Тест: Full Stage 1 с TestNetworkApp.exe (проверка JSON output)
  - Тест: Stage 2 с mock profile (проверка ProblemClassifier)
  - Тест: Stage 3 с mock DNS fix (проверка netsh calls)

---

## 📚 Документация

### CLAUDE.md Update
- [ ] **Добавить Exe-scenario architecture**
  - Секция: "Exe-scenario Workflow" с диаграммой Stage 1→2→3
  - Секция: "WinDivert Integration" с NETWORK layer объяснением
  - Секция: "DNS/SNI Parsing" с примерами packet структур

### Code Comments
- [ ] **Добавить комментарии к WinDivert P/Invoke**
  - Объяснить: Почему NETWORK layer вместо SOCKET
  - Объяснить: Формат filter string "outbound and (tcp or udp)"
  - Объяснить: OpenFlags.Sniff для passive monitoring

- [ ] **Добавить комментарии к DNS parsing**
  - Объяснить: DNS compression pointer format (0xC0 + offset)
  - Объяснить: Почему max 10 jumps (предотвращение infinite loop)
  - Объяснить: Почему игнорируем не-A records (TYPE != 1)

---

## ⚠️ Известные ограничения

### Не планируется исправлять
- **IPv6 support** - WinDivert фильтр использует только IPv4, IPv6 игнорируется
- **QUIC protocol** - HTTP/3 над UDP не парсится (нет SNI extraction для QUIC)
- **Encrypted DNS (DoH in-app)** - Приложения с встроенным DoH не детектируются (DNS через HTTPS, не port 53)
- **VPN tunnel inspection** - Трафик внутри VPN туннеля не видим WinDivert

### Требует исследования
- **Kernel-mode WinDivert driver signature** - Может требоваться Disable Driver Signature Enforcement на некоторых системах
- **Windows 11 24H2 compatibility** - Не тестировалось на последней версии Windows 11
- **ARM64 support** - WinDivert64.sys только x64, ARM64 не поддерживается

---

## 🎯 Roadmap

### v1.0 (Current - Exe-scenario MVP)
- ✅ Stage 1: Traffic Analyzer с DNS/SNI parsing
- ✅ Stage 2: Problem Classifier + Strategy Planner
- ✅ Stage 3: DNS Fix + WinDivert Bypass
- ⏳ End-to-end testing
- ⏳ Documentation complete

### v1.1 (Post-MVP)
- CLI поддержка для Exe-scenario (`--exe-mode --path "app.exe"`)
- Multi-profile management (история захватов)
- Performance improvements (async packet processing)
- Extended logging (save to file)

### v2.0 (Advanced Features)
- QUIC/HTTP3 support (SNI extraction)
- IPv6 support (WinDivert IPv6 filters)
- Real-time capture visualization (live graph)
- Auto-update mechanism (GitHub Releases)

---

## 📝 Notes

**Последнее обновление:** 20 ноября 2025 г.  
**Автор:** Nafancheg  
**Контекст:** Feature branch feature/wpf-new-migration после коммита a0830a8

**Ключевые решения:**
1. Reverse DNS технические имена ЛУЧШЕ user-friendly доменов для ISP диагностики
2. DNS cache → SNI → Reverse DNS приоритет для максимального покрытия
3. MaterialDesign удалён из CapturedTargetsWindow для избежания StaticResource ошибок
4. Stage 2 использует _capturedProfile напрямую (не через RunAuditAsync)
5. Port caching каждые 2 секунды (не per-packet) для performance

**Следующий шаг:** End-to-end testing с TestNetworkApp.exe для валидации DNS/SNI parsing effectiveness.
