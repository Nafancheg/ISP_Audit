# ISP_Audit Copilot Instructions

## Общие правила работы

**Язык общения**: Только русский язык. Все ответы, объяснения и диалоги вести исключительно на русском языке.

**Комментарии в коде**: Все комментарии в коде должны быть на русском языке. Исключение составляют только общепринятые технические термины (DNS, TCP, HTTP, WPF, GUI, CLI, WinDivert, P/Invoke и т.д.), которые не требуют перевода.

**Документация**: Используй MCP сервер Context7 для получения актуальной документации по библиотекам (.NET, WPF, MaterialDesign и т.д.).

**Workflow**: После завершения итерации редактирования кода делать `git push`.

**Актуализация документации**: При изменении архитектуры, создании новых файлов, классов или процедур, ОБЯЗАТЕЛЬНО обновлять `ARCHITECTURE_CURRENT.md` и `docs\full_repo_audit_v2.md`, чтобы отразить текущее состояние проекта.

## Контекст проекта
Windows-native .NET 9 WPF приложение для диагностики блокировок сети на уровне провайдера (DNS фильтрация, DPI, инъекция TCP RST). Основной сценарий использования: проблемы с подключением к Star Citizen. Поставляется как single-file executable (~164MB), только GUI режим.

**Технологии**: .NET 9, WPF, MaterialDesignInXaml 5.1.0, WinDivert 2.2.0 (модуль обхода блокировок)

## Архитектура (Кратко)

```
Program.cs → [GUI: App.xaml + MainWindow]
                           ↓
              MainViewModelRefactored
                           ↓
              DiagnosticOrchestrator
                           ↓
              LiveTestingPipeline (Sniffer → Tester → Classifier)
                           ↓
              Results → UI Updates (Live)
```

**Точка входа**: `Program.Main()` инициализирует GUI режим, скрывает консоль, загружает профиль по умолчанию из `Profiles/`.

**Поток тестирования**: `LiveTestingPipeline` (Sniffer → Tester → Classifier) → `DiagnosticOrchestrator` обновляет GUI через `IProgress`.
- **Sniffer**: `TrafficCollector` (WinDivert) захватывает новые соединения.
- **Tester**: `StandardHostTester` проверяет DNS, TCP, TLS.
- **Classifier**: `StandardBlockageClassifier` определяет тип блокировки (DPI, RST, DNS).

**GUI**: Паттерн MVVM (`ViewModels/MainViewModelRefactored.cs`), карточки Material Design показываются ТОЛЬКО при обнаружении проблем.

## Критические паттерны кода

### 1. Правила Async (СТРОГО)
```csharp
// ✅ ВСЕГДА используй ConfigureAwait(false) в коде библиотек/тестов
var result = await DoWorkAsync().ConfigureAwait(false);

// ❌ НИКОГДА не блокируй async
var result = DoWorkAsync().Result; // НЕТ
DoWorkAsync().Wait(); // НЕТ

// ✅ Передавай CancellationToken в длительные операции
await httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
```

### 2. Отчет о прогрессе (Контракт GUI)
```csharp
// Сообщай строковые сообщения для лога UI
progress?.Report($"[TESTER] Checking {host}...");
```

### 3. Кодировка Traceroute (КРИТИЧНО для русской Windows)
```csharp
// System tracert.exe использует OEM866 (CP866) для кириллицы
process.StandardOutput.CurrentEncoding = Encoding.GetEncoding(866);
// Без этого: русские хопы → ?????
```

### 4. Логика DNS (Упрощенное дерево решений)
```csharp
// StandardHostTester.cs
// 1. Reverse DNS (опционально)
// 2. Forward DNS (КРИТИЧНО) - если не удалось, dnsOk = false
if (completedTask != dnsCheckTask) {
    dnsOk = false;
    dnsStatus = "DNS_TIMEOUT";
}
```

### 5. Критические цели (На основе профиля)
```csharp
// Profiles/Default.json
// Цели загружаются из JSON профиля.
// Критические цели должны тестироваться даже если DNS не работает (используя FallbackIp если доступен).
```

### 6. Material Design UI (Карточки)
```xaml
<!-- По умолчанию: скрыто -->
<materialDesign:Card x:Name="FirewallCard" Visibility="Collapsed">
  <TextBlock Text="• Problem 1&#x0a;• Problem 2&#x0a;&#x0a;Рекомендация: ..." />
</materialDesign:Card>
```
Показывать карточки ТОЛЬКО когда `result.Status != "OK"`.

### 7. Обнаружение VPN (Адаптивные таймауты)
```csharp
if (NetUtils.LikelyVpnActive()) { // проверяет TAP/TUN адаптеры
    config.HttpTimeoutSeconds = 12; // норма: 6
    config.TcpTimeoutSeconds = 8;   // норма: 3
    config.UdpTimeoutSeconds = 4;   // норма: 2
}
```

## Ключевые рабочие процессы

### Сборка и запуск
```powershell
# Debug
dotnet build -c Debug

# Single-file release
dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true /p:PublishTrimmed=false -o ./publish

# GUI (скрывает консоль)
dotnet run

# CLI
dotnet run -- --targets youtube.com --report result.json --verbose
```

### Добавление нового теста
1. `Tests/MyTest.cs`: async `RunAsync()` → возвращает `MyTestResult`
2. `AuditRunner.RunAsync()`: вызов с отчетами о прогрессе
3. `ReportWriter.BuildSummary()`: агрегация статуса
4. `MainWindow.UpdateProgress()`: обработка GUI для нового `TestKind`

### Изменение карточек GUI
```csharp
// MainWindow.xaml.cs ShowResults()
if (result.firewall.Status != "OK") {
    FirewallCard.Visibility = Visibility.Visible;
    FirewallText.Text = $"• {string.Join("\n• ", issues)}\n\nРекомендация: {fix}";
}
```

## Рабочий процесс агентов (Multi-Context Development)

**ВАЖНО**: Агенты работают в отдельных контекстах (новые сессии чата). См. `agents/README.md` для полного описания процесса.

1. **Task Owner** (фиолетовый): Интерактив → `agents/task_owner/current_task.md`
2. **Research** (красный): Глубокий анализ → `agents/research_agent/findings.md`
3. **Planning** (синий): Подзадачи → `agents/planning_agent/plan.md`
4. **Coding** (зеленый): Реализация ОДНОЙ подзадачи за раз (используй Haiku для экономии)
5. **QA** (желтый): Валидация → `agents/qa_agent/test_report.md`
6. **Delivery** (циан): Коммит + changelog

**При кодировании**: Проверяй `agents/task_owner/current_task.md` для контекста, используй `agents/planning_agent/plan.md` как единственный источник истины, читай ТОЛЬКО файлы, относящиеся к текущей подзадаче.

## Частые ошибки

1. **OEM866 traceroute**: Забытая кодировка → Кириллица превращается в мусор
2. **DoH в логике DNS**: Использование DoH для принятия решений → ложные предупреждения FILTERED
3. **Показ всех карточек**: Показ карточек по умолчанию → перегруженный UI
4. **Блокировка async**: `.Result`/`.Wait()` → дедлоки в GUI
5. **Пропуск критических целей**: DNS не работает → пропуск лаунчера → игра не запускается
6. **Хардкод Cloudflare**: Применение фикса DNS → сначала протестируй ВСЕХ провайдеров DoH (1.1.1.1, 8.8.8.8, 9.9.9.9)
7. **Изменения DNS в реестре**: Требует перезагрузки → используй `netsh` (мгновенный эффект, требует UAC)

## Сценарии тестирования (Только ручные)

- VPN: Включи VPN → проверь адаптивные таймауты, отсутствие ложных DNS_FILTERED
- Блокировка DNS: Направь DNS на 0.0.0.0 → проверь FILTERED + появление кнопки исправления
- Firewall: Заблокируй порты 8000-8003 → появление FirewallCard со списком портов
- Нет прав админа: Проверь, что тесты Firewall/ISP возвращают UNKNOWN корректно

## Ключевые файлы

**Вход**: `Program.cs` (определение режима), `AuditRunner.cs` (оркестратор), `Config.cs` (парсинг CLI)  
**Тесты**: `Tests/{DnsTest,TcpTest,HttpTest,TracerouteTest,FirewallTest,IspTest,RouterTest,SoftwareTest}.cs`  
**GUI**: `ViewModels/MainViewModel.cs`, `MainWindow.xaml`, `Wpf/ServiceItemViewModel.cs`  
**Вывод**: `Output/ReportWriter.cs`, `Output/{Firewall,Isp,Router,Software}TestResult.cs`  
**Bypass**: `Bypass/WinDivertBypassManager.cs` (требует админа)  
**Данные**: `star_citizen_targets.json`, `Profiles/StarCitizen.json`, `bypass_profile.json`

## Быстрые ссылки

- **Детальная архитектура**: `CLAUDE.md` (Русский, 500+ строк)
- **Документация пользователя**: `README.md` (Русский, примеры использования)
- **Методология агентов**: `agents/README.md` (Стратегия оптимизации затрат API)
- **CI/CD**: `.github/workflows/build.yml` (single-file артефакт)

---

**При сомнениях**: Проверь `CLAUDE.md` → `README.md` → примеры кода в `Tests/` или `AuditRunner.cs`.
