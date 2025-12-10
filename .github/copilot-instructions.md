# ISP_Audit Copilot Instructions

## Общие правила работы

**Язык общения**: Только русский язык. Все ответы, объяснения и диалоги вести исключительно на русском языке.

**Комментарии в коде**: Все комментарии в коде должны быть на русском языке. Исключение составляют только общепринятые технические термины (DNS, TCP, HTTP, WPF, GUI, CLI, WinDivert, P/Invoke и т.д.), которые не требуют перевода.

**Документация**: Используй MCP сервер Context7 для получения актуальной документации по библиотекам (.NET, WPF, MaterialDesign и т.д.).

**Workflow**: После завершения итерации редактирования кода делать `git push`.

**Актуализация документации**: При изменении архитектуры, создании новых файлов, классов или процедур, ОБЯЗАТЕЛЬНО обновлять `ARCHITECTURE_CURRENT.md` и `docs\full_repo_audit_v2.md`, чтобы отразить текущее состояние проекта.

## Контекст проекта
Windows-native .NET 9 WPF приложение для диагностики блокировок сети на уровне провайдера (DNS фильтрация, DPI, инъекция TCP RST). Основной сценарий использования: проблемы с подключением к игровым и прочим сетевым сервисам. Поставляется как single-file executable (~164MB), только GUI режим.

**Технологии**: .NET 9, WPF, MaterialDesignInXaml 5.1.0, WinDivert 2.2.0 (модуль обхода блокировок)

## Архитектура (Кратко)

```
Program.cs → [GUI: App.xaml + MainWindow]
                           ↓
              MainViewModelRefactored ──┬──→ BypassController (TrafficEngine)
                                        ↓
                           DiagnosticOrchestrator
                                        ↓
                           LiveTestingPipeline (Sniffer → Tester → Classifier)
                                        ↓
                           Results → UI Updates (Live)
```

**Точка входа**: `Program.Main()` инициализирует GUI режим, скрывает консоль, загружает профиль по умолчанию из `Profiles/`.

**Компоненты**:
- **MainViewModel**: Связывает UI, оркестратор и контроллер обхода.
- **BypassController**: Управляет стратегиями обхода (DPI/RST) через `TrafficEngine`.
- **DiagnosticOrchestrator**: Управляет жизненным циклом диагностики.

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

### 4. Material Design UI (Карточки)
```xaml
<!-- По умолчанию: скрыто -->
<materialDesign:Card x:Name="FirewallCard" Visibility="Collapsed">
  <TextBlock Text="• Problem 1&#x0a;• Problem 2&#x0a;&#x0a;Рекомендация: ..." />
</materialDesign:Card>
```
Показывать карточки ТОЛЬКО когда `result.Status != "OK"`.

### 5. Обнаружение VPN (Адаптивные таймауты)
```csharp
if (NetUtils.LikelyVpnActive()) { // проверяет TAP/TUN адаптеры
    config.HttpTimeoutSeconds = 12; // норма: 6
    config.TcpTimeoutSeconds = 8;   // норма: 3
    config.UdpTimeoutSeconds = 4;   // норма: 2
}
```
