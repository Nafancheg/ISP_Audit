# ISP_Audit Copilot Instructions

## Общие правила работы

**Язык общения**: Только русский язык. Все ответы, объяснения и диалоги вести исключительно на русском языке.

**Комментарии в коде**: Все комментарии в коде должны быть на русском языке. Исключение составляют только общепринятые технические термины (DNS, TCP, HTTP, WPF, GUI, CLI, WinDivert, P/Invoke и т.д.), которые не требуют перевода.

**Документация**: Используй MCP сервер Context7 для получения актуальной документации по библиотекам (.NET, WPF, MaterialDesign и т.д.).

**Workflow**: После завершения итерации редактирования кода делать `git push`.

## Project Context
Windows-native .NET 9 WPF application for diagnosing ISP-level network blocking (DNS filtering, DPI, TCP RST injection). Primary use case: Star Citizen connectivity issues. Ships as single-file executable (~164MB), GUI mode only.

**Tech**: .NET 9, WPF, MaterialDesignInXaml 5.1.0, WinDivert 2.2.0 (bypass module)

## Architecture at a Glance

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

**Entry point**: `Program.Main()` initializes GUI mode, hides console, loads default profile from `Profiles/`.

**Test flow**: `LiveTestingPipeline` (Sniffer → Tester → Classifier) → `DiagnosticOrchestrator` updates GUI via `IProgress`.
- **Sniffer**: `TrafficCollector` (WinDivert) captures new connections.
- **Tester**: `StandardHostTester` checks DNS, TCP, TLS.
- **Classifier**: `StandardBlockageClassifier` determines blockage type (DPI, RST, DNS).

**GUI**: MVVM pattern (`ViewModels/MainViewModelRefactored.cs`), Material Design cards shown ONLY when problems detected.

## Critical Code Patterns

### 1. Async Rules (STRICT)
```csharp
// ✅ ALWAYS use ConfigureAwait(false) in library/test code
var result = await DoWorkAsync().ConfigureAwait(false);

// ❌ NEVER block on async
var result = DoWorkAsync().Result; // NO
DoWorkAsync().Wait(); // NO

// ✅ Pass CancellationToken to long operations
await httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
```

### 2. Progress Reporting (GUI Contract)
```csharp
// Report string messages for UI log
progress?.Report($"[TESTER] Checking {host}...");
```

### 3. Traceroute Encoding (CRITICAL for Russian Windows)
```csharp
// System tracert.exe uses OEM866 (CP866) for Cyrillic output
process.StandardOutput.CurrentEncoding = Encoding.GetEncoding(866);
// Without this: русские хопы → ?????
```

### 4. DNS Logic (Simplified Decision Tree)
```csharp
// StandardHostTester.cs
// 1. Reverse DNS (optional)
// 2. Forward DNS (CRITICAL) - if fails, dnsOk = false
if (completedTask != dnsCheckTask) {
    dnsOk = false;
    dnsStatus = "DNS_TIMEOUT";
}
```

### 5. Critical Targets (Profile-Driven)
```csharp
// Profiles/Default.json
// Targets are loaded from JSON profile.
// Critical targets should be tested even if DNS fails (using FallbackIp if available).
```

### 6. Material Design UI (Cards)
```xaml
<!-- Default: collapsed -->
<materialDesign:Card x:Name="FirewallCard" Visibility="Collapsed">
  <TextBlock Text="• Problem 1&#x0a;• Problem 2&#x0a;&#x0a;Рекомендация: ..." />
</materialDesign:Card>
```
Show cards ONLY when `result.Status != "OK"`.

### 7. VPN Detection (Adaptive Timeouts)
```csharp
if (NetUtils.LikelyVpnActive()) { // checks TAP/TUN adapters
    config.HttpTimeoutSeconds = 12; // normal: 6
    config.TcpTimeoutSeconds = 8;   // normal: 3
    config.UdpTimeoutSeconds = 4;   // normal: 2
}
```

## Key Workflows

### Build & Run
```powershell
# Debug
dotnet build -c Debug

# Single-file release
dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true /p:PublishTrimmed=false -o ./publish

# GUI (hides console)
dotnet run

# CLI
dotnet run -- --targets youtube.com --report result.json --verbose
```

### Add New Test
1. `Tests/MyTest.cs`: async `RunAsync()` → return `MyTestResult`
2. `AuditRunner.RunAsync()`: invoke with progress reports
3. `ReportWriter.BuildSummary()`: aggregate status
4. `MainWindow.UpdateProgress()`: GUI handling for new `TestKind`

### Modify GUI Cards
```csharp
// MainWindow.xaml.cs ShowResults()
if (result.firewall.Status != "OK") {
    FirewallCard.Visibility = Visibility.Visible;
    FirewallText.Text = $"• {string.Join("\n• ", issues)}\n\nРекомендация: {fix}";
}
```

## Agent Workflow (Multi-Context Development)

**IMPORTANT**: Agents run in separate contexts (new chat sessions). See `agents/README.md` for full workflow.

1. **Task Owner** (purple): Interactive → `agents/task_owner/current_task.md`
2. **Research** (red): Deep analysis → `agents/research_agent/findings.md`
3. **Planning** (blue): Subtasks → `agents/planning_agent/plan.md`
4. **Coding** (green): Implement ONE subtask at a time (use Haiku for cost efficiency)
5. **QA** (yellow): Validate → `agents/qa_agent/test_report.md`
6. **Delivery** (cyan): Commit + changelog

**When coding**: Check `agents/task_owner/current_task.md` for context, use `agents/planning_agent/plan.md` as single source of truth, read ONLY files relevant to current subtask.

## Common Mistakes

1. **OEM866 traceroute**: Forget encoding → Cyrillic becomes garbage
2. **DoH in DNS logic**: Use DoH for decisions → false FILTERED warnings
3. **Show all cards**: Show cards by default → cluttered UI
4. **Blocking async**: `.Result`/`.Wait()` → deadlocks in GUI
5. **Skip critical targets**: DNS fails → skip launcher → game unplayable
6. **Hardcode Cloudflare**: Apply DNS fix → test ALL DoH providers first (1.1.1.1, 8.8.8.8, 9.9.9.9)
7. **Registry DNS changes**: Requires reboot → use `netsh` (immediate effect, requires UAC)

## Test Scenarios (Manual Only)

- VPN: Enable VPN → verify adaptive timeouts, no false DNS_FILTERED
- DNS block: Point DNS to 0.0.0.0 → verify FILTERED + Fix button appears
- Firewall: Block ports 8000-8003 → FirewallCard appears with ports listed
- No admin: Verify Firewall/ISP tests return UNKNOWN gracefully

## Key Files

**Entry**: `Program.cs` (mode detect), `AuditRunner.cs` (orchestrator), `Config.cs` (CLI parse)  
**Tests**: `Tests/{DnsTest,TcpTest,HttpTest,TracerouteTest,FirewallTest,IspTest,RouterTest,SoftwareTest}.cs`  
**GUI**: `ViewModels/MainViewModel.cs`, `MainWindow.xaml`, `Wpf/ServiceItemViewModel.cs`  
**Output**: `Output/ReportWriter.cs`, `Output/{Firewall,Isp,Router,Software}TestResult.cs`  
**Bypass**: `Bypass/WinDivertBypassManager.cs` (admin required)  
**Data**: `star_citizen_targets.json`, `Profiles/StarCitizen.json`, `bypass_profile.json`

## Quick Reference

- **Detailed architecture**: `CLAUDE.md` (Russian, 500+ lines)
- **User docs**: `README.md` (Russian, usage examples)
- **Agent methodology**: `agents/README.md` (API cost optimization strategy)
- **CI/CD**: `.github/workflows/build.yml` (single-file artifact)

---

**When in doubt**: Check `CLAUDE.md` → `README.md` → code examples in `Tests/` or `AuditRunner.cs`.
