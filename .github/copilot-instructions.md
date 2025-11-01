# ISP_Audit — AI Coding Assistant Guide

## Project Overview

**ISP_Audit** — Windows-native .NET 9 WPF application for network diagnostics targeting ISP-level blocking (DNS filtering, TCP/UDP/TLS interference, DPI). Primary use case: diagnosing connectivity issues for **Star Citizen** game infrastructure (launcher, AWS game servers, Vivox voice chat).

**Tech Stack**: .NET 9 (Windows-only), WPF + MaterialDesignInXaml 5.1.0, single-file executable (~164MB), async/await throughout, no external dependencies beyond .NET runtime.

**Dual Mode**: GUI by default (no args), CLI when arguments provided. GUI hides console via Win32 API on startup.

## Architecture

### Entry Point & Mode Detection
- **Program.cs**: Determines mode (GUI/CLI), loads default profile, routes to WPF app or CLI runner
- **Config.cs**: CLI argument parsing, profile management (`GameProfile`), timeout configuration
- **AuditRunner.cs**: Test orchestrator — executes tests sequentially with `IProgress<TestProgress>` for GUI updates

### Test Infrastructure (Tests/)
All tests are **independent, async**, return domain-specific result objects:

- **DnsTest.cs**: System DNS + DoH (Cloudflare 1.1.1.1), detects bogus IPs (0.0.0.0, 127.x, 10.x, 192.168.x)
- **TcpTest.cs**: TCP port probing with 1-2 retries
- **HttpTest.cs**: HTTP(S) requests, SNI support, X.509 CN extraction
- **TracerouteTest.cs**: Wraps system `tracert.exe`, parses stdout with **OEM866 encoding** (Russian Windows)
- **UdpProbeRunner.cs**: UDP probes (DNS 53, game ports 64090-64094)
- **FirewallTest.cs**: Windows Firewall rules, blocked ports, Defender status (requires admin via WMI)
- **IspTest.cs**: ISP detection (ip-api.com), CGNAT (100.64.0.0/10), DPI heuristics
- **RouterTest.cs**: Gateway ping stability, UPnP availability, SIP ALG detection
- **SoftwareTest.cs**: Antivirus/VPN/proxy detection, hosts file analysis
- **RstHeuristic.cs**: RST injection timing heuristic (no pcap)

### Target Catalog & Profiles
- **TargetCatalog.cs**: Loads `star_citizen_targets.json` (or fallback), provides default targets/ports/UDP probes
- **TargetModels.cs**: `TargetDefinition` (Name, Host, Service), `UdpProbeDefinition`, `GameProfile` structure
- **Profiles/**: Game-specific JSON profiles (e.g., `StarCitizen.json`) — defines critical targets, test modes
- **TargetServiceProfiles.cs**: Per-service test customization (which tests to run, which ports)

### GUI (WPF + Material Design)
- **App.xaml**: Material Design theme (Light, Blue primary, Cyan secondary)
- **MainWindow.xaml**: Card-based UI (`materialDesign:Card` for warnings/success), service list with live status, progress bar
- **MainWindow.xaml.cs**: MVVM pattern, async test execution with `CancellationToken`, result interpretation, card visibility logic
- **ServiceItemViewModel.cs**: Observable model for service list items (`INotifyPropertyChanged`)

**GUI shows diagnostic cards ONLY when problems detected**:
- `FirewallCard`: Blocked ports, Defender interference → fix instructions
- `IspCard`: CGNAT, DPI, DNS filtering → VPN/DNS change recommendations
- `RouterCard`: UPnP, SIP ALG, high ping → router config instructions
- `SoftwareCard`: Antivirus/VPN conflicts → exclusion instructions
- `WarningCard`: Legacy DNS/TCP/TLS issues

### Bypass Module (Bypass/)
**WinDivert-based packet filtering** (admin required, Windows-only):
- **WinDivertBypassManager.cs**: Drop TCP RST, fragment TLS ClientHello, optional redirect rules
- **BypassProfile.cs**: JSON config (`bypass_profile.json`) for rule definitions
- **WinDivertNative.cs**: P/Invoke for WinDivert.dll

Activated **manually via GUI** only after problems detected (not by default).

### Output & Reporting (Output/)
- **ReportWriter.cs**: JSON report generation, human-readable console output, HTML/PDF export for support tickets
- **Result Models**: `IspTestResult`, `FirewallTestResult`, `RouterTestResult`, `SoftwareTestResult`, `UdpProbeResult`
- **Summary**: Aggregates test statuses into `playable` verdict (YES/NO/MAYBE) for Star Citizen

## Critical Conventions

### 1. Async Patterns
- **Always** use `ConfigureAwait(false)` for library/test code
- **Never** use `.Result` or `.Wait()` — use `await` exclusively
- Pass `CancellationToken` to all long-running operations (HTTP, traceroute)

### 2. Progress Reporting
GUI relies on `IProgress<TestProgress>` for live updates:
```csharp
progress?.Report(new TestProgress(TestKind.DNS, $"{targetName}: старт"));
// ... execute test ...
progress?.Report(new TestProgress(TestKind.DNS, $"{targetName}: завершено", success, status));
```
**Always** report: start → completion (with status). Summary reports after all targets.

### 3. Traceroute Encoding
**OEM866 (CP866)** for Russian Windows `tracert.exe` output:
```csharp
process.StandardOutput.CurrentEncoding = Encoding.GetEncoding(866);
```
Without this: Cyrillic characters become garbled.

### 4. DNS Status Logic
**Simplified** (System DNS only, DoH for info):
- `DNS_FILTERED`: System DNS empty, DoH returns addresses
- `DNS_BOGUS`: System DNS returns 0.0.0.0, 127.x, 10.x, 192.168.x
- `WARN`: System/DoH address sets don't overlap (CDN geo-balancing)
- `OK`: Otherwise

Do NOT use DoH results for decision logic — only for user information.

### 5. Critical Targets
**Profile-driven** (`Profiles/StarCitizen.json`):
- Targets have `critical: true/false` flag
- **Critical targets** (launcher, game servers, Vivox) → if DNS fails, use fallback IPs, never skip
- **Non-critical** (portals, CDN mirrors) → can skip on DNS failure
- AuditRunner **must not** early-exit for critical targets

### 6. Material Design UI
- Use `materialDesign:Card` for warnings/success messages
- Buttons: `Style="{StaticResource MaterialDesignRaisedButton}"`
- Colors: Blue primary (#2196F3), Red accent (#F44336)
- **Cards visibility**: `Visibility.Collapsed` by default, show only when problems detected

### 7. VPN Detection & Adaptive Timeouts
```csharp
bool vpnActive = NetUtils.LikelyVpnActive(); // checks for TAP/TUN adapters
if (vpnActive) {
    config.HttpTimeoutSeconds = 12; // vs 6 for normal
    config.TcpTimeoutSeconds = 8;   // vs 5
    config.UdpTimeoutSeconds = 4;   // vs 2
}
```
Reduces false positives on VPN connections.

## Key Workflows

### Build & Run
```powershell
# Debug build
dotnet build -c Debug

# Single-file Release
dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true /p:PublishTrimmed=false -o ./publish

# Run GUI
dotnet run

# Run CLI
dotnet run -- --targets youtube.com,discord.com --report result.json --verbose
```

### Adding a New Test
1. Create `Tests/MyTest.cs` with async `RunAsync()` method
2. Return domain-specific result object (`Output/MyTestResult.cs`)
3. Add test invocation in `AuditRunner.RunAsync()` with progress reports
4. Update `ReportWriter.BuildSummary()` to include new test status
5. Add GUI handling in `MainWindow.UpdateProgress()` for new `TestKind`

### Adding a New Target Profile
1. Create `Profiles/MyGame.json` with structure:
   ```json
   {
     "name": "MyGame",
     "testMode": "host",
     "exePath": "",
     "targets": [
       {"name": "Launcher", "host": "launcher.example.com", "critical": true, "ports": [80, 443]}
     ]
   }
   ```
2. Update `TargetCatalog.cs` or `Config.cs` to load new profile
3. Test with `--profile MyGame` CLI flag (if implemented)

### Modifying GUI Cards
When adding/modifying diagnostic cards in `MainWindow.xaml.cs`:
- **Only show cards when problems exist** (check result object properties)
- Format text as bulleted list: `"• Problem description\n• Next item"`
- Add `\n\nРекомендация: ...` section with actionable steps
- Update `ShowResults()` method to set `Card.Visibility`

## Agent-Based Development Workflow

**Project uses multi-agent methodology** (see `agents/README.md`):
- **Task Owner** (purple): Defines tasks interactively → `current_task.md`
- **Research Agent** (red): Deep code analysis → `findings.md`
- **Planning Agent** (blue): Breaks into subtasks → `plan.md`
- **Coding Agent** (green): Implements 1 subtask at a time (use lightweight models like Haiku)
- **QA Agent** (yellow): Validates against acceptance criteria → `test_report.md`
- **Delivery Agent** (cyan): Changelog + git commit

**Each agent runs in separate context** (new chat session). Agents communicate via files only.

When working on tasks:
1. Check `agents/task_owner/current_task.md` for active task
2. If multiple subtasks exist, work on ONE at a time
3. Keep context minimal — read only files relevant to current subtask
4. Use `agents/planning_agent/plan.md` as single source of truth for subtask scope

## Common Pitfalls

1. **Forgetting OEM866 for traceroute** → Cyrillic becomes `?????`
2. **Using DoH in DNS status logic** → False FILTERED warnings (DoH itself may be blocked)
3. **Showing all GUI cards by default** → Cluttered UI, users confused
4. **Blocking calls in async code** → Use `await`, never `.Result`/`.Wait()`
5. **Skipping critical targets on DNS fail** → Game unplayable even if servers reachable by IP
6. **Hardcoding Cloudflare as only DNS option** → Check availability of multiple DoH providers (Cloudflare, Google, Quad9) before applying
7. **Applying DNS changes without UAC** → Requires admin via `netsh`
8. **Using Registry for DNS changes** → Requires reboot; prefer `netsh` for immediate effect

## Testing Notes

- **No unit tests** — manual GUI/CLI testing workflow
- Test VPN scenarios: enable VPN → verify adaptive timeouts, no false DNS_FILTERED
- Test DNS blocking: point DNS to unresponsive server → verify FILTERED detection + Fix button appears
- Test firewall: block ports 8000-8003 → verify FirewallCard appears with correct ports listed
- Test without admin: verify graceful degradation (Firewall/ISP tests return UNKNOWN)

## Files to Know

**Core Logic**:
- `Program.cs` — entry point
- `AuditRunner.cs` — test orchestrator
- `Config.cs` — configuration + CLI parsing
- `TargetCatalog.cs` — target loading

**Tests** (Tests/): `DnsTest`, `TcpTest`, `HttpTest`, `TracerouteTest`, `UdpProbeRunner`, `FirewallTest`, `IspTest`, `RouterTest`, `SoftwareTest`

**GUI** (Wpf/): `MainWindow.xaml`, `MainWindow.xaml.cs`, `ServiceItemViewModel.cs`

**Output**: `ReportWriter.cs` (JSON, human-readable, HTML/PDF)

**Bypass**: `WinDivertBypassManager.cs`, `BypassProfile.cs`

**Data**: `star_citizen_targets.json`, `bypass_profile.json`, `Profiles/StarCitizen.json`

## References

- **README.md**: User-facing documentation (Russian)
- **CLAUDE.md**: Architecture deep-dive for Claude Code
- **agents/README.md**: Agent workflow methodology
- **.github/workflows/build.yml**: CI/CD (builds single-file exe artifact)

---

**When uncertain about project conventions**: Check `CLAUDE.md` first (detailed architecture), then `README.md` (user perspective), then code in `Tests/` or `Program.cs` for patterns.