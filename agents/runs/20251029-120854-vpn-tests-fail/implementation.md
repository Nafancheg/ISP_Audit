# Implementation approach — VPN-aware diagnostics (no code changes applied in this run)

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

## Changes recommended (future PR)
- Profile detection
  - Add `NetworkProfileDetector` (WMI/Netsh/PowerShell) to detect VPN adapters (e.g., `TunnelType`, TAP/TUN/Wintun descriptions) and DNS override.
  - Record: adapter list, DNS servers, default route, split/full hints.
- Config/profile
  - New `--profile` flag: `normal` (default), `vpn`. Auto-detect sets default to `vpn` when applicable.
  - In `vpn` profile: `EnableUdp=false`, `EnableTrace=false`, `Ports=[80,443]`, `HttpTimeout=10`, `TcpTimeout=5`, `UdpTimeout=4`.
- DNS classification tweaks (Tests/DnsTest.cs:1)
  - When VPN detected:
    - If system DNS empty and DoH returns → downgrade `DNS_FILTERED` → `INFO_VPN_DNS`.
    - If system DNS returns only RFC1918 and DoH returns public → downgrade `WARN` → `INFO_VPN_SPLIT_DNS`.
  - Increase DoH retry attempts (e.g., 3 tries with exponential backoff up to ~1.5–2s).
- UDP handling (AuditRunner.cs:200+)
  - In VPN profile, treat `expect_reply` UDP failures as INFO, not FAIL; still display note.
- HTTP
  - Keep permissive TLS; optionally surface CN mismatch more prominently as INFO under VPN (MITM/proxy common).

## Touch points (for later PR)
- DnsTest.ResolveAsync and ResolveDohAAsync — add VPN-aware classification and retry/backoff.
- Config defaults per profile; pass profile into `AuditRunner`.
- ReportWriter.BuildSummary — add environment header and VPN notes.

## Non-invasive interim workaround (no code changes)
- Run with adjusted config:
  - Disable UDP and traceroute when on VPN.
  - Limit TCP ports to [80,443].
  - Use longer `--timeout`.
- Document guidance in delivery.md for current users.
