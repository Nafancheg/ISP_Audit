# ADR — VPN-aware vs ISP-only diagnostics

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

## Decision
Adopt a VPN-aware profile to prevent false failures while keeping WARN signals visible.

## Context
Diagnostics were designed for direct ISP path; VPN alters DNS/routing/ICMP/UDP semantics.

## Options
- A) Keep ISP-only logic, document caveats (low UX, many false fails under VPN).
- B) Auto-detect VPN and adjust behavior (best UX, low risk).
- C) Force users to turn off VPN (impractical for many environments).

## Outcome
Choose B. Add profile switch and environment detection; downgrade certain checks under VPN.
