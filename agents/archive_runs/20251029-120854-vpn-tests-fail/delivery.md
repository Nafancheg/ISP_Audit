# Delivery Notes — guidance for users on VPN

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

## TL;DR
- When a VPN is ON, run in VPN profile to avoid false failures.

## How to run (no code changes)
- Prefer GUI toggles if present; otherwise CLI flags (examples):
  - Disable UDP and traceroute; use 80/443 only; increase timeout.
  - Example CLI (conceptual): `--timeout 8 --ports 80,443 --no-trace` and disable UDP via GUI.

## Interpreting results
- DNS mismatches (system vs DoH) are expected under VPN: treat as INFO/WARN, not ISP block.
- UDP/53 to 1.1.1.1 often fails under VPN: not an ISP issue.

## Next release suggestions (for maintainer)
- Add `--profile vpn` and auto-detection; adjust timeouts and classification as described in implementation.md.
