# QA Report — initial analysis only (no execution)

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

We did not execute the app in this run. Observed repository code indicates likely failures under VPN due to:
- DNS classification expecting ISP path, not VPN DNS override.
- UDP/53 expect-reply to 1.1.1.1 (often blocked by VPN).
- Tight timeouts for tunneled paths.

Next step: run on your machine with VPN on/off using the suggested profile settings and collect outputs for comparison.
