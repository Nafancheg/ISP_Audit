# Plan — Make results reliable with VPN

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

## Acceptance criteria
- With VPN enabled, diagnostics don’t mislabel expected VPN behaviors as ISP faults.
- Clear labeling: ISP-path issues vs VPN-environment constraints.
- Reproducible steps to validate in three modes: no VPN, split tunnel, full tunnel.

## Work breakdown
1. Detect environment
   - Detect active VPN adapters, DNS servers, split vs full tunnel indicators.
   - Record into report for transparency.
2. Adjust expectations and timeouts
   - Increase timeouts (HTTP/TCP/UDP) when VPN detected.
   - Downgrade UDP/53 (expect-reply) from FAIL→INFO when VPN present.
3. Reclassify DNS under VPN
   - Don’t mark `DNS_FILTERED` when system DNS is empty but DoH works if VPN detected.
   - Treat RFC1918-only answers as INFO under VPN.
4. Gate probes by profile
   - Introduce `--profile` (normal|vpn) or auto-detect and set defaults: disable traceroute; make UDP optional; restrict TCP ports to 80/443.
5. Surface guidance to user
   - Explain in report when VPN mode is on and what is skipped/downgraded.

## Control points / artifacts
- Env snapshot written to report: adapters, DNS servers, default route.
- Classification matrix updated: VPN vs non-VPN.
- Validation across three environments documented in qa_test_plan.md and qa_report.md.

## Risks / mitigations
- False negatives (masking real issues): keep WARNs visible; only downgrade severity where VPN is known to cause false fails.
- Diverse VPN clients: detect generically by adapter/tunnel properties and routing/DNS behavior.
