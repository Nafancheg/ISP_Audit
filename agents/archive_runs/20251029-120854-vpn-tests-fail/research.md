# Research — Diagnostics under VPN

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

## What the “tests” actually are
- The app orchestrates live network probes via `AuditRunner` (AuditRunner.cs:1). These are not unit tests; they depend on external network behavior.
- Components:
  - DNS: system DNS vs DoH at Cloudflare JSON API (Tests/DnsTest.cs:1). Up to 1 retry + 250ms backoff for timeouts (conservative).
  - HTTP: GET multiple URLs for a host, permissive TLS validation but collects CN; success = any 2xx/3xx (Tests/HttpTest.cs:1).
  - TCP: active connect to known ports, with single retry (Tests/TcpTest.cs:1).
  - UDP: one “expect reply” (Cloudflare UDP 53) + several raw probes with no reply expected (Tests/UdpProbeRunner.cs:1).
  - Traceroute: shell out to `tracert` (Tests/TracerouteTest.cs:1).

## Why VPN breaks results
1) Path and DNS are routed through VPN
- System DNS is typically overridden by the VPN adapter (split/full tunnel). DoH uses Cloudflare over HTTPS directly.
- Mismatch between system DNS and DoH triggers WARN/FILTERED in `DnsTest`:
  - If system DNS returns nothing and DoH returns A-records → classified as `DNS_FILTERED` (Tests/DnsTest.cs:1).
  - If system DNS returns only private RFC1918 addresses while DoH returns public → classified as `WARN`.
- Under corporate VPN, both are expected behaviors (not ISP filtering), so classification is misleading without VPN-awareness.

2) UDP and ICMP restrictions
- Many VPN profiles block/shape UDP or require it to traverse only inside the tunnel; direct UDP/53 to 1.1.1.1 often blocked → UDP test fails hard (AuditRunner marks UDP summary fail when `expect_reply` and `!success`).
- Traceroute (`tracert`) relies on ICMP behavior that can be filtered; results degrade or time out.

3) Tight timeouts for tunneled paths
- Default timeouts: HTTP 6s, TCP 3s, UDP 2s (Config.cs:1). Over VPN (especially full-tunnel + DPI), handshake and round-trips are slower, leading to timeouts inflating failure rate.

4) Targets selection
- Default targets focus on Star Citizen hosts and Cloudflare (TargetCatalog.cs:1). Some may require auth or be geo/DDoS protected; via VPN egress location the behavior changes (CDN edges differ), increasing WARN/timeout rate.

## Observed risk points in code
- DNS DoH retry is limited to 1 additional attempt with 250 ms backoff (Tests/DnsTest.cs:1) — too conservative when tunneled.
- UDP summary treats failure of UDP/53 as overall UDP FAIL (AuditRunner.cs:200+) — correct in ISP context, but not under VPN.
- No explicit VPN detection/profile to adjust expectations/timeouts.

## Hypotheses
- H1: With full-tunnel VPN, system DNS responses and UDP/53 to public resolvers are suppressed → DNS/UDP tests report FAIL/WARN en masse.
- H2: TCP to higher ports (8000–8020) is rate-limited or blocked by VPN policy → more TCP timeouts.
- H3: Traceroute is unreliable through VPN due to ICMP shaping → missing hops flagged as failure.

## Evidence from repository
- Enums/flags imply WARN/FAIL are derived from mismatches, not hard ISP proof. Without VPN-awareness, benign corporate/VPN patterns appear as “issues”.
- Config defaults enable UDP by default and disable traceroute by default. So bulk failures are likely from DNS/WARNs and UDP/53.

## Interim conclusion
- The app’s diagnostics are designed for direct ISP path. Under VPN, interpretations must change. Add a “VPN-aware profile” that:
  - Detects VPN presence and tunnel type.
  - Adjusts classification logic and timeouts.
  - Disables or downgrades certain probes (e.g., UDP/53 expect-reply) or marks them as INFO.
