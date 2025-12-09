# QA Test Plan — VPN and non-VPN modes

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

## Scope
- Validate diagnostics quality with: no VPN, split tunnel VPN, full tunnel VPN.

## Environments and data
- Windows host (same machine), VPN client in use.
- Targets: defaults (Star Citizen hosts + 1.1.1.1); optional extra: `example.com` for baseline.

## Scenarios / steps
- [ ] Baseline (no VPN): run app with defaults; expect mostly OK/WARN depending on ISP.
- [ ] Full-tunnel VPN: run with UDP disabled and traceroute disabled, ports [80,443], timeout ≥ 8s; expect INFO for UDP/DNS VPN effects, OK for HTTP to public hosts.
- [ ] Split-tunnel VPN: same as above; expect mixed DNS behavior; still INFO/WARN rather than FAIL.

## Observations to record
- DNS servers in use; default route; presence of TAP/TUN adapter.
- Which probes were downgraded/skipped under VPN profile.
