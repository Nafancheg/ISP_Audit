# Review — VPN-aware approach

Date: 2025-10-29 | ID: 20251029-120854-vpn-tests-fail

## Checklist
- Correctness: Reasoning matches network behavior under VPN.
- Simplicity: Profile switch avoids invasive code changes initially.
- Errors: Risk of masking real ISP issues mitigated by WARN instead of pass.
- Security: No sensitive data; guidance only.
- Testability: QA plan includes three environments.

## Notes
- Current code treats environment as ISP path; add environment-aware layer to avoid misclassification.
- UDP/53 and DNS comparison are the main false-fail sources under VPN.
