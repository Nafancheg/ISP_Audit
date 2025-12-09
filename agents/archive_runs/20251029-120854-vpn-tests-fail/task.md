# Diagnostics: tests fail under VPN

Date: 2025-10-29
ID: 20251029-120854-vpn-tests-fail

## Context
- In this project, “Tests” are network diagnostics (DNS/TCP/HTTP/UDP/Traceroute) executed by the app, not unit tests.
- With an active VPN, almost all checks report failures/timeouts or warnings.

## Goal and outcome
- Identify why results degrade under VPN and what is actually wrong.
- Provide an actionable plan to get reliable diagnostics with or without VPN.

## Scope and constraints
- In scope: analysis, recommendations, config/profile changes, classification logic, validation steps.
- Out of scope: altering user’s VPN configuration; non-essential refactors.
- Constraints: don’t modify app code in this run; produce guidance and artifacts only.

## Artifacts
- Research: research.md
- Plan: plan.md
- Implementation approach: implementation.md
- Review notes: review.md
- QA plan/report: qa_*.md
- Delivery notes: delivery.md; Changelog: changelog.md
- Decisions: decisions.md
- Checklist: checklist.md
