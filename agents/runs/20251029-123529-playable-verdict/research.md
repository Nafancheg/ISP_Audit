# Research — критерии «Играбельно»

Дата: 2025-10-29 | ID: 20251029-123529-playable-verdict

## Ключевые сигналы
- TLS (HTTPS к целям RSI): BLOCK_PAGE/MITM_SUSPECT → красный флаг; OK → зелёный.
- TCP Portal (80/443): FAIL → нельзя войти/авторизоваться; WARN → погранично.
- DNS: DNS_BOGUS/DNS_FILTERED → красный флаг; WARN → погранично.
- TCP Launcher/UDP: не блокирующие для «зайти и играть» прямо сейчас.

## Вердикт
- NO: tls ∈ {FAIL, BLOCK_PAGE, MITM_SUSPECT} ∨ dns ∈ {DNS_BOGUS, DNS_FILTERED} ∨ tcp_portal = FAIL.
- MAYBE: tls = SUSPECT ∨ dns = WARN ∨ tcp_portal = WARN.
- YES: tls = OK ∧ tcp_portal ≠ FAIL ∧ dns ≠ UNKNOWN.

## UI-рекомендации
- DNS-проблемы: DoH/DoT или смена резолвера (Cloudflare/Google/Quad9). VPN — только как обход.
- TLS BLOCK_PAGE: подозрение на блок‑страницу/DPI → альтернативный канал.
- TLS MITM: отключить HTTPS‑сканирование (антивирус/прокси).
- TCP 80/443 FAIL: роутер/фаервол/провайдер.
