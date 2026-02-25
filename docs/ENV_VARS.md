# ISP_Audit — Переменные окружения (ENV)

Назначение: централизованный реестр переменных окружения, которые читает приложение/тесты.

Принципы:

- `ISP_AUDIT_TEST_*` — **только DEBUG** (в Release игнорируются), чтобы тестовые хуки не могли незаметно менять поведение боевой сборки.
- Path override переменные используются только для диагностики/персиста (куда писать JSON рядом с приложением).
- Gate/тайминги — это runtime-настройки (могут применяться в Release), поэтому их нужно менять осознанно.
- Реализация чтения/парсинга ENV: `Utils/EnvVar.cs`.
- Единый источник строковых ключей ENV: `Utils/EnvKeys.cs`.

---

## 1) TEST hooks (только DEBUG)

- `ISP_AUDIT_TEST_APPLY_DELAY_MS`
  - Назначение: искусственная задержка внутри apply, чтобы детерминированно проверить таймаут/фазовую диагностику (`REG-016`).
  - Поведение: учитывается только в DEBUG.

- `ISP_AUDIT_TEST_SKIP_TLS_APPLY`
  - Назначение: пропустить фазу применения TLS-опций в executor apply для smoke/regression (`REG-022`).
  - Поведение: учитывается только в DEBUG.

---

## 2) Path override (перенаправление персиста/артефактов)

- `ISP_AUDIT_APPLY_TRANSACTIONS_PATH`
  - Перенаправляет файл транзакций apply (по умолчанию `state\\apply_transactions.json`).

- `ISP_AUDIT_OPERATOR_CONSENT_PATH`
  - Перенаправляет файл согласия оператора на DNS/DoH изменения (по умолчанию `state\\operator_consent.json`).

- `ISP_AUDIT_OPERATOR_EVENTS_PATH`
  - Перенаправляет legacy-лог Operator-событий (по умолчанию `state\\operator_events.json`).

- `ISP_AUDIT_OPERATOR_SESSIONS_PATH`
  - Перенаправляет историю Operator-сессий (по умолчанию `state\\operator_sessions.json`).

- `ISP_AUDIT_USER_FLOW_POLICIES_PATH`
  - Перенаправляет файл пользовательских policy-driven политик (по умолчанию `state\\user_flow_policies.json`).

- `ISP_AUDIT_POST_APPLY_CHECKS_PATH`
  - Перенаправляет файл результатов пост‑проверки (по умолчанию `state\\post_apply_checks.json`).

- `ISP_AUDIT_WINS_STORE_PATH`
  - Перенаправляет файл wins-библиотеки (по умолчанию `state\\wins_store.json`).

- `ISP_AUDIT_BLOCKPAGE_HOSTS_PATH`
  - Перенаправляет каталог хостов blockpage (по умолчанию `state\\blockpage_hosts.json`).

- `ISP_AUDIT_BYPASS_SESSION_PATH`
  - Перенаправляет журнал bypass-сессий (используется также в smoke для краш/вотчдог сценариев).

- `ISP_AUDIT_TRAFFICENGINE_CRASH_DIR`
  - Перенаправляет директорию, куда `TrafficEngine` пишет crash-report JSON (по умолчанию под `state\\crash_reports\\traffic_engine\\`).

---

## 3) Feature gates / runtime switches

- `ISP_AUDIT_POLICY_DRIVEN_UDP443`
- `ISP_AUDIT_POLICY_DRIVEN_TTLBLOCK`
- `ISP_AUDIT_POLICY_DRIVEN_TCP80`
- `ISP_AUDIT_POLICY_DRIVEN_TCP443`
  - Назначение: включение policy-driven execution по направлениям.
  - Примечание: при старте приложения `ISP_AUDIT_POLICY_DRIVEN_TCP443` по умолчанию принудительно выставляется в `1`, если переменная не задана.

- `ISP_AUDIT_ENABLE_INTEL_DOH`
  - Назначение: флаг включения рекомендаций DoH в INTEL-контуре (исторический/совместимость). Фактическое применение DNS/DoH дополнительно ограничено consent gate.

- `ISP_AUDIT_ENABLE_V2_DOH`
  - Назначение: legacy алиас для `ISP_AUDIT_ENABLE_INTEL_DOH`.

- `ISP_AUDIT_ENABLE_AUTO_RETEST`
  - Назначение: автоперепроверка при изменении bypass-тумблеров.

- `ISP_AUDIT_CLASSIC_MODE`
  - Назначение: ClassicMode (freeze mutation within-run).
  - Семантика: при `1` реактивные мутации в текущем run переводятся в observe-only (сейчас: `ReactiveTargetSync`, авто-ретест от bypass-тумблеров, auto-adjust `TlsBypassService` — `AutoAdjustAggressive/AutoTTL`, и runtime auto-add targets для селективного QUIC→TCP), но ручные операции `apply/escalate/rollback` остаются разрешены.
  - По умолчанию: `0`.

- `ISP_AUDIT_RETEST_DEBOUNCE_MS`
  - Назначение: минимальный интервал (debounce/throttle) между автоперетестами при изменении bypass.
  - Значение: число миллисекунд.
  - По умолчанию: `5000`.
  - Примечание: `0` отключает debounce, отрицательное значение также отключает debounce (для экспериментов).

- `ISP_AUDIT_AUTO_APPLY_MIN_CONFIDENCE`
  - Назначение: минимальная уверенность (`PlanConfidence`) для auto-apply.
  - Значение: целое число `0..100` (вне диапазона clamp).
  - По умолчанию: `70`.
  - Примечание: используется только для policy-гейта auto-apply; при недостижении порога фиксируется `skip_reason=LOW_CONFIDENCE`.

- `ISP_AUDIT_AUTO_APPLY_SAFE_MIN_CONFIDENCE`
  - Назначение: отдельный порог уверенности для safe-tier auto-apply.
  - Значение: целое число `0..100` (вне диапазона clamp).
  - По умолчанию: `70`.
  - Семантика: применяется только для safe-only плана (`TlsFragment` и/или assist `DropUdp443`); для остальных случаев используется `ISP_AUDIT_AUTO_APPLY_MIN_CONFIDENCE`.

- `ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_WINDOW_MINUTES`
  - Назначение: окно (в минутах) для накопления повторяемых low-confidence срабатываний одного и того же `scope+planSig`.
  - По умолчанию: `10`.
  - Диапазон: `1..120`.

- `ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_REQUIRED_HITS`
  - Назначение: число повторений low-confidence в окне, после которого включается boost confidence.
  - По умолчанию: `3`.
  - Диапазон: `1..20`.

- `ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_PER_HIT`
  - Назначение: шаг повышения confidence за каждое повторение сверх порога.
  - По умолчанию: `5`.
  - Диапазон: `0..50`.

- `ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_MAX`
  - Назначение: верхний предел суммарного boost confidence.
  - По умолчанию: `20`.
  - Диапазон: `0..50`.

---

## 4) Тайминги/пороговые значения (runtime)

- `ISP_AUDIT_WATCHDOG_TICK_MS`
- `ISP_AUDIT_WATCHDOG_STALE_MS`
  - Назначение: параметры watchdog.

- `ISP_AUDIT_ACTIVATION_ENGINE_GRACE_MS`
- `ISP_AUDIT_ACTIVATION_WARMUP_MS`
- `ISP_AUDIT_ACTIVATION_NO_TRAFFIC_MS`
- `ISP_AUDIT_ACTIVATION_STALE_MS`
  - Назначение: параметры activation/staged validation.

- `ISP_AUDIT_OUTCOME_DELAY_MS`
- `ISP_AUDIT_OUTCOME_TIMEOUT_MS`
  - Назначение: задержка/таймаут outcome-probe.

- `ISP_AUDIT_REDIRECT_BURST_N`
  - Назначение: порог `N` для soft-score suspicious redirect (число разных eTLD+1 в окне `T`).
  - По умолчанию: `3`.
  - Диапазон: `1..20` (вне диапазона clamp).

- `ISP_AUDIT_REDIRECT_BURST_WINDOW_MINUTES`
  - Назначение: размер окна `T` (в минутах) для burst-cache redirect.
  - По умолчанию: `10`.
  - Диапазон: `1..1440`.

- `ISP_AUDIT_REDIRECT_WINDOW_RETENTION_MINUTES`
  - Назначение: retention (в минутах) для redirect burst-cache и cleanup устаревших IP-записей.
  - По умолчанию: `30`.
  - Диапазон: `1..1440`.
  - Примечание: если задано меньше `BURST_WINDOW`, автоматически повышается до значения окна.
