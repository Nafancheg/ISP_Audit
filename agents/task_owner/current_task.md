# [PURPLE] Task Owner: DPI Intelligence (INTEL, Phase 2) — MVP Signals → Diagnosis → Strategy (без авто-применения)

## Проблема
Сейчас обход работает нестабильно и рекомендует нерелевантные действия; пользователю непонятно, что делать. Если бы текущая схема работала — мы бы не обсуждали внедрение INTEL-слоя.

Причина: диагностика и обход живут в разных «мирах». Нужен слой intelligence между сигналами и выбором стратегий.

Критичность: CRITICAL (в текущем виде продукт воспринимается как бесполезный).

## Цель (MVP)
Внедрить объяснимый слой DPI Intelligence (INTEL):
- собирать факты как временные события (последовательность),
- агрегировать в `BlockageSignalsV2`,
- получать `DiagnosisResult` (диагноз + confidence + объяснение),
- формировать `BypassPlan` (рекомендации стратегий) детерминированно,
- в MVP не применять обход автоматически (только рекомендации; ручное применение возможно только по явному действию пользователя).

Основной фокус успешности: сценарии YouTube / ChatGPT / MSFS 2024 (MSFS — только сценарий тестирования, не список доменов).

## Ограничения (жёстко)
- Diagnosis Engine не знает про параметры стратегий/фрагментацию/TTL и не зависит от bypass.
- Strategy Selector не читает сенсоры напрямую и работает только по `DiagnosisResult`.
- В MVP запрещено auto-apply обхода.

Технические правила проекта:
- .NET 9, WPF + MaterialDesign.
- Async: `ConfigureAwait(false)` в библиотечном коде/тестах, не блокировать async, поддерживать `CancellationToken`.

## Definition of Done
- В коде существует слой INTEL с границами: SignalsAdapterV2 → DiagnosisEngineV2 → StrategySelectorV2 → ExecutorMvp (логирование).
- В UI/логах видны: `DiagnosisId`, `Confidence`, краткое объяснение и рекомендации (если confidence достаточно).
- Рекомендации детерминированы; при слабом диагнозе (низкая уверенность/Unknown) рекомендации не показываются.
- Legacy не удаляется первым шагом, но используется только справочно и не управляет рекомендациями INTEL.
- Auto-apply не происходит ни при каких условиях.

## Валидация (гейты)
Гейты и критерии проверки фиксируются в [agents/planning_agent/plan.md](agents/planning_agent/plan.md).

## Схема работы агентов
- [1] [RED] Research Agent: исследует код/логи/UI; создаёт agents/research_agent/findings.md.
- [2] [BLUE] Planning Agent: по findings формирует план в agents/planning_agent/plan.md (минимум подзадач, группировать по файлам).
- [3] [GREEN] Coding Agent: выполняет подзадачи из плана, не создаёт лишних файлов.
- [4] [YELLOW] QA Agent: проверяет критерии, dotnet build/run при необходимости; пишет agents/qa_agent/test_report.md.
- [5] [CYAN] Delivery Agent: changelog + git commit.

## [1] [RED] Research Agent
**Статус**: TODO

**Вход**: agents/task_owner/current_task.md

**Выход**: agents/research_agent/findings.md со структурой:
- Точки интеграции v2 в пайплайн: где брать `HostTested`, где удобнее всего наблюдать сигналы, где формировать UI-вывод.
- Доступность данных для MVP-диагнозов (DnsHijack/SilentDrop) и риски “Unknown”.
- Риски производительности/шума UI и рекомендации по компактному логированию.
- Что оставить от legacy (только справочно) и как не дать ему «перебивать» v2.

## [2] [BLUE] Planning Agent
**Статус**: TODO

**Вход**: current_task.md, findings.md

**Выход**: agents/planning_agent/plan.md — детальные подзадачи Step 0–5 DPI Intelligence v2, включая gates и обязательное обновление ARCHITECTURE_CURRENT.md и docs/full_repo_audit_v2.md при добавлении новых слоёв.

## [3] [GREEN] Coding Agent
**Статус**: TODO

**Задача**: выполнить подзадачу N из plan.md, править только указанные файлы, соблюдать async/await/ConfigureAwait(false), не ломать существующие сценарии обхода.

## [4] [YELLOW] QA Agent
**Статус**: TODO

**Задача**: проверить критерии приёмки (работоспособность обхода по логам/метрикам, обновлённая документация, UX-улучшения), dotnet build -c Debug; при GUI-изменениях — ручной прогон, тестовая эксплуатация, собрать фидбек; результат в agents/qa_agent/test_report.md.

## [5] [CYAN] Delivery Agent
**Статус**: TODO

**Задача**: обновить agents/delivery_agent/changelog.md, сделать git commit с итогами.

## Заметки
- MSFS 2024 валидируется как сценарий (не список доменов).
- Карточки/старый вывод могут быть шумными; приоритет — объяснимые рекомендации v2 и стабильность.
