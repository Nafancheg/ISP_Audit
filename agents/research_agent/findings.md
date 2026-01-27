# Findings — TLS Fragment/Disorder (Research Agent)

## Затронутые файлы
- [Bypass/TlsBypassService.cs](Bypass/TlsBypassService.cs) — сервисный слой TLS bypass (опции, метрики, вердикт, автокоррекция), не интегрирован в UI/оркестратор.
- [ViewModels/BypassController.cs](ViewModels/BypassController.cs) — фактическая логика/UI: тумблеры Fragment/Disorder/Fake/Drop RST/DoH, пресеты, метрики/вердикт, автокоррекция, преимптивное включение.
- [Core/Traffic/Filters/BypassFilter.cs](Core/Traffic/Filters/BypassFilter.cs) — применение стратегий Fragment/Disorder/Fake/Drop RST/TTL Trick; сбор метрик (RST/фрагментации/план).
- [Bypass/BypassProfile.cs](Bypass/BypassProfile.cs) — хранение параметров TLS фрагментации/стратегии и запись в bypass_profile.json.
- [ViewModels/DiagnosticOrchestrator.cs](ViewModels/DiagnosticOrchestrator.cs) — авто-включение TLS_DISORDER + DROP_RST при старте диагностики (enableAutoBypass=true).
- [Utils/LiveTestingPipeline.cs](Utils/LiveTestingPipeline.cs) — выдаёт рекомендации стратегий (TLS_FRAGMENT/DISORDER/FAKE/FAKE_FRAGMENT, DROP_RST, DOH), не включает их автоматически.
- [Core/Modules/StandardBlockageClassifier.cs](Core/Modules/StandardBlockageClassifier.cs) и [Bypass/StrategyMapping.cs](Bypass/StrategyMapping.cs) — формируют рекомендации/фильтруют активные стратегии.
- [Core/Modules/StandardHostTester.cs](Core/Modules/StandardHostTester.cs) — TLS проверяется только при наличии hostname; для IP-only TLS считается OK → возможен «нет фрагментаций».
- Документация: [docs/phase2_plan.md](docs/phase2_plan.md), [ARCHITECTURE_CURRENT.md](ARCHITECTURE_CURRENT.md), [docs/full_repo_audit_intel.md](docs/full_repo_audit_intel.md) — описывают 2.6 как выполненный и план переноса в сервис, но текущее состояние и разрыв UI/Service не отражены.

## Текущая реализация
- **Сервисный слой (пока отдельно):** TlsBypassService строит профиль из TlsBypassOptions, регистрирует BypassFilter в TrafficEngine, каждые 2с тянет метрики и вычисляет вердикт по ratio RST/фрагментаций (шум до 5 RST). Поддерживает AutoAdjust для пресета «Агрессивный» (сжимает мин-чанк до 4 при ранних RST, затем усиливает после 30с «зелёного»). События MetricsUpdated/VerdictChanged/StateChanged есть, но сервис нигде не создаётся.
- **Фактический путь UI:** BypassController напрямую формирует BypassProfile и регистрирует BypassFilter. Пресеты: Стандарт (64), Умеренный (96), Агрессивный (32/32, min=4), Профиль (из bypass_profile.json). Порог фрагментации фиксирован 128 байт; если ClientHello меньше или порт ≠443 — фрагментаций/метрик нет.
- **Метрики/вердикт в UI:** DispatcherTimer (2с) берёт snapshot из BypassFilter и красит карточку: нет фрагментаций → красный; <10 → серый; ratio RST/frag >4 → красный; >1.5 → жёлтый; иначе зелёный. Текст выводит сырые счётчики и LastFragmentPlan; отдельного статуса «нет TLS 443/короткий ClientHello» нет → шумит красным/серым.
- **Автокоррекция в UI:** опциональный флаг «Автокоррекция агрессивного» дублирует логику сервиса: при RST>2x фрагментов (5–20) ставит мин-чанк=4; при зелёном >30с уменьшает мин-чанк на 4 (не ниже 4) и повторно применяет фильтр. Состояние хранится в контроллере.
- **Применение стратегий:** BypassFilter фрагментирует только ClientHello на 443 с payload ≥ threshold; отправляет сегменты в прямом/обратном порядке, Fake снижает seq на 10000 для первого пакета нового соединения, TTL Trick отправляет копию с малым TTL. Метрики: TlsHandled, ClientHellosFragmented, RstDropped, RstDroppedRelevant (только для соединений, где применён bypass), LastFragmentPlan.
- **Рекомендации/автовключение:** LiveTestingPipeline/StandardBlockageClassifier предлагают TLS_* и DROP_RST, но не применяют; активные стратегии из BypassController исключаются из рекомендаций. DiagnosticOrchestrator при enableAutoBypass вызывает EnablePreemptiveBypassAsync → включает TLS_DISORDER+DROP_RST до старта тестов, без явного статуса «успех/неуспех».
- **Документация:** phase2_plan п.2.6 помечен «выполнено» с описанием будущего вынесения в сервис и метрик/вердикта; ARCHITECTURE_CURRENT описывает BypassController и метрики, но не фиксирует наличие TlsBypassService и дублирование; full_repo_audit_intel содержит устаревшие риски (async void в InitializeOnStartup, dnsOk=true), которые уже не совпадают с кодом.

## Риски и зависимости
- **Разрыв архитектуры/доков:** сервисный слой TlsBypassService создан, но не используется; UI продолжает прямое управление через BypassController → планы/архдоки несоответствуют, поддержка дублируется.
- **Шум/неочевидный вердикт:** при отсутствии подходящих ClientHello (порт ≠443, размер <128) вердикт всегда красный/серый «нет фрагментаций», нет явного состояния «нет данных/короткий ClientHello/нет TLS». Пользователь не получает ответ «работает/что делать».
- **Преимптивное включение без обратной связи:** Orchestrator включает TLS_DISORDER+DROP_RST автоматически (enableAutoBypass), но UI не показывает результат/эффективность, что может скрыть неработающий обход.
- **Дублирование автокоррекции/метрик:** сервис и контроллер имеют разные источники метрик (Timer vs DispatcherTimer), независимые состояния AutoAdjust; изменение одной логики не попадает в другую.
- **Зависимость от профиля:** параметры чанков/threshold берутся из bypass_profile.json; валидация есть, но UI не показывает текущий threshold/порог, из-за чего трудно понять причину отсутствия фрагментаций. TTL Trick/Fake доступны только через профиль, не из UI.
- **Детекция TLS ограничена hostname:** StandardHostTester пропускает TLS handshake без hostname (tlsOk=tcpOk) → часть трафика может не давать сигналов, что снижает шансы увидеть фрагментации/ratio.

## Рекомендации для Planning Agent
- Зафиксировать в документации фактическое состояние: UI использует BypassController, TlsBypassService не интегрирован; обновить docs/phase2_plan.md (п.2.6), ARCHITECTURE_CURRENT.md, docs/full_repo_audit_intel.md с указанием дублирования и планом миграции или консолидировать один подход.
- Решить целевой путь: либо подключить TlsBypassService (события метрик/вердикта, хранение опций, единая автокоррекция) и сделать BypassController тонким прокси, либо удалить сервис и оставить одну реализацию. Минимизировать дублирование метрик/автокоррекции.
- Добавить явный UX-вердикт и next steps: состояния «нет TLS данных/короткий ClientHello», «обход работает/не работает», подсказки «снизить threshold/сменить пресет/выключить DROP_RST»; сократить шум карточки до итогового вердикта + кратких действий.
- Пересмотреть преэмптивное включение: показывать в UI активированный режим и его результат (фрагментации/RST), дать быстрый откат; возможно запускать после первых детекций, а не сразу.
- Экспонировать параметры фрагментации в UI (threshold, текущий план) или давать warning при отсутствии фрагментаций из-за размера/порта; связать рекомендации из LiveTestingPipeline с кнопками пресетов вместо лог-спама.
- Уточнить ограничения TLS тестера (hostname) в рекомендации, чтобы ожидания по метрикам/вердикту были корректны при IP-only соединениях.
