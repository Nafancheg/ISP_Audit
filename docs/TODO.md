# ISP_Audit — TODO

Дата актуализации: 26.02.2026
Выполненное: [CHANGELOG.md](../CHANGELOG.md)
Архитектура: [ARCHITECTURE_CURRENT.md](../ARCHITECTURE_CURRENT.md)

---

## [NOW]

- [x] P1.18: унифицировать критерий `OK` между enqueue/local post-apply ретестом — **готово, когда** один и тот же вход даёт одинаковый verdict в обоих режимах + smoke/reg PASS.
- [x] P1.18: инвалидация/миграция `WinsStore` после изменения семантики outcome-probe — **готово, когда** legacy записи не дают «фальш-OK» и миграция покрыта smoke.
- [x] P2.7: атомарная запись state-файлов через `FileAtomicWriter` (`operator_sessions`, `feedback_store`, `operator_consent`, `domain_groups`, `post_apply_checks`, `ui_mode`) — **готово, когда** убраны прямые `File.WriteAllText` в указанных store и smoke round-trip PASS.
- [x] P2.6: корректная отписка от событий в shutdown/dispose (`OnLog`, `PropertyChanged`, `OnPerformanceUpdate`, `OnPipelineMessage`, `OnDiagnosticComplete`, др.) — **готово, когда** нет висящих подписок после завершения сессии и smoke PASS.
- [x] P2.5: устранить per-call создание `HttpClient` в `ProbeHttp3Async` (единый static client + handler) — **готово, когда** используется единый клиент и `smoke strict` PASS.

## [NEXT]

- [x] P2.2: Early noise filter в `ClassifierWorker` (noise+OK не эмитить в UI, noise+FAIL понижать до WARN) — **готово, когда** реализовано правило + `PIPE-011` PASS.
- [x] P2.3: история apply-транзакций в карточке (`TransactionHistory` + Engineer DataGrid) — **готово, когда** история сохраняется и отображается в UI.
- [ ] P2.4: fail-path smoke для `FixService` (`ERR-010/011/012`) — **готово, когда** все три кейса проходят без crash.
- [ ] P2.V23.1: методика пересмотра дефолтов `N/T/TTL` по телеметрии — **готово, когда** документирована процедура и критерии изменения дефолтов.
- [ ] Runtime incidents: чеклист сбора контекста зависаний/крашей (`±100` строк, классификация фазы, targeted timeout fix) — **готово, когда** шаблон инцидента оформлен и применяется на первом реальном кейсе.

## [LATER]

- [ ] Phase 4.3: декомпозиция `DiagnosticOrchestrator` (`PipelineManager`, `RecommendationEngine`, `CardActionHandler`) — **готово, когда** orchestration разделён на модули без изменения внешнего контракта и smoke PASS.
- [ ] Phase 5: Native Core (Rust DLL + WinDivert FFI + packet parser + TLS/SNI parser) — **готово, когда** есть рабочий минимальный контур сборки/интеграции и smoke strict PASS.

---

## Примечание

- Реализованные задачи и исторический прогресс перенесены в [CHANGELOG.md](../CHANGELOG.md).
- Этот файл содержит только актуальный backlog и приоритет выполнения.
