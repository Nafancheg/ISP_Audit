# ISP_Audit — TODO

Дата актуализации: 26.02.2026
Выполненное: [CHANGELOG.md](../CHANGELOG.md)
Архитектура: [ARCHITECTURE_CURRENT.md](../ARCHITECTURE_CURRENT.md)

---

## [NOW]

- [x] P2.ARCH.2: убрать прямую зависимость orchestration-модуля от WPF Dispatcher (`Application.Current`) — **готово, когда** `PipelineManager` работает через абстракцию диспетчеризации, а WPF-деталь остаётся только в UI composition.
- [x] P2.ASYNC.1: привести UI-слой к контракту async/await (без `ConfigureAwait(false)` в command-цепочках с обновлением bindable-состояния) — **готово, когда** UI-команды не нарушают thread-affinity WPF и smoke UI/reg PASS.
- [x] P2.RUNTIME.1: снизить sync-over-async в shutdown/dispose путях (`Wait/Result` на stop-операциях) — **готово, когда** остановка сервисов выполняется без блокирующих ожиданий на UI-пути и без регрессий smoke strict.
- [x] P2.OBS.1: убрать пустые `catch` в runtime-коде и добавить контрактное логирование контекста — **готово, когда** в production-коде нет silent catch без причины/лога, а инциденты можно трассировать по логам.

## [NEXT]

- [x] P2.ARCH.3: унифицировать UI-bridge (confirm/error/dialog/open-file/show-details) в одном месте composition root — **готово, когда** wiring сделан централизованно и не дублируется между командами.
- [ ] P2.ARCH.4: уточнить границы слоёв в архитектурной документации (допустимые зависимости для ViewModels/Orchestrator/Core) — **готово, когда** в `ARCHITECTURE_CURRENT.md` добавлен раздел «Layering contracts» и ссылки на smoke-gates.

## [LATER]

- [ ] Phase 5: Native Core (Rust DLL + WinDivert FFI + packet parser + TLS/SNI parser) — **готово, когда** есть рабочий минимальный контур сборки/интеграции и smoke strict PASS.

---

## Примечание

- Реализованные задачи и исторический прогресс перенесены в [CHANGELOG.md](../CHANGELOG.md).
- Этот файл содержит только актуальный backlog и приоритет выполнения.
