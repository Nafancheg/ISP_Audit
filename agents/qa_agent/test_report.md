# QA Test Report — Gates INTEL (16.12.2025)

Цель: проверить сборку и гейты из раздела “Gates …” в [agents/planning_agent/plan.md](agents/planning_agent/plan.md).

Примечание по входным требованиям: задача и DoD зафиксированы в [agents/task_owner/current_task.md](agents/task_owner/current_task.md), а формальные Gate 1→5 описаны в [agents/planning_agent/plan.md](agents/planning_agent/plan.md).

## Сборка
- PASS: `dotnet build -c Debug` (локально)
- PASS: `dotnet build -c Release` (локально)
- Автотесты: в решении не обнаружены (ручная валидация критична)

## Gate 1→2 (SignalsAdapter → DiagnosisEngine)

Критерии:
- SignalEvent без исключений
- HostKey непустой
- По логам восстанавливается цепочка событий

Статус: PARTIAL

Что подтверждено статически (по коду):
- PASS: HostKey не может быть пустым: построение ключа в [Core/Intelligence/Signals/SignalsAdapter.cs](Core/Intelligence/Signals/SignalsAdapter.cs) возвращает IP/Key/"<unknown>", а стор выбрасывает исключение на пустом HostKey в [Core/Intelligence/Signals/InMemorySignalSequenceStore.cs](Core/Intelligence/Signals/InMemorySignalSequenceStore.cs).

Что НЕ подтверждено/есть риск несоответствия критериям Gate:
- FAIL (по логам): текущий Gate-лог в UI — это агрегированная строка вида `[INTEL][GATE1] hostKey=... recentTypes=...`, без порядка событий/таймлайна. Это позволяет увидеть “какие типы были”, но не даёт восстановить именно цепочку “что раньше/что потом” (требование “HostTested → потом …”) по одному только логу.
- RISK: условие “у каждого HostKey минимум 2 события” может не выполняться в “тихих” сценариях: в INTEL всегда добавляется `HostTested`, но второе событие зависит от наличия legacy-сигналов (retx/rst/redirect/udp) и дебаунса.

Шаги воспроизведения (для подтверждения/опровержения):
1) Запустить GUI (Debug).
2) Запустить диагностику на 2–3 минуты (браузер + фоновые соединения).
3) В логе UI найти строки `[INTEL][GATE1]`.
4) Проверить, что hostKey не пустой и что для одних и тех же hostKey появляются разные комбинации типов.
5) Проверить, можно ли по логу восстановить последовательность событий (на текущем формате это, вероятно, невозможно без расширения логирования).

## Gate 2→3 (DiagnosisEngine → StrategySelector)

Критерии:
- Для 5 проблемных целей: диагноз не `Unknown` и `Confidence > 30`
- Для 5 рабочих целей: `NoBlockage` либо `Unknown` с низкой уверенностью
- ExplanationNotes основаны на фактах

Статус: PARTIAL (нужен ручной прогон)

Что подтверждено статически (по коду):
- PASS: `ExplanationNotes` формируются из наблюдаемых фактов (DNS/TCP/TLS/retx/redirect), без “магических” предположений: [Core/Intelligence/Diagnosis/StandardDiagnosisEngine.cs](Core/Intelligence/Diagnosis/StandardDiagnosisEngine.cs).

Что НЕ подтверждено/есть риск несоответствия критериям Gate:
- RISK: многие реальные “проблемные” случаи сейчас мапятся в `Unknown` (например: `tcp-timeout-only`, `tcp-rst-only`, `tls-issue-only`). Это прямо конфликтует с требованием “5 проблемных целей → диагноз не Unknown”.
- NOT RUN: ручные сценарии (YouTube/ChatGPT/прочие) в этой QA-сессии не запускались (нужен реальный сетевой трафик и интерактивный GUI).

Шаги воспроизведения (для подтверждения/опровержения):
1) Запустить диагностику.
2) Выполнить 5 “рабочих” сценариев из [agents/planning_agent/plan.md](agents/planning_agent/plan.md).
3) Собрать 5 “проблемных” сценариев по фактическим жалобам.
4) Для каждого проблемного хоста зафиксировать хвост в строке вида `(... [INTEL] диагноз=... уверенность=...% ...)` и убедиться, что диагноз не `Unknown` и уверенность > 30.

## Gate 3→4 (StrategySelector → ExecutorMvp)

Критерии:
- `Unknown/NoBlockage` → пустой план
- `Confidence < 50` → пустой план
- RiskLevel.High не появляется при `confidence < 70`
- План детерминирован

Статус: PASS (статически)

Обоснование:
- Порог `confidence < 50` возвращает пустой план: [Core/Intelligence/Strategies/StandardStrategySelector.cs](Core/Intelligence/Strategies/StandardStrategySelector.cs).
- NoBlockage/Unknown не имеют маппинга → пустой план.
- High-risk фильтр при `confidence < 70` присутствует (контракт 70 в [Core/Intelligence/Contracts/StrategyContract.cs](Core/Intelligence/Contracts/StrategyContract.cs) и проверка в селекторе).
- Сортировка стабильная (priority↓, risk↑, id↑) → детерминизм.

## Gate 4→5 (ExecutorMvp → UI интеграция)

Критерии:
- Нет auto-apply
- Логи компактны
- Рекомендации только при уверенных диагнозах

Статус: PARTIAL

Что подтверждено статически (по коду):
- PASS: auto-apply принудительно отключён и явно логируется: [ViewModels/DiagnosticOrchestrator.cs](ViewModels/DiagnosticOrchestrator.cs).
- PASS: Step 4 — только форматирование/дедуп логов, без применения техник: [Core/Intelligence/Execution/BypassExecutorMvp.cs](Core/Intelligence/Execution/BypassExecutorMvp.cs).
- PASS: рекомендации строятся только если селектор вернул непустой план (а он, в свою очередь, режет `confidence < 50`): [Utils/LiveTestingPipeline.cs](Utils/LiveTestingPipeline.cs).

Что НЕ подтверждено (нужен ручной прогон):
- NOT RUN: “1–2 строки на проблемный хост без спама” зависит от частоты появления проблемных событий и от поведения фильтра трафика/дедупа в реальной сессии.

## Финальный gate (MSFS 2024)

Критерии:
- INTEL рекомендации приоритетнее legacy
- Нет заметных подвисаний GUI
- В “рабочих” сценариях нет агрессивных/High рекомендаций
- MSFS 2024: запуск из Steam, быстрая загрузка, доступность мира/карьеры/погоды/карты

Статус: NOT RUN (требуется ручная валидация на машине с установленным MSFS 2024)

Шаги ручной проверки:
1) Включить “Режим Steam” в UI и запустить диагностику.
2) Запустить MSFS 2024 из Steam.
3) Зафиксировать время до главного меню и до загрузки мира (сравнить с baseline без ISP_Audit).
4) Проверить внутри игры: мир/карьера/погода/карта.
5) Если игра не работает — проверить, что в UI появляются INTEL диагноз/пояснение и рекомендации, и что обход не включается автоматически.

## Найденные проблемы / риски

1) Gate 1→2: “цепочки восстанавливаются по логам” — текущий формат `[INTEL][GATE1] ... recentTypes=...` не содержит порядка/таймлайна событий (только множество типов). Это может не проходить критерий “восстановить цепочку HostTested → потом …”.
	- Как увидеть: запустить диагностику и посмотреть строки `[INTEL][GATE1]` — там нет времени/порядка.

2) Gate 2→3: требование “5 проблемных целей → диагноз не Unknown” выглядит несовместимым с текущими правилами StandardDiagnosisEngine для типичных проблем (RST-only / TLS-timeout-only / TCP-timeout-only возвращают Unknown).
	- Как увидеть: при проблеме уровня TLS timeout ожидаемо будет `DiagnosisId.Unknown` с `Confidence=50`.

## Итог
- Сборка Debug/Release: PASS.
- Gate 3→4: PASS (по коду).
- Gate 1→2, 2→3, 4→5, финальный (MSFS 2024): требуется ручной прогон, иначе остаются существенные риски; по двум гейтам есть потенциальные несоответствия критериям (см. “Найденные проблемы / риски”).

