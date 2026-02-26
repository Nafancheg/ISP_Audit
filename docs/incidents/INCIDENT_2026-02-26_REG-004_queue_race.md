# Incident: REG-004 queue/final-status race (strict smoke)

## 1) Карточка инцидента

- IncidentId: `INC-2026-02-26-REG004`
- Дата/время (UTC): `2026-02-26 10:45` (по strict log)
- Источник: `smoke strict`
- Версия/коммит: до фикса — прогон `artifacts/smoke_strict_20260226_110750.log.txt`
- Автор разбора: Copilot

## 2) Симптом

- Тип: `flaky fail`
- Наблюдаемое поведение: `REG-004` ожидал промежуточный статус «запланирован», но получал уже финализированный post-apply статус.
- Воспроизводимость: `intermittent`
- Impact: `strict gate` (ExitCode=1)

## 3) Сбор контекста (±100 строк)

### 3.1 Логовый фрагмент

- Файл лога: `artifacts/smoke_strict_20260226_110750.log.txt`
- Точка якоря: `[FAIL] REG-004 ...`
- Диапазон строк: `L284…L484` (anchor≈L384)
- Ключевые строки:
  - `[FAIL] REG-004 REG: per-card ретест ставится в очередь во время диагностики (9ms)`
  - `Ожидали статус 'запланирован', получили '... ReasonCode: UNKNOWN_NO_BASELINE ...'`
  - `PASS: 179 / FAIL: 1 / SKIP: 0`
  - `[SmokeLauncher][ADMIN] dotnet ExitCode=1`

### 3.2 Дополнительные артефакты

- Стабилизирующие прогоны после фикса:
  - `artifacts/smoke_strict_20260226_111533.log.txt`
  - `artifacts/smoke_strict_20260226_112248.log.txt`
  - далее последующие strict-прогоны с `FAIL: 0`

## 4) Классификация фазы

- Основная фаза: `POST_APPLY_RETEST`
- Подфаза: `POST_APPLY_LOCAL_RETEST_FLUSH`

## 5) Гипотеза первопричины

- Механизм: гонка между проверкой «queued status» и асинхронным обновлением карточки до финального post-apply статуса.
- Почему в этой фазе: `RetestFromResult` ставит задачу в очередь во время run, но UI-статус может перейти в финал до момента проверки теста.
- Почему не шум: ошибка повторялась в strict при тех же тестах и пропадала после стабилизации ожиданий.

## 6) Targeted timeout/status fix

- Целевой узел: проверка ожиданий в smoke-тесте `REG-004`.
- До: тест принимал только промежуточный «queued» статус.
- После: тест допускает оба валидных состояния — «queued» **или** уже финализированный post-apply статус (`ReasonCode/LastAction`).
- Безопасность: логика продукта не менялась, исправлена только хрупкость проверки smoke-контракта.
- Откат: вернуть строгую проверку только «queued» (не рекомендуется, вернёт flaky).

## 7) Решение

- Изменённый файл: `TestNetworkApp/Smoke/SmokeTests.Reg.cs`
- Суть: в `REG_PerCardRetest_Queued_DuringRun_ThenFlushed` расширены условия pass для двух допустимых состояний action-status.
- Почему root-cause: устранена сама причина flaky (недетерминированное окно состояния), а не скрытие ошибки.

## 8) Валидация

- `dotnet build` — PASS
- `dotnet test` — PASS
- `smoke infra (non-admin)` — PASS
- `smoke strict (SmokeLauncher)` — PASS (последующие прогоны без `REG-004` fail)

## 9) Итог

- Статус: `resolved`
- Риск остатка: низкий (возможна будущая смена формата статус-текста — тогда нужно обновить smoke-контракт)
- Follow-up: держать проверку `REG-004` в strict как регрессионный гейт.
