# P0.1 — Карта «подозреваемых коллекций» (Collection was modified)

Цель: зафиксировать все места, где возможна ошибка вида `Collection was modified; enumeration operation may not execute` (или близкие гонки) и понять, чем они закрыты (lock/snapshot/Concurrent/immutable).

## 1) TrafficEngine

- [Core/Traffic/TrafficEngine.cs](../Core/Traffic/TrafficEngine.cs)
  - `List<IPacketFilter> _filters`
    - Риск: `foreach` по live `List<>` + реэнтрантная мутация из `filter.Process(...)`.
    - Митигировано: loop итерируется по `IPacketFilter[] _filtersSnapshot` (refresh на Register/Remove/Clear).
  - `event Action<double>? OnPerformanceUpdate`
    - Риск: падение подписчика может уронить loop.
    - Митигировано: invoke обёрнут try/catch + throttling ошибок.

## 2) Core/Traffic/Filters

- [Core/Traffic/Filters/BypassFilter.Udp443.cs](../Core/Traffic/Filters/BypassFilter.Udp443.cs)
  - `volatile uint[] _udp443DropTargetDstIps`
    - Чтение в hot path: линейный поиск по массиву.
    - Запись: присваивание нового массива (после дедуп/сортировки). reference-swap безопасен для конкурентного чтения.
  - `volatile DecisionGraphSnapshot? _decisionGraphSnapshot`
    - Чтение: копия ссылки в локальную переменную.
    - Snapshot: иммутабелен (см. ниже).

- [Core/Models/DecisionGraphSnapshot.cs](../Core/Models/DecisionGraphSnapshot.cs)
  - `ImmutableArray<FlowPolicy> Policies`, `ImmutableDictionary<Key, ImmutableArray<FlowPolicy>> Index`
    - Иммутабельные структуры, безопасны для конкурентного чтения.

- [Core/Traffic/Filters/BypassFilter.ProbeFlows.cs](../Core/Traffic/Filters/BypassFilter.ProbeFlows.cs)
  - `ConcurrentDictionary<ConnectionKey,long> _probeFlowsUntilTick`
    - Перечисление snapshot-safe по контракту `ConcurrentDictionary`.

- [Core/Traffic/Filters/TemporaryEndpointBlockFilter.cs](../Core/Traffic/Filters/TemporaryEndpointBlockFilter.cs)
  - `_ipv4Targets` (`HashSet<uint>`) и `_ipv4TargetsImmutable` (`ImmutableHashSet<uint>`)
    - `_ipv4Targets` заполняется в ctor и далее используется только для `Contains`.
    - Policy-driven ветка использует иммутабельный snapshot.

## 3) Вне Traffic (смежные кандидаты)

- [Core/IntelligenceV2/Signals/InMemorySignalSequenceStore.cs](../Core/IntelligenceV2/Signals/InMemorySignalSequenceStore.cs)
  - `ConcurrentDictionary<string, SequenceBucket> _buckets`
    - Перечисление snapshot-safe, а мутации `Sequence.Events` защищены per-host lock (`bucket.Gate`).

## Smoke/Regression покрытие

- `INFRA-006`: реэнтрантная мутация списка фильтров во время обработки.
- `INFRA-007`: конкурентный churn Register/Remove параллельно обработке.
- `INFRA-008`: rapid Apply/Disable через `BypassStateManager` во время обработки.
- `INFRA-009`: конкурентные обновления `DecisionGraphSnapshot`/UDP targets во время обработки.

Следующий шаг: пройтись по всем hot-path перечислениям (LINQ/foreach) в `Core/Traffic` и подтвердить, что источники данных либо immutable, либо snapshot-safe.
