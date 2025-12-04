# TODO: Улучшение детекции блокировок (реальный код)

## 1. Текущее состояние детекции (по коду)

### 1.1. StandardHostTester (`Core/Modules/StandardHostTester.cs`)

- **DNS:**
  - Используется только reverse DNS через `Dns.GetHostEntryAsync(ip)` с таймаутом 2 секунды.
  - Результат DNS **не влияет** на статус `dnsOk` и `dnsStatus` — они всегда фиксированы (`dnsOk = true`, `dnsStatus = "OK"`).
  - `_dnsCache` (из `DnsParserService.DnsCache`) используется только как быстрый источник hostname, но **не участвует** в логике блокировок.

- **TCP:**
  - Создаётся `TcpClient`, подключение к `host.RemoteIp:host.RemotePort` с таймаутом 3 секунды через `CancellationTokenSource.CancelAfter(3000)`.
  - При успешном `ConnectAsync`:
    - `tcpOk = true`.
    - `tcpLatencyMs` = время с начала `Stopwatch`.
  - При `OperationCanceledException`:
    - `blockageType = "TCP_TIMEOUT"`.
  - При `SocketException`:
    - `ConnectionRefused` → `blockageType = "PORT_CLOSED"`, `tcpOk = false`.
    - `ConnectionReset` → `blockageType = "TCP_RST"`, `tcpOk = false`.
    - Любая другая ошибка → `blockageType = "TCP_ERROR"`, `tcpOk = false`.

- **TLS:**
  - Проверяется **только для порта 443** и только если `tcpOk == true` и есть `hostname`.
  - Создаётся новый `TcpClient`, повторное `ConnectAsync` на 443 с таймаутом 3 секунды.
  - Создаётся `SslStream` и вызывается `AuthenticateAsClientAsync` с `Tls12|Tls13` и отключенной проверкой отзыва сертификата.
  - При успехе: `tlsOk = true`.
  - При `OperationCanceledException`: `blockageType = "TLS_TIMEOUT"`.
  - При `AuthenticationException`: `tlsOk = false`, `blockageType = "TLS_DPI"`.
  - При любом другом исключении: `tlsOk = false`, `blockageType = blockageType ?? "TLS_ERROR"` (не перетирает уже установленный `blockageType`, если он был).
  - Если порт 443, но hostname нет → `tlsOk = tcpOk` (TLS по сути не проверяется).
  - Для не-HTTPS (`RemotePort != 443`) → `tlsOk = tcpOk`.

- **Итог:**
  - Возвращаемый `HostTested` содержит:
    - `DnsOk` (всегда true), `DnsStatus` (всегда "OK").
    - `TcpOk`, `TlsOk`.
    - `BlockageType` (одно строковое поле, например `TCP_TIMEOUT`, `TCP_RST`, `PORT_CLOSED`, `TLS_DPI`, `TLS_ERROR`, `TLS_TIMEOUT`, `TCP_ERROR`).
    - Временная метка `DateTime.UtcNow`.
  - Никаких счётчиков, окон времени, информации о ретрансмиссиях, HTTP-редиректах или анализе RST на уровне пакетов здесь **нет**.

### 1.2. StandardBlockageClassifier (`Core/Modules/StandardBlockageClassifier.cs`)

- На вход получает один `HostTested`.
- Использует `StrategyMapping.GetStrategiesFor(tested)` для выбора возможных bypass-стратегий, но это **уже уровень рекомендаций**, не детекции.
- Детекция/классификация реализована следующим образом:
  - Если IP в диапазоне `198.18.0.0/15` или hostname == `openwrt.lan` →
    - Считается `ROUTER_REDIRECT`.
    - В `HostTested` принудительно проставляется `BlockageType = "FAKE_IP"`.
  - Если `BlockageType == "PORT_CLOSED"` →
    - Считается "не блокировка, просто сервис недоступен".
    - Стратегия `NONE`, текстовое описание с упоминанием порта.
  - Если `DnsOk && TcpOk && TlsOk` →
    - Стратегия `NONE`, `action = "OK"`.
  - В остальных случаях:
    - Если есть `rec.Applicable` (подходящие стратегии из `StrategyMapping`) → берётся первая, `action = "Рекомендуемая стратегия: ..."`.
    - Иначе если есть `rec.Manual` → первая, `action = "Требуется ручное вмешательство: ..."`.
    - Иначе → стратегия `UNKNOWN`, `action = "Неизвестная проблема ..."`.
- ВАЖНО: класс **не ведёт никакого состояния** во времени:
  - Нет агрегирования по хосту,
  - Нет счётчиков ошибок,
  - Нет учёта окон времени,
  - Нет отдельного поля "уверенности" или `DpiSuspicionScore`.
- Вся логика опирается на **однократный результат `HostTested`** и статический `StrategyMapping`.

### 1.3. ConnectionMonitorService (`Utils/ConnectionMonitorService.cs`)

- Отвечает за **мониторинг попыток соединений**.
- Два режима:
  - `UsePollingMode = true` → polling через `TcpConnectionWatcher` (IP Helper API).
  - `UsePollingMode = false` (основной) → WinDivert Socket Layer (`Layer.Socket`, `Sniff+RecvOnly`).
- Событие `OnConnectionEvent` даёт:
  - `eventCount` (общий счётчик событий),
  - `pid` процесса,
  - `protocol` (TCP/UDP),
  - `remoteIp`, `remotePort`, `localPort`.
- Внутри `RunSocketLoop`:
  - Открывается WinDivert с фильтром `"true"` на Socket Layer, приоритет -1000, флаги `Sniff | RecvOnly`.
  - Цикл читает `WinDivertRecv`, проверяет `addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT`.
  - Фильтрует loopback.
  - Считает общее количество событий `_totalEventsCount`, фиксирует `MonitorStartedUtc` и `FirstEventUtc`.
  - Поднимает `OnConnectionEvent`.
- ВАЖНО: сервис **не анализирует сами TCP-пакеты**, только события connect:
  - Нет информации о `seq/ack`.
  - Нет сигналов о ретрансмиссиях.
  - Нет RST-инспекции.
  - Нет привязки к результатам `HostTested` (кроме того, что оба работают в рамках общего процесса диагностики).

### 1.4. NetworkMonitorService (`Utils/NetworkMonitorService.cs`)

- Обёртка над WinDivert Network Layer (обычно `Layer.Network`, `Sniff`).
- Открывает WinDivert с заданным фильтром (`_filter`) и приоритетом (`_priority`).
- В цикле:
  - Делает `WinDivertRecv` в буфер 1500 байт.
  - Для каждого пакета:
    - Увеличивает `PacketsCount`.
    - Делает копию буфера для события.
    - Вызывает `OnPacketReceived(PacketData)` с полями:
      - `PacketNumber`,
      - `Buffer` (сырые данные),
      - `Length`,
      - `IsOutbound`,
      - `IsLoopback`.
- Сервис **НЕ содержит никакой логики парсинга** TCP/UDP/HTTP/DNS:
  - Нет разбора TCP-заголовков.
  - Нет подсчёта ретрансмиссий.
  - Нет анализа HTTP-ответов/редиректов.
  - Он только предоставляет поток пакетов подписчикам.

### 1.5. LiveTestingPipeline (`Utils/LiveTestingPipeline.cs`)

- Архитектурно: `Sniffer → Tester → Classifier → Bypass → UI`.
- Использует:
  - `IHostTester` → конкретно `StandardHostTester`.
  - `IBlockageClassifier` → `StandardBlockageClassifier`.
  - `DnsParserService` (для кеша DNS и отображения hostname).
  - `ITrafficFilter` (`UnifiedTrafficFilter`) для дедупликации/шумовых хостов.
- Потоки:
  - `_snifferQueue: Channel<HostDiscovered>` — вход от `TrafficCollector`.
  - `_testerQueue: Channel<HostTested>` — результаты тестера.
  - `_bypassQueue: Channel<HostBlocked>` — для UI.

- **TesterWorker:**
  - Забирает `HostDiscovered` из `_snifferQueue`.
  - Берёт hostname из `_dnsParser?.DnsCache` (если есть) только для фильтрации.
  - Через `_filter.ShouldTest(host, hostname)` решает, тестировать ли.
  - Вызывает `_tester.TestHostAsync(host, ct)` → `HostTested`.
  - Кладёт результат в `_testerQueue`.

- **ClassifierWorker:**
  - Забирает `HostTested`.
  - Вызывает `_classifier.ClassifyBlockage(tested)` → `HostBlocked`.
  - Через `_filter.ShouldDisplay(blocked)` решает, показывать ли результат.
  - Дополнительно обновляет hostname из DNS-кеша и фильтрует шум (`NoiseHostFilter`).
  - Если нужно показать → кладёт в `_bypassQueue`.

- **UiWorker:**
  - Забирает `HostBlocked`.
  - Формирует человекочитаемое сообщение:
    - `host:port (latency) | DNS/TCP/TLS флаги | BlockageType`.
    - Если `BypassStrategy` != `NONE/UNKNOWN` → логирует рекомендацию.
- ВАЖНО: Pipeline **не добавляет новых детекционных сигналов**, он только:
  - прогоняет хосты через `StandardHostTester`,
  - классифицирует через `StandardBlockageClassifier`,
  - фильтрует/логирует/передаёт в UI.

---

## 2. Выводы по текущему состоянию детекций

1. **TCP Retransmissions — отсутствует полностью:**
   - Ни один модуль не анализирует `seq/ack` TCP-пакетов.
   - `ConnectionMonitorService` работает на Socket Layer и видит только события connect.
   - `NetworkMonitorService` отдаёт сырые пакеты, но **нет потребителя**, который бы считал ретрансмиссии.

2. **HTTP redirect detect — отсутствует:**
   - Нет парсинга HTTP-ответов (`Status-Code`, `Location`).
   - Нет сравнения домена редиректа с исходным хостом.
   - `StandardHostTester` вообще не делает HTTP-запросы, только TCP connect + TLS handshake.

3. **RST packet inspection — отсутствует:**
   - RST фиксируется только на уровне `SocketException.ConnectionReset` в TCP connect.
   - Нет анализа RST-пакетов в Network Layer (TTL, направление, сигнатуры DPI).
   - Нет статистики по RST в `ConnectionMonitorService`.

4. **Fail counter + time window — отсутствует:**
   - `StandardBlockageClassifier` и `LiveTestingPipeline` работают **на уровне одного результата** (`HostTested`).
   - Нет хранилища состояния per-host/per-IP/per-domain.
   - Нет окна времени (например, 3 фейла за 60 секунд).
   - `TestResultsManager` (по другим файлам) хранит результаты, но в текущем анализе он **не используется** в детекции внутри `StandardBlockageClassifier`.

5. **Существующие сигналы:**
   - `TCP_RST` — детектируется через `SocketError.ConnectionReset` при TCP connect.
   - `TCP_TIMEOUT` — через `OperationCanceledException` по истечении 3с таймаута.
   - `TLS_DPI` — через `AuthenticationException` при TLS handshake.
   - `TLS_TIMEOUT` — через `OperationCanceledException` в TLS.
   - `PORT_CLOSED` — через `SocketError.ConnectionRefused`.
   - `FAKE_IP` — через диапазон `198.18.0.0/15` и hostname `openwrt.lan`.

6. **Связка с bypass-стратегиями:**
   - Через `StrategyMapping.GetStrategiesFor(tested)` на основе полей `DnsOk/TcpOk/TlsOk/BlockageType`.
   - Так как продвинутые сигналы (retransmissions/HTTP redirect/RST-inspection/fail counter) отсутствуют, `StrategyMapping` вынужден опираться на примитивные признаки → это ограничивает качество выбора стратегии.

---

## 3. План доработки детекции (минимально инвазивный)

> Цель: добавить новые сигналы и агрегирование так, чтобы **минимально ломать** текущий рабочий пайплайн (`StandardHostTester` → `StandardBlockageClassifier` → `LiveTestingPipeline`), расширяя его, а не переписывая с нуля.

### 3.1. Fail counter + time window

**Статус:** базовая реализация и первый шаг агрегатора сигналов **сделаны**.

- [x] Добавить новый модельный класс, например `HostBlockageState` (`Core/Models`):
  - `HostKey` (IP + порт и/или hostname).
  - `List<FailureEvent>` с `Timestamp`, `BlockageType`, флагами (`IsHardFail`, `IsTimeout`, `IsTls`, и т.п.).
  - Расчётные свойства: `FailCountLastWindow(TimeSpan window)`, `HasRecentHardFails`, и т.п.

- [x] Добавить простой стор для состояний, например `IBlockageStateStore` + реализация (в оперативной памяти):
  - Методы вида `RegisterResult(HostTested result)` и выдача статистики по окну (`FailWindowStats`).

- [x] Расширить `StandardBlockageClassifier` так, чтобы:
  - В конструктор принимался `IBlockageStateStore` (через DI или с дефолтной реализацией).
  - В `ClassifyBlockage` запрашивалась статистика фейлов за окно и она использовалась хотя бы в текстовой части рекомендаций ("фейлов за 60с: N").

- [x] В `LiveTestingPipeline` заменить создание `new StandardBlockageClassifier()` на внедрение через конструктор:
  - передавать общий `IBlockageStateStore`.

- [x] Развить стор до первого варианта агрегатора сигналов:
  - Ввести DTO `BlockageSignals` (fail-count, hard-fail-count, окно, retranmission-count).
  - Добавить метод `GetSignals(HostTested, TimeSpan)` в `IBlockageStateStore` и реализовать его в `InMemoryBlockageStateStore`.
  - Перевести `StandardBlockageClassifier` на использование `BlockageSignals` для формирования текстовой части и мягкой эвристики `TCP_RETRY_HEAVY`.

- [ ] Дальнейшее развитие агрегатора сигналов:
  - Расширить `BlockageSignals` дополнительными полями (RST, HTTP-redirect, TLS-auth-fails) по мере реализации детекторов.
  - При необходимости выделить отдельный `IBlockageSignalsProvider`, оставив `IBlockageStateStore` тонкой обёрткой над историей `HostTested`.

**Плюсы:**
- Не ломает интерфейс `IBlockageClassifier` и сигнатуры `ClassifyBlockage`.
- Вся новая логика сосредоточена в отдельном сторе и немного в `StandardBlockageClassifier`.

### 3.2. TCP Retransmissions на базе NetworkMonitorService

**Статус:** минимальная реализация ретрансмиссий **сделана**, сигнал уже попадает в агрегатор, классификатор **и UI**.
- [x] Создать модуль `TcpRetransmissionTracker` (`Core/Modules/TcpRetransmissionTracker.cs`):
  - Подписывается на `NetworkMonitorService.OnPacketReceived`.
  - Парсит IPv4+TCP-заголовок из `PacketData.Buffer`.
  - Идентифицирует потоки по нормализованному `TcpFlowKey` (src/dst IP+порт, направление-агностично).
  - Считает ретрансмиссии по повторяющемуся `seq`.

- [x] Вести агрегированные счётчики per-host:
  - `TcpRetransmissionTracker.GetRetransmissionCountForIp(IPAddress ip)` суммирует ретрансмиссии по всем потокам с этим IP.

- [x] Интеграция со стором и классификатором:
  - `InMemoryBlockageStateStore` принимает опциональный `TcpRetransmissionTracker` и включает `RetransmissionCount` в `BlockageSignals`.
  - `DiagnosticOrchestrator` создаёт `TcpRetransmissionTracker`, подписывает его на `NetworkMonitorService` и передаёт в `LiveTestingPipeline` через `InMemoryBlockageStateStore`.
  - `StandardBlockageClassifier` добавляет `ретрансмиссий: N` в текст рекомендаций и при `HasSignificantRetransmissions` + пустом `BlockageType` выставляет мягкий тип `TCP_RETRY_HEAVY`.
  - `LiveTestingPipeline.UiWorker` в live-строке (`❌ host | … | BlockageType (…)`) подмешивает хвост из `HostBlocked.RecommendedAction`, так что в UI видно `ретрансмиссий: N` (и другие агрегированные сигналы).

**Дальнейшие шаги по ретрансмиссиям:**

- [ ] Уточнить эвристику `HasSignificantRetransmissions` (пороги, сглаживание по окну, возможно нормализация по количеству пакетов).
- [ ] Связать ретрансмиссии с конкретными типами фейлов (`TCP_TIMEOUT`, `TCP_RST`) для более точной типизации (например, усиление DPI-подозрения при сочетании таймаутов и высокого числа ретрансов).

**Минимизация вторжений:**
- Не меняем `StandardHostTester`.
- Не ломаем `ConnectionMonitorService`.
- Только добавляем подписчика к `NetworkMonitorService` и меняем классификацию.

### 3.3. HTTP redirect detection

**Статус:** минимальный детектор и протяжка сигнала в агрегатор **сделаны**, сигнал учитывается в классификаторе и виден в live-логе UI.

- [x] Создать модуль `HttpRedirectDetector` (`Core/Modules/HttpRedirectDetector.cs`):
  - Подписывается на `NetworkMonitorService.OnPacketReceived` через метод `Attach`.
  - Фокусируется на TCP-ответах с порта 80 (сервер → клиент).
  - Для каждого TCP-потока (по `TcpFlowKey`) аккумулирует до 2 КБ первых байт полезной нагрузки.
  - Грубым ASCII-парсером ищет HTTP-ответы `HTTP/1.x 3xx` и заголовок `Location`.
  - Через `Uri.TryCreate` извлекает целевой `Host` и сохраняет per-IP (`ConcurrentDictionary<IPAddress, RedirectInfo>`).

- [x] Хранить per-host состояние в агрегаторе сигналов:
  - `InMemoryBlockageStateStore` принимает опциональный `HttpRedirectDetector`.
  - В `GetSignals` при наличии IP и детектора вызывает `TryGetRedirectHost`.
  - В `BlockageSignals` добавлены поля `HasHttpRedirectDpi` и `RedirectToHost`.

- [x] Интеграция с оркестратором и пайплайном:
  - `DiagnosticOrchestrator` создаёт `HttpRedirectDetector`, подписывает его на `NetworkMonitorService` и передаёт в `LiveTestingPipeline` через `InMemoryBlockageStateStore`.
  - Существующие интерфейсы пайплайна не менялись, сигнал идёт через уже введённый слой `BlockageSignals`.
  - `StandardBlockageClassifier` использует `HasHttpRedirectDpi/RedirectToHost` для формирования мягкого `BlockageType = "HTTP_REDIRECT_DPI"` (если тип ещё не задан) и дописывает в текст рекомендаций «HTTP-редирект на {RedirectToHost}». `UiWorker` вытаскивает этот хвост и показывает его в live-строке.

**Дополнительно:**

- [x] В `DnsParserService` (`Utils/DnsSnifferService.cs`) фоновой цикл таймаутов (`CleanupPendingRequestsLoop`) переведён на `CancellationToken`, `Dispose` корректно гасит таск; варнинги CS0162 по этому файлу устранены, сборка проходит без предупреждений по DNS-снифферу.

- [ ] Логика детекции (следующие шаги):
  - Имея исходный hostname (из DNS/TrafficCollector/TestResult) и `RedirectToHost` из `BlockageSignals`:
    - Выделять SLD (second-level domain) исходного и целевого доменов.
    - Если SLD различаются (например, `youtube.com` → `provider-portal.ru`), выставлять флаг `IsDpiRedirect = true` внутри классификатора.

- [ ] Интеграция с классификатором и UI:
  - В `StandardBlockageClassifier` при наличии `HasHttpRedirectDpi/RedirectToHost` добавлять в описание явную пометку про «HTTP-редирект на {RedirectToHost} (возможно, портал провайдера / DPI)».
  - При желании ввести мягкий `BlockageType`, например `HTTP_REDIRECT_DPI`, не ломая существующие типы.
  - В UI/логах сделать отдельную строку/бейдж для HTTP-редиректа, чтобы пользователь явно видел, что трафик уводится на другой домен.

### 3.4. RST packet inspection

**Идея:** рядом с RST Blocker (который уже есть в `WinDivertBypassManager`) или через отдельный `NetworkMonitorService`-подписчик отслеживать RST-пакеты и их характеристики.

- [ ] Создать модуль `RstInspectionService`:
  - Подписывается на `NetworkMonitorService.OnPacketReceived` или использует отдельный фильтр WinDivert (`tcp.Rst == 1`).
  - Для каждого RST-пакета:
    - Определяет `(srcIp, dstIp, srcPort, dstPort)`.
    - Извлекает TTL и другие поля.
  - Сравнивает TTL RST с TTL обычных пакетов для этого же направления (потребуется небольшое состояние per-flow/per-host).

- [ ] Эвристика:
  - Если TTL RST значительно отличается от типичного TTL реального сервера,
  - и такие RST появляются стабильно при попытках TLS/HTTP к одному и тому же хосту,
  - выставлять флаг `SuspiciousRst` / `HasDpiRst`.

- [ ] Интеграция:
  - Как и в предыдущих пунктах, хранить состояние per-host и давать доступ через API (например, `GetRstSuspicionScore(HostKey)`).
  - `StandardBlockageClassifier` либо новый агрегатор будет учитывать этот сигнал при выборе `BlockageType` и стратегии.

---

## 4. Общие принципы минимально болезненной доработки

- **Не менять существующие интерфейсы**, если это не строго необходимо:
  - `IHostTester`, `IBlockageClassifier` и сигнатуры их методов оставить прежними.
  - Новые сигналы передавать через доп. сервисы/сторы, доступные по DI или синглтонам, а не через изменение `HostTested` сразу на первом шаге.

- **Добавлять новые модули как подписчиков к уже существующим сервисам**:
  - `NetworkMonitorService` уже даёт поток пакетов — достаточно добавить над ним `TcpRetransmissionTracker`, `HttpRedirectDetector`, `RstInspectionService`.
  - `ConnectionMonitorService` можно оставить как есть (он даёт события connect, но не нужен для низкоуровневой DPI-аналитики).

- **Агрегация сигналов — отдельный слой:**
  - Ввести что-то вроде `BlockageSignalAggregator`/`IBlockageStateStore`, который:
    - собирает все сигналы (из тестов и снифферов),
    - хранит состояние per-host во времени,
    - предоставляет удобные методы для `StandardBlockageClassifier` и `StrategyMapping`.

- **Пошаговое внедрение:**
  1. Сначала реализовать `Fail counter + time window` (на базе только `HostTested`), чтобы ничего не трогать в WinDivert.
  2. Затем добавить `TcpRetransmissionTracker` (подписчик к `NetworkMonitorService`).
  3. Потом `HttpRedirectDetector`.
  4. И в конце — `RstInspectionService`.

Это позволит на каждом шаге иметь рабочее приложение и поэтапно улучшать детекцию без больших ломок в архитектуре.

---

## 5. Риски раздувания (god objects) и как их избежать

### 5.1. Потенциальные точки раздувания

- `StandardHostTester`:
  - Уже содержит немало логики (reverse DNS, TCP connect, TLS handshake).
  - Риск: если сюда добавлять HTTP-запросы, анализ ответов, счётчики, окна времени, анализ ретрансмиссий и т.п., класс превратится в "универсальный анализатор" вместо узкого активного тестера.
  - Решение: держать его зоной ответственности только за **активный тест соединения** (DNS/TCP/TLS) и не добавлять DPI-специфичные эвристики.

- `StandardBlockageClassifier`:
  - Сейчас компактный: несколько `if` по `BlockageType` + выбор стратегии через `StrategyMapping`.
  - Риск: при наращивании детекции естественно захотеть добавить сюда:
    - fail-counter,
    - учёт ретрансмиссий,
    - HTTP redirect DPI,
    - RST-инспекцию,
    - расчёт `DpiSuspicionScore` и др.
  - В таком виде он станет god object-ом по части "детекция + агрегация + стратегия".
  - Решение: вынести сбор и агрегацию сигналов в отдельный сервис (`BlockageSignalAggregator` / `IBlockageSignalsProvider`), а `StandardBlockageClassifier` оставить тонким потребителем этих сигналов.

- `ConnectionMonitorService` и `NetworkMonitorService`:
  - Сейчас отвечают только за транспорт (Socket события и stream пакетов).
  - Риск: если внутрь добавлять разбор TCP/HTTP, подсчёт ретрансмиссий, DPI-эвристики — они станут перегруженными.
  - Решение: оставлять их **чистыми источниками событий**, а детекторы реализовывать как подписчиков (`TcpRetransmissionTracker`, `HttpRedirectDetector`, `RstInspectionService`).

- `LiveTestingPipeline`:
  - Уже координирует очереди и модули (`Tester`, `Classifier`, фильтры, UI).
  - Риск: превращение в центр всей логики (state-store, анализ пакетов, DPI-эвристики, управление bypass и т.п.).
  - Решение: pipeline должен только **оркестрировать** потоки данных и вызывать внешние сервисы, не храня внутри сложное состояние детекции.

### 5.2. Стратегия разбиения по слоям

- Слой "сырых сигналов" (подписчики):
  - `TcpRetransmissionTracker` — считает ретрансмиссии по TCP.
  - `HttpRedirectDetector` — парсит HTTP-ответы и ищет DPI-редиректы.
  - `RstInspectionService` — анализирует RST-пакеты (TTL, паттерны).
  - `FailCounterStore` / `BlockageStateStore` — хранит историю `HostTested` и считает N фейлов за окно.

- Слой агрегации:
  - `BlockageSignalAggregator` / `IBlockageSignalsProvider` собирает данные из всех детекторов и предоставляет компактный DTO `BlockageSignals` (`HasTcpRetransmissions`, `HasHttpRedirectDpi`, `HasSuspiciousRst`, `FailCount`, `WindowSeconds`, `DpiSuspicionScore` и т.д.).
  - `StandardBlockageClassifier` получает на вход `HostTested` + `BlockageSignals` и решает `BlockageType`/severity, не зная деталей реализации детекторов.

- Слой решения (стратегий обхода):
  - `StrategyMapping` и `BypassCoordinator` работают только с уже классифицированными данными (`HostTested`, `HostBlocked`, `BlockageSignals`), без доступа к низкоуровневым сервисам (`NetworkMonitorService`, `TcpRetransmissionTracker` и др.).

### 5.3. Правила, которые стоит явно соблюдать при доработке

- Не расширять зоны ответственности существующих классов за пределы одной задачи (тестер тестирует, классификатор классифицирует, монитор только мониторит).
- Не добавлять анализ TCP/HTTP/TTL и сложные эвристики непосредственно в `StandardHostTester`, `StandardBlockageClassifier`, `ConnectionMonitorService` или `LiveTestingPipeline`.
- Все новые функции детекции оформлять:
  - отдельным файлом,
  - с узким интерфейсом,
  - подключая его через DI/подписку, а не через жёсткие зависимые вызовы из центра.

Фиксация этих рисков в планах позволит не потерять архитектурную чистоту при постепенном добавлении новых детекторов DPI.