# TODO: Умная диагностика и подбор bypass-стратегии

## Проблема

**Текущая ситуация:**
- Сниф показывает какие хосты использует игра
- Stage2 тестирует их (DNS/TCP/HTTP)
- НО: не понятно **ЧТО именно** блокирует соединение
- НО: нет **автоматического подбора** обходной стратегии

**Что нужно пользователю:**
- Для Podkop: белый список хостов → обход через VPN
- Для остальных: **конкретная WinDivert стратегия** с параметрами

## Правильный флоу диагностики

### Этап 1: Сниф (ЧТО пытается делать игра)
✅ **Готово**: `TrafficAnalyzer.AnalyzeProcessTrafficAsync()` → `GameProfile`
- Захват реальных соединений через WinDivert
- Список хостов/портов/протоколов

### Этап 2: Диагностика (ЧТО из этого НЕ РАБОТАЕТ)
⚠️ **Есть, но недостаточно**: `AuditRunner.RunAsync()` с захваченными целями
- DNS/TCP/HTTP тесты показывают Pass/Fail
- **Проблема**: не детектируем ТИП блокировки

**Что нужно добавить:**
1. ❌ **RST detection** — включить `EnableRst = true` в Stage2
   - Показывает активные TCP RST инъекции провайдера
   - `RstHeuristic.cs` уже есть, но не используется
   
2. ❌ **TLS handshake timing** 
   - Медленное рукопожатие (>500ms) = DPI inspection
   - Быстрое (<100ms) = нормальное соединение
   
3. ❌ **HTTP/TLS analysis**
   - Где именно падает: ClientHello? ServerHello? Application Data?
   
4. ❌ **UDP drop detection**
   - Пакеты уходят но ответов нет (STUN/QUIC)

### Этап 3: Классификация проблем (ТОЧНЫЙ тип блокировки)
⚠️ **Есть, но примитивная**: `ProblemClassifier.ClassifyProblems()`
- Текущая классификация: Firewall/ISP/Router/Software (слишком общая)

**Нужны точные типы блокировок:**
```csharp
enum BlockageType {
    DNS_FILTERED,        // Домен не резолвится (DoH поможет)
    DNS_BOGUS,           // Фейковый IP (DoH + проверка IP)
    TCP_RST,             // RST injection (Fake packets)
    TLS_DPI,             // HTTPS блокировка (SNI/TLS fragmentation)
    UDP_DROP,            // UDP пакеты теряются (Fake initial packets)
    FIREWALL_BLOCK,      // Порты закрыты файрволом
    SLOW_CONNECTION      // Throttling (не блокировка, но проблема)
}
```

**Структура проблемы:**
```csharp
BlockageProblem {
    Type: TCP_RST,
    Target: "roberts-space-industries.com:443",
    Evidence: "TCP connect OK, но RST после ClientHello",
    RecommendedFix: "fake,multisplit с badseq"
}
```

### Этап 4: Генератор стратегии (КАК обойти)
❌ **Заглушка**: `BypassStrategyPlanner.PlanBypassStrategy()`
- Принимает `BlockageProblem[]`
- Должен генерировать `BypassProfile` с WinDivert параметрами

**Примеры стратегий (из zapret-discord-youtube):**

**DNS_FILTERED:**
```csharp
strategy.DnsRedirect = "1.1.1.1"; // принудительный DoH через Cloudflare
// ИЛИ через DnsFixApplicator (уже есть)
```

**TCP_RST на хост X порт 443:**
```csharp
strategy.Rules.Add(new BypassRule {
    Host = "roberts-space-industries.com",
    Port = 443,
    Protocol = TCP,
    Method = "fake,multisplit",
    Params = "--dpi-desync=fake,multisplit --dpi-desync-split-pos=1 --dpi-desync-repeats=6 --dpi-desync-fooling=badseq"
});
```

**TLS_DPI (глубокая инспекция HTTPS):**
```csharp
strategy.Rules.Add(new BypassRule {
    Host = "manifest.robertsspaceindustries.com",
    Port = 443,
    Protocol = TCP,
    Method = "fake,fakedsplit",
    Params = "--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=tls_clienthello_www_google_com.bin"
});
```

**UDP_DROP (игровые порты):**
```csharp
strategy.Rules.Add(new BypassRule {
    Protocol = UDP,
    Ports = "64090-64094",
    Method = "fake",
    Params = "--dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1"
});
```

### Этап 5: Автоматическое тестирование стратегий
❌ **Не реализовано**

**Флоу:**
1. Применить стратегию (запустить WinDivert с параметрами)
2. Повторить Stage2 диагностику (те же хосты)
3. Если Pass → стратегия работает, показать пользователю
4. Если Fail → пробовать другую комбинацию (как в zapret — ALT/ALT2/...)

## Инсайты из zapret-discord-youtube

**Ключевые техники DPI bypass:**

### TCP методы:
- **multisplit** — разбивка пакета на части с overlap (seq overlap)
- **fake + badseq** — отправка фейкового пакета с неправильным seq number
- **fakedsplit** — fake packet + split
- **syndata** — данные в SYN пакете (для агрессивного DPI)
- **hostfakesplit** — модификация Host header

### UDP методы:
- **fake с autottl=2** — фейковые пакеты expire до DPI (не достигают сервера)
- **fake-quic** — используют реальный QUIC Initial packet

### Важные параметры:
- `--dpi-desync-repeats` — 6-12 повторов fake-пакетов (важно!)
- `--dpi-desync-autottl` — TTL так что пакет умрет до DPI
- `--dpi-desync-fooling` — badseq, ts, md5sig (обман DPI)
- `--dpi-desync-fake-tls` — использовать реальный TLS ClientHello (bin файл)

### Фильтрация целей:
```bat
--filter-tcp=443 --hostlist="lists/list-general.txt"
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun
```

**Discord специфика:**
- UDP 19294-19344, 50000-50100 (Voice)
- TCP 2053, 2083, 2087, 2096, 8443 (Media CDN)
- Отдельная стратегия для `discord.media`

## Конкретный план реализации

### Приоритет 1: Улучшить диагностику (Stage2)

**Файл:** `ViewModels/MainViewModel.cs` → Stage2 config

**Изменения:**
```csharp
// Включить RST detection
_config = new Config {
    EnableDns = true,
    EnableTcp = true,
    EnableHttp = false,  // Уже отключен
    EnableRst = true,    // ← ДОБАВИТЬ!
    EnableTrace = false,
    EnableUdp = false
};
```

**Новый файл:** `Tests/TlsTimingAnalyzer.cs`
```csharp
// Замерять время TLS handshake
// > 500ms = DPI inspection
// < 100ms = normal
```

**Обновить:** `Tests/HttpTest.cs`
```csharp
// Добавить детали где именно падает:
// - Timeout на ClientHello?
// - RST после ClientHello?
// - Timeout на ServerHello?
```

### Приоритет 2: Точная классификация блокировок

**Файл:** `Utils/ProblemClassifier.cs`

**Добавить enum:**
```csharp
public enum BlockageType {
    DNS_FILTERED,
    DNS_BOGUS,
    TCP_RST,
    TLS_DPI,
    UDP_DROP,
    FIREWALL_BLOCK,
    SLOW_CONNECTION
}
```

**Обновить `BlockageProblem`:**
```csharp
public class BlockageProblem {
    public BlockageType Type { get; set; }
    public string Target { get; set; }      // "host:port"
    public string Evidence { get; set; }     // Что конкретно сломано
    public string RecommendedFix { get; set; } // Какая стратегия поможет
}
```

**Улучшить логику классификации:**
```csharp
// DNS Fail + DoH OK = DNS_FILTERED
// TCP Pass + HTTP Fail + RST detected = TCP_RST
// TCP Pass + HTTP slow (>500ms) = TLS_DPI
// UDP sent but no response = UDP_DROP
```

### Приоритет 3: Генератор WinDivert стратегии

**Файл:** `Utils/BypassStrategyPlanner.cs`

**Реализовать реальную логику:**
```csharp
public static BypassProfile PlanBypassStrategy(
    List<BlockageProblem> problems,
    GameProfile? capturedProfile,
    IProgress<string>? progress)
{
    var profile = new BypassProfile();
    
    foreach (var problem in problems) {
        switch (problem.Type) {
            case BlockageType.DNS_FILTERED:
                // DoH через DnsFixApplicator (уже есть)
                progress?.Report("DNS блокировка: рекомендуется DoH (Cloudflare/Google)");
                break;
                
            case BlockageType.TCP_RST:
                // Fake packets для TCP
                profile.RedirectRules.Add(new BypassRedirectRule {
                    DomainPattern = problem.TargetHost,
                    Port = problem.TargetPort,
                    Protocol = "tcp",
                    WinDivertFilter = $"tcp.DstPort == {problem.TargetPort}",
                    Strategy = "fake,multisplit",
                    Parameters = "--dpi-desync=fake,multisplit --dpi-desync-repeats=6 --dpi-desync-fooling=badseq"
                });
                progress?.Report($"TCP RST на {problem.Target}: fake packets стратегия");
                break;
                
            case BlockageType.TLS_DPI:
                // TLS fragmentation
                profile.RedirectRules.Add(new BypassRedirectRule {
                    DomainPattern = problem.TargetHost,
                    Port = 443,
                    Protocol = "tcp",
                    Strategy = "fake,fakedsplit",
                    Parameters = "--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fake-tls=tls_clienthello.bin"
                });
                progress?.Report($"TLS DPI на {problem.Target}: fragmentation стратегия");
                break;
                
            case BlockageType.UDP_DROP:
                // Fake initial packets для UDP
                profile.RedirectRules.Add(new BypassRedirectRule {
                    Protocol = "udp",
                    PortRange = problem.PortRange,
                    Strategy = "fake",
                    Parameters = "--dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12"
                });
                progress?.Report($"UDP drop на портах {problem.PortRange}: fake initial пакеты");
                break;
        }
    }
    
    return profile;
}
```

### Приоритет 4: Тестирование стратегий

**Новый файл:** `Utils/BypassStrategyTester.cs`

```csharp
public class BypassStrategyTester {
    // 1. Запустить WinDivert с стратегией
    public async Task<bool> ApplyStrategy(BypassProfile strategy);
    
    // 2. Повторить Stage2 тесты
    public async Task<TestResults> RerunDiagnostics(GameProfile profile);
    
    // 3. Сравнить результаты (было Fail → стало Pass?)
    public BypassTestResult CompareResults(TestResults before, TestResults after);
}
```

**Флоу в MainViewModel:**
```csharp
// После Stage3: PlanBypassStrategy
var strategy = BypassStrategyPlanner.PlanBypassStrategy(problems, profile, progress);

// Stage3.5: Тест стратегии
var tester = new BypassStrategyTester();
await tester.ApplyStrategy(strategy);
var resultsAfter = await tester.RerunDiagnostics(profile);

if (resultsAfter.AllPassed) {
    MessageBox.Show("✓ Стратегия работает! Bypass применен.");
} else {
    // Попробовать альтернативную стратегию (ALT2, ALT3...)
}
```

## Минимальный MVP

**Что нужно для работающего решения:**

1. ✅ Stage1: Сниф (готово)
2. ⚠️ Stage2: Диагностика + RST detection (нужно включить RST)
3. ❌ Stage2.5: Точная классификация (BlockageType)
4. ❌ Stage3: Генератор стратегии (реализовать)
5. ❌ Stage3.5: Тест стратегии (опционально, но желательно)

**Начать с:**
1. Включить `EnableRst = true` в Stage2
2. Обновить `ProblemClassifier` с точными типами блокировок
3. Реализовать `BypassStrategyPlanner` с WinDivert параметрами

## Инсайты из GoodbyeDPI (что реально применимо)

### 1. TLS/HTTP фрагментация

- **TLS фрагментация по SNI** (`--frag-by-sni`)
    - Идея: находить в ClientHello смещение поля SNI и резать пакет так, чтобы
        значение SNI начиналось со второго сегмента.
    - Что взять:
        - В `WinDivertBypassManager` добавить парсер TLS ClientHello уровня SNI
            и режим "fragment-before-sni" вместо тупого `TlsFirstFragmentSize = N`.
        - Использовать этот режим только для хостов из профиля (аналог blacklist).

- **Обратная фрагментация** (`--reverse-frag`)
    - Идея: отправлять фрагменты в обратном порядке, чтобы DPI, который
        делает reassemble, не смог нормально распознать поток.
    - Что взять:
        - В `RunTlsFragmenter` добавить экспериментальный режим reverse-frag:
            сначала инжектить второй фрагмент, потом первый.
        - Включать только для конкретных целей через профиль `BypassProfile`.

- **Native fragmentation** (`--native-frag`)
    - Идея: не занижать TCP window, а реально резать payload на несколько
        пакетов, сохраняя нормальные параметры TCP.
    - Что взять:
        - Пересмотреть текущую реализацию фрагментации: максимально приблизить
            логику к native-frag (менять только payload и длины, не трогая
            окно и флаги).

### 2. Fake Request Mode (ложные пакеты)

- **Fake TLS/HTTP пакеты с низким TTL / неправильным SEQ/CHK**
    - GoodbyeDPI шлёт один или несколько фейковых запросов, которые DPI
        видит как "запрос к запрещённому ресурсу", но реальный сервер их
        не получает (TTL истёк, checksum неверный, seq устаревший).
    - Что взять в MVP для TLS:
        - В `WinDivertBypassManager` спроектировать простую функцию:
            `SendFakeTlsClientHelloAsync(IPAddress ip, int port, string sni, FakeMode mode)`.
        - `FakeMode` варианты:
            - `LowTtl` — IP TTL занижен так, чтобы пакет умер до сервера;
            - `WrongChecksum` — TCP checksum заведомо неверный;
            - `WrongSeq` — seq в прошлом.
        - Вызывать эту функцию из `LiveTestingPipeline` **до** реальной
            попытки TLS‑handshake для целей с `TLS_DPI`/`TCP_RST`.

- **Множество повторов** (`--fake-resend`, `--dpi-desync-repeats`)
    - Что взять:
        - При Fake Request Mode отправлять не один, а 3–6 фейковых пакетов
            подряд для повышения шанса, что DPI "насытится" ложными сессиями.

### 3. DNS редирект на нестандартный порт

- **`--dns-addr` + `--dns-port` / `--dnsv6-addr`**
    - GoodbyeDPI перенаправляет plain UDP DNS на публичный резолвер
        (например, `77.88.8.8:1253`), чтобы обойти провайдерский DNS spoofing.
    - Что взять:
        - Добавить в `BypassProfile` режим `DnsRedirect` с указанием IP/порта.
        - В `WinDivertBypassManager` реализовать фильтр для `udp.DstPort == 53`
            и переписывание dst IP/port на указанные значения.
        - Интегрировать как стратегию для `DNS_FILTERED` / `DNS_BOGUS` помимо
            уже существующего `DnsFixApplicator`.

### 4. Таргетинг по доменам (аналог blacklist)

- **`--blacklist` + SNI/Host‑match**
    - GoodbyeDPI применяет трюки только к нужным доменам из списков.
    - Что взять:
        - Расширить `BypassProfile`/`BypassRedirectRule` так, чтобы
            WinDivert‑фильтры могли опционально ограничиваться по SNI/Host,
            а не только по IP/порту.
        - В `LiveTestingPipeline` и профилях Star Citizen/FsHud держать явные
            доменные паттерны (аналог blacklist) и включать тяжёлые режимы
            (fake, reverse-frag) только для них.

### 5. Ограничение нагрузки (`--max-payload`)

- **Пропуск больших пакетов**
    - GoodbyeDPI не обрабатывает TCP пакеты с большим payload, чтобы не
        тратить CPU на уже установленные сессии/скачивания.
    - Что взять:
        - Добавить порог `MaxPayloadBytes` в профиль fragmenter/fake‑логики,
            чтобы `RunTlsFragmenter` и будущий Fake Request Mode просто игнорировали
            огромные сегменты.

## Полезные ресурсы

- **zapret-discord-youtube**: https://github.com/Flowseal/zapret-discord-youtube
    - 10+ готовых стратегий (general.bat, ALT, ALT2-10, FAKE TLS)
    - Реальные параметры для Discord/YouTube/игр
  
- **zapret документация**: https://github.com/bol-van/zapret/blob/master/docs/readme.md#nfqws
    - Полное описание всех параметров nfqws/winws
  
- **WinDivert**: https://reqrypt.org/windivert-doc.html
    - Документация по фильтрам и API
