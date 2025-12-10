# ISP_Audit — Архитектура (v2)

**Дата обновления:** 10.12.2025
**Версия:** 2.0 (GUI-only)
**Технологии:** .NET 9, WPF, WinDivert 2.2.0

---

## 1. Обзор

ISP_Audit — это Windows-приложение для диагностики сетевых блокировок (DPI, DNS-фильтрация, TCP RST injection) и автоматического подбора методов обхода. Приложение работает в режиме реального времени, анализируя исходящий трафик пользователя.

### Ключевые особенности
*   **Passive Sniffing**: Захват новых TCP/UDP соединений через WinDivert.
*   **Active Testing**: Проверка доступности хостов (DNS, TCP Handshake, TLS Handshake).
*   **Classification**: Определение типа блокировки (DNS, TCP RST, DPI Redirect, и т.д.).
*   **Auto-Bypass**: Автоматический подбор стратегий обхода (Fragmentation, Disorder, Fake TTL).

---

## 2. Архитектура высокого уровня

```mermaid
graph TD
    User[Пользователь] --> UI[WPF UI (MainWindow)]
    UI --> VM[MainViewModelRefactored]
    
    subgraph Orchestration Layer
        VM --> Orchestrator[DiagnosticOrchestrator]
        Orchestrator --> Pipeline[LiveTestingPipeline]
    end
    
    subgraph Core Logic
        Pipeline --> Sniffer[TrafficCollector]
        Pipeline --> Tester[StandardHostTester]
        Pipeline --> Classifier[StandardBlockageClassifier]
        Pipeline --> BypassCoord[BypassCoordinator]
    end
    
    subgraph Network Layer
        Sniffer --> WinDivert[WinDivert Driver]
        Tester --> Network[Network Stack]
        BypassCoord --> TrafficEngine[TrafficEngine]
    end
    
    TrafficEngine --> WinDivert
```

---

## 3. Компоненты системы

### 3.1 UI Layer (WPF)
*   **`MainWindow.xaml`**: Основное окно. Использует MaterialDesignInXaml.
*   **`MainViewModelRefactored`**: Главная ViewModel. Управляет состоянием UI, командами и связью с оркестратором.
*   **`BypassController`**: ViewModel для управления настройками обхода (Disorder, Fake, DoH).

### 3.2 Orchestration Layer
*   **`DiagnosticOrchestrator`**: Центральный класс, управляющий жизненным циклом диагностики. Запускает/останавливает пайплайн, следит за процессами.
*   **`LiveTestingPipeline`**: Конвейер обработки данных. Связывает компоненты через асинхронные каналы (`System.Threading.Channels`).

### 3.3 Core Modules
*   **`TrafficCollector`**: Слушает сетевой интерфейс через WinDivert. Фильтрует "шумные" хосты (CDN, Microsoft, Google) и передает новые уникальные IP/Host в пайплайн.
*   **`StandardHostTester`**: Выполняет активные проверки:
    1.  **DNS**: Резолвинг имени (System DNS).
    2.  **TCP**: Попытка соединения (Syn/Ack).
    3.  **TLS**: Проверка Handshake (ClientHello).
*   **`StandardBlockageClassifier`**: Анализирует результаты тестов и определяет тип проблемы:
    *   `DNS_TIMEOUT` / `DNS_ERROR`: Проблемы с DNS.
    *   `TCP_RST`: Сброс соединения (активный DPI).
    *   `TCP_TIMEOUT`: Дроп пакетов.
    *   `TLS_DPI`: Блокировка на этапе Handshake.
*   **`BypassCoordinator`**: Если обнаружена блокировка, пробует применить стратегии обхода и делает ретест.

### 3.4 Bypass Layer
*   **`TrafficEngine`**: Обертка над WinDivert. Управляет правилами фильтрации и модификации пакетов.
*   **`BypassFilter`**: Реализует логику модификации пакетов (разбиение на фрагменты, перестановка, подмена TTL).

---

## 4. Поток данных (Data Flow)

1.  **Sniffing**: Пользователь открывает браузер. `TrafficCollector` перехватывает SYN-пакет к `example.com`.
2.  **Queueing**: Хост `example.com` попадает в канал `_snifferQueue`.
3.  **Testing**: Воркер забирает хост и запускает `StandardHostTester`.
    *   Проверяется DNS.
    *   Проверяется TCP/TLS.
4.  **Classification**: Результат теста передается в `StandardBlockageClassifier`.
5.  **Decision**:
    *   Если `Status == OK` -> Результат отправляется в UI (зеленый).
    *   Если `Status != OK` -> `BypassCoordinator` пробует включить стратегию (например, `Disorder`).
    *   Проводится ретест.
6.  **Reporting**: Итоговый результат (с блокировкой или успешным обходом) отображается в `TestResultsManager` -> `DataGrid`.

---

## 5. Структура проекта

```
ISP_Audit/
├── Core/                   # Ядро логики
│   ├── Modules/            # Тестеры, Классификаторы
│   ├── Models/             # DTO (HostDiscovered, TestResult)
│   └── Traffic/            # Работа с трафиком
├── Utils/                  # Утилиты и сервисы (Pipeline, Collector)
├── ViewModels/             # MVVM ViewModels
├── Views/                  # XAML окна и контролы
├── Bypass/                 # Логика обхода (WinDivert)
├── Profiles/               # JSON профили целей
└── legacy/                 # Устаревший код (Tests/)
```

---

## 6. Ключевые технические решения

*   **Asynchronous I/O**: Весь I/O (сеть, файлы) строго асинхронный (`async/await`).
*   **Bounded Channels**: Для передачи данных между этапами пайплайна используются ограниченные каналы (Backpressure protection).
*   **Single-File Deployment**: Приложение собирается в один EXE файл (Self-contained).
*   **WinDivert**: Используется как для пассивного мониторинга, так и для активного вмешательства в трафик (Bypass).

---

## 7. Известные ограничения

*   Требуются права администратора (для драйвера WinDivert).
*   Несовместимость с некоторыми античитами (из-за подписанного драйвера, но нестандартного использования).
*   Только Windows (x64).
