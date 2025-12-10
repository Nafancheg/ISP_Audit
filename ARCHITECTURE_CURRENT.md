# ISP_Audit — Архитектура (v3.0)

**Дата обновления:** 10.12.2025
**Версия:** 3.0 (Unified Structure)
**Технологии:** .NET 9, WPF, WinDivert 2.2.0

---

## 1. Обзор проекта

**ISP_Audit** — это специализированный инструмент для диагностики сетевых блокировок на уровне провайдера (ISP). Приложение работает в режиме реального времени, анализируя исходящий трафик пользователя, и автоматически определяет наличие DPI (Deep Packet Inspection), DNS-фильтрации или TCP RST инъекций.

### Основные возможности
*   **Passive Sniffing**: Перехват новых соединений через драйвер WinDivert без разрыва связи.
*   **Active Testing**: Активная проверка подозрительных хостов (DNS, TCP, TLS).
*   **Classification**: Эвристический анализ типа блокировки.
*   **Bypass Strategies**: Встроенные методы обхода (Fragmentation, Disorder, Fake TTL).

---

## 2. Архитектура (High-Level)

```mermaid
graph TD
    User[Пользователь] --> UI[WPF UI (MainWindow)]
    UI --> VM[MainViewModelRefactored]
    
    subgraph Orchestration
        VM --> Orchestrator[DiagnosticOrchestrator]
        Orchestrator --> Pipeline[LiveTestingPipeline]
    end
    
    subgraph Core Logic
        Pipeline --> ConnectionMonitor[ConnectionMonitorService]
        ConnectionMonitor --> Sniffer[TrafficCollector]
        Sniffer --> NoiseFilter[NoiseHostFilter]
        NoiseFilter --> Tester[StandardHostTester]
        Tester --> Classifier[StandardBlockageClassifier]
        Classifier --> StateStore[InMemoryBlockageStateStore]
    end
    
    subgraph Inspection Services
        StateStore --> RstInspector[RstInspectionService]
        StateStore --> UdpInspector[UdpInspectionService]
        StateStore --> RetransTracker[TcpRetransmissionTracker]
        StateStore --> RedirectDetector[HttpRedirectDetector]
    end
    
    subgraph Network Layer
        Sniffer --> WinDivert[WinDivert Driver]
        Tester --> Network[Network Stack]
        VM --> BypassCtrl[BypassController]
        BypassCtrl --> TrafficEngine[TrafficEngine]
    end
```

---

## 3. Компоненты системы

### 3.1 UI Layer (WPF)
*   **`MainWindow.xaml`**: Основной интерфейс на базе MaterialDesignInXaml.
*   **`MainViewModelRefactored`**: Связующее звено между UI и бизнес-логикой.
*   **`BypassController`**: Управление настройками обхода (Disorder, Fake, DoH).

### 3.2 Core Modules (`IspAudit.Core`)
*   **`TrafficCollector`**: Фильтрация и захват трафика.
*   **`StandardHostTester`**: Исполнитель активных проверок (DNS Resolve, TCP Handshake, TLS Hello).
*   **`StandardBlockageClassifier`**: Логика принятия решений (Blocked vs OK).
*   **`InMemoryBlockageStateStore`**: Хранилище состояния (предотвращение дублей).

### 3.3 Inspection Services
Фоновые сервисы для глубокого анализа:
*   **`RstInspectionService`**: Анализ TTL/IP-ID у RST пакетов.
*   **`UdpInspectionService`**: Детекция блокировок QUIC/UDP.
*   **`TcpRetransmissionTracker`**: Подсчет потерь пакетов.
*   **`HttpRedirectDetector`**: Обнаружение заглушек провайдера.

### 3.4 Bypass Layer (`IspAudit.Bypass`)
*   **`TrafficEngine`**: Низкоуровневая работа с пакетами через WinDivert.
*   **`BypassFilter`**: Реализация стратегий обхода (Desync, Fragmentation).

---

## 4. Структура проекта

```
ISP_Audit/
├── Core/                       # Бизнес-логика и модели
│   ├── Interfaces/             # Контракты (IHostTester, etc.)
│   ├── Models/                 # DTO (HostTested, TestResult)
│   ├── Modules/                # Реализация логики (Tester, Classifier)
│   └── Traffic/                # Работа с сетью (TrafficEngine)
│
├── ViewModels/                 # MVVM
│   ├── MainViewModelRefactored.cs
│   └── DiagnosticOrchestrator.cs
│
├── Utils/                      # Инфраструктура
│   ├── LiveTestingPipeline.cs  # Основной конвейер
│   ├── TrafficCollector.cs     # Сниффер
│   └── FixService.cs           # Системные фиксы (DNS)
│
├── Bypass/                     # Логика обхода
│   ├── StrategyMapping.cs      # Рекомендации
│   └── WinDivertNative.cs      # P/Invoke
│
└── docs/                       # Документация
    ├── ARCHITECTURE_CURRENT.md
    └── WORK_PLAN.md
```

---

## 5. Известные ограничения (Known Issues)

| Компонент | Ограничение | Влияние |
|-----------|-------------|---------|
| **WinDivert** | Требует права Администратора | Приложение не работает без UAC elevation. |
| **Deployment** | Single-file ~160MB | Большой размер из-за встроенного .NET Runtime и WPF. |
| **VPN** | Конфликт с TAP-адаптерами | Возможны ложные срабатывания или пропуск трафика при включенном VPN. |
| **Locale** | CP866 (OEM) | Требует корректной кодировки для чтения вывода `tracert.exe` в русской Windows. |

---

## 6. Технический долг (Technical Debt)

1.  **Global State**: Использование статических `Config.ActiveProfile` и `Program.Targets` затрудняет тестирование.
2.  **Singleton**: `NoiseHostFilter.Instance` создает скрытые зависимости.
3.  **Manual Composition**: Отсутствие DI-контейнера, ручное создание графа объектов в `MainWindow`.
4.  **Hardcoded Paths**: Пути к профилям и логам иногда зашиты в коде.

---

## 7. План развития (Roadmap)

### Phase 4: Refactoring (Q1 2026)
*   [ ] Внедрение DI Container (Microsoft.Extensions.DependencyInjection).
*   [ ] Уход от статических конфигов.
*   [ ] Покрытие тестами `StandardBlockageClassifier`.

### Phase 5: Advanced Bypass
*   [ ] Поддержка новых стратегий (Geneva, Kyber).
*   [ ] Автоматический подбор стратегии (Auto-Tune).

### Phase 6: UI/UX
*   [ ] Графики задержек в реальном времени.
*   [ ] История проверок с экспортом в PDF.
