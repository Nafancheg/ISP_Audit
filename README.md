# ISP Audit

**Диагностика сетевых проблем и восстановление доступа для игр и приложений**

Windows-приложение для анализа сетевого трафика, выявления проблем соединения (DPI, DNS, нестабильные TCP-сессии) и их автоматического устранения. Работает с любым приложением — просто укажите .exe файл.

![.NET 9](https://img.shields.io/badge/.NET-9.0-purple)
![Windows](https://img.shields.io/badge/Windows-10%2F11-blue)
![WinDivert](https://img.shields.io/badge/WinDivert-2.2-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## Как это работает

1. **Выбираете .exe** игры или приложения
2. **Запускаете диагностику** — приложение стартует автоматически
3. **Наблюдаете в реальном времени** как тестируются обнаруженные соединения
4. **Получаете результат** — какие хосты работают нестабильно и почему

Оптимизация соединения включается автоматически при старте диагностики.

## Интерфейс

![ISP Audit - Главное окно](docs/ssh0t.png)

## Возможности

### Live Testing Pipeline
- **Перехват трафика** через WinDivert (Socket + Network layer)
- **SNI-парсинг** — определение реальных доменов из TLS ClientHello
- **DNS-мониторинг** — захват DNS-запросов/ответов приложения
- **Параллельное тестирование** — проверка хостов по мере обнаружения
- **Продвинутая детекция**:
  - **HTTP Redirect** — обнаружение "заглушек" провайдера
  - **RST Inspection** — анализ TTL для выявления DPI-инжектов
  - **TCP Retransmissions** — подсчет потерь пакетов
  - **Fail Counters** — анализ стабильности во времени
- **Классификация проблем**: `DNS_FILTERED`, `TLS_AUTH_FAILURE` (legacy: `TLS_DPI`), `TCP_CONNECTION_RESET` (legacy: `TCP_RST`), `TCP_CONNECT_TIMEOUT` (legacy: `TCP_TIMEOUT`), `HTTP_REDIRECT_DPI`

### Оптимизация соединения
- **TrafficEngine 2.0** — модульная архитектура на базе Chain of Responsibility
- **Performance Monitoring** — встроенный мониторинг задержек обработки пакетов (<0.5ms)
- **TLS Fragmentation** — разбиение ClientHello для стабильности
- **TLS Disorder** — отправка фрагментов в обратном порядке (улучшает совместимость)
- **TLS Fake** — дополнительные пакеты для повышения стабильности
- **RST Drop** — фильтрация аномальных TCP RST пакетов
- **DoH (DNS-over-HTTPS)** — защищённый DNS через Cloudflare/Google/Quad9

### Отчётность
- Генерация профиля приложения (JSON)
- Подробный лог в `Logs/isp_audit_*.log`
- Статистика: хосты ✓/❌, задержки, типы проблем

## Установка

### Готовый exe (рекомендуется)
1. Скачайте `ISP_Audit.exe` из [Releases](https://github.com/Nafancheg/ISP_Audit/releases)
2. Скачайте [WinDivert 2.2](https://github.com/basil00/Divert/releases) и распакуйте `WinDivert64.sys` и `WinDivert.dll` рядом с exe
3. Запустите **от имени администратора** (требуется для WinDivert)

### Сборка из исходников

```powershell
# Требуется .NET 9 SDK
git clone https://github.com/Nafancheg/ISP_Audit.git
cd ISP_Audit

# Скачайте WinDivert 2.2 и распакуйте в native/
# - native/WinDivert64.sys
# - native/WinDivert.dll

# Соберите тестовое приложение (нужно для тестирования)
cd TestNetworkApp
dotnet publish -c Release -r win-x64 --self-contained false -o bin/Publish
cd ..

# Debug
dotnet build

# Release single-file
dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:SelfContained=true -o ./publish
```

### TestNetworkApp (для разработки)
Тестовое приложение для калибровки и проверки работы ISP Audit:
- Устанавливает соединения к 7 известным хостам (Google, YouTube, Discord, GitHub и др.)
- Работает 60 секунд с повторяющимися запросами
- Используйте как эталон для проверки захвата трафика

```powershell
# Сборка
cd TestNetworkApp
dotnet publish -c Release -r win-x64 --self-contained false -o bin/Publish

# Использование: в ISP Audit выберите TestNetworkApp\bin\Publish\TestNetworkApp.exe
```

## Использование

### GUI (по умолчанию)

```powershell
# Запуск GUI
.\ISP_Audit.exe

# или из исходников
dotnet run
```

1. Нажмите **Обзор** и выберите .exe файл приложения
2. Нажмите **Запустить диагностику**
3. Приложение запустится автоматически
4. Используйте приложение как обычно — ISP Audit анализирует трафик в фоне
5. Закройте приложение или нажмите **Стоп** — получите результаты

### Overlay (мини-окно)
Во время диагностики отображается компактное окно поверх всех окон:
- Время сессии
- Количество соединений
- Кнопка остановки

### Результаты
После завершения:
- Профиль сохраняется в `Profiles/{AppName}_{timestamp}.json`
- Лог сессии в `Logs/isp_audit_vm_{timestamp}.log`

## Типы проблем

| Статус | Описание | Решение |
|--------|----------|--------|
| `TLS_AUTH_FAILURE` (legacy: `TLS_DPI`) | Ошибка TLS рукопожатия (AuthenticationException) | Зависит от сценария (прокси/антивирус/фильтрация); часто помогает VPN |
| `TLS_HANDSHAKE_TIMEOUT` (legacy: `TLS_TIMEOUT`) | TLS рукопожатие не завершается за таймаут | VPN / прокси |
| `TCP_CONNECTION_RESET` (legacy: `TCP_RST`) | Сброс соединения (TCP reset) | DROP_RST |
| `TCP_CONNECT_TIMEOUT` (legacy: `TCP_TIMEOUT`) | TCP connect не завершается за таймаут | VPN / прокси |
| `DNS_FILTERED` | DNS возвращает пустой ответ | DoH |
| `DNS_BOGUS` | DNS возвращает некорректный IP | DoH |
| `HTTP_REDIRECT_DPI` | Подмена HTTP-ответа провайдером | VPN / TTL Trick |
| `TCP_RETRY_HEAVY` | Высокий % ретрансмиссий пакетов | VPN / Проверка канала |

## Архитектура

```mermaid
graph TB
    subgraph UI["🖥️ UI Layer"]
        MainVM[MainViewModel]
        BypassCtrl[BypassController]
        TestResults[TestResultsManager]
    end
    
    subgraph Orchestration["🎭 Orchestration"]
        Orchestrator[DiagnosticOrchestrator]
        Pipeline[LiveTestingPipeline<br/>Channels]
    end
    
    subgraph Core["⚙️ Core Logic"]
        Collector[TrafficCollector<br/>Smart Sniffer]
        Filters[NoiseFilter +<br/>UnifiedFilter]
        Tester[StandardHostTester<br/>DNS/TCP/TLS]
        Classifier[Blockage<br/>Classifier]
        StateStore[BlockageStateStore]
    end
    
    subgraph Inspection["🔍 Inspection"]
        Inspectors[RST/UDP/Retrans/<br/>Redirect Detectors]
    end
    
    subgraph Network["🌐 Network"]
        WinDivert[WinDivert Driver]
        Services[ConnectionMonitor<br/>DnsParser<br/>PidTracker]
        TrafficEngine[TrafficEngine +<br/>BypassFilter]
    end
    
    %% Main Flow
    MainVM --> Orchestrator
    Orchestrator --> Pipeline
    Orchestrator --> Collector
    
    Pipeline -.->|Queue| Tester
    Pipeline -.->|Queue| Classifier
    
    Collector --> Filters
    Filters --> Pipeline
    Tester --> Classifier
    Classifier --> StateStore
    StateStore --> Inspectors
    StateStore --> TestResults
    
    %% Network Layer
    Services --> Collector
    Services --> WinDivert
    Tester -.-> WinDivert
    
    %% Bypass
    BypassCtrl --> TrafficEngine
    TrafficEngine --> WinDivert
    Classifier -.->|Recommendations| BypassCtrl
    
    %% Styling
    classDef ui fill:#1976d2,stroke:#0d47a1,color:#fff
    classDef core fill:#7b1fa2,stroke:#4a148c,color:#fff
    classDef network fill:#388e3c,stroke:#1b5e20,color:#fff
    classDef inspect fill:#f57c00,stroke:#e65100,color:#fff
    
    class MainVM,BypassCtrl,TestResults ui
    class Collector,Filters,Tester,Classifier,StateStore core
    class WinDivert,Services,TrafficEngine network
    class Inspectors inspect
```

### Ключевые компоненты

#### 🖥️ UI Layer
| Компонент | Файл | Описание |
|-----------|------|----------|
| MainViewModel | `ViewModels/MainViewModelRefactored.cs` | Корневая ViewModel, связывает UI и логику |
| BypassController | `ViewModels/BypassController.cs` | Управление стратегиями обхода (Bypass) |
| TestResultsManager | `ViewModels/TestResultsManager.cs` | Управление результатами тестов и рекомендациями |

#### 🎭 Orchestration
| Компонент | Файл | Описание |
|-----------|------|----------|
| DiagnosticOrchestrator | `ViewModels/DiagnosticOrchestrator.cs` | Координатор процесса диагностики |
| LiveTestingPipeline | `Utils/LiveTestingPipeline.cs` | Конвейер обработки: Sniffer → Tester → Classifier |

#### ⚙️ Core Logic
| Компонент | Файл | Описание |
|-----------|------|----------|
| TrafficCollector | `Utils/TrafficCollector.cs` | Сбор сетевых событий и обогащение данными |
| UnifiedTrafficFilter | `Utils/UnifiedTrafficFilter.cs` | Фильтрация шума и дедупликация |
| StandardHostTester | `Core/Modules/StandardHostTester.cs` | Активное тестирование хостов (DNS, TCP, TLS) |
| BlockageClassifier | `Core/Modules/StandardBlockageClassifier.cs` | Анализ результатов и определение типа блокировки |
| BlockageStateStore | `Core/Modules/InMemoryBlockageStateStore.cs` | Хранение состояния блокировок и истории |

#### 🔍 Inspection
| Компонент | Файл | Описание |
|-----------|------|----------|
| RstInspectionService | `Core/Modules/RstInspectionService.cs` | Анализ TCP RST пакетов (TTL, Flags) |
| HttpRedirectDetector | `Core/Modules/HttpRedirectDetector.cs` | Детекция HTTP-заглушек провайдера |
| TcpRetransmissionTracker | `Core/Modules/TcpRetransmissionTracker.cs` | Подсчет потерь пакетов (Retransmissions) |
| UdpInspectionService | `Core/Modules/UdpInspectionService.cs` | Анализ UDP трафика (QUIC/DTLS) |

#### 🌐 Network
| Компонент | Файл | Описание |
|-----------|------|----------|
| TrafficEngine | `Core/Traffic/TrafficEngine.cs` | Движок перехвата пакетов (WinDivert wrapper) |
| BypassFilter | `Core/Traffic/Filters/BypassFilter.cs` | Применение стратегий обхода на уровне пакетов |
| ConnectionMonitor | `Utils/ConnectionMonitorService.cs` | Мониторинг сокетов (WinDivert/IP Helper) |
| DnsParser | `Utils/DnsSnifferService.cs` | Парсинг DNS-пакетов и SNI |
| PidTracker | `Utils/PidTrackerService.cs` | Отслеживание PID целевого процесса |

## Системные требования

- **ОС**: Windows 10/11 (x64)
- **Права**: Администратор (для WinDivert)
- **.NET**: 9.0 (включён в single-file exe)

## FAQ

**Q: Почему нужны права администратора?**  
A: WinDivert — это kernel driver для перехвата пакетов. Без админ-прав он не запустится.

**Q: Влияет ли на другие приложения?**  
A: Нет. Оптимизация применяется только к выбранному приложению (фильтрация по PID).

**Q: Безопасно ли это?**  
A: Да. Приложение:
- Не отправляет данные в интернет
- Не модифицирует системные файлы
- Оптимизация отключается при закрытии ISP Audit

**Q: Что делать если "0 соединений"?**  
1. Убедитесь что запустили от администратора
2. Убедитесь что приложение делает сетевые запросы
3. Попробуйте `ipconfig /flushdns` перед диагностикой

**Q: Hostname показывает технические имена (1e100.net)?**  
A: Это reverse-DNS от Google CDN. SNI-парсинг показывает реальные домены, если они доступны в TLS ClientHello.

## Лицензия

MIT License. См. [LICENSE](LICENSE).

## Благодарности

- [WinDivert](https://github.com/basil00/Divert) — перехват пакетов
- [MaterialDesignInXaml](https://github.com/MaterialDesignInXAML/MaterialDesignInXamlToolkit) — UI компоненты

