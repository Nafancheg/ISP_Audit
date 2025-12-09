# Глубокий аудит проекта ISP_Audit (Code-First Analysis)

**Дата:** 9 декабря 2025 г.
**Методология:** Анализ "от кода к документации". Сначала фиксируется фактическое состояние кодовой базы, затем оно сравнивается с документацией и здравым смыслом.

---

## 1. Фактическое состояние проекта (Code Reality)

### 1.1. Точка входа (`Program.cs`)
- **Режим работы:** Только GUI (WPF).
- **Аргументы:** Игнорируются.
- **DI:** Отсутствует. Ручная инициализация.
- **Профиль:** Загружается "Default".

### 1.2. UI Слой (`App.xaml`, `MainWindow.xaml`)
- **Фреймворк:** WPF (.NET 9).
- **Стили:** Кастомные (`App.xaml`).
- **Material Design:** **Отсутствует** (нет ссылок в `.csproj`, нет пространств имен в XAML).
- **Архитектура:** MVVM (частично). `MainWindow.xaml.cs` содержит логику обработки кликов (нарушение MVVM), но есть `MainViewModelRefactored`.

### 1.3. Логика (`ViewModels`, `Core`)
- **ViewModel:** `MainViewModelRefactored` — основной класс. Старого `MainViewModel` нет.
- **Асинхронность:** Смешанная. Есть `async/await`, но встречаются `async void` (опасно) и `.Result` (плохой стиль).
- **Сетевой слой:** WinDivert (P/Invoke).

---

## 2. Найденные несоответствия и артефакты (Discrepancies)

### 2.1. Артефакты документации (Phantom Features)
Документация описывает функции, которых **нет в коде**:
1.  **CLI Режим:**
    - *Документация (`copilot-instructions.md`):* "Ships as single-file executable... dual GUI/CLI mode... `dotnet run -- --targets ...`".
    - *Код:* Вырезан полностью.
    - *Вердикт:* **Удалить упоминания CLI из всех docs.**

2.  **Material Design:**
    - *Документация:* "MaterialDesignInXaml 5.1.0... Material Design cards shown...".
    - *Код:* Библиотека не подключена. Используются стандартные контролы с кастомными стилями.
    - *Вердикт:* **Удалить упоминания Material Design.**

3.  **Устаревшие файлы документации:**
    - `todo_detect.md`: Ссылается на `StandardHostTester`, который реализован с ошибками (см. ниже).

### 2.2. Артефакты кода (Dead/Legacy Code)
1.  **Мертвые тесты:**
    - Файлы `Tests/IspTest.cs`, `Tests/RouterTest.cs`, `Tests/SoftwareTest.cs` существуют, но **нигде не используются** (0 usages).
    - *Вердикт:* **Удалить.**

2.  **`MainViewModelRefactored`:**
    - Суффикс `Refactored` — это временная метка, ставшая постоянной.
    - *Рекомендация:* Переименовать в `MainViewModel`.

3.  **`Config.cs`:**
    - Содержит legacy-свойства (`NoTrace`), которые не используются в GUI.

### 2.3. Проблемы реализации (Logic Bugs)
1.  **DNS Blindness (Критично):**
    - `LiveTestingPipeline` использует `StandardHostTester`.
    - `StandardHostTester` (строки 23-25) жестко задает `dnsOk = true` и `dnsStatus = "OK"`.
    - **Результат:** В режиме Live-диагностики приложение **физически не может обнаружить DNS-блокировку**, так как тестер всегда рапортует "OK".
    - *Решение:* Интегрировать логику из `DnsTest.cs` в `StandardHostTester` или заменить тестер.

2.  **Async Risks:**
    - `Tests/UdpProbeRunner.cs`: Использование `.Result` (хоть и под `WhenAny`, но это плохой стиль, скрывающий исключения в `AggregateException`).
    - `MainViewModelRefactored.cs`: `async void` в методах инициализации (риск краша).

---

## 3. План очистки (Cleanup Plan)

1.  **Documentation Purge:**
    - Вычистить все упоминания CLI и Material Design из `copilot-instructions.md`, `README.md`, `ARCHITECTURE_CURRENT.md`.
    - Актуализировать описание архитектуры (только GUI).

2.  **Code Cleanup:**
    - Удалить мертвые файлы (`IspTest.cs`, `RouterTest.cs`, `SoftwareTest.cs`).
    - Переименовать `MainViewModelRefactored` -> `MainViewModel`.
    - Исправить `StandardHostTester` (внедрить нормальную проверку DNS).
    - Исправить `.Result` и `async void`.

3.  **Verification:**
    - Проверить работу Live-режима после исправления DNS-тестера.
