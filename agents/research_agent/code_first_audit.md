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
- **Асинхронность:** Смешанная. Есть `async/await`, но встречаются `async void` (опасно) и `.Result` (Deadlock).
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
    - `todo_detect.md`: Ссылается на `StandardHostTester`, который нужно проверить на соответствие текущему `Tests/`.

### 2.2. Артефакты кода (Dead/Legacy Code)
1.  **`MainViewModelRefactored`:**
    - Суффикс `Refactored` — это временная метка, ставшая постоянной. Это "шум" в нейминге.
    - *Рекомендация:* Переименовать в `MainViewModel`.

2.  **`Config.cs` (CLI парсер):**
    - Если CLI вырезан, используется ли класс `Config` для чего-то еще, кроме загрузки профиля?
    - *Нужна проверка:* Если там осталась логика парсинга аргументов (`CommandLineParser`), она теперь мертвый груз.

### 2.3. Проблемы реализации (Code Issues)
1.  **Deadlock Trap:** `Tests/UdpProbeRunner.cs` использует `.Result`. Это бомба замедленного действия для WPF.
2.  **Crash Trap:** `async void` в инициализации (`BypassController.cs`).
3.  **Hardcoded Sleep:** `Thread.Sleep(50)` в сервисах мониторинга. Блокирует поток пула.

---

## 3. План очистки (Cleanup Plan)

1.  **Documentation Purge:**
    - Вычистить все упоминания CLI и Material Design из `copilot-instructions.md`, `README.md`, `ARCHITECTURE_CURRENT.md`.
    - Актуализировать описание архитектуры (только GUI).

2.  **Code Cleanup:**
    - Переименовать `MainViewModelRefactored` -> `MainViewModel`.
    - Проверить и почистить `Config.cs` (удалить парсинг аргументов, если он там есть).
    - Исправить `.Result` и `async void`.

3.  **Verification:**
    - Убедиться, что `StandardHostTester` (из `todo_detect.md`) соответствует реальности или удалить этот файл.
