# ISP_Audit.UITests

Автоматизированные UI тесты для ISP_Audit на базе **FlaUI** (UI Automation для Windows Desktop).

## Структура

- `ExeScenarioTests.cs` - тесты для Exe-scenario workflow (основаны на `docs/e2e_test_checklist.md`)

## Что тестируется

### Test01_FullFlow_Stage1To3_Automatic
- ✅ Выбор Exe-scenario
- ✅ Установка пути к TestNetworkApp.exe
- ✅ Клик "Analyze Traffic" и блокировка кнопки
- ✅ Stage1 progress bar (30 сек)
- ✅ Автоматический переход Stage1→Stage2 (БЕЗ MessageBox)
- ✅ Stage2 progress bar и тесты
- ✅ Автоматический переход Stage2→Stage3
- ✅ Stage3 progress bar
- ✅ Проверка что кнопка "Сбросить" доступна

### Test02_ResetButton_ClearsState
- ✅ Запуск упрощённого flow
- ✅ Нажатие "Сбросить"
- ✅ Проверка что кнопка "Analyze" снова активна
- ✅ Проверка что progress bars сброшены

### Test03_ButtonBlocking_DuringOperation
- ✅ Запуск Stage1
- ✅ Проверка что все кнопки заблокированы во время операции:
  - Analyze
  - Diagnose
  - Apply Bypass

### Test04_ProfileScenario_NotAffected
- ✅ Переключение на "Выбор профиля"
- ✅ Проверка что UI переключился (ComboBox появился)
- ✅ Проверка что элементы управления доступны

### Test05_ZeroConnections_ShowsWarning
- ✅ Запуск с notepad.exe (0 сетевых соединений)
- ✅ Проверка что Stage2 НЕ запустился автоматически

## Требования

### Для запуска тестов:

1. **ISP_Audit.exe** должен быть собран в Release:
   ```powershell
   dotnet build -c Release
   ```

2. **TestNetworkApp.exe** должен быть собран:
   ```powershell
   cd TestNetworkApp
   dotnet build -c Release
   ```

3. **Администраторские права** (для WinDivert в Stage1)

4. **Нет запущенных экземпляров ISP_Audit** (тесты сами запускают приложение)

## Запуск

### Все тесты:
```powershell
dotnet test ISP_Audit.UITests/ISP_Audit.UITests.csproj
```

### Конкретный тест:
```powershell
dotnet test ISP_Audit.UITests/ISP_Audit.UITests.csproj --filter "FullName~Test01_FullFlow"
```

### С детальным выводом:
```powershell
dotnet test ISP_Audit.UITests/ISP_Audit.UITests.csproj -v detailed
```

## Важные замечания

⚠️ **Тесты запускаются на РЕАЛЬНОМ GUI**:
- Откроется окно ISP_Audit
- Будет клик по кнопкам
- Не трогай мышь/клавиатуру во время теста

⚠️ **Длительность**:
- Test01 (full flow): ~1.5-2 минуты (30 сек Stage1 + 30 сек Stage2 + Stage3)
- Test02-05: ~30-60 секунд каждый
- Все тесты: ~5-7 минут

⚠️ **Администратор**:
- Запускай терминал/VS Code **от администратора**
- Иначе WinDivert в Stage1 не сможет захватить трафик

## Troubleshooting

### "ISP_Audit.exe не найден"
```powershell
dotnet build -c Release
```

### "Window не отвечает"
- Закрой все экземпляры ISP_Audit
- Перезапусти тест

### "Access Denied" в Stage1
- Запусти терминал от администратора

### Тест Test01 падает на Stage2
- Проверь что TestNetworkApp.exe работает:
  ```powershell
  cd TestNetworkApp/bin/Release/net9.0
  .\TestNetworkApp.exe
  ```
- Должен показывать успешные HTTP запросы к google.com, youtube.com

## Технологии

- **xUnit** - test runner
- **FlaUI 5.0.0** - UI Automation framework
- **UIA3** - UI Automation provider (Windows)

## Автор

Создано для автоматизации E2E тестирования после задачи "End-to-End Testing + UX Polish".

## См. также

- `docs/e2e_test_checklist.md` - ручной чеклист (34 шага)
- `agents/qa_agent/test_report.md` - QA отчёт по коду
