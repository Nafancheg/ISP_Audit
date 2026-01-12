# TestNetworkApp

`TestNetworkApp` выполняет две задачи:

1) **Генератор сетевой активности** — небольшой exe, который открывает типичные TCP/HTTPS соединения, чтобы было удобно воспроизводимо проверять захват/разбор трафика в основном приложении.
2) **Smoke-runner** — консольный запуск набора smoke-тестов репозитория (без GUI), включая проверки пайплайна, парсеров, форматирования, и части низкоуровневых модулей.

## 1) Генератор сетевой активности (TestNetworkApp.exe)

### Что делает
- Делает серию HTTP/HTTPS запросов к набору известных хостов
- Делает один цикл запросов и завершает работу
- Печатает статусы запросов и PID процесса

### Примеры целей
- `google.com:443`
- `youtube.com:443`
- `discord.com:443`
- `github.com:443`
- `api.ipify.org:443`
- `cloudflare.com:443`
- `1.1.1.1:443`

### Сборка
```powershell
cd TestNetworkApp
dotnet publish -c Release -r win-x64 --self-contained false -o bin/Publish
```

### Ручной запуск
```powershell
.\TestNetworkApp\bin\Publish\TestNetworkApp.exe
```

## 2) Smoke-тесты (TestNetworkApp как runner)

Smoke-runner запускается параметром `--smoke` и использует план тестов из `TestNetworkApp/smoke_tests_plan.md`.
Реализации тестов находятся в `TestNetworkApp/Smoke/SmokeTests.*.cs`, а каркас раннера — в `TestNetworkApp/Smoke/SmokeRunner.cs`.

### Быстрый старт

Запуск всех smoke-тестов (нестрогий режим; часть environment-зависимых проверок может быть пропущена):
```powershell
dotnet run -c Debug --project TestNetworkApp\TestNetworkApp.csproj -- --smoke all
```

Строгий запуск без пропусков (любые `SKIP` считаются ошибкой):
```powershell
dotnet run -c Debug --project TestNetworkApp\TestNetworkApp.csproj -- --smoke all --strict
```

Выгрузка отчёта в JSON:
```powershell
dotnet run -c Debug --project TestNetworkApp\TestNetworkApp.csproj -- --smoke all --json artifacts\smoke_all.json
```

### Категории
Runner поддерживает категории вида `--smoke <category>` (например: `infra`, `pipe`, `insp`, `ui`, `dpi2`, `orch`, `cfg`, `err`, `e2e`, `perf`, `reg`).

## 3) Smoke UI-редьюсера (без запуска GUI)

Быстрый воспроизводимый прогон типовых строк пайплайна через `TestResultsManager.ParsePipelineMessage`.

Запуск:
```powershell
dotnet run -c Debug --project TestNetworkApp\TestNetworkApp.csproj -- --ui-reducer-smoke
```

## Файлы

- `TestNetworkApp/Program.cs` — генератор сетевой активности
- `TestNetworkApp/Smoke/SmokeRunner.cs` — каркас smoke-runner
- `TestNetworkApp/Smoke/SmokeTests.*.cs` — реализации smoke-тестов
- `TestNetworkApp/smoke_tests_plan.md` — перечень и описание smoke-тестов

