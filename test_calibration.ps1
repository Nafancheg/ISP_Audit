# Тестовый скрипт для калибровки ISP_Audit Exe-scenario
# Автоматически тестирует весь workflow Stage 1-3

param(
    [switch]$BuildOnly
)

$ErrorActionPreference = "Stop"

Write-Host "`n=== ISP_Audit Exe-Scenario Calibration Test ===" -ForegroundColor Cyan
Write-Host ""

# Пути
$testAppExe = "TestNetworkApp\bin\Release\net9.0\TestNetworkApp.exe"
$ispAuditExe = "bin\Debug\net9.0-windows\ISP_Audit.exe"

# Проверка admin прав
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[WARN] Запущено БЕЗ прав администратора!" -ForegroundColor Yellow
    Write-Host "       WinDivert требует администратора для работы." -ForegroundColor Yellow
    Write-Host ""
    $continue = Read-Host "Продолжить сборку? (y/n)"
    if ($continue -ne 'y') {
        exit 1
    }
}

# Шаг 1: Сборка TestNetworkApp
Write-Host "[1/4] Сборка TestNetworkApp..." -ForegroundColor Green
Push-Location TestNetworkApp
dotnet build -c Release | Out-Null
Pop-Location

if (-not (Test-Path $testAppExe)) {
    Write-Host "[ERROR] Не удалось собрать TestNetworkApp.exe" -ForegroundColor Red
    exit 1
}

Write-Host "      ✓ TestNetworkApp.exe готов: $testAppExe" -ForegroundColor Gray

# Шаг 2: Сборка ISP_Audit
Write-Host "[2/4] Сборка ISP_Audit..." -ForegroundColor Green
dotnet build -c Debug | Out-Null

if (-not (Test-Path $ispAuditExe)) {
    Write-Host "[ERROR] Не удалось собрать ISP_Audit.exe" -ForegroundColor Red
    exit 1
}

Write-Host "      ✓ ISP_Audit.exe готов: $ispAuditExe" -ForegroundColor Gray

if ($BuildOnly) {
    Write-Host "`n=== Сборка завершена ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Для ручного тестирования:" -ForegroundColor Yellow
    Write-Host "  1. Запустите ISP_Audit.exe ОТ АДМИНИСТРАТОРА"
    Write-Host "  2. Browse -> выберите TestNetworkApp.exe"
    Write-Host "  3. Stage 1: Запустить анализ (30 сек)"
    Write-Host "  4. Проверьте Output окно для логов"
    Write-Host ""
    exit 0
}

# Шаг 3: Ручной запуск TestNetworkApp для проверки
Write-Host "[3/4] Тестовый запуск TestNetworkApp (10 сек)..." -ForegroundColor Green

$testProc = Start-Process -FilePath (Resolve-Path $testAppExe).Path -PassThru -WindowStyle Normal

Write-Host "      ✓ TestNetworkApp запущен, PID=$($testProc.Id)" -ForegroundColor Gray
Write-Host "        Ожидание 10 секунд для генерации трафика..." -ForegroundColor Gray

Start-Sleep -Seconds 10

if (-not $testProc.HasExited) {
    Write-Host "        Завершение TestNetworkApp..." -ForegroundColor Gray
    $testProc.Kill()
    $testProc.WaitForExit()
}

Write-Host "      ✓ Тест завершен" -ForegroundColor Gray

# Шаг 4: Инструкции для ручного тестирования ISP_Audit
Write-Host "[4/4] Готово к тестированию ISP_Audit" -ForegroundColor Green
Write-Host ""
Write-Host "=== Следующие шаги ===" -ForegroundColor Cyan
Write-Host ""

if (-not $isAdmin) {
    Write-Host "⚠️  ВАЖНО: Запустите ISP_Audit ОТ АДМИНИСТРАТОРА!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Правый клик на ISP_Audit.exe -> 'Запуск от имени администратора'" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "1. Запустите ISP_Audit:" -ForegroundColor White
Write-Host "   Start-Process '$ispAuditExe' -Verb RunAs" -ForegroundColor Gray
Write-Host ""
Write-Host "2. В ISP_Audit GUI:" -ForegroundColor White
Write-Host "   - Browse -> выберите: $testAppExe" -ForegroundColor Gray
Write-Host "   - Stage 1: нажмите 'Запустить анализ'" -ForegroundColor Gray
Write-Host "   - Ожидайте 30 секунд захвата" -ForegroundColor Gray
Write-Host "   - Проверьте результат: должно быть ~7 целей (Google, YouTube, Discord, etc.)" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Ожидаемые цели:" -ForegroundColor White
Write-Host "   - google.com" -ForegroundColor Gray
Write-Host "   - youtube.com" -ForegroundColor Gray
Write-Host "   - discord.com" -ForegroundColor Gray
Write-Host "   - github.com" -ForegroundColor Gray
Write-Host "   - api.ipify.org" -ForegroundColor Gray
Write-Host "   - cloudflare.com" -ForegroundColor Gray
Write-Host "   - 1.1.1.1" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Проверка логов:" -ForegroundColor White
Write-Host "   - Откройте Output окно в ISP_Audit" -ForegroundColor Gray
Write-Host "   - Найдите: [Stage1] Process started: EXE=TestNetworkApp.exe, PID=..." -ForegroundColor Gray
Write-Host "   - Найдите: [Stage1] WinDivert NETWORK layer активирован" -ForegroundColor Gray
Write-Host "   - Найдите: [Stage1] Захвачено событий: ..." -ForegroundColor Gray
Write-Host "   - Найдите: [Stage1] SUCCESS: X unique hosts captured" -ForegroundColor Gray
Write-Host ""

Write-Host "=== Диагностика проблем ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Если 'Захват завершен: 0 событий':" -ForegroundColor Yellow
Write-Host "  → Проверьте права администратора" -ForegroundColor Gray
Write-Host "  → Проверьте WinDivert: native\WinDivert.dll (47KB)" -ForegroundColor Gray
Write-Host "  → Проверьте, что TestNetworkApp реально запустился" -ForegroundColor Gray
Write-Host ""
Write-Host "Если 'ERROR 87':" -ForegroundColor Yellow
Write-Host "  → Фильтр или Layer несовместимы" -ForegroundColor Gray
Write-Host "  → Проверьте WinDivert версию 2.2.0" -ForegroundColor Gray
Write-Host ""
Write-Host "Если 'ERROR 5 (Access Denied)':" -ForegroundColor Yellow
Write-Host "  → НЕ запущено от администратора" -ForegroundColor Gray
Write-Host ""

Write-Host "=== Готово ===" -ForegroundColor Green
Write-Host ""
