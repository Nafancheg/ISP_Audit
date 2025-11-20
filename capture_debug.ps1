# Захват Debug Output от приложения ISP_Audit
# Использует System.Diagnostics.Trace для захвата Debug.WriteLine()

param(
    [Parameter(Mandatory=$false)]
    [int]$ProcessId = 0,
    [Parameter(Mandatory=$false)]
    [int]$DurationSeconds = 30
)

Write-Host "=== Debug Output Capture ===" -ForegroundColor Cyan

if ($ProcessId -eq 0) {
    $processes = Get-Process -Name ISP_Audit -ErrorAction SilentlyContinue
    if ($processes.Count -eq 0) {
        Write-Host "[ERROR] Процесс ISP_Audit не найден" -ForegroundColor Red
        exit 1
    }
    $ProcessId = $processes[0].Id
    Write-Host "Найден процесс: PID=$ProcessId" -ForegroundColor Green
} else {
    Write-Host "Используется Process ID: $ProcessId" -ForegroundColor Green
}

# Проверяем существование файла лога
$logPath = Join-Path $PSScriptRoot "bin\Debug\net9.0-windows\isp_audit.log"
if (-not (Test-Path $logPath)) {
    Write-Host "[WARN] Файл лога не найден: $logPath" -ForegroundColor Yellow
    Write-Host "Приложение может не запустить логирование или используется другой путь" -ForegroundColor Yellow
}

Write-Host "`nЖдём $DurationSeconds секунд для сбора Debug сообщений..." -ForegroundColor Cyan
Start-Sleep -Seconds $DurationSeconds

# Ищем Debug сообщения в различных источниках

# 1. OutputDebugString (если используется DebugView или похожий инструмент)
Write-Host "`n1. Проверка Debug Output через файл лога (если есть):" -ForegroundColor Yellow
if (Test-Path $logPath) {
    $logContent = Get-Content $logPath -Tail 100
    $debugLines = $logContent | Where-Object { $_ -match '\[TestResult\.' -or $_ -match '\[TestCard\.' }
    
    if ($debugLines.Count -gt 0) {
        Write-Host "  ✓ Найдено $($debugLines.Count) Debug строк:" -ForegroundColor Green
        $debugLines | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "  ✗ Debug строк не найдено в логе" -ForegroundColor Red
    }
} else {
    Write-Host "  ⊘ Лог файл не существует" -ForegroundColor Gray
}

# 2. Проверка через окно Debug в Visual Studio (если доступно)
Write-Host "`n2. Проверка Debug через консоль (System.Diagnostics.Debug):" -ForegroundColor Yellow
Write-Host "  ⚠ Для захвата Debug.WriteLine() нужен Debugger (Visual Studio) или DebugView" -ForegroundColor Yellow
Write-Host "  ⚠ PowerShell НЕ МОЖЕТ захватить OutputDebugString напрямую" -ForegroundColor Yellow

# 3. Альтернатива: проверяем UI через UIAutomation
Write-Host "`n3. Альтернатива - проверка UI через UIAutomation:" -ForegroundColor Yellow
$scriptPath = Join-Path $PSScriptRoot "test_ui_real_check.ps1"
if (Test-Path $scriptPath) {
    Write-Host "  → Запускаем test_ui_real_check.ps1..." -ForegroundColor Cyan
    & $scriptPath -ProcessId $ProcessId
} else {
    Write-Host "  ✗ Скрипт test_ui_real_check.ps1 не найден" -ForegroundColor Red
}

Write-Host "`n=== Захват завершён ===" -ForegroundColor Cyan
