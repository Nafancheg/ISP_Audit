# Автоматический тест UI - проверка видимости элементов
$ErrorActionPreference = "Stop"

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "АВТОМАТИЧЕСКИЙ ТЕСТ UI" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# 1. Остановить процесс если запущен
Write-Host "`n[1] Остановка ISP_Audit..." -ForegroundColor Yellow
Get-Process ISP_Audit -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# 2. Очистить лог
Write-Host "[2] Очистка логов..." -ForegroundColor Yellow
Remove-Item "$env:USERPROFILE\Desktop\isp_audit_vm_log.txt" -ErrorAction SilentlyContinue

# 3. Запустить приложение
Write-Host "[3] Запуск приложения..." -ForegroundColor Yellow
$proc = Start-Process -FilePath ".\bin\Debug\net9.0-windows\ISP_Audit.exe" -PassThru
Write-Host "    PID: $($proc.Id)" -ForegroundColor Green

# 4. Ждать инициализацию
Write-Host "[4] Ожидание инициализации (3 сек)..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# 5. Проверить ШАГ 1
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ПРОВЕРКА ШАГ 1: НАЧАЛЬНОЕ СОСТОЯНИЕ" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

$logContent = Get-Content "$env:USERPROFILE\Desktop\isp_audit_vm_log.txt" -ErrorAction SilentlyContinue
if ($logContent) {
    $step1 = $logContent | Select-String "ШАГ 1: НАЧАЛЬНОЕ СОСТОЯНИЕ"
    if ($step1) {
        Write-Host "✓ ШАГ 1 найден в логе" -ForegroundColor Green
        
        $testResultsCount = ($logContent | Select-String "TestResults инициализирована \(Count=(\d+)\)" | ForEach-Object { $_.Matches.Groups[1].Value })
        if ($testResultsCount) {
            Write-Host "✓ TestResults.Count = $testResultsCount" -ForegroundColor Green
        }
        
        $screenState = ($logContent | Select-String "ScreenState = '(\w+)'" | Select-Object -First 1 | ForEach-Object { $_.Matches.Groups[1].Value })
        if ($screenState -eq "start") {
            Write-Host "✓ ScreenState = '$screenState' (ожидается 'start')" -ForegroundColor Green
        } else {
            Write-Host "✗ ScreenState = '$screenState' (ожидается 'start')" -ForegroundColor Red
        }
    } else {
        Write-Host "✗ ШАГ 1 НЕ НАЙДЕН в логе!" -ForegroundColor Red
    }
} else {
    Write-Host "✗ Лог файл не создан!" -ForegroundColor Red
}

# 6. Симулировать нажатие кнопки (через UI Automation)
Write-Host "`n[6] Симуляция нажатия 'Начать проверку'..." -ForegroundColor Yellow
Write-Host "    ВНИМАНИЕ: Нажмите кнопку 'Начать проверку' вручную!" -ForegroundColor Magenta
Write-Host "    Ожидание 15 секунд..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# 7. Проверить ШАГ 2
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ПРОВЕРКА ШАГ 2: ПОСЛЕ НАЖАТИЯ КНОПКИ" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

$logContent = Get-Content "$env:USERPROFILE\Desktop\isp_audit_vm_log.txt"
$step2 = $logContent | Select-String "ШАГ 2: НАЖАТИЕ 'НАЧАТЬ ПРОВЕРКУ'"
if ($step2) {
    Write-Host "✓ ШАГ 2 найден в логе" -ForegroundColor Green
    
    # Проверить смену ScreenState
    $screenStateChange = $logContent | Select-String "ScreenState: 'start' → 'running'"
    if ($screenStateChange) {
        Write-Host "✓ ScreenState изменён на 'running'" -ForegroundColor Green
    } else {
        Write-Host "✗ ScreenState НЕ изменился на 'running'" -ForegroundColor Red
    }
    
    # Проверить создание карточек
    $cardsCreated = $logContent | Select-String "КАРТОЧКИ ТЕСТОВ: ДОЛЖНЫ ПОЯВИТЬСЯ \((\d+) шт\)"
    if ($cardsCreated) {
        $cardCount = $cardsCreated.Matches.Groups[1].Value
        Write-Host "✓ Ожидается $cardCount карточек" -ForegroundColor Green
    }
} else {
    Write-Host "✗ ШАГ 2 НЕ НАЙДЕН!" -ForegroundColor Red
}

# 8. Ждать выполнение тестов
Write-Host "`n[8] Ожидание выполнения тестов (60 сек)..." -ForegroundColor Yellow
Start-Sleep -Seconds 60

# 9. Проверить ШАГ 3
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ПРОВЕРКА ШАГ 3: ВЫПОЛНЕНИЕ ТЕСТОВ" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

$logContent = Get-Content "$env:USERPROFILE\Desktop\isp_audit_vm_log.txt"
$step3 = $logContent | Select-String "ШАГ 3: ВЫПОЛНЕНИЕ ТЕСТОВ"
if ($step3) {
    Write-Host "✓ ШАГ 3 найден в логе" -ForegroundColor Green
    
    # Проверить изменения статусов
    $runningTransitions = @($logContent | Select-String "Idle → Running")
    $passTransitions = @($logContent | Select-String "Running → Pass")
    $failTransitions = @($logContent | Select-String "Running → Fail")
    
    Write-Host "✓ Переходов Idle → Running: $($runningTransitions.Count)" -ForegroundColor Green
    Write-Host "✓ Переходов Running → Pass: $($passTransitions.Count)" -ForegroundColor Green
    Write-Host "✓ Переходов Running → Fail: $($failTransitions.Count)" -ForegroundColor Green
    
    # Проверить финальные счётчики
    $finalCounters = $logContent | Select-String "ФИНАЛЬНЫЕ СЧЁТЧИКИ:" -Context 0,4
    if ($finalCounters) {
        Write-Host "`nФИНАЛЬНЫЕ СЧЁТЧИКИ:" -ForegroundColor Cyan
        Write-Host $finalCounters.Context.PostContext -ForegroundColor White
    }
} else {
    Write-Host "✗ ШАГ 3 НЕ НАЙДЕН!" -ForegroundColor Red
}

# 10. Проверить Debug вывод TestCard
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ПРОВЕРКА: TestCard.UpdateCard вызовы" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Debug.WriteLine не попадает в файл, только в Debug Output
Write-Host "ВНИМАНИЕ: Debug.WriteLine() выводится только в Debug Output VS Code!" -ForegroundColor Magenta
Write-Host "Для проверки используйте DebugView (Sysinternals) или VS Code Output → Debug Console" -ForegroundColor Yellow

# 11. ИТОГОВЫЙ ВЕРДИКТ
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ИТОГОВЫЙ ВЕРДИКТ" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

$testsPassed = 0
$testsFailed = 0

if ($step1) { $testsPassed++ } else { $testsFailed++ }
if ($step2 -and $screenStateChange) { $testsPassed++ } else { $testsFailed++ }
if ($step3 -and $runningTransitions.Count -gt 0) { $testsPassed++ } else { $testsFailed++ }

Write-Host "`nТестов пройдено: $testsPassed" -ForegroundColor Green
Write-Host "Тестов провалено: $testsFailed" -ForegroundColor Red

if ($testsFailed -eq 0) {
    Write-Host "`n✓ ВСЕ ЛОГИЧЕСКИЕ ТЕСТЫ ПРОЙДЕНЫ" -ForegroundColor Green
    Write-Host "  ОДНАКО: Если UI не показывает изменения - проблема в рендеринге!" -ForegroundColor Yellow
} else {
    Write-Host "`n✗ ЕСТЬ ПРОВАЛЕННЫЕ ТЕСТЫ" -ForegroundColor Red
}

Write-Host "`nПолный лог сохранён в: $env:USERPROFILE\Desktop\isp_audit_vm_log.txt" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan
