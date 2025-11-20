# Тест функционала кнопки "Подробности"
param(
    [int]$ProcessId
)

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ТЕСТ: Кнопка 'Подробности'" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

if (-not $ProcessId) {
    $proc = Get-Process ISP_Audit -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) {
        $ProcessId = $proc.Id
        Write-Host "✓ Найден процесс ISP_Audit (PID: $ProcessId)" -ForegroundColor Green
    } else {
        Write-Host "✗ Процесс ISP_Audit не найден" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nОжидание 30 секунд для завершения тестов..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

Write-Host "`nПоиск элементов UI..." -ForegroundColor Yellow

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::RootElement
$condition = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId
)
$window = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)

if (-not $window) {
    Write-Host "✗ Окно не найдено" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Главное окно найдено: $($window.Current.Name)" -ForegroundColor Green

# Поиск кнопок "Подробности"
$allCondition = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty, 
    [System.Windows.Automation.ControlType]::Button
)

$buttons = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $allCondition)
$detailsButtons = @()

foreach ($button in $buttons) {
    if ($button.Current.Name -eq "Подробности") {
        $detailsButtons += $button
    }
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "РЕЗУЛЬТАТЫ" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

Write-Host "Найдено кнопок 'Подробности': $($detailsButtons.Count)" -ForegroundColor $(if ($detailsButtons.Count -gt 0) { "Green" } else { "Red" })

if ($detailsButtons.Count -gt 0) {
    Write-Host "`nПопытка нажать первую кнопку 'Подробности'..." -ForegroundColor Yellow
    
    $firstButton = $detailsButtons[0]
    $invokePattern = $firstButton.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    
    if ($invokePattern) {
        $invokePattern.Invoke()
        Write-Host "✓ Кнопка нажата" -ForegroundColor Green
        
        Start-Sleep -Seconds 2
        
        # Поиск окна "Подробности теста"
        $dialogCondition = New-Object System.Windows.Automation.AndCondition(@(
            (New-Object System.Windows.Automation.PropertyCondition(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty, 
                [System.Windows.Automation.ControlType]::Window
            )),
            (New-Object System.Windows.Automation.PropertyCondition(
                [System.Windows.Automation.AutomationElement]::ProcessIdProperty, 
                $ProcessId
            ))
        ))
        
        $allWindows = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $dialogCondition)
        
        $detailsWindow = $null
        foreach ($win in $allWindows) {
            if ($win.Current.Name -like "*Подробности*" -or $win.Current.Name -ne $window.Current.Name) {
                $detailsWindow = $win
                break
            }
        }
        
        if ($detailsWindow) {
            Write-Host "✓ Диалоговое окно открылось: $($detailsWindow.Current.Name)" -ForegroundColor Green
            
            # Поиск текстовых элементов в окне
            $textCondition = New-Object System.Windows.Automation.PropertyCondition(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty, 
                [System.Windows.Automation.ControlType]::Text
            )
            $texts = $detailsWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $textCondition)
            
            Write-Host "`nСодержимое окна (первые 10 текстовых элементов):" -ForegroundColor Yellow
            $count = 0
            foreach ($text in $texts) {
                if ($count -ge 10) { break }
                $name = $text.Current.Name
                if ($name -and $name.Trim() -ne "") {
                    Write-Host "  • $name" -ForegroundColor Gray
                    $count++
                }
            }
            
            # Закрываем окно
            Start-Sleep -Seconds 3
            $detailsWindow.SetFocus()
            [System.Windows.Forms.SendKeys]::SendWait("{ESC}")
            Write-Host "`n✓ Окно закрыто (ESC)" -ForegroundColor Green
        } else {
            Write-Host "✗ Диалоговое окно не найдено" -ForegroundColor Red
        }
    } else {
        Write-Host "✗ Не удалось получить InvokePattern" -ForegroundColor Red
    }
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
