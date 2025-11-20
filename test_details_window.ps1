# Тест окна Details через UIAutomation
param([int]$ProcessId)

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$automation = [System.Windows.Automation.AutomationElement]

Write-Host "`n=== UIAutomation Test: Details Window ===" -ForegroundColor Cyan
Write-Host "PID: $ProcessId`n" -ForegroundColor Yellow

# Найти главное окно
$process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
if (-not $process) {
    Write-Host "Process not found!" -ForegroundColor Red
    exit 1
}

$mainWindowHandle = $process.MainWindowHandle
if ($mainWindowHandle -eq [IntPtr]::Zero) {
    Write-Host "Main window not found!" -ForegroundColor Red
    exit 1
}

$mainWindow = $automation::FromHandle($mainWindowHandle)
Write-Host "Main Window: $($mainWindow.Current.Name)" -ForegroundColor Green

# Найти кнопку "Подробности"
$buttonCondition = New-Object System.Windows.Automation.PropertyCondition(
    $automation::NameProperty,
    "Подробности"
)

$detailsButton = $mainWindow.FindFirst(
    [System.Windows.Automation.TreeScope]::Descendants,
    $buttonCondition
)

if ($detailsButton) {
    Write-Host "`n✓ Found 'Подробности' button" -ForegroundColor Green
    
    # Получить InvokePattern
    $invokePattern = $detailsButton.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    
    Write-Host "Clicking button..." -ForegroundColor Yellow
    $invokePattern.Invoke()
    
    Start-Sleep -Seconds 2
    
    # Найти окно Details
    $desktopRoot = $automation::RootElement
    $detailsWindowCondition = New-Object System.Windows.Automation.PropertyCondition(
        $automation::NameProperty,
        "Подробности теста"
    )
    
    $detailsWindow = $desktopRoot.FindFirst(
        [System.Windows.Automation.TreeScope]::Children,
        $detailsWindowCondition
    )
    
    if ($detailsWindow) {
        Write-Host "`n✓✓✓ Details Window OPENED!" -ForegroundColor Green
        Write-Host "Title: $($detailsWindow.Current.Name)" -ForegroundColor Cyan
        
        # Проверить фон окна (должен быть НЕ черный)
        Write-Host "`nChecking window background..." -ForegroundColor Yellow
        
        # Найти все TextBlock элементы
        $textCondition = New-Object System.Windows.Automation.PropertyCondition(
            $automation::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Text
        )
        
        $textElements = $detailsWindow.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            $textCondition
        )
        
        Write-Host "`nFound $($textElements.Count) text elements:" -ForegroundColor Cyan
        $count = 0
        foreach ($textEl in $textElements) {
            $text = $textEl.Current.Name
            if ($text -and $text.Trim() -ne "") {
                $count++
                Write-Host "  [$count] $text" -ForegroundColor White
                if ($count -ge 10) { break }
            }
        }
        
        if ($count -gt 0) {
            Write-Host "`n✓✓✓ WINDOW HAS VISIBLE TEXT!" -ForegroundColor Green
        } else {
            Write-Host "`n✗✗✗ WINDOW IS EMPTY!" -ForegroundColor Red
        }
        
        # Закрыть окно
        Start-Sleep -Seconds 2
        $closeCondition = New-Object System.Windows.Automation.PropertyCondition(
            $automation::NameProperty,
            "Закрыть"
        )
        $closeButton = $detailsWindow.FindFirst(
            [System.Windows.Automation.TreeScope]::Descendants,
            $closeCondition
        )
        if ($closeButton) {
            Write-Host "`nClosing window..." -ForegroundColor Yellow
            $closePattern = $closeButton.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
            $closePattern.Invoke()
            Write-Host "✓ Window closed" -ForegroundColor Green
        }
        
    } else {
        Write-Host "`n✗✗✗ Details Window NOT FOUND!" -ForegroundColor Red
    }
    
} else {
    Write-Host "`n✗ 'Подробности' button not found" -ForegroundColor Red
}

Write-Host "`n=== Test Complete ===`n" -ForegroundColor Cyan
