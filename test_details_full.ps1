param([int]$ProcessId)

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::RootElement
$condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
$mainWindow = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)

if (-not $mainWindow) {
    Write-Host "❌ Окно не найдено для PID $ProcessId" -ForegroundColor Red
    exit 1
}

Write-Host "`n✓ Главное окно найдено: $($mainWindow.Current.Name)" -ForegroundColor Green

# Ищем кнопки "Подробности"
$buttonCondition = New-Object System.Windows.Automation.AndCondition(@(
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Подробности"))
))

$detailsButtons = $mainWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $buttonCondition)

if ($detailsButtons.Count -eq 0) {
    Write-Host "❌ Кнопки 'Подробности' не найдены" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Найдено кнопок 'Подробности': $($detailsButtons.Count)" -ForegroundColor Green

# Кликаем на первую видимую кнопку
$clicked = $false
foreach ($button in $detailsButtons) {
    if ($button.Current.IsOffscreen -eq $false) {
        Write-Host "`nКликаю на кнопку 'Подробности'..." -ForegroundColor Cyan
        $invokePattern = $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
        $invokePattern.Invoke()
        $clicked = $true
        Start-Sleep -Seconds 2
        break
    }
}

if (-not $clicked) {
    Write-Host "❌ Не удалось кликнуть на кнопку (все offscreen)" -ForegroundColor Red
    exit 1
}

# Ищем диалоговое окно "Подробности теста"
$dialogCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Подробности теста")
$dialog = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $dialogCondition)

if (-not $dialog) {
    Write-Host "❌ Диалоговое окно 'Подробности теста' не найдено" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Диалоговое окно открыто: $($dialog.Current.Name)" -ForegroundColor Green

# Анализируем содержимое окна
$allText = $dialog.FindAll([System.Windows.Automation.TreeScope]::Descendants, 
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)))

Write-Host "`nСодержимое окна:" -ForegroundColor Yellow
$textCount = 0
foreach ($text in $allText) {
    $content = $text.Current.Name
    if (-not [string]::IsNullOrWhiteSpace($content)) {
        Write-Host "  • $content"
        $textCount++
    }
}

if ($textCount -eq 0) {
    Write-Host "❌ Окно пустое - текста не найдено!" -ForegroundColor Red
    exit 1
}

Write-Host "`n✓ Найдено текстовых элементов: $textCount" -ForegroundColor Green

# Проверяем наличие ключевых элементов
$hasTargetName = $allText | Where-Object { $_.Current.Name -match "Launcher|Patcher|Service" }
$hasHost = $allText | Where-Object { $_.Current.Name -match "robertsspaceindustries\.com|amazonaws\.com" }
$hasStatus = $allText | Where-Object { $_.Current.Name -match "Успешно|Ошибка|Предупреждение" }

Write-Host "`nПроверка ключевых элементов:" -ForegroundColor Yellow
Write-Host "  Имя цели: $(if ($hasTargetName) { '✓' } else { '✗' })" -ForegroundColor $(if ($hasTargetName) { 'Green' } else { 'Red' })
Write-Host "  Хост: $(if ($hasHost) { '✓' } else { '✗' })" -ForegroundColor $(if ($hasHost) { 'Green' } else { 'Red' })
Write-Host "  Статус: $(if ($hasStatus) { '✓' } else { '✗' })" -ForegroundColor $(if ($hasStatus) { 'Green' } else { 'Red' })

# Закрываем окно
$closeButton = $dialog.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
    (New-Object System.Windows.Automation.AndCondition(@(
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Закрыть"))
    ))))

if ($closeButton) {
    Write-Host "`nЗакрываю окно..." -ForegroundColor Cyan
    $invokePattern = $closeButton.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $invokePattern.Invoke()
    Write-Host "✓ Окно закрыто" -ForegroundColor Green
}

Write-Host "`n✅ ТЕСТ ПРОЙДЕН" -ForegroundColor Green
