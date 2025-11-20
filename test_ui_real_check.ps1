# РЕАЛЬНАЯ проверка UI через UIAutomation
$ErrorActionPreference = "Stop"

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ПРОВЕРКА РЕАЛЬНОГО СОСТОЯНИЯ UI" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Проверка наличия процесса
$proc = Get-Process ISP_Audit -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "✗ ISP_Audit не запущен!" -ForegroundColor Red
    exit 1
}

Write-Host "✓ ISP_Audit запущен (PID: $($proc.Id))" -ForegroundColor Green

# Загрузить UIAutomation
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

try {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
    $window = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)
    
    if (-not $window) {
        Write-Host "✗ Не удалось найти окно приложения через UIAutomation!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✓ Окно найдено: $($window.Current.Name)" -ForegroundColor Green
    
    # Найти все элементы
    Write-Host "`nПоиск UI элементов..." -ForegroundColor Yellow
    
    $allCondition = [System.Windows.Automation.Condition]::TrueCondition
    $allElements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $allCondition)
    
    Write-Host "Всего элементов найдено: $($allElements.Count)" -ForegroundColor Cyan
    
    # Найти карточки тестов
    $cards = @()
    foreach ($element in $allElements) {
        $className = $element.Current.ClassName
        $name = $element.Current.Name
        
        if ($className -eq "TestCard" -or $name -like "*Launcher*" -or $name -like "*Server*") {
            $cards += $element
            Write-Host "  → Найден элемент: $className | $name" -ForegroundColor Green
        }
    }
    
    if ($cards.Count -eq 0) {
        Write-Host "`n✗ КАРТОЧКИ ТЕСТОВ НЕ НАЙДЕНЫ!" -ForegroundColor Red
        Write-Host "  Проблема: ItemsControl не рендерит элементы" -ForegroundColor Yellow
    } else {
        Write-Host "`n✓ Найдено $($cards.Count) карточек" -ForegroundColor Green
    }
    
    # Найти кнопку "Начать проверку"
    $startButtonCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
    $buttons = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $startButtonCondition)
    
    Write-Host "`nНайдено кнопок: $($buttons.Count)" -ForegroundColor Cyan
    foreach ($button in $buttons) {
        $buttonName = $button.Current.Name
        Write-Host "  → Кнопка: $buttonName" -ForegroundColor White
        
        if ($buttonName -like "*Начать*" -or $buttonName -like "*Остановить*") {
            Write-Host "    ✓ Основная кнопка найдена!" -ForegroundColor Green
        }
    }
    
    # Найти текстовые элементы
    $textCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
    $textElements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $textCondition)
    
    Write-Host "`nТекстовых элементов: $($textElements.Count)" -ForegroundColor Cyan
    
    $statusTexts = @()
    foreach ($text in $textElements) {
        $textValue = $text.Current.Name
        if ($textValue -like "*Проверяем*" -or $textValue -like "*Успешно*" -or $textValue -like "*Ошибка*") {
            $statusTexts += $textValue
            Write-Host "  → СТАТУС: $textValue" -ForegroundColor Yellow
        }
    }
    
    if ($statusTexts.Count -eq 0) {
        Write-Host "`n✗ НЕТ СТАТУСНЫХ ТЕКСТОВ!" -ForegroundColor Red
        Write-Host "  Это значит: карточки либо не созданы, либо StatusText.Visibility=Collapsed" -ForegroundColor Yellow
    } else {
        Write-Host "`n✓ Найдено $($statusTexts.Count) статусных текстов" -ForegroundColor Green
    }
    
} catch {
    Write-Host "`n✗ ОШИБКА UIAutomation: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Возможно, приложение запущено не в GUI режиме" -ForegroundColor Yellow
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "ВЫВОД:" -ForegroundColor Cyan
Write-Host "  Если карточки НЕ найдены → проблема в XAML биндинге" -ForegroundColor Yellow
Write-Host "  Если карточки найдены, но без статусов → проблема в UpdateCard()" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan
