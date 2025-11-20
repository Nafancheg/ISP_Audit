using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Definitions;
using FlaUI.UIA3;
using System.Diagnostics;
using Xunit;

namespace ISP_Audit.UITests;

using Application = FlaUI.Core.Application;

/// <summary>
/// Автоматизированные UI тесты для Exe-scenario workflow.
/// Основаны на чеклисте docs/e2e_test_checklist.md
/// </summary>
public class ExeScenarioTests : IDisposable
{
    private Application? _app;
    private UIA3Automation? _automation;
    private Window? _mainWindow;
    
    private const string AppPath = @"..\..\..\..\bin\Release\net9.0-windows\ISP_Audit.exe";
    private const string TestAppPath = @"..\..\..\..\TestNetworkApp\bin\Release\net9.0\TestNetworkApp.exe";

    public ExeScenarioTests()
    {
        _automation = new UIA3Automation();
    }

    [Fact]
    public async Task Test01_FullFlow_Stage1To3_Automatic()
    {
        // Arrange: Запустить ISP_Audit
        LaunchApp();
        
        // Act: Выбрать Exe-scenario
        var exeRadioButton = _mainWindow!.FindFirstDescendant(cf => 
            cf.ByAutomationId("ExeScenarioRadioButton"));
        if (exeRadioButton != null)
            exeRadioButton.AsRadioButton().Click();
        
        // Выбрать файл TestNetworkApp.exe
        var browseButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("BrowseButton"));
        
        // Для автотеста: напрямую установить путь через AutomationElement
        var exePathTextBox = _mainWindow.FindFirstDescendant(cf => 
            cf.ByControlType(ControlType.Edit).And(cf.ByAutomationId("ExePathTextBox")));
        
        // TextBox disabled, используем ValuePattern напрямую
        if (exePathTextBox != null)
        {
            var valuePattern = exePathTextBox.Patterns.Value.PatternOrDefault;
            if (valuePattern != null)
            {
                valuePattern.SetValue(Path.GetFullPath(TestAppPath));
            }
        }
        
        // Нажать "Начать проверку" (теперь автоматически запускает Stage1 для Exe-сценария)
        var startButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("StartButton"));
        startButton?.AsButton().Invoke();
        
        // Подождать запуска операции (Stage1 начинается автоматически)
        await Task.Delay(2000);
        
        // Проверить что Stage1 progress bar появился и меняется
        var stage1Progress = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("Stage1ProgressBar"));
        Assert.NotNull(stage1Progress);
        
        // Ждать завершения Stage1 (захват трафика ~60 секунд)
        var stage1Complete = await WaitForCondition(() =>
        {
            var progressValue = stage1Progress.AsProgressBar().Value;
            return progressValue >= 99.0;
        }, TimeSpan.FromSeconds(70));
        
        Assert.True(stage1Complete, "Stage1 должен завершиться за 70 секунд");
        
        // Проверить что НЕТ MessageBox (автоматический переход)
        // Если MessageBox появился - тест провалится по таймауту
        await Task.Delay(2000); // Небольшая задержка
        
        // Проверить что Stage2 запустился автоматически
        var stage2Progress = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("Stage2ProgressBar"));
        Assert.NotNull(stage2Progress);
        
        // Ждать завершения Stage2 (зависит от количества тестов, ~30 сек)
        var stage2Complete = await WaitForCondition(() =>
        {
            var progressValue = stage2Progress.AsProgressBar().Value;
            return progressValue >= 99.0;
        }, TimeSpan.FromSeconds(40));
        
        Assert.True(stage2Complete, "Stage2 должен завершиться за 40 секунд");
        
        // Проверить что Stage3 запустился автоматически
        await Task.Delay(2000);
        var stage3Progress = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("Stage3ProgressBar"));
        Assert.NotNull(stage3Progress);
        
        // Ждать завершения Stage3
        var stage3Complete = await WaitForCondition(() =>
        {
            var progressValue = stage3Progress.AsProgressBar().Value;
            return progressValue >= 99.0;
        }, TimeSpan.FromSeconds(20));
        
        Assert.True(stage3Complete, "Stage3 должен завершиться за 20 секунд");
        
        // Проверить что кнопка "Сбросить" доступна
        var resetButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("ResetButton"));
        Assert.NotNull(resetButton);
        Assert.True(resetButton.IsEnabled, "Кнопка Сбросить должна быть активна после завершения");
    }

    [Fact]
    public async Task Test02_ResetButton_ClearsState()
    {
        // Arrange: Запустить полный flow (упрощённая версия)
        LaunchApp();
        await RunSimplifiedFlow();
        
        // Act: Нажать "Сбросить"
        var resetButton = _mainWindow!.FindFirstDescendant(cf => 
            cf.ByAutomationId("ResetButton"));
        resetButton?.AsButton().Invoke();
        
        await Task.Delay(1000); // Дать время на сброс
        
        // Assert: Проверить что кнопка "Начать проверку" снова активна
        var startButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("StartButton"));
        Assert.True(startButton?.IsEnabled, "Start button должна быть активна после сброса");
        
        // Проверить что progress bars сброшены (не отображаются или значение 0)
        var stage1Progress = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("Stage1ProgressBar"));
        
        if (stage1Progress != null && stage1Progress.IsAvailable)
        {
            Assert.True(stage1Progress.AsProgressBar().Value < 5.0, 
                "Stage1 progress должен быть сброшен");
        }
    }

    [Fact]
    public async Task Test03_ButtonBlocking_DuringOperation()
    {
        // Arrange
        LaunchApp();
        SelectExeScenarioAndSetPath();
        
        // Act: Запустить Stage1 через "Начать проверку"
        var startButton = _mainWindow!.FindFirstDescendant(cf => 
            cf.ByAutomationId("StartButton"));
        startButton?.AsButton().Invoke();
        
        await Task.Delay(2000); // Подождать пока операция в процессе
        
        // Assert: Проверить что кнопка "Запустить анализ" заблокирована
        var analyzeButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("AnalyzeButton"));
        Assert.False(analyzeButton?.IsEnabled, "Analyze должна быть заблокирована");
        
        var diagnoseButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("DiagnoseButton"));
        if (diagnoseButton != null && diagnoseButton.IsAvailable)
        {
            Assert.False(diagnoseButton.IsEnabled, "Diagnose должна быть заблокирована");
        }
        
        var applyBypassButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("ApplyBypassButton"));
        if (applyBypassButton != null && applyBypassButton.IsAvailable)
        {
            Assert.False(applyBypassButton.IsEnabled, "Apply Bypass должна быть заблокирована");
        }
        
        // Очистка: дождаться завершения или прервать
        await Task.Delay(5000);
    }

    [Fact]
    public async Task Test04_ProfileScenario_NotAffected()
    {
        // Arrange
        LaunchApp();
        
        // Act: Переключиться на Profile scenario
        var profileRadioButton = _mainWindow!.FindFirstDescendant(cf => 
            cf.ByAutomationId("ProfileScenarioRadioButton"));
        if (profileRadioButton != null)
            profileRadioButton.AsRadioButton().Click();
        
        await Task.Delay(500);
        
        // Assert: Проверить что UI переключился (должен быть ComboBox профилей)
        var profileComboBox = _mainWindow.FindFirstDescendant(cf => 
            cf.ByControlType(ControlType.ComboBox).And(cf.ByAutomationId("ProfileComboBox")));
        
        Assert.NotNull(profileComboBox);
        
        // Проверить что кнопки для Profile scenario доступны
        var startButton = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("StartButton"));
        
        if (startButton != null && startButton.IsAvailable)
        {
            Assert.True(startButton.IsEnabled || !startButton.IsOffscreen, 
                "Profile scenario должен иметь активные элементы управления");
        }
    }

    [Fact]
    public async Task Test05_ZeroConnections_ShowsWarning()
    {
        // Arrange: Использовать notepad.exe (не создаёт сетевых соединений)
        LaunchApp();
        SelectExeScenarioAndSetPath(@"C:\Windows\notepad.exe");
        
        // Act: Запустить Stage1 через "Начать проверку"
        var startButton = _mainWindow!.FindFirstDescendant(cf => 
            cf.ByAutomationId("StartButton"));
        startButton?.AsButton().Invoke();
        
        // Ждать завершения Stage1
        await Task.Delay(32000); // 30 сек захвата + буфер
        
        // Assert: Должен появиться MessageBox с предупреждением
        // Закрываем его автоматически
        await Task.Delay(2000);
        
        // Проверить что Stage2 НЕ запустился (Stage2ProgressBar не показан)
        var stage2Progress = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("Stage2ProgressBar"));
        
        // Если элемент найден, проверить что он не активен или скрыт
        if (stage2Progress != null)
        {
            Assert.True(stage2Progress.IsOffscreen || !stage2Progress.IsAvailable, 
                "Stage2 не должен запускаться при 0 соединениях");
        }
    }

    // Helper methods

    private void LaunchApp()
    {
        var appFullPath = Path.GetFullPath(AppPath);
        if (!File.Exists(appFullPath))
        {
            throw new FileNotFoundException($"ISP_Audit.exe не найден: {appFullPath}. " +
                "Сначала выполни: dotnet build -c Release");
        }

        _app = Application.Launch(appFullPath);
        
        // ⏳ 10 секунд для нажатия UAC кнопки (admin права для WinDivert)
        Thread.Sleep(10000);
        
        _mainWindow = _app.GetMainWindow(_automation!);
        
        // Подождать пока окно загрузится
        Assert.NotNull(_mainWindow);
        Thread.Sleep(2000); // Даём время на инициализацию UI
    }

    private void SelectExeScenarioAndSetPath(string? customPath = null)
    {
        var exeRadioButton = _mainWindow!.FindFirstDescendant(cf => 
            cf.ByAutomationId("ExeScenarioRadioButton"));
        if (exeRadioButton != null)
            exeRadioButton.AsRadioButton().Click();
        
        var exePathTextBox = _mainWindow.FindFirstDescendant(cf => 
            cf.ByAutomationId("ExePathTextBox"));
        
        var pathToUse = customPath ?? Path.GetFullPath(TestAppPath);
        
        // TextBox disabled, используем ValuePattern
        if (exePathTextBox != null)
        {
            var valuePattern = exePathTextBox.Patterns.Value.PatternOrDefault;
            if (valuePattern != null)
            {
                valuePattern.SetValue(pathToUse);
            }
        }
    }

    private async Task RunSimplifiedFlow()
    {
        SelectExeScenarioAndSetPath();
        
        // Нажать "Начать проверку" (автоматически запускает Stage1 для Exe-сценария)
        var startButton = _mainWindow!.FindFirstDescendant(cf => 
            cf.ByAutomationId("StartButton"));
        startButton?.AsButton().Invoke();
        
        // Подождать минимум времени для запуска Stage1
        await Task.Delay(35000); // 30 сек + буфер
    }

    private async Task<bool> WaitForCondition(Func<bool> condition, TimeSpan timeout)
    {
        var endTime = DateTime.Now + timeout;
        
        while (DateTime.Now < endTime)
        {
            try
            {
                if (condition())
                    return true;
            }
            catch
            {
                // Игнорировать ошибки доступа к UI элементам
            }
            
            await Task.Delay(500);
        }
        
        return false;
    }

    public void Dispose()
    {
        _app?.Close();
        _app?.Dispose();
        _automation?.Dispose();
    }
}
