using System;
using IspAudit.Models;

using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace IspAudit.Windows;

internal sealed class MainViewModelUiBridgeHandlers
{
    public required Action<string, string> ShowError { get; init; }
    public required Func<string, string, bool> ConfirmOkCancel { get; init; }
    public required Func<string, string, bool> ConfirmYesNo { get; init; }
    public required Func<string?> PickExecutablePath { get; init; }
    public required Action<TestResult, string?> ShowTestDetails { get; init; }
}

internal static class MainViewModelUiBridge
{
    public static MainViewModelUiBridgeHandlers CreateHandlers()
    {
        return new MainViewModelUiBridgeHandlers
        {
            ShowError = ShowError,
            ConfirmOkCancel = ConfirmOkCancel,
            ConfirmYesNo = ConfirmYesNo,
            PickExecutablePath = PickExecutablePath,
            ShowTestDetails = ShowTestDetails
        };
    }

    public static void ShowError(string title, string message)
    {
        MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
    }

    public static bool ConfirmOkCancel(string title, string message)
    {
        var result = MessageBox.Show(message, title, MessageBoxButton.OKCancel, MessageBoxImage.Question);
        return result == MessageBoxResult.OK;
    }

    public static bool ConfirmYesNo(string title, string message)
    {
        var result = MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question);
        return result == MessageBoxResult.Yes;
    }

    public static string? PickExecutablePath()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*",
            Title = "Выберите exe файл приложения"
        };

        if (dialog.ShowDialog() == true)
        {
            return dialog.FileName;
        }

        return null;
    }

    public static void ShowTestDetails(TestResult result, string? applyDetailsJson)
    {
        var window = new TestDetailsWindow(result, applyDetailsJson)
        {
            Owner = Application.Current?.MainWindow
        };

        window.ShowDialog();
    }
}
