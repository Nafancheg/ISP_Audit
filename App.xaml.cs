namespace IspAudit;

public partial class App : System.Windows.Application
{
    public App()
    {
        // Загрузить ресурсы из XAML
        InitializeComponent();
        
        this.DispatcherUnhandledException += App_DispatcherUnhandledException;
    }

    private void App_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        System.Windows.MessageBox.Show($"Ошибка: {e.Exception.Message}\n\nStack trace:\n{e.Exception.StackTrace}", "Ошибка приложения", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        e.Handled = true;
    }

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            var mainWindow = new MainWindow();
            mainWindow.Show();
        }
        catch (System.Exception ex)
        {
            System.Windows.MessageBox.Show($"КРИТИЧЕСКАЯ ОШИБКА при создании окна:\n\n{ex.Message}\n\n{ex.StackTrace}", "Критическая ошибка", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            this.Shutdown();
        }
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        try
        {
            if (this.MainWindow?.DataContext is IspAudit.ViewModels.MainViewModelRefactored vm)
            {
                vm.OnAppExit();
            }
        }
        catch
        {
            // ignore
        }

        base.OnExit(e);
    }
}
