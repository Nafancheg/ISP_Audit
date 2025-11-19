namespace ISPAudit;

public partial class App : System.Windows.Application
{
    public App()
    {
        var logPath = System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop), "isp_audit_debug.txt");
        System.IO.File.AppendAllText(logPath, "App constructor started\n");
        
        // Загрузить ресурсы из XAML
        InitializeComponent();
        
        System.IO.File.AppendAllText(logPath, "App resources initialized\n");
        
        this.DispatcherUnhandledException += App_DispatcherUnhandledException;
        
        System.IO.File.AppendAllText(logPath, "App constructor finished\n");
    }

    private void App_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        var logPath = System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop), "isp_audit_debug.txt");
        System.IO.File.AppendAllText(logPath, $"DispatcherUnhandledException: {e.Exception}\n");
        
        System.Windows.MessageBox.Show($"Ошибка: {e.Exception.Message}\n\nStack trace:\n{e.Exception.StackTrace}", "Ошибка приложения", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        e.Handled = true;
    }

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        var logPath = System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop), "isp_audit_debug.txt");
        System.IO.File.AppendAllText(logPath, "App.OnStartup called\n");
        
        System.IO.File.AppendAllText(logPath, $"Application.Current.Resources.Count = {this.Resources.Count}\n");
        System.IO.File.AppendAllText(logPath, $"Has BgBrush? {this.Resources.Contains("BgBrush")}\n");
        
        base.OnStartup(e);

        try
        {
            System.IO.File.AppendAllText(logPath, "Creating MainWindow...\n");
            
            var mainWindow = new MainWindow();
            
            System.IO.File.AppendAllText(logPath, "MainWindow created, calling Show()...\n");
            
            mainWindow.Show();
            
            System.IO.File.AppendAllText(logPath, "MainWindow.Show() called\n");
        }
        catch (System.Exception ex)
        {
            System.IO.File.AppendAllText(logPath, $"CRITICAL ERROR in OnStartup:\n{ex}\n");
            System.Windows.MessageBox.Show($"КРИТИЧЕСКАЯ ОШИБКА при создании окна:\n\n{ex.Message}\n\n{ex.StackTrace}", "Критическая ошибка", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            this.Shutdown();
        }
    }
}
