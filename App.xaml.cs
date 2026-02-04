namespace IspAudit;

public partial class App : System.Windows.Application
{
    private IspAudit.ViewModels.MainViewModel? _sharedMainViewModel;

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
            // По умолчанию запускаем «Операторский» UI.
            // Инженерный режим открывается по подтверждению и сохраняется в state/ui_mode.json.
            var mode = IspAudit.Utils.UiModeStore.LoadOrDefault(IspAudit.Utils.UiMode.Operator);

            if (mode == IspAudit.Utils.UiMode.Engineer)
            {
                ShowEngineerWindow();
            }
            else
            {
                ShowOperatorWindow();
            }
        }
        catch (System.Exception ex)
        {
            System.Windows.MessageBox.Show($"КРИТИЧЕСКАЯ ОШИБКА при создании окна:\n\n{ex.Message}\n\n{ex.StackTrace}", "Критическая ошибка", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            this.Shutdown();
        }
    }

    internal IspAudit.ViewModels.MainViewModel GetSharedMainViewModel()
    {
        return _sharedMainViewModel ??= new IspAudit.ViewModels.MainViewModel();
    }

    internal async System.Threading.Tasks.Task EnsureInitializedAsync()
    {
        try
        {
            await GetSharedMainViewModel().InitializeAsync().ConfigureAwait(false);
        }
        catch
        {
            // ignore
        }
    }

    internal void ShowOperatorWindow()
    {
        var window = new IspAudit.Windows.OperatorWindow(GetSharedMainViewModel);
        MainWindow = window;
        _ = EnsureInitializedAsync();
        window.Show();
    }

    internal void ShowEngineerWindow()
    {
        var window = new MainWindow();
        window.DataContext = GetSharedMainViewModel();
        MainWindow = window;
        _ = EnsureInitializedAsync();
        window.Show();
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        try
        {
            if (_sharedMainViewModel != null)
            {
                // Критично: DNS/DoH должен откатываться при выходе из приложения.
                // OnExit не async, поэтому выполняем синхронное ожидание завершения.
                _sharedMainViewModel.ShutdownAsync().GetAwaiter().GetResult();
            }
        }
        catch
        {
            // ignore
        }

        base.OnExit(e);
    }
}
