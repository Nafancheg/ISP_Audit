using Microsoft.Extensions.DependencyInjection;
using IspAudit.Utils;

namespace IspAudit;

public partial class App : System.Windows.Application
{
    private ServiceProvider? _services;

    internal T? GetServiceOrNull<T>() where T : class
    {
        return _services?.GetService<T>();
    }

    internal T GetRequiredService<T>() where T : notnull
    {
        if (_services == null)
        {
            throw new InvalidOperationException("DI контейнер не инициализирован.");
        }

        return _services.GetRequiredService<T>();
    }

    public App()
    {
        // Загрузить ресурсы из XAML
        InitializeComponent();

        this.DispatcherUnhandledException += App_DispatcherUnhandledException;

        // Глобальные обработчики: фиксируем необработанные исключения в crash-report.
        AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
    }

    private void App_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            IspAudit.Utils.AppCrashReporter.TryWrite(e.Exception, source: "DispatcherUnhandledException", isTerminating: false);
        }
        catch
        {
            // ignore
        }

        System.Windows.MessageBox.Show(
            "Произошла критическая ошибка. Приложение будет закрыто.\n\n" +
            "Отчёт сохранён в папке state\\crash_reports\\app\\ рядом с приложением.",
            "Критическая ошибка",
            System.Windows.MessageBoxButton.OK,
            System.Windows.MessageBoxImage.Error);

        // Важно: лучше завершиться контролируемо, чем продолжать в неопределённом состоянии.
        e.Handled = true;
        try
        {
            Shutdown(-1);
        }
        catch
        {
            // ignore
        }
    }

    private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        try
        {
            if (e.ExceptionObject is Exception ex)
            {
                IspAudit.Utils.AppCrashReporter.TryWrite(ex, source: "AppDomain.UnhandledException", isTerminating: e.IsTerminating);
            }
            else
            {
                IspAudit.Utils.AppCrashReporter.TryWrite(
                    new Exception($"UnhandledException (non-Exception): {e.ExceptionObject}"),
                    source: "AppDomain.UnhandledException",
                    isTerminating: e.IsTerminating);
            }
        }
        catch
        {
            // ignore
        }
    }

    private static void TaskScheduler_UnobservedTaskException(object? sender, System.Threading.Tasks.UnobservedTaskExceptionEventArgs e)
    {
        try
        {
            IspAudit.Utils.AppCrashReporter.TryWrite(e.Exception, source: "TaskScheduler.UnobservedTaskException", isTerminating: null);
            e.SetObserved();
        }
        catch
        {
            // ignore
        }
    }

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            // Composition root: DI контейнер живёт весь срок приложения.
            // Минимально регистрируем MainViewModel как singleton.
            var services = new ServiceCollection();
            ConfigureServices(services);
            _services = services.BuildServiceProvider(new ServiceProviderOptions
            {
                ValidateOnBuild = false,
                ValidateScopes = false,
            });

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

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddIspAuditServices();
    }

    internal IspAudit.ViewModels.MainViewModel GetSharedMainViewModel()
    {
        if (_services == null)
        {
            throw new InvalidOperationException("DI контейнер не инициализирован. OnStartup должен быть вызван до запроса MainViewModel.");
        }

        return _services.GetRequiredService<IspAudit.ViewModels.MainViewModel>();
    }

    internal async System.Threading.Tasks.Task EnsureInitializedAsync()
    {
        try
        {
            await GetSharedMainViewModel().InitializeAsync().ConfigureAwait(false);
        }
        catch (System.Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[App] EnsureInitializedAsync: {ex.Message}");
        }
    }

    internal void ShowOperatorWindow()
    {
        if (_services == null)
        {
            throw new InvalidOperationException("DI контейнер не инициализирован.");
        }

        var window = new IspAudit.Windows.OperatorWindow(_services.GetRequiredService<Func<IspAudit.ViewModels.MainViewModel>>());
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
            if (_services != null)
            {
                var vm = _services.GetService<IspAudit.ViewModels.MainViewModel>();
                if (vm == null)
                {
                    base.OnExit(e);
                    return;
                }

                // Критично: DNS/DoH должен откатываться при выходе из приложения.
                // OnExit не async — используем Task.Run чтобы избежать deadlock SynchronizationContext.
                Task.Run(() => vm.ShutdownAsync()).Wait(TimeSpan.FromSeconds(10));

                try
                {
                    (vm as IDisposable)?.Dispose();
                }
                catch
                {
                    // ignore
                }

                try
                {
                    _services.Dispose();
                }
                catch
                {
                    // ignore
                }
            }
        }
        catch
        {
            // ignore
        }

        base.OnExit(e);
    }
}
