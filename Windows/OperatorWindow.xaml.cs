using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using IspAudit.Wpf;
using IspAudit.Utils;
using IspAudit.ViewModels;

using WpfApplication = System.Windows.Application;
using WpfMessageBox = System.Windows.MessageBox;

namespace IspAudit.Windows
{
    public partial class OperatorWindow : Window
    {
        private readonly Func<MainViewModel> _getMainViewModel;
        private bool _switchingToEngineer;

        private bool _shutdownInProgress;
        private bool _shutdownCompleted;

        public OperatorWindow(Func<MainViewModel> getMainViewModel)
        {
            _getMainViewModel = getMainViewModel ?? throw new ArgumentNullException(nameof(getMainViewModel));

            InitializeComponent();
            Closing += Window_Closing;

            var main = _getMainViewModel();
            DataContext = new OperatorWindowDataContext(new OperatorViewModel(main), this);
        }

        private void Bypass_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                var main = _getMainViewModel();
                var bypass = main.Bypass;

                // В операторском режиме включаем самый безопасный и понятный базовый обход:
                // TLS Fragment (без агрессивных/глобальных действий).
                // Если пользователь уже включил что-то в Engineer — не ломаем.
                if (!bypass.IsBypassActive)
                {
                    var anyOptionEnabled = bypass.IsFragmentEnabled
                        || bypass.IsDisorderEnabled
                        || bypass.IsFakeEnabled
                        || bypass.IsDropRstEnabled
                        || bypass.IsQuicFallbackEnabled
                        || bypass.IsAllowNoSniEnabled;

                    if (!anyOptionEnabled)
                    {
                        bypass.IsFragmentEnabled = true;
                    }
                    else
                    {
                        _ = bypass.ApplyBypassOptionsAsync();
                    }
                }
            }
            catch
            {
                // ignore
            }
        }

        private void Bypass_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                var main = _getMainViewModel();
                _ = main.Bypass.DisableAllAsync();
            }
            catch
            {
                // ignore
            }
        }

        private async void Window_Closing(object? sender, CancelEventArgs e)
        {
            if (_switchingToEngineer)
            {
                return;
            }

            if (_shutdownCompleted)
            {
                return;
            }

            e.Cancel = true;

            if (_shutdownInProgress)
            {
                return;
            }

            _shutdownInProgress = true;

            try
            {
                var main = _getMainViewModel();
                await main.ShutdownAsync();
            }
            catch
            {
                // ignore
            }
            finally
            {
                _shutdownInProgress = false;
                _shutdownCompleted = true;

                _ = Dispatcher.BeginInvoke(new Action(() =>
                {
                    try { Close(); } catch { }
                }));
            }
        }

        private sealed class OperatorWindowDataContext
        {
            public OperatorViewModel Vm { get; }
            public MainViewModel Main => Vm.Main;

            public RelayCommand EngineerCommand { get; }
            public RelayCommand RollbackCommand { get; }

            public OperatorWindowDataContext(OperatorViewModel vm, OperatorWindow window)
            {
                Vm = vm;

                EngineerCommand = new RelayCommand(_ =>
                {
                    window.SwitchToEngineer();
                });

                RollbackCommand = new RelayCommand(async _ =>
                {
                    try
                    {
                        await Vm.Main.Bypass.DisableAllAsync().ConfigureAwait(false);
                    }
                    catch
                    {
                        // ignore
                    }
                });
            }
        }

        private void SwitchToEngineer()
        {
            var result = WpfMessageBox.Show(
                "Открыть инженерный режим?\n\nТам больше настроек и деталей.",
                "Переход в инженерный режим",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.OK)
            {
                return;
            }

            try
            {
                UiModeStore.SaveBestEffort(UiMode.Engineer);
            }
            catch
            {
                // ignore
            }

            _switchingToEngineer = true;

            try
            {
                if (WpfApplication.Current is IspAudit.App app)
                {
                    app.ShowEngineerWindow();
                }
            }
            catch
            {
                // ignore
            }

            try
            {
                Close();
            }
            catch
            {
                // ignore
            }
        }
    }
}
