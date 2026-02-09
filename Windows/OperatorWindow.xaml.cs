using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
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

        private bool _dnsDohConsentConfirmedThisSession;

        private bool _shutdownInProgress;
        private bool _shutdownCompleted;

        public OperatorWindow(Func<MainViewModel> getMainViewModel)
        {
            _getMainViewModel = getMainViewModel ?? throw new ArgumentNullException(nameof(getMainViewModel));

            InitializeComponent();
            Closing += Window_Closing;

            var main = _getMainViewModel();

            // Если согласие уже было выдано и подхвачено из state — считаем, что подтверждение уже получено.
            _dnsDohConsentConfirmedThisSession = main.AllowDnsDohSystemChanges;

            DataContext = new OperatorWindowDataContext(new OperatorViewModel(main), this);
        }

        private void DnsDohConsentToggle_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            // Важно: перехватываем ДО того, как ToggleButton успеет поменять IsChecked.
            // Так мы гарантируем, что при Cancel не будет даже кратковременной записи согласия в state.
            e.Handled = true;

            try
            {
                if (sender is not System.Windows.Controls.Primitives.ToggleButton tb)
                {
                    return;
                }

                if (DataContext is not OperatorWindowDataContext ctx)
                {
                    return;
                }

                var currentlyAllowed = ctx.Main.AllowDnsDohSystemChanges;

                // Выключение — без подтверждения.
                if (currentlyAllowed)
                {
                    try
                    {
                        ctx.Main.AllowDnsDohSystemChanges = false;
                    }
                    catch
                    {
                        // ignore
                    }

                    _dnsDohConsentConfirmedThisSession = false;
                    return;
                }

                // Включение — с подтверждением. В рамках сессии подтверждаем только один раз.
                if (!_dnsDohConsentConfirmedThisSession)
                {
                    var result = WpfMessageBox.Show(
                        "Разрешить системные изменения DNS/DoH?\n\n" +
                        "Это может изменять сетевые настройки Windows (DNS/DoH) и влиять на все приложения на компьютере.\n\n" +
                        "Если вы не уверены — оставьте выключенным. Рекомендации обхода без этого продолжат применяться, а DoH будет пропущен.",
                        "Подтверждение: DNS/DoH",
                        MessageBoxButton.OKCancel,
                        MessageBoxImage.Warning);

                    if (result != MessageBoxResult.OK)
                    {
                        return;
                    }

                    _dnsDohConsentConfirmedThisSession = true;
                }

                try
                {
                    ctx.Main.AllowDnsDohSystemChanges = true;
                }
                catch
                {
                    // ignore
                }
            }
            catch
            {
                // Best-effort: не ломаем UI из-за диалога.
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
            public RelayCommand SettingsCommand { get; }
            public RelayCommand HelpCommand { get; }

            public OperatorWindowDataContext(OperatorViewModel vm, OperatorWindow window)
            {
                Vm = vm;

                EngineerCommand = new RelayCommand(_ =>
                {
                    window.SwitchToEngineer();
                });

                SettingsCommand = new RelayCommand(_ =>
                {
                    window.OpenSettings();
                });

                HelpCommand = new RelayCommand(_ =>
                {
                    window.OpenHelp();
                });
            }
        }

        private void OpenSettings()
        {
            try
            {
                var main = _getMainViewModel();
                var w = new OperatorSettingsWindow(main)
                {
                    Owner = this
                };

                w.ShowDialog();
            }
            catch
            {
                // ignore
            }
        }

        private void OpenHelp()
        {
            try
            {
                var w = new OperatorHelpWindow(() => SwitchToEngineer())
                {
                    Owner = this
                };

                w.ShowDialog();
            }
            catch
            {
                // ignore
            }
        }

        private void SwitchToEngineer()
        {
            // В smoke/не-GUI контекстах не показываем модальные окна.
            if (WpfApplication.Current is not null)
            {
                var result = WpfMessageBox.Show(
                    "Вы переходите в расширенный режим — здесь доступны технические детали и настройки.\n\nПродолжить?",
                    "Расширенный режим",
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Question);

                if (result != MessageBoxResult.OK)
                {
                    return;
                }
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
