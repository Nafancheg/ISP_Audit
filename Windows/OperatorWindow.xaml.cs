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

        private void DnsDohConsentToggle_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is not System.Windows.Controls.Primitives.ToggleButton tb)
                {
                    return;
                }

                // Интересует только включение.
                if (tb.IsChecked != true)
                {
                    return;
                }

                // В рамках текущей сессии подтверждаем только один раз, чтобы не раздражать.
                if (_dnsDohConsentConfirmedThisSession)
                {
                    return;
                }

                if (DataContext is not OperatorWindowDataContext ctx)
                {
                    return;
                }

                var result = WpfMessageBox.Show(
                    "Разрешить системные изменения DNS/DoH?\n\n" +
                    "Это может изменять сетевые настройки Windows (DNS/DoH) и влиять на все приложения на компьютере.\n\n" +
                    "Если вы не уверены — оставьте выключенным. Рекомендации обхода без этого продолжат применяться, а DoH будет пропущен.",
                    "Подтверждение: DNS/DoH",
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.OK)
                {
                    _dnsDohConsentConfirmedThisSession = true;
                    return;
                }

                // Пользователь отменил — откатываем UI и состояние.
                try { tb.IsChecked = false; } catch { }
                try { ctx.Main.AllowDnsDohSystemChanges = false; } catch { }
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

            public OperatorWindowDataContext(OperatorViewModel vm, OperatorWindow window)
            {
                Vm = vm;

                EngineerCommand = new RelayCommand(_ =>
                {
                    window.SwitchToEngineer();
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
