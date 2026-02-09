using System;
using System.Windows;
using System.Windows.Input;

using WpfMessageBox = System.Windows.MessageBox;

namespace IspAudit.Windows
{
    public partial class OperatorSettingsWindow : Window
    {
        private bool _dnsDohConsentConfirmedThisSession;

        public OperatorSettingsWindow(IspAudit.ViewModels.MainViewModel main)
        {
            InitializeComponent();

            DataContext = main ?? throw new ArgumentNullException(nameof(main));

            // Если согласие уже было выдано и подхвачено из state — считаем, что подтверждение уже получено.
            _dnsDohConsentConfirmedThisSession = main.AllowDnsDohSystemChanges;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            try { Close(); } catch { }
        }

        private void DnsDohConsentToggle_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            // Важно: перехватываем ДО того, как ToggleButton успеет поменять IsChecked.
            // Так мы гарантируем, что при Cancel не будет даже кратковременной записи согласия в state.
            e.Handled = true;

            try
            {
                if (DataContext is not IspAudit.ViewModels.MainViewModel main)
                {
                    return;
                }

                var currentlyAllowed = main.AllowDnsDohSystemChanges;

                // Выключение — без подтверждения.
                if (currentlyAllowed)
                {
                    try
                    {
                        main.AllowDnsDohSystemChanges = false;
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
                    main.AllowDnsDohSystemChanges = true;
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
    }
}
