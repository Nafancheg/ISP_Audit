using System;
using System.Windows;

namespace IspAudit.Windows
{
    public partial class OperatorHelpWindow : Window
    {
        private readonly Action _openEngineer;

        public OperatorHelpWindow(Action openEngineer)
        {
            _openEngineer = openEngineer ?? throw new ArgumentNullException(nameof(openEngineer));

            InitializeComponent();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            try { Close(); } catch { }
        }

        private void OpenEngineer_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Сначала закрываем модальное окно, затем переключаем режим.
                Close();
            }
            catch
            {
                // ignore
            }

            try
            {
                _openEngineer();
            }
            catch
            {
                // ignore
            }
        }
    }
}
