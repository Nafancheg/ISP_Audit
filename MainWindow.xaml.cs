using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ISPAudit.Models;
using ISPAudit.ViewModels;

namespace ISPAudit
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Позиционирование окна: Слева по центру
            var workArea = SystemParameters.WorkArea;
            this.Left = workArea.Left + 50; // Отступ 50px от левого края
            this.Top = workArea.Top + (workArea.Height - this.Height) / 2;
        }

        private void DataGridRow_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (sender is DataGridRow row && row.DataContext is TestResult result)
            {
                if (DataContext is MainViewModel viewModel && viewModel.DetailsCommand.CanExecute(result))
                {
                    viewModel.DetailsCommand.Execute(result);
                }
            }
        }
    }
}
