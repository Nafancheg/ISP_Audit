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

        private void ToggleFixDetails_Click(object sender, RoutedEventArgs e)
        {
            if (FixDetailsList.Visibility == Visibility.Collapsed)
            {
                FixDetailsList.Visibility = Visibility.Visible;
                ToggleFixDetailsButton.Content = "▲ Свернуть";
            }
            else
            {
                FixDetailsList.Visibility = Visibility.Collapsed;
                ToggleFixDetailsButton.Content = "▼ Подробнее";
            }
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
