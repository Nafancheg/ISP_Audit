using System.Windows;

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
    }
}
