using System.Windows;

namespace ISPAudit
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            var logPath = System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop), "isp_audit_debug.txt");
            System.IO.File.AppendAllText(logPath, "MainWindow constructor started\n");
            
            try
            {
                InitializeComponent();
                System.IO.File.AppendAllText(logPath, "MainWindow InitializeComponent finished\n");
            }
            catch (System.Exception ex)
            {
                System.IO.File.AppendAllText(logPath, $"MainWindow InitializeComponent FAILED:\n{ex}\n");
                throw;
            }
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
