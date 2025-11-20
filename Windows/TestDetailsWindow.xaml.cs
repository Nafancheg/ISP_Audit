using System.Windows;
using ISPAudit.Models;

namespace ISPAudit.Windows
{
    public partial class TestDetailsWindow : Window
    {
        public TestDetailsWindow(TestResult testResult)
        {
            InitializeComponent();
            DataContext = new TestDetailsViewModel(testResult);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }

    public class TestDetailsViewModel
    {
        public TestDetailsViewModel(TestResult testResult)
        {
            TargetName = testResult.Target?.Name ?? "Unknown";
            Host = testResult.Target?.Host ?? "N/A";
            Service = testResult.Target?.Service ?? "Unknown";
            Status = testResult.Status;
            StatusText = testResult.StatusText;
            Error = testResult.Error ?? "";
            FallbackIp = testResult.Target?.FallbackIp ?? "";
            Critical = testResult.Target?.Critical ?? false;
            Details = testResult.Details ?? "Детальная информация недоступна";
        }

        public string TargetName { get; }
        public string Host { get; }
        public string Service { get; }
        public TestStatus Status { get; }
        public string StatusText { get; }
        public string Error { get; }
        public string FallbackIp { get; }
        public bool Critical { get; }
        public string Details { get; }

        public bool HasError => !string.IsNullOrEmpty(Error);
        public bool HasFallbackIp => !string.IsNullOrEmpty(FallbackIp);
        public bool HasDetails => !string.IsNullOrEmpty(Details) && Details != "Детальная информация недоступна";
        public string CriticalText => Critical ? "Критичный сервис" : "Некритичный сервис";
    }
}
