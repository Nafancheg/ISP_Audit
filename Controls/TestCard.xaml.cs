using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using ISPAudit.Models;
using ISPAudit.Utils;

namespace ISPAudit.Controls
{
    public partial class TestCard : System.Windows.Controls.UserControl
    {
        public static readonly DependencyProperty TestResultProperty =
            DependencyProperty.Register("TestResult", typeof(TestResult), typeof(TestCard),
                new PropertyMetadata(null, OnTestResultChanged));

        public TestResult TestResult
        {
            get => (TestResult)GetValue(TestResultProperty);
            set => SetValue(TestResultProperty, value);
        }

        public TestCard()
        {
            InitializeComponent();
        }

        private static void OnTestResultChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var card = (TestCard)d;
            if (e.OldValue is TestResult oldResult)
            {
                oldResult.PropertyChanged -= card.TestResult_PropertyChanged;
            }
            if (e.NewValue is TestResult newResult)
            {
                newResult.PropertyChanged += card.TestResult_PropertyChanged;
                card.UpdateCard();
            }
        }

        private void TestResult_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            Dispatcher.Invoke(() => UpdateCard());
        }

        private void UpdateCard()
        {
            try
            {
                if (TestResult == null || TestResult.Target == null)
                {
                    return;
                }

                var target = TestResult.Target;
                
                statusDot.Status = TestResult.Status;
                titleText.Text = target.Name;
                serviceText.Text = target.Service;
                hostText.Text = target.Host;

                criticalBadge.Visibility = target.Critical ? Visibility.Visible : Visibility.Collapsed;

                if (!string.IsNullOrEmpty(target.FallbackIp))
                {
                    fallbackText.Text = $"Fallback: {target.FallbackIp}";
                    fallbackText.Visibility = Visibility.Visible;
                    if (CopyFallbackIpItem != null) CopyFallbackIpItem.Visibility = Visibility.Visible;
                }
                else
                {
                    fallbackText.Visibility = Visibility.Collapsed;
                    if (CopyFallbackIpItem != null) CopyFallbackIpItem.Visibility = Visibility.Collapsed;
                }

                if (TestResult.Status != TestStatus.Idle)
                {
                    statusText.Text = TestResult.StatusText;
                    statusText.Foreground = GetStatusBrush(TestResult.Status);
                    statusText.Visibility = Visibility.Visible;
                }
                else
                {
                    statusText.Visibility = Visibility.Collapsed;
                }

                detailsButton.Visibility = TestResult.ShowDetailsButton ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[TestCard.UpdateCard] EXCEPTION: {ex.Message}");
            }
        }

        private System.Windows.Media.Brush GetStatusBrush(TestStatus status)
        {
            return status switch
            {
                TestStatus.Idle => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("IdleBrush"),
                TestStatus.Running => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("RunningBrush"),
                TestStatus.Pass => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("PassBrush"),
                TestStatus.Fail => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("FailBrush"),
                TestStatus.Warn => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("WarnBrush"),
                _ => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("MutedBrush")
            };
        }

        private void DetailsButton_Click(object sender, RoutedEventArgs e)
        {
            if (TestResult == null) return;
            
            var detailsWindow = new ISPAudit.Windows.TestDetailsWindow(TestResult)
            {
                Owner = System.Windows.Application.Current.MainWindow
            };
            detailsWindow.ShowDialog();
        }

        private void CopyHost_Click(object sender, RoutedEventArgs e)
        {
            if (TestResult?.Target?.Host is string host && !string.IsNullOrEmpty(host))
            {
                System.Windows.Clipboard.SetText(host);
            }
        }

        private void CopyFallbackIp_Click(object sender, RoutedEventArgs e)
        {
            if (TestResult?.Target?.FallbackIp is string ip && !string.IsNullOrEmpty(ip))
            {
                System.Windows.Clipboard.SetText(ip);
            }
        }
    }
}
