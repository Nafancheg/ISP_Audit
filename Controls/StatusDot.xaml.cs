using System.Windows;
using System.Windows.Controls;
using IspAudit.Models;

namespace IspAudit.Controls
{
    public partial class StatusDot : System.Windows.Controls.UserControl
    {
        public static readonly DependencyProperty StatusProperty =
            DependencyProperty.Register("Status", typeof(TestStatus), typeof(StatusDot),
                new PropertyMetadata(TestStatus.Idle, OnStatusChanged));

        public TestStatus Status
        {
            get => (TestStatus)GetValue(StatusProperty);
            set => SetValue(StatusProperty, value);
        }

        public StatusDot()
        {
            InitializeComponent();
            UpdateStatus();
        }

        private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            ((StatusDot)d).UpdateStatus();
        }

        private void UpdateStatus()
        {
            IdleDot.Visibility = Status == TestStatus.Idle ? Visibility.Visible : Visibility.Collapsed;
            RunningDot.Visibility = Status == TestStatus.Running ? Visibility.Visible : Visibility.Collapsed;
            PassDot.Visibility = Status == TestStatus.Pass ? Visibility.Visible : Visibility.Collapsed;
            FailDot.Visibility = Status == TestStatus.Fail ? Visibility.Visible : Visibility.Collapsed;
            WarnDot.Visibility = Status == TestStatus.Warn ? Visibility.Visible : Visibility.Collapsed;
        }
    }
}
