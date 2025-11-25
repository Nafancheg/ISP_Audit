using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace ISPAudit.Windows
{
    public partial class OverlayWindow : Window
    {
        private TaskCompletionSource<bool>? _silenceTcs;
        private readonly DispatcherTimer _timer;
        private int _secondsRemaining;

        public event Action? StopRequested;

        public OverlayWindow()
        {
            InitializeComponent();
            
            // Позиционирование в правом нижнем углу
            try 
            {
                var desktop = SystemParameters.WorkArea;
                double width = double.IsNaN(this.Width) ? 320 : this.Width;
                double height = double.IsNaN(this.Height) ? 140 : this.Height;
                
                this.Left = desktop.Right - width - 20;
                this.Top = desktop.Bottom - height - 20;
            }
            catch 
            {
                this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            }

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += Timer_Tick;
        }

        public void UpdateStatus(string status)
        {
            StatusText.Text = status;
        }

        public Task<bool> ShowSilencePromptAsync(int timeoutSeconds)
        {
            _silenceTcs = new TaskCompletionSource<bool>();
            _secondsRemaining = timeoutSeconds;
            UpdateTimerText();
            
            // Switch to Silence Mode
            TimerPanel.Visibility = Visibility.Visible;
            ExtendButton.Visibility = Visibility.Visible;
            StopButton.Content = "Завершить";
            Grid.SetColumnSpan(StopButton, 1);
            
            _timer.Start();
            
            return _silenceTcs.Task;
        }

        private void HideSilencePrompt()
        {
            _timer.Stop();
            TimerPanel.Visibility = Visibility.Collapsed;
            ExtendButton.Visibility = Visibility.Collapsed;
            StopButton.Content = "Остановить";
            Grid.SetColumnSpan(StopButton, 2);
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            _secondsRemaining--;
            UpdateTimerText();
            
            if (_secondsRemaining <= 0)
            {
                // Auto-stop
                _silenceTcs?.TrySetResult(false);
                HideSilencePrompt();
            }
        }

        private void UpdateTimerText()
        {
            TimerText.Text = $"{_secondsRemaining} с";
        }

        private void Extend_Click(object sender, RoutedEventArgs e)
        {
            _silenceTcs?.TrySetResult(true);
            HideSilencePrompt();
        }

        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            if (_silenceTcs != null && !_silenceTcs.Task.IsCompleted)
            {
                // If in silence mode, this means "Finish now"
                _silenceTcs.TrySetResult(false);
                HideSilencePrompt();
            }
            else
            {
                // If in normal mode, this means "User requested stop"
                StopRequested?.Invoke();
            }
        }
        
        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            _timer.Stop();
            _silenceTcs?.TrySetResult(false);
        }
    }
}
