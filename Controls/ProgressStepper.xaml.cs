using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ISPAudit.Controls
{
    public partial class ProgressStepper : System.Windows.Controls.UserControl
    {
        public static readonly DependencyProperty TotalProperty =
            DependencyProperty.Register("Total", typeof(int), typeof(ProgressStepper),
                new PropertyMetadata(0, OnStepChanged));

        public static readonly DependencyProperty CurrentProperty =
            DependencyProperty.Register("Current", typeof(int), typeof(ProgressStepper),
                new PropertyMetadata(0, OnStepChanged));

        public static readonly DependencyProperty CompletedProperty =
            DependencyProperty.Register("Completed", typeof(int), typeof(ProgressStepper),
                new PropertyMetadata(0, OnStepChanged));

        public int Total
        {
            get => (int)GetValue(TotalProperty);
            set => SetValue(TotalProperty, value);
        }

        public int Current
        {
            get => (int)GetValue(CurrentProperty);
            set => SetValue(CurrentProperty, value);
        }

        public int Completed
        {
            get => (int)GetValue(CompletedProperty);
            set => SetValue(CompletedProperty, value);
        }

        public ProgressStepper()
        {
            InitializeComponent();
        }

        private static void OnStepChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            ((ProgressStepper)d).UpdateSteps();
        }

        private void UpdateSteps()
        {
            var steps = new ObservableCollection<StepViewModel>();

            for (int i = 1; i <= Total; i++)
            {
                bool isCompleted = i <= Completed;
                bool isCurrent = i == Current;
                bool showLine = i < Total;

                var step = new StepViewModel
                {
                    Number = i.ToString(),
                    Background = GetStepBackground(isCompleted, isCurrent),
                    Foreground = GetStepForeground(isCompleted, isCurrent),
                    BorderBrush = GetStepBorder(isCompleted, isCurrent),
                    BorderThickness = (isCompleted || isCurrent) ? new Thickness(0) : new Thickness(1),
                    LineColor = i < Current ? (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("PassBrush") : 
                                              (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("BorderBrush"),
                    ShowLine = showLine ? Visibility.Visible : Visibility.Collapsed
                };

                steps.Add(step);
            }

            stepsControl.ItemsSource = steps;
        }

        private System.Windows.Media.Brush GetStepBackground(bool isCompleted, bool isCurrent)
        {
            if (isCompleted)
                return (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("PassBrush");
            if (isCurrent)
                return (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("RunningBrush");
            return new SolidColorBrush(System.Windows.Media.Color.FromRgb(249, 250, 251));
        }

        private System.Windows.Media.Brush GetStepForeground(bool isCompleted, bool isCurrent)
        {
            if (isCompleted || isCurrent)
                return System.Windows.Media.Brushes.White;
            return (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("IdleBrush");
        }

        private System.Windows.Media.Brush GetStepBorder(bool isCompleted, bool isCurrent)
        {
            if (isCompleted || isCurrent)
                return System.Windows.Media.Brushes.Transparent;
            return (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("BorderBrush");
        }
    }

    public class StepViewModel
    {
        public string Number { get; set; } = "";
        public System.Windows.Media.Brush Background { get; set; } = System.Windows.Media.Brushes.Transparent;
        public System.Windows.Media.Brush Foreground { get; set; } = System.Windows.Media.Brushes.Black;
        public System.Windows.Media.Brush BorderBrush { get; set; } = System.Windows.Media.Brushes.Transparent;
        public Thickness BorderThickness { get; set; }
        public System.Windows.Media.Brush LineColor { get; set; } = System.Windows.Media.Brushes.Transparent;
        public Visibility ShowLine { get; set; }
    }
}
