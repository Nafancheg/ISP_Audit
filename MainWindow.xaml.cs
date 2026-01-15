using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using IspAudit.Models;
using IspAudit.ViewModels;
using System.ComponentModel;
using System.Windows.Threading;

namespace IspAudit
{
    public partial class MainWindow : Window
    {
        private bool _shutdownInProgress;
        private bool _shutdownCompleted;

        public MainWindow()
        {
            InitializeComponent();
            Closing += Window_Closing;
        }

        private async void Window_Closing(object? sender, CancelEventArgs e)
        {
            // Если shutdown уже завершён, даём окну закрыться штатно.
            if (_shutdownCompleted)
            {
                return;
            }

            e.Cancel = true;

            // Shutdown уже выполняется — не даём закрыть окно, пока он не завершится.
            if (_shutdownInProgress)
            {
                return;
            }

            _shutdownInProgress = true;

            try
            {
                if (DataContext is MainViewModel viewModel)
                {
                    await viewModel.ShutdownAsync();
                }
            }
            catch
            {
                // ignore
            }
            finally
            {
                _shutdownInProgress = false;
                _shutdownCompleted = true;

                // ВАЖНО: нельзя вызывать Close() из обработчика Closing.
                // Планируем повторное закрытие через Dispatcher после выхода из текущего стека.
                _ = Dispatcher.BeginInvoke(
                    DispatcherPriority.Background,
                    new Action(() =>
                    {
                        try
                        {
                            Close();
                        }
                        catch
                        {
                            // ignore
                        }
                    }));
            }
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Позиционирование окна: Слева по центру
            var workArea = SystemParameters.WorkArea;
            this.Left = workArea.Left + 50; // Отступ 50px от левого края
            this.Top = workArea.Top + (workArea.Height - this.Height) / 2;

            if (DataContext is MainViewModel viewModel)
            {
                await viewModel.InitializeAsync();
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

        private void CopyHost_Click(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItems.Count > 0)
            {
                var hosts = new System.Collections.Generic.List<string>();
                foreach (var item in ResultsGrid.SelectedItems)
                {
                    if (item is TestResult result && !string.IsNullOrEmpty(result.Target?.Host))
                    {
                        hosts.Add(result.Target.Host);
                    }
                }

                if (hosts.Count > 0)
                {
                    System.Windows.Clipboard.SetText(string.Join(Environment.NewLine, hosts));
                }
            }
        }

        private void CopyFallbackIp_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuItem menuItem && menuItem.DataContext is TestResult result)
            {
                if (!string.IsNullOrEmpty(result.Target?.FallbackIp))
                {
                    System.Windows.Clipboard.SetText(result.Target.FallbackIp);
                }
            }
        }
    }
}
