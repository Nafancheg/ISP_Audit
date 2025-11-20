using System.IO;
using System.Linq;
using System.Windows;
using IspAudit.Utils;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;
using MessageBox = System.Windows.MessageBox;

namespace IspAudit.Windows
{
    public partial class CapturedTargetsWindow : Window
    {
        private readonly GameProfile _profile;

        public CapturedTargetsWindow(GameProfile profile)
        {
            InitializeComponent();
            _profile = profile;
            LoadData();
        }

        private void LoadData()
        {
            if (_profile?.Targets == null)
                return;

            // Статистика
            var totalTargets = _profile.Targets.Count;
            var criticalTargets = _profile.Targets.Count(t => t.Critical);
            
            StatsText.Text = $"Всего целей: {totalTargets}\n" +
                           $"Критичных: {criticalTargets}\n" +
                           $"Режим теста: {_profile.TestMode}";

            // Список целей
            TargetsDataGrid.ItemsSource = _profile.Targets;
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "JSON файлы (*.json)|*.json|Все файлы (*.*)|*.*",
                DefaultExt = "json",
                FileName = $"{_profile.Name}_targets.json"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var json = System.Text.Json.JsonSerializer.Serialize(_profile, new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
                    File.WriteAllText(dialog.FileName, json);

                    MessageBox.Show(
                        $"Профиль сохранен:\n{dialog.FileName}",
                        "Сохранение успешно",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        $"Ошибка сохранения:\n{ex.Message}",
                        "Ошибка",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error
                    );
                }
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
