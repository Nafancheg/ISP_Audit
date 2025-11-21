using System.IO;
using System.Linq;
using System.Text;
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
            var totalPorts = _profile.Targets.Sum(t => t.Ports?.Count ?? 0);
            
            StatsText.Text = $"Всего целей: {totalTargets}\n" +
                           $"Критичных: {criticalTargets}\n" +
                           $"Уникальных портов: {totalPorts}\n" +
                           $"Режим теста: {_profile.TestMode}";

            // Список целей с ViewModel обёрткой для отображения
            TargetsDataGrid.ItemsSource = _profile.Targets.Select(t => new TargetDisplayItem(t)).ToList();
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

        private void CopyButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("=== Захваченные цели ===");
                sb.AppendLine($"Профиль: {_profile.Name}");
                sb.AppendLine($"Всего целей: {_profile.Targets.Count}");
                sb.AppendLine();

                foreach (var target in _profile.Targets)
                {
                    sb.AppendLine($"Хост: {target.Host}");
                    sb.AppendLine($"  IP: {target.FallbackIp}");
                    sb.AppendLine($"  Порты: {string.Join(", ", target.Ports ?? new List<int>())}");
                    sb.AppendLine($"  Протоколы: {string.Join(", ", target.Protocols ?? new List<string>())}");
                    sb.AppendLine($"  Сервис: {target.Service}");
                    sb.AppendLine();
                }

                System.Windows.Clipboard.SetText(sb.ToString());

                MessageBox.Show(
                    "Список целей скопирован в буфер обмена!",
                    "Копирование успешно",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Ошибка копирования:\n{ex.Message}",
                    "Ошибка",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
        }

        /// <summary>
        /// ViewModel для отображения целей с форматированными полями
        /// </summary>
        private class TargetDisplayItem
        {
            private readonly TargetDefinition _target;

            public TargetDisplayItem(TargetDefinition target)
            {
                _target = target;
            }

            public string Host => _target.Host;
            public string? FallbackIp => _target.FallbackIp;
            public string Service => _target.Service;
            public bool Critical => _target.Critical;
            
            public string PortsDisplay => _target.Ports != null && _target.Ports.Any()
                ? string.Join(", ", _target.Ports.OrderBy(p => p))
                : "-";
            
            public string ProtocolsDisplay => _target.Protocols != null && _target.Protocols.Any()
                ? string.Join(", ", _target.Protocols)
                : "-";
        }
    }
}
