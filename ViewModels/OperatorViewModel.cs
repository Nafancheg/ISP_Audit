using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows.Input;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Лёгкая ViewModel для «Операторского» UI.
    /// Оборачивает MainViewModel и предоставляет упрощённые computed-свойства.
    /// </summary>
    public sealed class OperatorViewModel : INotifyPropertyChanged
    {
        public sealed class OperatorTargetItem
        {
            public OperatorTargetItem(string key, string title, bool isBasicServices)
            {
                Key = key;
                Title = title;
                IsBasicServices = isBasicServices;
            }

            public string Key { get; }
            public string Title { get; }
            public bool IsBasicServices { get; }

            public override string ToString() => Title;
        }

        public MainViewModel Main { get; }

        public OperatorViewModel(MainViewModel main)
        {
            Main = main ?? throw new ArgumentNullException(nameof(main));
            Main.PropertyChanged += (_, __) => RaiseDerivedProperties();

            AvailableTargets = new ObservableCollection<OperatorTargetItem>();
            LoadTargetsBestEffort();
        }

        public ObservableCollection<OperatorTargetItem> AvailableTargets { get; }

        private OperatorTargetItem? _selectedTarget;
        public OperatorTargetItem? SelectedTarget
        {
            get => _selectedTarget;
            set
            {
                if (ReferenceEquals(_selectedTarget, value)) return;
                _selectedTarget = value;
                OnPropertyChanged(nameof(SelectedTarget));
                ApplySelectedTargetToMainBestEffort(value);
                RaiseDerivedProperties();
            }
        }

        public string Headline
        {
            get
            {
                if (Main.IsRunning) return "Идёт проверка";
                if (Main.IsDone && ShowFixButton) return "Найдены проблемы";
                if (Main.IsDone && !ShowFixButton) return "Похоже, всё в порядке";
                return "Готов к проверке";
            }
        }

        public string SummaryLine
        {
            get
            {
                if (Main.IsRunning)
                {
                    return Main.RunningStatusText;
                }

                if (Main.IsDone)
                {
                    return $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";
                }

                var target = SelectedTarget?.Title;
                if (!string.IsNullOrWhiteSpace(target))
                {
                    return $"Цель: {target}. Нажмите «Проверить».";
                }

                return "Выберите цель и нажмите «Проверить».";
            }
        }

        public bool ShowFixButton => Main.IsDone && Main.HasAnyRecommendations;
        public bool ShowPrimaryButton => !ShowFixButton;

        public string PrimaryButtonText => Main.IsRunning ? "Остановить" : "Проверить";
        public ICommand PrimaryCommand => Main.StartLiveTestingCommand;

        public string FixButtonText => Main.IsApplyRunning ? "Исправляю…" : "Исправить";
        public ICommand FixCommand => Main.ApplyRecommendationsCommand;

        public event PropertyChangedEventHandler? PropertyChanged;

        private void LoadTargetsBestEffort()
        {
            try
            {
                AvailableTargets.Clear();

                // 1) Базовые сервисы — всегда доступны
                AvailableTargets.Add(new OperatorTargetItem("basic", "Базовые сервисы (Google/YouTube/Discord)", isBasicServices: true));

                // 2) Профили из каталога Profiles
                var profilesDir = Path.Combine(AppPaths.AppDirectory, "Profiles");
                if (Directory.Exists(profilesDir))
                {
                    foreach (var file in Directory.GetFiles(profilesDir, "*.json").OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                    {
                        var key = Path.GetFileNameWithoutExtension(file);
                        if (string.IsNullOrWhiteSpace(key)) continue;

                        var title = $"Профиль: {key}";

                        try
                        {
                            var json = File.ReadAllText(file);
                            var profile = JsonSerializer.Deserialize<DiagnosticProfile>(json);
                            var name = (profile?.Name ?? string.Empty).Trim();
                            if (!string.IsNullOrWhiteSpace(name))
                            {
                                title = name;
                            }
                        }
                        catch
                        {
                            // ignore
                        }

                        AvailableTargets.Add(new OperatorTargetItem(key, title, isBasicServices: false));
                    }
                }

                // 3) Выбор по умолчанию
                // Если уже активен профиль Default — показываем его.
                var defaultProfile = AvailableTargets.FirstOrDefault(t => !t.IsBasicServices && t.Key.Equals("Default", StringComparison.OrdinalIgnoreCase));
                SelectedTarget = defaultProfile ?? AvailableTargets.FirstOrDefault();
            }
            catch
            {
                // ignore
            }
        }

        private void ApplySelectedTargetToMainBestEffort(OperatorTargetItem? selected)
        {
            try
            {
                if (selected == null) return;

                if (selected.IsBasicServices)
                {
                    Main.IsBasicTestMode = true;
                    return;
                }

                Main.IsBasicTestMode = false;

                // Operator выбирает только ЦЕЛЬ (профиль), но не стратегию обхода.
                // Технические решения остаются за Orchestrator/INTEL.
                Config.SetActiveProfile(selected.Key);
            }
            catch
            {
                // ignore
            }
        }

        private void RaiseDerivedProperties()
        {
            OnPropertyChanged(nameof(Headline));
            OnPropertyChanged(nameof(SummaryLine));
            OnPropertyChanged(nameof(ShowFixButton));
            OnPropertyChanged(nameof(ShowPrimaryButton));
            OnPropertyChanged(nameof(PrimaryButtonText));
            OnPropertyChanged(nameof(FixButtonText));
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
