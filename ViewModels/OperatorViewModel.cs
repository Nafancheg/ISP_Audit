using System;
using System.ComponentModel;
using System.Windows.Input;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Лёгкая ViewModel для «Операторского» UI.
    /// Оборачивает MainViewModel и предоставляет упрощённые computed-свойства.
    /// </summary>
    public sealed class OperatorViewModel : INotifyPropertyChanged
    {
        public MainViewModel Main { get; }

        public OperatorViewModel(MainViewModel main)
        {
            Main = main ?? throw new ArgumentNullException(nameof(main));
            Main.PropertyChanged += (_, __) => RaiseDerivedProperties();
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
