using System;
using System.ComponentModel;
using System.IO;
using System.Windows.Input;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Лёгкая ViewModel для «Операторского» UI.
    /// Оборачивает MainViewModel и предоставляет упрощённые computed-свойства.
    /// </summary>
    public sealed class OperatorViewModel : INotifyPropertyChanged
    {
        public enum OperatorStatus
        {
            Idle,
            Checking,
            Ok,
            Warn,
            Blocked,
            Fixing
        }

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
                return Status switch
                {
                    OperatorStatus.Checking => "Идёт проверка",
                    OperatorStatus.Fixing => "Исправляю…",
                    OperatorStatus.Blocked => "Найдены проблемы",
                    OperatorStatus.Warn => "Есть ограничения",
                    OperatorStatus.Ok => "Всё в порядке",
                    _ => "Готов к проверке"
                };
            }
        }

        public string SummaryLine
        {
            get
            {
                if (Status == OperatorStatus.Checking)
                {
                    return Main.RunningStatusText;
                }

                if (Status == OperatorStatus.Fixing)
                {
                    return string.IsNullOrWhiteSpace(Main.ApplyStatusText)
                        ? "Применяю безопасные действия и перепроверяю…"
                        : Main.ApplyStatusText;
                }

                if (Main.IsDone)
                {
                    return $"OK: {Main.PassCount} • Нестабильно: {Main.WarnCount} • Блокируется: {Main.FailCount}";
                }

                // Idle
                if (Main.IsBasicTestMode)
                {
                    return "Источник: быстрая проверка интернета. Нажмите «Проверить».";
                }

                var exePath = (Main.ExePath ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(exePath))
                {
                    try
                    {
                        return $"Источник: {Path.GetFileName(exePath)}. Нажмите «Проверить».";
                    }
                    catch
                    {
                        return "Источник: выбранное приложение (.exe). Нажмите «Проверить».";
                    }
                }

                return "Выберите источник трафика и нажмите «Проверить».";
            }
        }

        public OperatorStatus Status
        {
            get
            {
                if (Main.IsApplyRunning) return OperatorStatus.Fixing;
                if (Main.IsRunning) return OperatorStatus.Checking;

                if (Main.IsDone)
                {
                    if (Main.FailCount > 0) return OperatorStatus.Blocked;
                    if (Main.WarnCount > 0) return OperatorStatus.Warn;
                    return OperatorStatus.Ok;
                }

                return OperatorStatus.Idle;
            }
        }

        public PackIconKind HeroIconKind
        {
            get
            {
                return Status switch
                {
                    OperatorStatus.Checking => PackIconKind.Radar,
                    OperatorStatus.Fixing => PackIconKind.Wrench,
                    OperatorStatus.Blocked => PackIconKind.ShieldAlert,
                    OperatorStatus.Warn => PackIconKind.ShieldOutline,
                    OperatorStatus.Ok => PackIconKind.ShieldCheck,
                    _ => PackIconKind.Shield
                };
            }
        }

        public System.Windows.Media.Brush HeroAccentBrush
        {
            get
            {
                return Status switch
                {
                    OperatorStatus.Checking => System.Windows.Media.Brushes.DodgerBlue,
                    OperatorStatus.Fixing => System.Windows.Media.Brushes.DodgerBlue,
                    OperatorStatus.Blocked => System.Windows.Media.Brushes.IndianRed,
                    OperatorStatus.Warn => System.Windows.Media.Brushes.DarkOrange,
                    OperatorStatus.Ok => System.Windows.Media.Brushes.SeaGreen,
                    _ => System.Windows.Media.Brushes.Gray
                };
            }
        }

        public bool IsSourceStepVisible =>
            Status == OperatorStatus.Idle
            || Status == OperatorStatus.Ok
            || Status == OperatorStatus.Warn
            || Status == OperatorStatus.Blocked;

        public bool IsProgressStepVisible => Status == OperatorStatus.Checking;

        public bool IsSummaryStepVisible =>
            Status == OperatorStatus.Ok
            || Status == OperatorStatus.Warn
            || Status == OperatorStatus.Blocked;

        public bool IsFixingStepVisible => Status == OperatorStatus.Fixing;

        public bool IsSourceSelectionEnabled => IsSourceStepVisible && !Main.IsRunning && !Main.IsApplyRunning;

        public bool ShowFixButton =>
            (Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
            && Main.HasAnyRecommendations
            && !Main.IsApplyRunning;

        public bool ShowPrimaryButton => !ShowFixButton;

        public string PrimaryButtonText
        {
            get
            {
                if (Status == OperatorStatus.Checking) return "Остановить";
                if (Status == OperatorStatus.Ok) return "Проверить снова";
                if (Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked)
                {
                    return Main.HasAnyRecommendations ? "Исправить" : "Проверить снова";
                }
                return "Проверить";
            }
        }

        public ICommand PrimaryCommand
        {
            get
            {
                if ((Status == OperatorStatus.Warn || Status == OperatorStatus.Blocked) && Main.HasAnyRecommendations)
                {
                    return Main.ApplyRecommendationsCommand;
                }
                return Main.StartLiveTestingCommand;
            }
        }

        public string FixButtonText => Main.IsApplyRunning ? "Исправляю…" : "Исправить";
        public ICommand FixCommand => Main.ApplyRecommendationsCommand;

        public event PropertyChangedEventHandler? PropertyChanged;

        private void RaiseDerivedProperties()
        {
            OnPropertyChanged(nameof(Status));
            OnPropertyChanged(nameof(HeroIconKind));
            OnPropertyChanged(nameof(HeroAccentBrush));
            OnPropertyChanged(nameof(IsSourceStepVisible));
            OnPropertyChanged(nameof(IsProgressStepVisible));
            OnPropertyChanged(nameof(IsSummaryStepVisible));
            OnPropertyChanged(nameof(IsFixingStepVisible));
            OnPropertyChanged(nameof(IsSourceSelectionEnabled));
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
