using System.ComponentModel;

namespace ISPAudit.Models
{
    public enum TestStatus
    {
        Idle,
        Running,
        Pass,
        Fail,
        Warn
    }

    public class TestResult : INotifyPropertyChanged
    {
        private TestStatus _status;
        private string _error;
        private string? _details;

        public Target Target { get; set; }

        public TestStatus Status
        {
            get => _status;
            set
            {
                _status = value;
                OnPropertyChanged(nameof(Status));
                OnPropertyChanged(nameof(StatusText));
                OnPropertyChanged(nameof(ShowFixButton));
                OnPropertyChanged(nameof(ShowDetailsButton));
            }
        }

        public string Error
        {
            get => _error;
            set
            {
                _error = value;
                OnPropertyChanged(nameof(Error));
            }
        }

        public string? Details
        {
            get => _details;
            set
            {
                _details = value;
                OnPropertyChanged(nameof(Details));
            }
        }

        public bool Fixable { get; set; }

        /// <summary>
        /// Тип исправления для этого теста (None = не исправляется автоматически)
        /// </summary>
        public FixType FixType { get; set; } = FixType.None;

        /// <summary>
        /// Инструкции для ручного исправления (для FixType.Manual)
        /// </summary>
        public string? FixInstructions { get; set; }

        public string StatusText
        {
            get
            {
                return Status switch
                {
                    TestStatus.Idle => "Ожидание",
                    TestStatus.Running => "Проверяем…",
                    TestStatus.Pass => "Успешно",
                    TestStatus.Fail => Error ?? "Ошибка",
                    TestStatus.Warn => "Предупреждение",
                    _ => ""
                };
            }
        }

        public bool ShowFixButton => Status == TestStatus.Fail && FixType != FixType.None;
        public bool ShowDetailsButton => (Status == TestStatus.Fail && FixType == FixType.None) || 
                                         Status == TestStatus.Pass || 
                                         Status == TestStatus.Warn;

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
