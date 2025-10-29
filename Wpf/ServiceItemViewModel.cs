using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;

namespace IspAudit.Wpf;

/// <summary>
/// ViewModel для одного сервиса в списке
/// </summary>
public class ServiceItemViewModel : INotifyPropertyChanged
{
    private string _serviceName = "";
    private string _details = "ожидание";
    private bool _isRunning;
    private bool _isCompleted;
    private string _statusIcon = "HelpCircle";
    private string _statusColor = "#9E9E9E";

    public string ServiceName
    {
        get => _serviceName;
        set { _serviceName = value; OnPropertyChanged(); }
    }

    public string Details
    {
        get => _details;
        set { _details = value; OnPropertyChanged(); }
    }

    private string _detailedMessage = string.Empty;
    public string DetailedMessage
    {
        get => _detailedMessage;
        set { _detailedMessage = value; OnPropertyChanged(); }
    }

    public bool IsRunning
    {
        get => _isRunning;
        set
        {
            _isRunning = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(RunningVisibility));
        }
    }

    public bool IsCompleted
    {
        get => _isCompleted;
        set
        {
            _isCompleted = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CompletedVisibility));
        }
    }

    public Visibility RunningVisibility => IsRunning ? Visibility.Visible : Visibility.Collapsed;
    public Visibility CompletedVisibility => IsCompleted ? Visibility.Visible : Visibility.Collapsed;

    public string StatusIcon
    {
        get => _statusIcon;
        set { _statusIcon = value; OnPropertyChanged(); }
    }

    public string StatusColor
    {
        get => _statusColor;
        set { _statusColor = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public void SetRunning(string details)
    {
        IsRunning = true;
        IsCompleted = false;
        Details = details;
    }

    public void SetSuccess(string details)
    {
        IsRunning = false;
        IsCompleted = true;
        Details = details;
        StatusIcon = "CheckCircle";
        StatusColor = "#4CAF50"; // Green
    }

    public void SetWarning(string details)
    {
        IsRunning = false;
        IsCompleted = true;
        Details = details;
        StatusIcon = "AlertCircle";
        StatusColor = "#FF9800"; // Orange
    }

    public void SetError(string details)
    {
        IsRunning = false;
        IsCompleted = true;
        Details = details;
        StatusIcon = "CloseCircle";
        StatusColor = "#F44336"; // Red
    }
}
