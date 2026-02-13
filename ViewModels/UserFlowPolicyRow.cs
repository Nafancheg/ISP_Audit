using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Редактируемая строка пользовательской политики для UI (DataGrid).
    /// Хранит поля в простом виде (строки/числа), чтобы избежать init-only моделей.
    /// </summary>
    public sealed class UserFlowPolicyRow : INotifyPropertyChanged
    {
        private string _id = string.Empty;
        private string _scope = "Local";
        private int _priority;
        private string _proto = "Tcp";
        private string _port = "443";
        private string _tlsStage = "ClientHello";
        private string _sniPattern = "";
        private string _action = "TlsBypassStrategy";
        private string _tlsStrategy = "Fake";

        public string Id { get => _id; set => Set(ref _id, value); }
        public string Scope { get => _scope; set => Set(ref _scope, value); }
        public int Priority { get => _priority; set => Set(ref _priority, value); }
        public string Proto { get => _proto; set => Set(ref _proto, value); }
        public string Port { get => _port; set => Set(ref _port, value); }
        public string TlsStage { get => _tlsStage; set => Set(ref _tlsStage, value); }
        public string SniPattern { get => _sniPattern; set => Set(ref _sniPattern, value); }

        /// <summary>
        /// PASS | BLOCK | DropUdp443 | HttpHostTricks | TlsBypassStrategy
        /// </summary>
        public string Action { get => _action; set => Set(ref _action, value); }

        /// <summary>
        /// Для Action=TlsBypassStrategy: Fake/Fragment/Disorder/FakeFragment/FakeDisorder и т.д.
        /// </summary>
        public string TlsStrategy { get => _tlsStrategy; set => Set(ref _tlsStrategy, value); }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
        {
            if (Equals(field, value)) return;
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        public static UserFlowPolicyRow CreateDefault()
            => new()
            {
                Id = $"user_{DateTime.UtcNow:yyyyMMdd_HHmmss}",
                Scope = "Local",
                Priority = 0,
                Proto = "Tcp",
                Port = "443",
                TlsStage = "ClientHello",
                SniPattern = "*.example.com",
                Action = "TlsBypassStrategy",
                TlsStrategy = "Fake"
            };
    }
}
