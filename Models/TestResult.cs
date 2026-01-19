using System;
using System.ComponentModel;
using System.Linq;
using IspAudit.Core.Diagnostics;

namespace IspAudit.Models
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
        private string _error = string.Empty;
        private string? _details;

        private Target _target = null!;

        public Target Target
        {
            get => _target;
            set
            {
                _target = value;
                OnPropertyChanged(nameof(Target));
                OnPropertyChanged(nameof(DisplayIp));
                OnPropertyChanged(nameof(DisplayHost));
            }
        }

        public string DisplayIp
        {
            get
            {
                var ip = Target?.FallbackIp;
                if (!string.IsNullOrWhiteSpace(ip)) return ip;

                // На старом контракте Host мог быть IP. На новом Host часто становится человеко‑понятным ключом.
                return Target?.Host ?? string.Empty;
            }
        }

        public string DisplayHost
        {
            get
            {
                var sni = Target?.SniHost;
                if (!string.IsNullOrWhiteSpace(sni)) return sni;

                var host = Target?.Host;
                if (!string.IsNullOrWhiteSpace(host)) return host;

                return Target?.Name ?? string.Empty;
            }
        }

        public TestStatus Status
        {
            get => _status;
            set
            {
                _status = value;
                OnPropertyChanged(nameof(Status));
                OnPropertyChanged(nameof(StatusText));
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

        private bool _isRstInjection;
        public bool IsRstInjection
        {
            get => _isRstInjection;
            set
            {
                _isRstInjection = value;
                OnPropertyChanged(nameof(IsRstInjection));
            }
        }

        private bool _isHttpRedirect;
        public bool IsHttpRedirect
        {
            get => _isHttpRedirect;
            set
            {
                _isHttpRedirect = value;
                OnPropertyChanged(nameof(IsHttpRedirect));
            }
        }

        private bool _isRetransmissionHeavy;
        public bool IsRetransmissionHeavy
        {
            get => _isRetransmissionHeavy;
            set
            {
                _isRetransmissionHeavy = value;
                OnPropertyChanged(nameof(IsRetransmissionHeavy));
            }
        }

        private bool _isUdpBlockage;
        public bool IsUdpBlockage
        {
            get => _isUdpBlockage;
            set
            {
                _isUdpBlockage = value;
                OnPropertyChanged(nameof(IsUdpBlockage));
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

        /// <summary>
        /// Стратегия обхода (WinDivert), полученная от LiveTestingPipeline
        /// </summary>
        private string? _bypassStrategy;
        public string? BypassStrategy
        {
            get => _bypassStrategy;
            set
            {
                _bypassStrategy = value;
                OnPropertyChanged(nameof(BypassStrategy));
                OnPropertyChanged(nameof(ShowConnectButton));
                OnPropertyChanged(nameof(StrategyIconNames));
                OnPropertyChanged(nameof(StrategyIconHint));
            }
        }

        /// <summary>
        /// Источник рекомендации по стратегии обхода.
        /// Нужен, чтобы legacy-логика не «перебивала» рекомендации v2.
        /// </summary>
        private bool _isBypassStrategyFromV2;
        public bool IsBypassStrategyFromV2
        {
            get => _isBypassStrategyFromV2;
            set
            {
                _isBypassStrategyFromV2 = value;
                OnPropertyChanged(nameof(IsBypassStrategyFromV2));
                OnPropertyChanged(nameof(ShowConnectButton));
                OnPropertyChanged(nameof(StrategyIconNames));
                OnPropertyChanged(nameof(StrategyIconHint));
            }
        }

        private bool _isAppliedBypassTarget;
        public bool IsAppliedBypassTarget
        {
            get => _isAppliedBypassTarget;
            set
            {
                _isAppliedBypassTarget = value;
                OnPropertyChanged(nameof(IsAppliedBypassTarget));
            }
        }

        private string _lastApplyTransactionText = string.Empty;
        public string LastApplyTransactionText
        {
            get => _lastApplyTransactionText;
            set
            {
                if (string.Equals(_lastApplyTransactionText, value, StringComparison.Ordinal)) return;
                _lastApplyTransactionText = value ?? string.Empty;
                OnPropertyChanged(nameof(LastApplyTransactionText));
                OnPropertyChanged(nameof(ShowLastApplyTransactionText));
            }
        }

        public bool ShowLastApplyTransactionText => !string.IsNullOrWhiteSpace(LastApplyTransactionText);

        private string _actionStatusText = string.Empty;
        public string ActionStatusText
        {
            get => _actionStatusText;
            set
            {
                if (string.Equals(_actionStatusText, value, StringComparison.Ordinal)) return;
                _actionStatusText = value ?? string.Empty;
                OnPropertyChanged(nameof(ActionStatusText));
                OnPropertyChanged(nameof(ShowActionStatusText));
            }
        }

        public bool ShowActionStatusText => !string.IsNullOrWhiteSpace(ActionStatusText);

        /// <summary>
        /// Фактически применённая стратегия обхода для этой карточки (после нажатия "Подключить"/Apply).
        /// </summary>
        private string? _appliedBypassStrategy;
        public string? AppliedBypassStrategy
        {
            get => _appliedBypassStrategy;
            set
            {
                _appliedBypassStrategy = value;
                OnPropertyChanged(nameof(AppliedBypassStrategy));
                OnPropertyChanged(nameof(StrategyIconNames));
                OnPropertyChanged(nameof(StrategyIconHint));
            }
        }

        public bool ShowConnectButton
            => IsBypassStrategyFromV2 &&
               !string.IsNullOrWhiteSpace(BypassStrategy) &&
               !string.Equals(BypassStrategy, PipelineContract.BypassNone, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(BypassStrategy, PipelineContract.BypassUnknown, StringComparison.OrdinalIgnoreCase);

        public string StrategyIconHint
        {
            get
            {
                var applied = AppliedBypassStrategy;
                var recommended = ShowConnectButton ? (BypassStrategy ?? string.Empty) : string.Empty;

                if (!string.IsNullOrWhiteSpace(applied) && !string.IsNullOrWhiteSpace(recommended)
                    && !string.Equals(applied, recommended, StringComparison.OrdinalIgnoreCase))
                {
                    return $"Применено: {applied}\nРекомендация: {recommended}";
                }

                if (!string.IsNullOrWhiteSpace(applied))
                {
                    return $"Применено: {applied}";
                }

                return recommended;
            }
        }

        public string[] StrategyIconNames
        {
            get
            {
                var text = !string.IsNullOrWhiteSpace(AppliedBypassStrategy)
                    ? AppliedBypassStrategy!
                    : (ShowConnectButton ? (BypassStrategy ?? string.Empty) : string.Empty);
                if (string.IsNullOrWhiteSpace(text)) return Array.Empty<string>();

                // Иконки делаем консистентными для таблицы и кнопок слева.
                // Используем emoji-глифы по ТЗ (визуально понятные и не зависят от PackIcon).
                var icons = new System.Collections.Generic.List<string>();

                bool Contains(string s) => text.Contains(s, StringComparison.OrdinalIgnoreCase);

                // ✂️ Frag / 🔀 Frag+Rev
                if (Contains("Frag+Rev") || Contains("Disorder") || Contains("Rev"))
                {
                    icons.Add("🔀");
                }
                else if (Contains("Frag"))
                {
                    icons.Add("✂️");
                }

                // 🎭 TLS Fake
                if (Contains("TLS Fake") || Contains("Fake"))
                {
                    icons.Add("🎭");
                }

                // 🛡️ Drop RST
                if (Contains("Drop RST") || Contains("RST"))
                {
                    icons.Add("🛡️");
                }

                // ⬇️ QUIC→TCP
                if (Contains("QUIC→TCP") || Contains("QUIC") || Contains("UDP/443"))
                {
                    icons.Add("⬇️");
                }

                // 🕶️ No SNI
                if (Contains("No SNI") || Contains("ALLOW_NO_SNI"))
                {
                    icons.Add("🕶️");
                }

                // 🔒 DoH
                if (Contains("DoH") || Contains("DNS-over-HTTPS"))
                {
                    icons.Add("🔒");
                }

                return icons.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            }
        }

        public string StatusText
        {
            get
            {
                return Status switch
                {
                    TestStatus.Idle => "Ожидание",
                    TestStatus.Running => "Проверяем…",
                    TestStatus.Pass => "Доступно",
                    TestStatus.Fail => "Блокировка",
                    TestStatus.Warn => "Нестабильно",
                    _ => ""
                };
            }
        }

        public bool ShowDetailsButton => Status == TestStatus.Fail || Status == TestStatus.Pass || Status == TestStatus.Warn;

        public event PropertyChangedEventHandler? PropertyChanged;

        public void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
