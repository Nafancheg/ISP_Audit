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

        public bool ShowConnectButton
            => IsBypassStrategyFromV2 &&
               !string.IsNullOrWhiteSpace(BypassStrategy) &&
               !string.Equals(BypassStrategy, PipelineContract.BypassNone, StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(BypassStrategy, PipelineContract.BypassUnknown, StringComparison.OrdinalIgnoreCase);

        public string StrategyIconHint
            => ShowConnectButton ? (BypassStrategy ?? string.Empty) : string.Empty;

        public string[] StrategyIconNames
        {
            get
            {
                if (!ShowConnectButton) return Array.Empty<string>();

                var text = BypassStrategy ?? string.Empty;
                if (string.IsNullOrWhiteSpace(text)) return Array.Empty<string>();

                // Иконки делаем консистентными для таблицы и кнопок слева.
                // Используем безопасные иконки, которые уже применяются в проекте.
                var icons = new System.Collections.Generic.List<string>();

                bool Contains(string s) => text.Contains(s, StringComparison.OrdinalIgnoreCase);

                // Frag / Frag+Rev
                if (Contains("Frag+Rev") || Contains("Disorder") || Contains("Rev"))
                {
                    icons.Add("ThemeLightDark");
                }
                else if (Contains("Frag"))
                {
                    icons.Add("Tune");
                }

                // TLS Fake
                if (Contains("Fake"))
                {
                    icons.Add("Alert");
                }

                // Drop RST
                if (Contains("RST"))
                {
                    icons.Add("InformationOutline");
                }

                // QUIC→TCP
                if (Contains("QUIC") || Contains("UDP/443"))
                {
                    icons.Add("LanConnect");
                }

                // No SNI
                if (Contains("No SNI") || Contains("ALLOW_NO_SNI"))
                {
                    icons.Add("ChartBar");
                }

                // DoH
                if (Contains("DoH") || Contains("DNS-over-HTTPS"))
                {
                    icons.Add("LightbulbOutline");
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
