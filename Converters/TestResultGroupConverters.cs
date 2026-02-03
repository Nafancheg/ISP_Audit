using System;
using System.Globalization;
using System.Net;
using System.Windows.Data;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.Converters
{
    public sealed class TestResultToGroupKeyConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (values.Length < 2) return string.Empty;

                var test = values[0] as TestResult;
                var suffix = values[1]?.ToString();

                var hostKey = GetPreferredHostKey(test);
                return ComputeApplyGroupKey(hostKey, suffix);
            }
            catch
            {
                return string.Empty;
            }
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }

        private static string GetPreferredHostKey(TestResult? test)
        {
            if (test?.Target == null) return string.Empty;

            // P1.9: если строка уже агрегирована и имеет детерминированный UiKey (например group-youtube),
            // используем его, чтобы Group/ACTIVE совпадали с ActiveApplyGroupKey.
            if (!string.IsNullOrWhiteSpace(test.UiKey))
            {
                return test.UiKey.Trim();
            }

            var candidates = new[]
            {
                test.Target.SniHost,
                test.Target.Host,
                test.Target.Name,
                test.Target.FallbackIp
            };

            foreach (var c in candidates)
            {
                if (string.IsNullOrWhiteSpace(c)) continue;
                var trimmed = c.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                if (IPAddress.TryParse(trimmed, out _))
                {
                    return trimmed;
                }

                if (!NoiseHostFilter.Instance.IsNoiseHost(trimmed))
                {
                    return trimmed;
                }
            }

            return candidates[0]?.Trim() ?? string.Empty;
        }

        private static string ComputeApplyGroupKey(string hostKey, string? suggestedDomainSuffix)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hostKey)) return string.Empty;

                // IP адрес не агрегируем.
                if (IPAddress.TryParse(hostKey, out _)) return hostKey;

                var suffix = (suggestedDomainSuffix ?? string.Empty).Trim().Trim('.');
                if (suffix.Length == 0) return hostKey;

                if (hostKey.Equals(suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                if (hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                return hostKey;
            }
            catch
            {
                return hostKey ?? string.Empty;
            }
        }
    }

    public sealed class TestResultIsInActiveGroupConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (values.Length < 4) return false;

                var test = values[0] as TestResult;
                var suffix = values[1]?.ToString();
                var activeGroupKey = values[2]?.ToString() ?? string.Empty;
                var isBypassActive = values[3] is bool b && b;

                if (!isBypassActive) return false;
                if (string.IsNullOrWhiteSpace(activeGroupKey)) return false;

                var hostKey = TestResultToGroupKeyConverterHostKey(test);
                var rowGroupKey = TestResultToGroupKeyConverterGroupKey(hostKey, suffix);

                return string.Equals(rowGroupKey, activeGroupKey.Trim().Trim('.'), StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }

        private static string TestResultToGroupKeyConverterHostKey(TestResult? test)
        {
            if (test?.Target == null) return string.Empty;

            // P1.9: предпочитаем UiKey (если присутствует), чтобы ACTIVE/Group были стабильны.
            if (!string.IsNullOrWhiteSpace(test.UiKey))
            {
                return test.UiKey.Trim();
            }

            var candidates = new[]
            {
                test.Target.SniHost,
                test.Target.Host,
                test.Target.Name,
                test.Target.FallbackIp
            };

            foreach (var c in candidates)
            {
                if (string.IsNullOrWhiteSpace(c)) continue;
                var trimmed = c.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                if (IPAddress.TryParse(trimmed, out _))
                {
                    return trimmed;
                }

                if (!NoiseHostFilter.Instance.IsNoiseHost(trimmed))
                {
                    return trimmed;
                }
            }

            return candidates[0]?.Trim() ?? string.Empty;
        }

        private static string TestResultToGroupKeyConverterGroupKey(string hostKey, string? suggestedDomainSuffix)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hostKey)) return string.Empty;

                if (IPAddress.TryParse(hostKey, out _)) return hostKey;

                var suffix = (suggestedDomainSuffix ?? string.Empty).Trim().Trim('.');
                if (suffix.Length == 0) return hostKey;

                if (hostKey.Equals(suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                if (hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                return hostKey;
            }
            catch
            {
                return hostKey ?? string.Empty;
            }
        }
    }

    public sealed class TestResultHasDomainSuggestionConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (values.Length < 3) return false;

                var test = values[0] as TestResult;
                var suffix = (values[1]?.ToString() ?? string.Empty).Trim().Trim('.');
                var canSuggest = values[2] is bool b && b;

                if (!canSuggest) return false;
                if (string.IsNullOrWhiteSpace(suffix)) return false;

                var hostKey = GetPreferredHostKey(test).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hostKey)) return false;

                if (IPAddress.TryParse(hostKey, out _)) return false;

                // 1) Классический режим: показываем кнопку только для текущей подсказки семейства.
                if (canSuggest && !string.IsNullOrWhiteSpace(suffix))
                {
                    if (hostKey.Equals(suffix, StringComparison.OrdinalIgnoreCase)
                        || hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                // 2) Практический fallback: если у строки есть рекомендация INTEL, позволяем применить доменный режим
                // даже без авто-подсказки (по базовому домену строки, например *.googlevideo.com → googlevideo.com).
                if (test != null && test.ShowConnectButton)
                {
                    return IspAudit.Utils.DomainUtils.TryGetBaseSuffix(hostKey, out _);
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }

        private static string GetPreferredHostKey(TestResult? test)
        {
            if (test?.Target == null) return string.Empty;

            var candidates = new[]
            {
                test.Target.SniHost,
                test.Target.Host,
                test.Target.Name,
                test.Target.FallbackIp
            };

            foreach (var c in candidates)
            {
                if (string.IsNullOrWhiteSpace(c)) continue;
                var trimmed = c.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                if (IPAddress.TryParse(trimmed, out _))
                {
                    return trimmed;
                }

                if (!NoiseHostFilter.Instance.IsNoiseHost(trimmed))
                {
                    return trimmed;
                }
            }

            return candidates[0]?.Trim() ?? string.Empty;
        }
    }

    public sealed class TestResultIsExcludedNoiseHostConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                var test = value as TestResult;
                if (test?.Target == null) return false;

                var candidates = new[]
                {
                    test.Target.SniHost,
                    test.Target.Host,
                    test.Target.Name,
                    test.Target.FallbackIp
                };

                foreach (var c in candidates)
                {
                    if (string.IsNullOrWhiteSpace(c)) continue;
                    var trimmed = c.Trim().Trim('.');
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;

                    // IP не считаем «исключением». Это может быть полезная цель.
                    if (IPAddress.TryParse(trimmed, out _)) return false;

                    return NoiseHostFilter.Instance.IsNoiseHost(trimmed);
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
