using System;
using System.Globalization;
using System.Windows.Data;
using MaterialDesignThemes.Wpf;

namespace IspAudit.Converters
{
    /// <summary>
    /// Конвертер: строка с именем иконки MaterialDesign -> PackIconKind.
    /// Нужен, чтобы подбирать иконки динамически (по стратегии) без жёстких зависимостей в XAML.
    /// </summary>
    public sealed class StringToPackIconKindConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (value is PackIconKind kind)
                {
                    return kind;
                }

                var s = value as string;
                if (string.IsNullOrWhiteSpace(s))
                {
                    return default(PackIconKind);
                }

                if (Enum.TryParse<PackIconKind>(s.Trim(), ignoreCase: true, out var parsed))
                {
                    return parsed;
                }

                return default(PackIconKind);
            }
            catch
            {
                return default(PackIconKind);
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value?.ToString() ?? string.Empty;
        }
    }
}
