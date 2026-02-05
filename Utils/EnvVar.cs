using System;

namespace IspAudit.Utils
{
    /// <summary>
    /// Утилиты для безопасного чтения переменных окружения (best-effort).
    /// Цель: централизовать trim/парсинг и убрать дублирование логики.
    /// </summary>
    public static class EnvVar
    {
        public static string? GetRaw(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;

            try
            {
                return Environment.GetEnvironmentVariable(name);
            }
            catch
            {
                return null;
            }
        }

        public static string? GetTrimmedNonEmpty(string name)
        {
            var raw = GetRaw(name);
            if (string.IsNullOrWhiteSpace(raw)) return null;

            var v = raw.Trim();
            return string.IsNullOrWhiteSpace(v) ? null : v;
        }

        public static bool ReadBool(string name, bool defaultValue)
        {
            var raw = GetTrimmedNonEmpty(name);
            if (raw == null) return defaultValue;

            return IsTrue(raw);
        }

        public static bool IsTrue(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return false;

            var v = raw.Trim();
            return v == "1"
                || v.Equals("true", StringComparison.OrdinalIgnoreCase)
                || v.Equals("yes", StringComparison.OrdinalIgnoreCase)
                || v.Equals("y", StringComparison.OrdinalIgnoreCase)
                || v.Equals("on", StringComparison.OrdinalIgnoreCase);
        }

        public static bool TryReadInt32(string name, out int value)
        {
            value = 0;

            var raw = GetTrimmedNonEmpty(name);
            if (raw == null) return false;

            return int.TryParse(raw, out value);
        }
    }
}
