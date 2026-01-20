using System;
using System.Net;

namespace IspAudit.Utils
{
    public static class DomainUtils
    {
        /// <summary>
        /// MVP: извлекает «базовый домен» как последние 2 лейбла (example.com).
        /// Для CDN/шардовых поддоменов этого достаточно.
        /// </summary>
        public static bool TryGetBaseSuffix(string hostKey, out string suffix)
        {
            suffix = string.Empty;

            try
            {
                hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
                if (hostKey.Length == 0) return false;

                if (IPAddress.TryParse(hostKey, out _)) return false;

                var parts = hostKey.Split('.');
                if (parts.Length < 2) return false;

                suffix = parts[^2] + "." + parts[^1];
                suffix = suffix.Trim().Trim('.');
                return suffix.Length >= 3;
            }
            catch
            {
                suffix = string.Empty;
                return false;
            }
        }

        public static bool IsHostInSuffix(string hostKey, string? suffix)
        {
            hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
            var s = (suffix ?? string.Empty).Trim().Trim('.');

            if (hostKey.Length == 0 || s.Length == 0) return false;

            if (IPAddress.TryParse(hostKey, out _)) return false;

            return hostKey.Equals(s, StringComparison.OrdinalIgnoreCase)
                || hostKey.EndsWith("." + s, StringComparison.OrdinalIgnoreCase);
        }
    }
}
