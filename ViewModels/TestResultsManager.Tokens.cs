using System;
using System.Text.RegularExpressions;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        private static string? ExtractToken(string msg, string token)
        {
            // token=VALUE, VALUE до пробела или '|'
            var m = Regex.Match(msg, $@"\b{Regex.Escape(token)}=([^\s\|]+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }

        private static string StripNameTokens(string msg)
        {
            try
            {
                // Убираем хвост вида " SNI=... RDNS=..." (в любом порядке, если появится)
                var cleaned = Regex.Replace(msg, @"\s+SNI=[^\s\|]+", string.Empty, RegexOptions.IgnoreCase);
                cleaned = Regex.Replace(cleaned, @"\s+DNS=[^\s\|]+", string.Empty, RegexOptions.IgnoreCase);
                cleaned = Regex.Replace(cleaned, @"\s+RDNS=[^\s\|]+", string.Empty, RegexOptions.IgnoreCase);
                // Сжимаем лишние пробелы
                cleaned = Regex.Replace(cleaned, @"\s{2,}", " ").Trim();
                return cleaned;
            }
            catch
            {
                return msg;
            }
        }
    }
}
