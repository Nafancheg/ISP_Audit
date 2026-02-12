namespace IspAudit.Bypass.Strategies
{
    /// <summary>
    /// QuicObfuscation: принудительный откат QUIC/HTTP3 → TCP/HTTPS.
    ///
    /// В текущей архитектуре это реализуется через опцию <see cref="TlsBypassOptions.DropUdp443"/>:
    /// фильтр трафика дропает UDP/443, и клиент (браузер/приложение) переключается на TCP.
    ///
    /// Режимы:
    /// - селективный (по цели): дроп UDP/443 только для наблюдаемых IPv4 адресов цели;
    /// - глобальный: дроп всего UDP/443 (управляется отдельным флагом DropUdp443Global).
    ///
    /// Важно: intel-стратегия включает только селективный флаг DropUdp443. Глобальный режим — осознанный выбор пользователя.
    /// </summary>
    public static class QuicObfuscationStrategy
    {
        public static TlsBypassOptions EnableSelective(TlsBypassOptions options)
        {
            // Не трогаем DropUdp443Global: это отдельный, более рискованный режим.
            return options with { DropUdp443 = true };
        }

        public static string GetApplyLogLine() => "[APPLY][Executor] QuicObfuscation: включаем QUIC→TCP (DROP UDP/443)";
    }
}
