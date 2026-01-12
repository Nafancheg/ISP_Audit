using IspAudit.Bypass;

namespace IspAudit.Core.Traffic
{
    /// <summary>
    /// Параметры отправки пакета (для стратегий, которым нужен контроль над пересчётом checksum).
    /// По умолчанию используется безопасный режим: пересчитать все checksum.
    /// </summary>
    public readonly record struct PacketSendOptions
    {
        /// <summary>
        /// Пересчитать checksum перед отправкой (рекомендуемый безопасный режим).
        /// </summary>
        public bool RecalculateChecksums { get; init; }

        /// <summary>
        /// Флаги WinDivertHelperCalcChecksums(). 0 = посчитать всё.
        /// </summary>
        public ulong CalcChecksumsFlags { get; init; }

        /// <summary>
        /// Сбросить флаги валидности checksum в адресе перед отправкой.
        /// Нужно только для специальных техник (например, "bad checksum").
        /// </summary>
        public bool UnsetChecksumFlagsInAddress { get; init; }

        public static PacketSendOptions Default => new()
        {
            RecalculateChecksums = true,
            CalcChecksumsFlags = 0,
            UnsetChecksumFlagsInAddress = false
        };

        public static PacketSendOptions BadChecksum => new()
        {
            RecalculateChecksums = false,
            CalcChecksumsFlags = 0,
            UnsetChecksumFlagsInAddress = true
        };
    }
}
