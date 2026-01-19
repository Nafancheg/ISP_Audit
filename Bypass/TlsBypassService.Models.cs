using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Bypass
{
    /// <summary>
    /// Описание пресета фрагментации TLS.
    /// </summary>
    public record TlsFragmentPreset(string Name, IReadOnlyList<int> Sizes, string Description);

    /// <summary>
    /// DTO с опциями TLS bypass.
    /// </summary>
    public record TlsBypassOptions
    {
        public bool FragmentEnabled { get; init; }
        public bool DisorderEnabled { get; init; }
        public bool FakeEnabled { get; init; }
        public bool DropRstEnabled { get; init; }

        /// <summary>
        /// Разрешить применение TLS-обхода даже когда SNI не распознан/отсутствует.
        /// </summary>
        public bool AllowNoSni { get; init; }

        /// <summary>
        /// QUIC fallback: глушить UDP/443, чтобы клиент откатился на TCP/HTTPS.
        /// </summary>
        public bool DropUdp443 { get; init; }

        /// <summary>
        /// Глобальный режим QUIC fallback: глушить ВЕСЬ UDP/443 (без привязки к цели).
        /// Используется как расширение к DropUdp443.
        /// </summary>
        public bool DropUdp443Global { get; init; }

        /// <summary>
        /// HTTP Host tricks (MVP): разрезать Host заголовок по границе TCP-сегментов.
        /// </summary>
        public bool HttpHostTricksEnabled { get; init; }

        /// <summary>
        /// Bad checksum (MVP): отправлять фейковые пакеты с некорректным TCP checksum.
        /// </summary>
        public bool BadChecksumEnabled { get; init; }

        public IReadOnlyList<int> FragmentSizes { get; init; } = Array.Empty<int>();
        public string PresetName { get; init; } = string.Empty;
        public bool AutoAdjustAggressive { get; init; }

        public bool TtlTrickEnabled { get; init; }
        public int TtlTrickValue { get; init; } = 3;
        public bool AutoTtlEnabled { get; init; }

        public static TlsBypassOptions CreateDefault(BypassProfile baseProfile)
        {
            var fragments = baseProfile.TlsFragmentSizes ?? new List<int> { baseProfile.TlsFirstFragmentSize };
            fragments = fragments.Select(v => Math.Max(4, v)).ToList();
            return new TlsBypassOptions
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = baseProfile.DropTcpRst,
                AllowNoSni = baseProfile.AllowNoSni,
                DropUdp443 = baseProfile.DropUdp443,
                DropUdp443Global = baseProfile.DropUdp443Global,
                HttpHostTricksEnabled = baseProfile.HttpHostTricks,
                BadChecksumEnabled = baseProfile.BadChecksum,
                FragmentSizes = fragments,
                PresetName = string.IsNullOrWhiteSpace(baseProfile.FragmentPresetName) ? "Профиль" : baseProfile.FragmentPresetName,
                AutoAdjustAggressive = baseProfile.AutoAdjustAggressive,
                TtlTrickEnabled = baseProfile.TtlTrick,
                TtlTrickValue = baseProfile.TtlTrickValue,
                AutoTtlEnabled = baseProfile.AutoTtl
            };
        }

        public bool IsAnyEnabled()
        {
            return FragmentEnabled
                || DisorderEnabled
                || FakeEnabled
                || DropRstEnabled
                || AllowNoSni
                || DropUdp443
                || TtlTrickEnabled
                || HttpHostTricksEnabled
                || BadChecksumEnabled;
        }

        public string FragmentSizesAsText()
        {
            return FragmentSizes.Any() ? string.Join('/', FragmentSizes) : "default";
        }

        public TlsBypassOptions Normalize()
        {
            var safe = FragmentSizes.Where(v => v > 0).Select(v => Math.Max(4, v)).Take(4).ToList();
            if (!safe.Any())
            {
                safe.Add(64);
            }

            var ttl = TtlTrickValue;
            if (ttl <= 0) ttl = 3;
            if (ttl > 255) ttl = 255;

            return this with { FragmentSizes = safe, TtlTrickValue = ttl };
        }

        public string ToReadableStrategy()
        {
            var parts = new List<string>();
            if (FragmentEnabled) parts.Add("Fragment");
            if (DisorderEnabled) parts.Add("Disorder");
            if (FakeEnabled) parts.Add("Fake");
            if (DropRstEnabled) parts.Add("DROP RST");
            if (DropUdp443) parts.Add(DropUdp443Global ? "DROP UDP/443 (GLOBAL)" : "DROP UDP/443");
            if (AllowNoSni) parts.Add("AllowNoSNI");
            if (TtlTrickEnabled) parts.Add(AutoTtlEnabled ? $"AutoTTL({TtlTrickValue})" : $"TTL({TtlTrickValue})");
            if (HttpHostTricksEnabled) parts.Add("HTTP Host tricks");
            if (BadChecksumEnabled) parts.Add("BadChecksum");
            return parts.Count > 0 ? string.Join(" + ", parts) : "Выключен";
        }
    }

    /// <summary>
    /// Метрики TLS bypass.
    /// </summary>
    public record TlsBypassMetrics
    {
        public long TlsHandled { get; init; }
        public long ClientHellosFragmented { get; init; }
        public long RstDroppedRelevant { get; init; }
        public long RstDropped { get; init; }
        public long Udp443Dropped { get; init; }
        public string Plan { get; init; } = "-";
        public string Since { get; init; } = "-";
        public long ClientHellosObserved { get; init; }
        public long ClientHellosShort { get; init; }
        public long ClientHellosNon443 { get; init; }
        public long ClientHellosNoSni { get; init; }
        public string PresetName { get; init; } = "-";
        public int FragmentThreshold { get; init; }
        public int MinChunk { get; init; }

        /// <summary>
        /// Статусы Semantic Groups (ENABLED/PARTIAL/NO_TRAFFIC) на основе matched-count метрик policy-driven execution.
        /// Пусто, если policy-driven ветка не активна или группы не применимы.
        /// </summary>
        public string SemanticGroupsStatusText { get; init; } = string.Empty;

        /// <summary>
        /// Короткая сводка статусов Semantic Groups (одной строкой) — для UI, который пользователь видит сразу.
        /// </summary>
        public string SemanticGroupsSummaryText { get; init; } = string.Empty;

        public static TlsBypassMetrics Empty => new();
    }

    /// <summary>
    /// Вердикт по состоянию обхода.
    /// </summary>
    public record TlsBypassVerdict(VerdictColor Color, string Text, string Reason)
    {
        public static TlsBypassVerdict CreateInactive()
        {
            return new TlsBypassVerdict(VerdictColor.Gray, "Bypass выключен", "Нет активного фильтра");
        }
    }

    public enum VerdictColor
    {
        Gray,
        Green,
        Yellow,
        Red
    }

    /// <summary>
    /// Состояние применённого фильтра (для UI badge/таймстампа).
    /// </summary>
    public record TlsBypassState(bool IsActive, string Plan, string Since);
}
