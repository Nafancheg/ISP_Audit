using System;
using System.Text.Json.Serialization;

namespace IspAudit.Models
{
    /// <summary>
    /// Завершённая «сессия» Operator UI: один полный цикл
    /// (проверка → список проблем → что применили → итог post-apply ретеста).
    /// Хранится best-effort в state/operator_sessions.json.
    /// </summary>
    public sealed record OperatorSessionEntry
    {
        public string Id { get; init; } = Guid.NewGuid().ToString("N");

        /// <summary>
        /// Время старта в UTC (формат "u").
        /// </summary>
        public string StartedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();

        /// <summary>
        /// Время завершения в UTC (формат "u").
        /// </summary>
        public string EndedAtUtc { get; init; } = string.Empty;

        /// <summary>
        /// Описание источника трафика (человеческое).
        /// </summary>
        public string TrafficSource { get; init; } = string.Empty;

        /// <summary>
        /// Было ли включено автоисправление в момент старта.
        /// </summary>
        public bool AutoFixEnabledAtStart { get; init; }

        /// <summary>
        /// Итог сессии (OK/WARN/FAIL/CANCELLED/UNKNOWN).
        /// </summary>
        public string Outcome { get; init; } = string.Empty;

        /// <summary>
        /// Сводка по счётчикам на завершении проверки.
        /// </summary>
        public string CountsText { get; init; } = string.Empty;

        /// <summary>
        /// Список проблем (многострочный текст, каждая строка начинается с "• ").
        /// </summary>
        public string ProblemsText { get; init; } = string.Empty;

        /// <summary>
        /// Список действий (многострочный текст, каждая строка начинается с "• ").
        /// </summary>
        public string ActionsText { get; init; } = string.Empty;

        /// <summary>
        /// Семантический итог post-apply проверки (OK/FAIL/PARTIAL/UNKNOWN), если был.
        /// </summary>
        public string PostApplyVerdict { get; init; } = string.Empty;

        /// <summary>
        /// Текст статуса post-apply (для наблюдаемости, но уже «человеческий»).
        /// </summary>
        public string PostApplyStatusText { get; init; } = string.Empty;

        [JsonIgnore]
        public DateTimeOffset StartedAt
        {
            get
            {
                if (string.IsNullOrWhiteSpace(StartedAtUtc)) return DateTimeOffset.MinValue;
                if (DateTimeOffset.TryParse(StartedAtUtc, out var dto)) return dto;
                return DateTimeOffset.MinValue;
            }
        }

        [JsonIgnore]
        public DateTimeOffset EndedAt
        {
            get
            {
                if (string.IsNullOrWhiteSpace(EndedAtUtc)) return DateTimeOffset.MinValue;
                if (DateTimeOffset.TryParse(EndedAtUtc, out var dto)) return dto;
                return DateTimeOffset.MinValue;
            }
        }

        [JsonIgnore]
        public string StartedAtLocalText
        {
            get
            {
                try
                {
                    var local = StartedAt.ToLocalTime();
                    if (local == DateTimeOffset.MinValue) return string.Empty;
                    return local.ToString("g");
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        [JsonIgnore]
        public string DurationText
        {
            get
            {
                try
                {
                    if (StartedAt == DateTimeOffset.MinValue || EndedAt == DateTimeOffset.MinValue) return string.Empty;

                    var d = EndedAt - StartedAt;
                    if (d.TotalSeconds < 0) return string.Empty;
                    if (d.TotalMinutes < 1) return $"{d.TotalSeconds:0} сек";
                    if (d.TotalHours < 1) return $"{d.TotalMinutes:0} мин";
                    return $"{d.TotalHours:0.#} ч";
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        [JsonIgnore]
        public bool HasProblems => !string.IsNullOrWhiteSpace(ProblemsText);

        [JsonIgnore]
        public bool HasActions => !string.IsNullOrWhiteSpace(ActionsText);

        [JsonIgnore]
        public bool HasPostApply => !string.IsNullOrWhiteSpace(PostApplyVerdict) || !string.IsNullOrWhiteSpace(PostApplyStatusText);
    }
}
