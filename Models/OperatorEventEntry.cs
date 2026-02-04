using System;
using System.Text.Json.Serialization;

namespace IspAudit.Models
{
    /// <summary>
    /// Операторское событие (не пакеты): для истории действий и итогов в Operator UI.
    /// Хранится в state/operator_events.json (best-effort).
    /// </summary>
    public sealed record OperatorEventEntry
    {
        public string Id { get; init; } = Guid.NewGuid().ToString("N");

        /// <summary>
        /// Время события в UTC (формат "u").
        /// </summary>
        public string OccurredAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();

        /// <summary>
        /// Категория (check/fix/rollback/mode/error/info).
        /// </summary>
        public string Category { get; init; } = string.Empty;

        /// <summary>
        /// Ключ группы/сервиса (если применимо): например youtube.com.
        /// </summary>
        public string GroupKey { get; init; } = string.Empty;

        /// <summary>
        /// Короткий заголовок события (человеческий).
        /// </summary>
        public string Title { get; init; } = string.Empty;

        /// <summary>
        /// Детали (можно техничнее; по умолчанию скрыты в UI под History).
        /// </summary>
        public string Details { get; init; } = string.Empty;

        /// <summary>
        /// Итог/результат (OK/WARN/FAIL/UNKNOWN/...).
        /// </summary>
        public string Outcome { get; init; } = string.Empty;

        /// <summary>
        /// Источник (operator/engineer/autopilot).
        /// </summary>
        public string Source { get; init; } = "operator";

        [JsonIgnore]
        public DateTimeOffset OccurredAt
        {
            get
            {
                if (string.IsNullOrWhiteSpace(OccurredAtUtc)) return DateTimeOffset.MinValue;
                if (DateTimeOffset.TryParse(OccurredAtUtc, out var dto)) return dto;
                return DateTimeOffset.MinValue;
            }
        }

        [JsonIgnore]
        public string OccurredAtLocalText
        {
            get
            {
                try
                {
                    var local = OccurredAt.ToLocalTime();
                    if (local == DateTimeOffset.MinValue) return string.Empty;
                    return local.ToString("g");
                }
                catch
                {
                    return string.Empty;
                }
            }
        }
    }
}
