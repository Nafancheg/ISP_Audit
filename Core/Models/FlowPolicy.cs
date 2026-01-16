using System;
using System.Text.Json.Serialization;

namespace IspAudit.Core.Models
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum PolicyScope
    {
        /// <summary>
        /// Политика применяется только к селективному скоупу (например, к наблюдаемым IP цели).
        /// </summary>
        Local,

        /// <summary>
        /// Политика глобальна (влияет на весь трафик, соответствующий match).
        /// </summary>
        Global
    }

    /// <summary>
    /// Декларативная политика выбора действия по признакам потока/пакета.
    /// Этап 0 (P0.2): только модель + компилятор конфликтов + snapshot, без включения в runtime.
    /// </summary>
    public sealed record FlowPolicy
    {
        public required string Id { get; init; }
        public required MatchCondition Match { get; init; }
        public required PolicyAction Action { get; init; }

        public PolicyScope Scope { get; init; } = PolicyScope.Local;

        /// <summary>
        /// Приоритет политики (больше = сильнее). Конфликты детектируются, когда пересечение мэтчей и одинаковый приоритет,
        /// но разные действия.
        /// </summary>
        public int Priority { get; init; } = 0;

        /// <summary>
        /// TTL политики (например, для reconnect-nudge блокировки endpoint-а). null = бессрочно.
        /// </summary>
        public TimeSpan? Ttl { get; init; }

        public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

        public override string ToString() => $"{Id} prio={Priority} scope={Scope} match=({Match}) action={Action}";
    }
}
