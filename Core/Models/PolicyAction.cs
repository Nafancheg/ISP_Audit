using System;
using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace IspAudit.Core.Models
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum PolicyActionKind
    {
        Pass,
        Block,
        Strategy
    }

    /// <summary>
    /// Действие для политики (как результат мэтча). На Этапе 0 используется как модель данных и для smoke-гейтов,
    /// без влияния на runtime.
    /// </summary>
    public sealed record PolicyAction
    {
        public const string StrategyIdDropUdp443 = "drop_udp_443";

        public PolicyActionKind Kind { get; init; }

        /// <summary>
        /// Идентификатор стратегии (для Kind=Strategy). Пока строка: runtime-мэппинг будет добавляться на следующих этапах P0.2.
        /// </summary>
        public string? StrategyId { get; init; }

        /// <summary>
        /// Параметры стратегии (для Kind=Strategy). Сериализуемо для репорта.
        /// </summary>
        public ImmutableDictionary<string, string> Parameters { get; init; } = ImmutableDictionary<string, string>.Empty;

        public static PolicyAction Pass { get; } = new() { Kind = PolicyActionKind.Pass };
        public static PolicyAction Block { get; } = new() { Kind = PolicyActionKind.Block };
        public static PolicyAction DropUdp443 { get; } = Strategy(StrategyIdDropUdp443);

        public static PolicyAction Strategy(string strategyId, ImmutableDictionary<string, string>? parameters = null)
        {
            if (string.IsNullOrWhiteSpace(strategyId)) throw new ArgumentException("strategyId не должен быть пустым", nameof(strategyId));
            return new PolicyAction
            {
                Kind = PolicyActionKind.Strategy,
                StrategyId = strategyId,
                Parameters = parameters ?? ImmutableDictionary<string, string>.Empty
            };
        }

        public override string ToString()
        {
            return Kind switch
            {
                PolicyActionKind.Pass => "PASS",
                PolicyActionKind.Block => "BLOCK",
                PolicyActionKind.Strategy => $"STRATEGY:{StrategyId}",
                _ => Kind.ToString()
            };
        }
    }
}
