using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Статус группы целей (Semantic Group) по факту работы policy bundle.
    /// </summary>
    public enum SemanticGroupStatus
    {
        /// <summary>
        /// Трафика, соответствующего политикам группы, не наблюдали.
        /// </summary>
        NoTraffic,

        /// <summary>
        /// Трафик есть, но часть политик группы ни разу не совпала (не matched).
        /// </summary>
        Partial,

        /// <summary>
        /// Все политики группы хотя бы раз совпали (matched).
        /// </summary>
        Enabled
    }

    public sealed record SemanticGroupStatusSnapshot(
        SemanticGroupStatus Status,
        string Text,
        string Details);

    /// <summary>
    /// Семантическая группа целей (Service Group): набор доменных паттернов и пакет политик.
    /// На P0.2 Stage 5 используется в первую очередь для статусов ENABLED/PARTIAL/NO_TRAFFIC.
    /// </summary>
    public sealed record SemanticGroup
    {
        public required string GroupKey { get; init; }
        public required string DisplayName { get; init; }

        /// <summary>
        /// Доменные паттерны, которые считаются частью группы (например: youtube.com, *.googlevideo.com).
        /// </summary>
        public ImmutableArray<string> DomainPatterns { get; init; } = ImmutableArray<string>.Empty;

        /// <summary>
        /// Текущий пакет политик группы (после merge по правилам группы).
        /// </summary>
        public ImmutableArray<FlowPolicy> PolicyBundle { get; init; } = ImmutableArray<FlowPolicy>.Empty;

        public override string ToString() => $"{GroupKey} ({DisplayName}), policies={PolicyBundle.Length}";
    }

    /// <summary>
    /// Вспомогательные merge-правила для policy bundle группы.
    /// P0.2 Stage 5.2 (MVP):
    /// - endpoints = union (DstIpSet/DstIpv4Set)
    /// - остальные поля должны совпадать (иначе политики не сливаем)
    /// </summary>
    public static class SemanticGroupPolicyBundleMerger
    {
        public static ImmutableArray<FlowPolicy> MergeByUnionEndpoints(string groupKey, IEnumerable<FlowPolicy> policies)
        {
            if (policies == null) throw new ArgumentNullException(nameof(policies));

            var list = policies.ToList();
            if (list.Count == 0) return ImmutableArray<FlowPolicy>.Empty;

            // Группируем по "семантически одинаковым" политикам, отличающимся только endpoint-наборами.
            var grouped = list.GroupBy(CreateMergeKey);

            var merged = ImmutableArray.CreateBuilder<FlowPolicy>();
            foreach (var g in grouped)
            {
                var first = g.First();

                var dstIpSet = UnionStringSet(g.Select(p => p.Match.DstIpSet));
                var dstIpv4Set = UnionUintSet(g.Select(p => p.Match.DstIpv4Set));

                var mergedMatch = first.Match with
                {
                    DstIpSet = dstIpSet,
                    DstIpv4Set = dstIpv4Set
                };

                // Детерминированный id: groupKey + key.
                var id = BuildMergedPolicyId(groupKey, g.Key);

                merged.Add(first with
                {
                    Id = id,
                    Match = mergedMatch
                });
            }

            return merged.ToImmutable();
        }

        private static string CreateMergeKey(FlowPolicy p)
        {
            // endpoint-наборы намеренно не включаем.
            var actionParams = p.Action.Parameters.Count == 0
                ? ""
                : string.Join(";", p.Action.Parameters.OrderBy(kv => kv.Key, StringComparer.Ordinal)
                    .Select(kv => kv.Key + "=" + kv.Value));

            return string.Join("|", new[]
            {
                p.Scope.ToString(),
                p.Priority.ToString(),
                p.Match.Proto?.ToString() ?? "ANY",
                p.Match.Port?.ToString() ?? "*",
                p.Match.TlsStage?.ToString() ?? "*",
                p.Match.SniPattern ?? "*",
                p.Action.Kind.ToString(),
                p.Action.StrategyId ?? "-",
                actionParams
            });
        }

        private static ImmutableHashSet<string>? UnionStringSet(IEnumerable<ImmutableHashSet<string>?> sets)
        {
            ImmutableHashSet<string>? acc = null;
            foreach (var set in sets)
            {
                if (set == null || set.Count == 0) continue;
                acc = acc == null ? set : acc.Union(set);
            }
            return acc;
        }

        private static ImmutableHashSet<uint>? UnionUintSet(IEnumerable<ImmutableHashSet<uint>?> sets)
        {
            ImmutableHashSet<uint>? acc = null;
            foreach (var set in sets)
            {
                if (set == null) continue;
                if (set.Count == 0) return ImmutableHashSet<uint>.Empty; // NONE доминирует
                acc = acc == null ? set : acc.Union(set);
            }
            return acc;
        }

        private static string BuildMergedPolicyId(string groupKey, string mergeKey)
        {
            groupKey = (groupKey ?? string.Empty).Trim();
            if (groupKey.Length == 0) groupKey = "group";

            // Стабильный и читаемый id, без хеша (чтобы было удобно в репорте).
            // Ограничиваем длину, чтобы не раздувать логи.
            var raw = $"sg_{groupKey}_{mergeKey}";
            raw = SanitizeId(raw);
            return raw.Length <= 120 ? raw : raw.Substring(0, 120);
        }

        private static string SanitizeId(string value)
        {
            if (string.IsNullOrEmpty(value)) return "sg";

            Span<char> buffer = stackalloc char[value.Length];
            var len = 0;
            foreach (var ch in value)
            {
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-')
                {
                    buffer[len++] = ch;
                }
                else
                {
                    buffer[len++] = '_';
                }
            }
            return new string(buffer.Slice(0, len));
        }
    }
}
