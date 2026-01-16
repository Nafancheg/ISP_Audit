using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Снимок "Decision Graph" — иммутабельное представление политики-lookup.
    /// Этап 0: используется как продукт компилятора и для будущей интеграции в execution plane.
    /// </summary>
    public sealed class DecisionGraphSnapshot
    {
        public readonly record struct Key(FlowTransportProtocol? Proto, int? Port, TlsStage? TlsStage)
        {
            public override string ToString()
            {
                var p = Proto?.ToString().ToUpperInvariant() ?? "ANY";
                var port = Port?.ToString() ?? "*";
                var tls = TlsStage?.ToString() ?? "*";
                return $"{p}:{port} tls={tls}";
            }
        }

        public ImmutableArray<FlowPolicy> Policies { get; }

        /// <summary>
        /// Грубый индекс по основным дискриминаторам (proto/port/tlsStage). На Этапе 0 это достаточный каркас,
        /// runtime-lookup будет уточнён на следующих этапах P0.2.
        /// </summary>
        public ImmutableDictionary<Key, ImmutableArray<FlowPolicy>> Index { get; }

        internal DecisionGraphSnapshot(ImmutableArray<FlowPolicy> policies, ImmutableDictionary<Key, ImmutableArray<FlowPolicy>> index)
        {
            Policies = policies;
            Index = index;
        }

        public IEnumerable<FlowPolicy> GetCandidates(FlowTransportProtocol? proto, int? port, TlsStage? tlsStage)
        {
            var key = new Key(proto, port, tlsStage);
            if (Index.TryGetValue(key, out var list)) return list;

            // Fallback на более широкий ключ.
            var fallbackKeys = new[]
            {
                new Key(proto, port, null),
                new Key(proto, null, tlsStage),
                new Key(null, port, tlsStage),
                new Key(proto, null, null),
                new Key(null, port, null),
                new Key(null, null, tlsStage),
                new Key(null, null, null)
            };

            foreach (var fk in fallbackKeys)
            {
                if (Index.TryGetValue(fk, out var l))
                {
                    return l;
                }
            }

            return Array.Empty<FlowPolicy>();
        }

        internal static DecisionGraphSnapshot Create(IEnumerable<FlowPolicy> policies)
        {
            var arr = policies
                .OrderByDescending(p => p.Priority)
                .ThenBy(p => p.Id, StringComparer.Ordinal)
                .ToImmutableArray();

            var groups = arr
                .GroupBy(p => new Key(p.Match.Proto, p.Match.Port, p.Match.TlsStage))
                .ToImmutableDictionary(
                    g => g.Key,
                    g => g.ToImmutableArray());

            return new DecisionGraphSnapshot(arr, groups);
        }
    }
}
