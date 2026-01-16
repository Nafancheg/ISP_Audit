using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using IspAudit.Core.Models;

namespace IspAudit.Core.Bypass
{
    public sealed record PolicyConflict(string PolicyAId, string PolicyBId, string Reason)
    {
        public override string ToString() => $"{PolicyAId} <-> {PolicyBId}: {Reason}";
    }

    public sealed class PolicyCompilationException : Exception
    {
        public ImmutableArray<PolicyConflict> Conflicts { get; }

        public PolicyCompilationException(ImmutableArray<PolicyConflict> conflicts)
            : base(BuildMessage(conflicts))
        {
            Conflicts = conflicts;
        }

        private static string BuildMessage(ImmutableArray<PolicyConflict> conflicts)
        {
            if (conflicts.IsDefaultOrEmpty) return "Policy compilation failed";

            var head = $"Policy compilation failed: hard-conflicts={conflicts.Length}";
            var lines = conflicts.Take(5).Select(c => "- " + c);
            var tail = conflicts.Length > 5 ? "- ..." : string.Empty;
            return string.Join(Environment.NewLine, new[] { head }.Concat(lines).Concat(string.IsNullOrEmpty(tail) ? Array.Empty<string>() : new[] { tail }));
        }
    }

    /// <summary>
    /// Компилятор набора FlowPolicy в DecisionGraphSnapshot.
    /// Этап 0 (P0.2): отвечает за детект hard-конфликтов (неоднозначность при одинаковом приоритете) и сбор snapshot.
    /// </summary>
    public static class PolicySetCompiler
    {
        public static DecisionGraphSnapshot CompileOrThrow(IEnumerable<FlowPolicy> policies)
        {
            if (policies is null) throw new ArgumentNullException(nameof(policies));

            var list = policies.ToList();

            var conflicts = DetectHardConflicts(list);
            if (!conflicts.IsDefaultOrEmpty)
            {
                throw new PolicyCompilationException(conflicts);
            }

            return DecisionGraphSnapshot.Create(list);
        }

        /// <summary>
        /// Hard-конфликт: есть пересечение мэтчей и одинаковый приоритет, но разные действия.
        /// В таком случае для конкретного пакета/потока невозможно детерминированно выбрать одно действие.
        /// </summary>
        public static ImmutableArray<PolicyConflict> DetectHardConflicts(IReadOnlyList<FlowPolicy> policies)
        {
            if (policies is null) throw new ArgumentNullException(nameof(policies));

            var conflicts = ImmutableArray.CreateBuilder<PolicyConflict>();

            for (var i = 0; i < policies.Count; i++)
            {
                var a = policies[i];
                for (var j = i + 1; j < policies.Count; j++)
                {
                    var b = policies[j];

                    if (a.Priority != b.Priority) continue;
                    if (ActionsEquivalent(a.Action, b.Action)) continue;

                    if (!MatchCondition.Overlaps(a.Match, b.Match)) continue;

                    conflicts.Add(new PolicyConflict(a.Id, b.Id,
                        $"Пересечение match при одинаковом приоритете {a.Priority}: {a.Match} VS {b.Match} (actions: {a.Action} vs {b.Action})"));
                }
            }

            return conflicts.ToImmutable();
        }

        private static bool ActionsEquivalent(PolicyAction a, PolicyAction b)
        {
            if (a is null) return b is null;
            if (b is null) return false;

            if (a.Kind != b.Kind) return false;

            if (a.Kind == PolicyActionKind.Strategy)
            {
                return string.Equals(a.StrategyId, b.StrategyId, StringComparison.OrdinalIgnoreCase);
            }

            return true;
        }
    }
}
