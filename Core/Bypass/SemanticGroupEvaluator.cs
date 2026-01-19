using System;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Core.Models;

namespace IspAudit.Core.Bypass
{
    public static class SemanticGroupEvaluator
    {
        public static SemanticGroupStatusSnapshot EvaluateStatus(
            SemanticGroup group,
            IReadOnlyDictionary<string, long> policyMatchedCounts)
        {
            if (group == null) throw new ArgumentNullException(nameof(group));
            policyMatchedCounts ??= new Dictionary<string, long>();

            var policies = group.PolicyBundle;
            if (policies.IsDefaultOrEmpty)
            {
                return new SemanticGroupStatusSnapshot(
                    SemanticGroupStatus.NoTraffic,
                    "NO_TRAFFIC",
                    "у группы нет policy bundle");
            }

            var matchedPolicyCount = 0;
            var totalMatchEvents = 0L;
            var missing = new List<string>();

            foreach (var p in policies)
            {
                if (p == null || string.IsNullOrWhiteSpace(p.Id))
                {
                    missing.Add("<invalid_policy>");
                    continue;
                }

                if (policyMatchedCounts.TryGetValue(p.Id, out var cnt) && cnt > 0)
                {
                    matchedPolicyCount++;
                    totalMatchEvents += cnt;
                }
                else
                {
                    missing.Add(p.Id);
                }
            }

            if (totalMatchEvents == 0)
            {
                return new SemanticGroupStatusSnapshot(
                    SemanticGroupStatus.NoTraffic,
                    "NO_TRAFFIC",
                    $"matched=0/{policies.Length}");
            }

            if (matchedPolicyCount == policies.Length)
            {
                return new SemanticGroupStatusSnapshot(
                    SemanticGroupStatus.Enabled,
                    "ENABLED",
                    $"matched={matchedPolicyCount}/{policies.Length}, events={totalMatchEvents}");
            }

            var missingPreview = string.Join(", ", missing.Take(3));
            var missingTail = missing.Count > 3 ? $" (+{missing.Count - 3})" : string.Empty;

            return new SemanticGroupStatusSnapshot(
                SemanticGroupStatus.Partial,
                "PARTIAL",
                $"matched={matchedPolicyCount}/{policies.Length}, missing=[{missingPreview}]{missingTail}");
        }
    }
}
