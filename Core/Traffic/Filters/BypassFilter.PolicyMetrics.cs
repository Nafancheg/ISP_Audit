using System.Collections.Concurrent;
using System.Collections.Generic;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter
    {
        private readonly ConcurrentDictionary<string, long> _policyAppliedCounts = new();

        private void RecordPolicyApplied(string policyId)
        {
            if (string.IsNullOrWhiteSpace(policyId)) return;
            _policyAppliedCounts.AddOrUpdate(policyId, 1, (_, v) => v + 1);
        }

        /// <summary>
        /// Runtime-only наблюдаемость: сколько раз была применена конкретная policy по id.
        /// Используется в smoke и для будущей расширяемости execution plane.
        /// </summary>
        internal IReadOnlyDictionary<string, long> GetPolicyAppliedCountsSnapshot()
        {
            // Возвращаем копию, чтобы не светить внутреннюю структуру.
            return new Dictionary<string, long>(_policyAppliedCounts);
        }
    }
}
