using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
        public sealed record ActiveTargetPolicy
        {
            public string HostKey { get; init; } = string.Empty;
            public DateTime LastAppliedUtc { get; init; } = DateTime.MinValue;

            public bool DropUdp443 { get; init; }
            public bool AllowNoSni { get; init; }
            public bool HttpHostTricksEnabled { get; init; }

            public TlsBypassStrategy TlsStrategy { get; init; } = TlsBypassStrategy.None;
        }

        private const int ActiveTargetPoliciesCapacity = 4;
        private static readonly TimeSpan ActiveTargetPoliciesTtl = TimeSpan.FromMinutes(20);
        private readonly object _activeTargetPoliciesSync = new();
        private readonly Dictionary<string, ActiveTargetPolicy> _activeTargetPolicies = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// P0.1 Step 1: запомнить «активную цель» и её желаемую политику обхода.
        /// Используется, чтобы несколько целей (Steam + YouTube) могли оставаться активными одновременно,
        /// а decision graph выбирал действие по признакам пакета.
        /// </summary>
        public void RememberActiveTargetPolicy(ActiveTargetPolicy policy)
        {
            if (policy == null) return;
            if (string.IsNullOrWhiteSpace(policy.HostKey)) return;

            var normalizedHost = policy.HostKey.Trim();
            if (string.IsNullOrWhiteSpace(normalizedHost)) return;

            var now = DateTime.UtcNow;
            var safe = policy with
            {
                HostKey = normalizedHost,
                LastAppliedUtc = policy.LastAppliedUtc == DateTime.MinValue ? now : policy.LastAppliedUtc
            };

            lock (_activeTargetPoliciesSync)
            {
                PruneActiveTargetPoliciesUnsafe(now);
                _activeTargetPolicies[normalizedHost] = safe;

                // Cap: оставляем только N самых свежих.
                if (_activeTargetPolicies.Count > ActiveTargetPoliciesCapacity)
                {
                    var victims = _activeTargetPolicies.Values
                        .OrderByDescending(v => v.LastAppliedUtc)
                        .Skip(ActiveTargetPoliciesCapacity)
                        .Select(v => v.HostKey)
                        .Where(k => !string.IsNullOrWhiteSpace(k))
                        .ToArray();

                    foreach (var v in victims)
                    {
                        _activeTargetPolicies.Remove(v);
                    }
                }
            }
        }

        public void ClearActiveTargetPolicies()
        {
            lock (_activeTargetPoliciesSync)
            {
                _activeTargetPolicies.Clear();
            }
        }

        internal ActiveTargetPolicy[] GetActiveTargetPoliciesSnapshot(string? preferredHostKey)
        {
            var now = DateTime.UtcNow;

            lock (_activeTargetPoliciesSync)
            {
                PruneActiveTargetPoliciesUnsafe(now);

                var list = _activeTargetPolicies.Values
                    .OrderByDescending(v => v.LastAppliedUtc)
                    .ToList();

                if (!string.IsNullOrWhiteSpace(preferredHostKey))
                {
                    var idx = list.FindIndex(v => string.Equals(v.HostKey, preferredHostKey, StringComparison.OrdinalIgnoreCase));
                    if (idx > 0)
                    {
                        var item = list[idx];
                        list.RemoveAt(idx);
                        list.Insert(0, item);
                    }
                }

                return list.ToArray();
            }
        }

        private void PruneActiveTargetPoliciesUnsafe(DateTime nowUtc)
        {
            if (_activeTargetPolicies.Count == 0) return;

            var expired = _activeTargetPolicies.Values
                .Where(v => v.LastAppliedUtc != DateTime.MinValue && nowUtc - v.LastAppliedUtc > ActiveTargetPoliciesTtl)
                .Select(v => v.HostKey)
                .Where(k => !string.IsNullOrWhiteSpace(k))
                .ToArray();

            foreach (var k in expired)
            {
                _activeTargetPolicies.Remove(k);
            }
        }
    }
}
