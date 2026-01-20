using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace IspAudit.Core.Bypass
{
    /// <summary>
    /// P0.1 Step 14: хранилище состояния групп (groupKey) и их вкладов (attachments).
    ///
    /// Используется в UI-слое как единый источник истины для:
    /// - manual participation (excluded hostKey per group)
    /// - pinning hostKey -> groupKey (стабильный groupKey)
    /// - детерминированного merge EffectiveGroupConfig (endpoints union, assist flags OR)
    ///
    /// Потокобезопасно: все операции под одним lock.
    /// </summary>
    public sealed class GroupBypassAttachmentStore
    {
        private readonly object _sync = new();
        private readonly Dictionary<string, GroupBypassAttachmentSet> _setsByGroupKey = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _pinnedGroupKeyByHostKey = new(StringComparer.OrdinalIgnoreCase);

        public static string GetPersistPath()
        {
            var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var dir = Path.Combine(baseDir, "ISP_Audit");
            return Path.Combine(dir, "group_participation.json");
        }

        public bool TryGetPinnedGroupKey(string hostKey, out string groupKey)
        {
            hostKey = NormalizeKey(hostKey);
            lock (_sync)
            {
                if (_pinnedGroupKeyByHostKey.TryGetValue(hostKey, out var pinned) && !string.IsNullOrWhiteSpace(pinned))
                {
                    groupKey = pinned;
                    return true;
                }
            }

            groupKey = string.Empty;
            return false;
        }

        public void PinHostKeyToGroupKey(string hostKey, string groupKey)
        {
            hostKey = NormalizeKey(hostKey);
            groupKey = NormalizeKey(groupKey);
            if (string.IsNullOrWhiteSpace(hostKey) || string.IsNullOrWhiteSpace(groupKey)) return;

            lock (_sync)
            {
                _pinnedGroupKeyByHostKey[hostKey] = groupKey;
                // Пиннинг не должен менять ручное участие (например, не должен снимать excluded).
                var set = GetOrCreateSetUnsafe(groupKey);
                _ = set.SetExcluded(hostKey, excluded: set.IsExcluded(hostKey));
            }
        }

        public bool ToggleExcluded(string groupKey, string hostKey)
        {
            groupKey = NormalizeKey(groupKey);
            hostKey = NormalizeKey(hostKey);
            if (string.IsNullOrWhiteSpace(groupKey) || string.IsNullOrWhiteSpace(hostKey)) return false;

            lock (_sync)
            {
                var set = GetOrCreateSetUnsafe(groupKey);
                var excludedNow = !set.IsExcluded(hostKey);
                set.SetExcluded(hostKey, excludedNow);
                return excludedNow;
            }
        }

        public bool IsExcluded(string groupKey, string hostKey)
        {
            groupKey = NormalizeKey(groupKey);
            hostKey = NormalizeKey(hostKey);
            if (string.IsNullOrWhiteSpace(groupKey) || string.IsNullOrWhiteSpace(hostKey)) return false;

            lock (_sync)
            {
                return _setsByGroupKey.TryGetValue(groupKey, out var set) && set.IsExcluded(hostKey);
            }
        }

        public IReadOnlyList<string> GetExcludedHostsSnapshot(string groupKey)
        {
            groupKey = NormalizeKey(groupKey);
            if (string.IsNullOrWhiteSpace(groupKey)) return Array.Empty<string>();

            lock (_sync)
            {
                if (!_setsByGroupKey.TryGetValue(groupKey, out var set)) return Array.Empty<string>();
                return set.GetAttachmentsSnapshot()
                    .Where(a => a.Excluded)
                    .Select(a => a.HostKey)
                    .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public GroupBypassAttachmentSet.EffectiveGroupConfig GetEffectiveGroupConfig(string groupKey)
        {
            groupKey = NormalizeKey(groupKey);
            if (string.IsNullOrWhiteSpace(groupKey))
            {
                return new GroupBypassAttachmentSet.EffectiveGroupConfig(Array.Empty<string>(), false, false, 0, 0, 0);
            }

            lock (_sync)
            {
                if (!_setsByGroupKey.TryGetValue(groupKey, out var set))
                {
                    return new GroupBypassAttachmentSet.EffectiveGroupConfig(Array.Empty<string>(), false, false, 0, 0, 0);
                }

                return set.ComputeEffectiveConfig();
            }
        }

        public void UpdateAttachmentFromApply(
            string groupKey,
            string hostKey,
            IReadOnlyList<string>? candidateIpEndpoints,
            string? planText)
        {
            groupKey = NormalizeKey(groupKey);
            hostKey = NormalizeKey(hostKey);
            if (string.IsNullOrWhiteSpace(groupKey) || string.IsNullOrWhiteSpace(hostKey)) return;

            var endpoints = (candidateIpEndpoints ?? Array.Empty<string>())
                .Select(s => (s ?? string.Empty).Trim())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var tokens = SplitPlanTokens(planText);
            var dropUdp443 = tokens.Contains("DROP_UDP_443");
            var allowNoSni = tokens.Contains("ALLOW_NO_SNI");

            lock (_sync)
            {
                var set = GetOrCreateSetUnsafe(groupKey);

                // Обновление не должно отменять ручное исключение.
                var excluded = set.IsExcluded(hostKey);

                set.UpsertAttachment(new GroupBypassAttachmentSet.GroupBypassAttachment(
                    HostKey: hostKey,
                    Excluded: excluded,
                    CandidateIpEndpoints: endpoints,
                    DropUdp443: dropUdp443,
                    AllowNoSni: allowNoSni,
                    UpdatedAtUtc: DateTimeOffset.UtcNow));
            }
        }

        public JsonNode BuildParticipationSnapshotNode(string groupKey)
        {
            groupKey = NormalizeKey(groupKey);

            lock (_sync)
            {
                var set = _setsByGroupKey.TryGetValue(groupKey, out var s) ? s : null;
                var excluded = set == null
                    ? Array.Empty<string>()
                    : set.GetAttachmentsSnapshot().Where(a => a.Excluded).Select(a => a.HostKey).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();

                var attachments = set == null
                    ? Array.Empty<GroupBypassAttachmentSet.GroupBypassAttachment>()
                    : set.GetAttachmentsSnapshot().ToArray();

                var pinnedHosts = _pinnedGroupKeyByHostKey
                    .Where(kvp => string.Equals(NormalizeKey(kvp.Value), groupKey, StringComparison.OrdinalIgnoreCase))
                    .Select(kvp => NormalizeKey(kvp.Key))
                    .Where(k => !string.IsNullOrWhiteSpace(k))
                    .OrderBy(k => k, StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                var cfg = set?.ComputeEffectiveConfig();

                var attachmentsJson = new JsonArray();
                foreach (var a in attachments)
                {
                    attachmentsJson.Add(new JsonObject
                    {
                        ["hostKey"] = a.HostKey,
                        ["excluded"] = a.Excluded,
                        ["candidateIpEndpoints"] = JsonSerializer.SerializeToNode(a.CandidateIpEndpoints ?? Array.Empty<string>()),
                        ["dropUdp443"] = a.DropUdp443,
                        ["allowNoSni"] = a.AllowNoSni,
                        ["updatedAtUtc"] = a.UpdatedAtUtc.ToString("u").TrimEnd()
                    });
                }

                return new JsonObject
                {
                    ["groupKey"] = groupKey,
                    ["pinnedHostKeys"] = JsonSerializer.SerializeToNode(pinnedHosts),
                    ["excludedHostKeys"] = JsonSerializer.SerializeToNode(excluded),
                    ["attachments"] = attachmentsJson,
                    ["effective"] = cfg == null
                        ? null
                        : new JsonObject
                        {
                            ["candidateIpEndpointsUnion"] = JsonSerializer.SerializeToNode(cfg.CandidateIpEndpointsUnion),
                            ["dropUdp443"] = cfg.DropUdp443,
                            ["allowNoSni"] = cfg.AllowNoSni,
                            ["attachmentCount"] = cfg.AttachmentCount,
                            ["includedCount"] = cfg.IncludedCount,
                            ["excludedCount"] = cfg.ExcludedCount
                        }
                };
            }
        }

        public void LoadFromDiskBestEffort(string? overridePath = null)
        {
            try
            {
                var path = string.IsNullOrWhiteSpace(overridePath) ? GetPersistPath() : overridePath;
                if (!File.Exists(path)) return;

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return;

                var root = JsonNode.Parse(json) as JsonObject;
                if (root == null) return;

                var excludedNode = root["ExcludedHostKeysByGroupKey"] as JsonObject;
                var pinnedNode = root["PinnedGroupKeyByHostKey"] as JsonObject;

                var excluded = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
                if (excludedNode != null)
                {
                    foreach (var kvp in excludedNode)
                    {
                        var gk = NormalizeKey(kvp.Key);
                        if (string.IsNullOrWhiteSpace(gk)) continue;

                        var arr = kvp.Value as JsonArray;
                        if (arr == null) continue;

                        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var v in arr)
                        {
                            var hk = NormalizeKey(v?.ToString());
                            if (string.IsNullOrWhiteSpace(hk)) continue;
                            set.Add(hk);
                        }

                        if (set.Count > 0)
                        {
                            excluded[gk] = set;
                        }
                    }
                }

                var pinned = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (pinnedNode != null)
                {
                    foreach (var kvp in pinnedNode)
                    {
                        var hk = NormalizeKey(kvp.Key);
                        var gk = NormalizeKey(kvp.Value?.ToString());
                        if (string.IsNullOrWhiteSpace(hk) || string.IsNullOrWhiteSpace(gk)) continue;
                        pinned[hk] = gk;
                    }
                }

                lock (_sync)
                {
                    _setsByGroupKey.Clear();
                    _pinnedGroupKeyByHostKey.Clear();

                    foreach (var kvp in excluded)
                    {
                        var set = GetOrCreateSetUnsafe(kvp.Key);
                        foreach (var hk in kvp.Value)
                        {
                            set.SetExcluded(hk, excluded: true);
                        }
                    }

                    foreach (var kvp in pinned)
                    {
                        _pinnedGroupKeyByHostKey[kvp.Key] = kvp.Value;

                        // Гарантируем, что attachment существует (без снятия исключения).
                        var set = GetOrCreateSetUnsafe(kvp.Value);
                        _ = set.SetExcluded(kvp.Key, set.IsExcluded(kvp.Key));
                    }

                    // Back-compat: если пиннингов нет — выводим их из excluded.
                    if (_pinnedGroupKeyByHostKey.Count == 0)
                    {
                        foreach (var kvp in excluded)
                        {
                            foreach (var hk in kvp.Value)
                            {
                                _pinnedGroupKeyByHostKey[hk] = kvp.Key;
                            }
                        }
                    }
                }
            }
            catch
            {
                // best-effort
            }
        }

        public void PersistToDiskBestEffort(string? overridePath = null)
        {
            try
            {
                var path = string.IsNullOrWhiteSpace(overridePath) ? GetPersistPath() : overridePath;
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                Dictionary<string, string[]> excluded;
                Dictionary<string, string> pinned;

                lock (_sync)
                {
                    excluded = _setsByGroupKey
                        .ToDictionary(
                            kvp => kvp.Key,
                            kvp => kvp.Value.GetAttachmentsSnapshot().Where(a => a.Excluded).Select(a => a.HostKey).ToArray(),
                            StringComparer.OrdinalIgnoreCase);

                    pinned = _pinnedGroupKeyByHostKey
                        .Where(kvp => !string.IsNullOrWhiteSpace(kvp.Key) && !string.IsNullOrWhiteSpace(kvp.Value))
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase);
                }

                var state = new PersistStateV3
                {
                    ExcludedHostKeysByGroupKey = excluded,
                    PinnedGroupKeyByHostKey = pinned
                };

                var json = JsonSerializer.Serialize(state, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(path, json, Encoding.UTF8);
            }
            catch
            {
                // best-effort
            }
        }

        private GroupBypassAttachmentSet GetOrCreateSetUnsafe(string groupKey)
        {
            if (_setsByGroupKey.TryGetValue(groupKey, out var existing)) return existing;
            var created = new GroupBypassAttachmentSet(groupKey);
            _setsByGroupKey[groupKey] = created;
            return created;
        }

        private static string NormalizeKey(string? value)
            => (value ?? string.Empty).Trim().Trim('.');

        private static HashSet<string> SplitPlanTokens(string? planText)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(planText)) return set;

            foreach (var part in planText.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var t = (part ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(t)) continue;
                set.Add(t);
            }

            return set;
        }

        private sealed record PersistStateV3
        {
            public string Version { get; init; } = "v3";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();

            public Dictionary<string, string[]> ExcludedHostKeysByGroupKey { get; init; } = new(StringComparer.OrdinalIgnoreCase);
            public Dictionary<string, string> PinnedGroupKeyByHostKey { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        }
    }
}
