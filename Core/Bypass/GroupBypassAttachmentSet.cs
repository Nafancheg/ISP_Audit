using System;
using System.Collections.Generic;
using System.Linq;

namespace IspAudit.Core.Bypass
{
    /// <summary>
    /// P0.1 Step 14: единый «источник истины» для состояния группы (groupKey).
    ///
    /// Хранит per-host вклад (attachment) и позволяет детерминированно собрать EffectiveGroupConfig:
    /// - endpoints = union (нормализация + сортировка)
    /// - assist flags = OR
    ///
    /// Этот объект НЕ является источником истины для policy-driven execution plane,
    /// но используется как стабильная модель данных для UI/наблюдаемости и для консистентного merge.
    /// </summary>
    public sealed class GroupBypassAttachmentSet
    {
        public sealed record GroupBypassAttachment(
            string HostKey,
            bool Excluded,
            IReadOnlyList<string> CandidateIpEndpoints,
            bool DropUdp443,
            bool AllowNoSni,
            DateTimeOffset UpdatedAtUtc);

        public sealed record EffectiveGroupConfig(
            IReadOnlyList<string> CandidateIpEndpointsUnion,
            bool DropUdp443,
            bool AllowNoSni,
            int AttachmentCount,
            int IncludedCount,
            int ExcludedCount);

        private readonly Dictionary<string, GroupBypassAttachment> _attachmentsByHostKey = new(StringComparer.OrdinalIgnoreCase);

        public string GroupKey { get; }

        public GroupBypassAttachmentSet(string groupKey)
        {
            GroupKey = (groupKey ?? string.Empty).Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(GroupKey))
            {
                GroupKey = "group";
            }
        }

        public IReadOnlyList<GroupBypassAttachment> GetAttachmentsSnapshot()
        {
            return _attachmentsByHostKey.Values
                .OrderBy(a => a.HostKey, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        public void UpsertAttachment(GroupBypassAttachment attachment)
        {
            if (attachment == null) throw new ArgumentNullException(nameof(attachment));
            var hostKey = (attachment.HostKey ?? string.Empty).Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(hostKey)) return;

            _attachmentsByHostKey[hostKey] = attachment with { HostKey = hostKey };
        }

        public bool SetExcluded(string hostKey, bool excluded)
        {
            hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(hostKey)) return false;

            if (_attachmentsByHostKey.TryGetValue(hostKey, out var existing))
            {
                _attachmentsByHostKey[hostKey] = existing with { Excluded = excluded, UpdatedAtUtc = DateTimeOffset.UtcNow };
            }
            else
            {
                _attachmentsByHostKey[hostKey] = new GroupBypassAttachment(
                    HostKey: hostKey,
                    Excluded: excluded,
                    CandidateIpEndpoints: Array.Empty<string>(),
                    DropUdp443: false,
                    AllowNoSni: false,
                    UpdatedAtUtc: DateTimeOffset.UtcNow);
            }

            return excluded;
        }

        public bool IsExcluded(string hostKey)
        {
            hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(hostKey)) return false;
            return _attachmentsByHostKey.TryGetValue(hostKey, out var a) && a.Excluded;
        }

        public EffectiveGroupConfig ComputeEffectiveConfig()
        {
            var attachments = _attachmentsByHostKey.Values.ToArray();

            var included = attachments.Where(a => !a.Excluded).ToArray();
            var excludedCount = attachments.Length - included.Length;

            var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var a in included)
            {
                foreach (var ip in a.CandidateIpEndpoints ?? Array.Empty<string>())
                {
                    var s = (ip ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(s)) continue;
                    endpoints.Add(s);
                }
            }

            var endpointsSorted = endpoints
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var dropUdp443 = included.Any(a => a.DropUdp443);
            var allowNoSni = included.Any(a => a.AllowNoSni);

            return new EffectiveGroupConfig(
                CandidateIpEndpointsUnion: endpointsSorted,
                DropUdp443: dropUdp443,
                AllowNoSni: allowNoSni,
                AttachmentCount: attachments.Length,
                IncludedCount: included.Length,
                ExcludedCount: excludedCount);
        }
    }
}
