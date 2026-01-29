using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace IspAudit.Utils
{
    public sealed class DomainGroupCatalogState
    {
        public int Version { get; set; } = 2;

        // Ручные группы доменов (пользователь/пакет предустановок).
        public List<DomainGroupEntry> PinnedGroups { get; set; } = new();

        // Автоматически выученные группы (advanced; по умолчанию просто храним структуру).
        public Dictionary<string, LearnedDomainGroupEntry> LearnedGroups { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        // Список learned-групп, которые пользователь отключил (не показывать подсказку).
        // Важно: это только UX, не влияет на фильтрацию пакетов.
        public List<string> IgnoredLearnedGroupKeys { get; set; } = new();
    }

    public sealed class DomainGroupEntry
    {
        public string Key { get; set; } = string.Empty;

        // Человекочитаемое имя (показываем в UI).
        public string DisplayName { get; set; } = string.Empty;

        // Домен(ы) без wildcard: базовые суффиксы, например youtube.com, googlevideo.com.
        public List<string> Domains { get; set; } = new();

        public string Note { get; set; } = string.Empty;
    }

    public sealed class LearnedDomainGroupEntry
    {
        public int EvidenceCount { get; set; }
        public string Reason { get; set; } = string.Empty;
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }

        // Домены, которые входят в группу (best-effort snapshot).
        public List<string> Domains { get; set; } = new();
    }

    public static class DomainGroupCatalog
    {
        private const string FileName = "domain_groups.json";

        public static bool TryIgnoreLearnedGroup(DomainGroupCatalogState state, string learnedGroupKey, Action<string>? log = null)
        {
            try
            {
                state ??= new DomainGroupCatalogState();
                state.IgnoredLearnedGroupKeys ??= new List<string>();
                state.LearnedGroups ??= new Dictionary<string, LearnedDomainGroupEntry>(StringComparer.OrdinalIgnoreCase);

                var key = (learnedGroupKey ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(key)) return false;

                // Игнорируем только learned-группы.
                if (!state.LearnedGroups.ContainsKey(key)) return false;

                if (!state.IgnoredLearnedGroupKeys.Any(k => string.Equals((k ?? string.Empty).Trim(), key, StringComparison.OrdinalIgnoreCase)))
                {
                    state.IgnoredLearnedGroupKeys.Add(key);
                }

                log?.Invoke($"[DomainGroups] Learned-группа скрыта: {key}");
                return true;
            }
            catch (Exception ex)
            {
                log?.Invoke($"[DomainGroups] Не удалось скрыть learned-группу: {ex.Message}");
                return false;
            }
        }

        public static bool TryPromoteLearnedGroupToPinned(
            DomainGroupCatalogState state,
            string learnedGroupKey,
            out string pinnedGroupKey,
            Action<string>? log = null)
        {
            pinnedGroupKey = string.Empty;

            try
            {
                state ??= new DomainGroupCatalogState();
                state.PinnedGroups ??= new List<DomainGroupEntry>();
                state.LearnedGroups ??= new Dictionary<string, LearnedDomainGroupEntry>(StringComparer.OrdinalIgnoreCase);
                state.IgnoredLearnedGroupKeys ??= new List<string>();

                var key = (learnedGroupKey ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(key)) return false;

                if (!state.LearnedGroups.TryGetValue(key, out var entry) || entry == null)
                {
                    return false;
                }

                var domains = (entry.Domains ?? new List<string>())
                    .Select(d => (d ?? string.Empty).Trim().Trim('.'))
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (domains.Count == 0) return false;

                pinnedGroupKey = ComputePinnedGroupKey(domains);
                var existing = new HashSet<string>(
                    (state.PinnedGroups ?? new List<DomainGroupEntry>()).Select(g => (g.Key ?? string.Empty).Trim()),
                    StringComparer.OrdinalIgnoreCase);

                if (existing.Contains(pinnedGroupKey))
                {
                    var baseKey = pinnedGroupKey;
                    for (int i = 2; i <= 99; i++)
                    {
                        var candidate = $"{baseKey}-{i}";
                        if (!existing.Contains(candidate))
                        {
                            pinnedGroupKey = candidate;
                            break;
                        }
                    }
                }

                var display = domains.Count == 1 ? domains[0] : string.Join(" + ", domains.Take(3));
                var note = $"Promoted from learned: {key}; evidence={entry.EvidenceCount}; at={DateTime.UtcNow:O}";

                var pinnedGroups = state.PinnedGroups ??= new List<DomainGroupEntry>();

                pinnedGroups.Add(new DomainGroupEntry
                {
                    Key = pinnedGroupKey,
                    DisplayName = display,
                    Domains = domains,
                    Note = note
                });

                // Убираем из learned и из ignore-листа.
                state.LearnedGroups.Remove(key);
                state.IgnoredLearnedGroupKeys = (state.IgnoredLearnedGroupKeys ?? new List<string>())
                    .Select(k => (k ?? string.Empty).Trim())
                    .Where(k => !string.IsNullOrWhiteSpace(k) && !string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                log?.Invoke($"[DomainGroups] Learned-группа закреплена: {key} -> {pinnedGroupKey} ({string.Join(", ", domains)})");
                return true;
            }
            catch (Exception ex)
            {
                log?.Invoke($"[DomainGroups] Не удалось закрепить learned-группу: {ex.Message}");
                pinnedGroupKey = string.Empty;
                return false;
            }
        }

        public static string CatalogFilePath
        {
            get
            {
                try
                {
                    AppPaths.EnsureStateDirectoryExists();
                    return AppPaths.GetStateFilePath(FileName);
                }
                catch
                {
                    return Path.Combine(AppPaths.AppDirectory, FileName);
                }
            }
        }

        public static DomainGroupCatalogState LoadOrDefault(Action<string>? log = null)
        {
            try
            {
                var path = CatalogFilePath;
                if (!File.Exists(path))
                {
                    var created = CreateDefault();

                    // UX: если каталога нет, создаём его на диске сразу,
                    // чтобы пользователю было проще редактировать pinned-группы вручную.
                    TryPersist(created, log);
                    return created;
                }

                var json = File.ReadAllText(path);
                var state = JsonSerializer.Deserialize<DomainGroupCatalogState>(json);
                return Normalize(state ?? CreateDefault());
            }
            catch (Exception ex)
            {
                log?.Invoke($"[DomainGroups] Не удалось загрузить каталог групп: {ex.Message}");
                return CreateDefault();
            }
        }

        public static void TryPersist(DomainGroupCatalogState state, Action<string>? log = null)
        {
            try
            {
                state = Normalize(state);
                var path = CatalogFilePath;
                var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[DomainGroups] Не удалось сохранить каталог групп: {ex.Message}");
            }
        }

        private static DomainGroupCatalogState CreateDefault()
        {
            // Quick win: одна предустановленная pinned-группа для YouTube.
            // Это не влияет на фильтрацию пакетов напрямую — только на UX (group apply/агрегация карточек).
            return new DomainGroupCatalogState
            {
                Version = 2,
                PinnedGroups = new List<DomainGroupEntry>
                {
                    new DomainGroupEntry
                    {
                        Key = "group-youtube",
                        DisplayName = "YouTube",
                        Domains = new List<string> { "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com" },
                        Note = "Предустановка: типичный набор доменов, которые идут вместе в браузере"
                    }
                }
            };
        }

        private static string ComputePinnedGroupKey(IReadOnlyList<string> domains)
        {
            try
            {
                var parts = (domains ?? Array.Empty<string>())
                    .Select(d => (d ?? string.Empty).Trim().Trim('.'))
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                    .Take(4)
                    .Select(SanitizeKeyPart)
                    .Where(p => !string.IsNullOrWhiteSpace(p))
                    .ToList();

                if (parts.Count == 0) return "group";

                var joined = string.Join("+", parts);
                if (joined.Length > 64)
                {
                    joined = joined.Substring(0, 64);
                }
                return "group-" + joined;
            }
            catch
            {
                return "group";
            }
        }

        private static string SanitizeKeyPart(string input)
        {
            try
            {
                input = (input ?? string.Empty).Trim().Trim('.');
                if (input.Length == 0) return string.Empty;

                var chars = input
                    .Select(ch =>
                    {
                        if (char.IsLetterOrDigit(ch)) return char.ToLowerInvariant(ch);
                        if (ch == '.' || ch == '-' || ch == '_') return '_';
                        return '_';
                    })
                    .ToArray();

                var s = new string(chars);
                while (s.Contains("__", StringComparison.Ordinal))
                {
                    s = s.Replace("__", "_", StringComparison.Ordinal);
                }
                return s.Trim('_');
            }
            catch
            {
                return string.Empty;
            }
        }

        private static DomainGroupCatalogState Normalize(DomainGroupCatalogState state)
        {
            state ??= new DomainGroupCatalogState();
            state.PinnedGroups ??= new List<DomainGroupEntry>();
            state.LearnedGroups ??= new Dictionary<string, LearnedDomainGroupEntry>(StringComparer.OrdinalIgnoreCase);
            state.IgnoredLearnedGroupKeys ??= new List<string>();

            foreach (var g in state.PinnedGroups)
            {
                g.Key = (g.Key ?? string.Empty).Trim();
                g.DisplayName = (g.DisplayName ?? string.Empty).Trim();
                g.Note = (g.Note ?? string.Empty).Trim();

                g.Domains ??= new List<string>();
                g.Domains = g.Domains
                    .Select(d => (d ?? string.Empty).Trim().Trim('.'))
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            // Убираем пустые/битые записи.
            state.PinnedGroups = state.PinnedGroups
                .Where(g => !string.IsNullOrWhiteSpace(g.Key) && g.Domains.Count > 0)
                .ToList();

            // Нормализация learned.
            var normalizedLearned = new Dictionary<string, LearnedDomainGroupEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in state.LearnedGroups)
            {
                var key = (kv.Key ?? string.Empty).Trim();
                var entry = kv.Value;
                if (string.IsNullOrWhiteSpace(key) || entry == null) continue;

                entry.Reason = (entry.Reason ?? string.Empty).Trim();
                entry.Domains ??= new List<string>();
                entry.Domains = entry.Domains
                    .Select(d => (d ?? string.Empty).Trim().Trim('.'))
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (entry.Domains.Count == 0) continue;

                // Best-effort: если даты не заданы, выставляем "сейчас".
                if (entry.FirstSeenUtc == default) entry.FirstSeenUtc = DateTime.UtcNow;
                if (entry.LastSeenUtc == default) entry.LastSeenUtc = entry.FirstSeenUtc;

                normalizedLearned[key] = entry;
            }

            state.LearnedGroups = normalizedLearned;

            state.IgnoredLearnedGroupKeys = (state.IgnoredLearnedGroupKeys ?? new List<string>())
                .Select(k => (k ?? string.Empty).Trim())
                .Where(k => !string.IsNullOrWhiteSpace(k))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            return state;
        }
    }
}
