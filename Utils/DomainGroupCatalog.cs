using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace IspAudit.Utils
{
    public sealed class DomainGroupCatalogState
    {
        public int Version { get; set; } = 1;

        // Ручные группы доменов (пользователь/пакет предустановок).
        public List<DomainGroupEntry> PinnedGroups { get; set; } = new();

        // Автоматически выученные группы (advanced; по умолчанию просто храним структуру).
        public Dictionary<string, LearnedDomainGroupEntry> LearnedGroups { get; set; } = new(StringComparer.OrdinalIgnoreCase);
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
                Version = 1,
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

        private static DomainGroupCatalogState Normalize(DomainGroupCatalogState state)
        {
            state ??= new DomainGroupCatalogState();
            state.PinnedGroups ??= new List<DomainGroupEntry>();
            state.LearnedGroups ??= new Dictionary<string, LearnedDomainGroupEntry>(StringComparer.OrdinalIgnoreCase);

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

            return state;
        }
    }
}
