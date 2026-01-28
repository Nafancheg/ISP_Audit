using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace IspAudit.Utils
{
    public sealed class DomainFamilyCatalogState
    {
        public int Version { get; set; } = 1;

        // Домены, которые пользователь может закрепить вручную (внешний справочник).
        // Если домен закреплён, подсказка/агрегация может включаться быстрее.
        public List<string> PinnedDomains { get; set; } = new();

        // Домены, которые система «выучила» автоматически по наблюдениям.
        public Dictionary<string, LearnedDomainEntry> LearnedDomains { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class LearnedDomainEntry
    {
        public int EvidenceCount { get; set; }
        public int EntropyEvidenceCount { get; set; }
        public string Reason { get; set; } = "";
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
    }

    public static class DomainFamilyCatalog
    {
        private const string FileName = "domain_families.json";

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

        public static DomainFamilyCatalogState LoadOrDefault(Action<string>? log = null)
        {
            try
            {
                var path = CatalogFilePath;
                if (!File.Exists(path))
                {
                    return new DomainFamilyCatalogState();
                }

                var json = File.ReadAllText(path);
                var state = JsonSerializer.Deserialize<DomainFamilyCatalogState>(json);
                return state ?? new DomainFamilyCatalogState();
            }
            catch (Exception ex)
            {
                log?.Invoke($"[DomainCatalog] Не удалось загрузить каталог доменов: {ex.Message}");
                return new DomainFamilyCatalogState();
            }
        }

        public static void TryPersist(DomainFamilyCatalogState state, Action<string>? log = null)
        {
            try
            {
                var path = CatalogFilePath;
                var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[DomainCatalog] Не удалось сохранить каталог доменов: {ex.Message}");
            }
        }
    }
}
