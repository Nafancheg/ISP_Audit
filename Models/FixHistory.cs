using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace ISPAudit.Models
{
    /// <summary>
    /// Типы исправлений, которые можно применить автоматически
    /// </summary>
    public enum FixType
    {
        None = 0,           // Нет исправления
        DnsChange = 1,      // Смена DNS серверов + DoH
        FirewallRule = 2,   // Добавление правил Windows Firewall
        HostsFile = 3,      // Изменение hosts файла
        Manual = 4          // Ручное исправление (показать инструкции)
    }

    /// <summary>
    /// Модель примененного исправления для persistence
    /// </summary>
    public class AppliedFix
    {
        public string FixId { get; set; } = Guid.NewGuid().ToString();
        public FixType Type { get; set; }
        public DateTime AppliedAt { get; set; } = DateTime.Now;
        public string Description { get; set; } = string.Empty;
        
        /// <summary>
        /// Оригинальные настройки для rollback (JSON-сериализуемый словарь)
        /// Например: {"adapter": "Ethernet", "dnsServers": "192.168.1.1", "dohEnabled": "false"}
        /// </summary>
        public Dictionary<string, string> OriginalSettings { get; set; } = new();
    }

    /// <summary>
    /// Менеджер для сохранения/загрузки истории примененных исправлений
    /// Persistence: %APPDATA%\ISP_Audit\fix_history.json
    /// </summary>
    public class FixHistoryManager
    {
        private static readonly string AppDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ISP_Audit"
        );
        private static readonly string HistoryFilePath = Path.Combine(AppDataPath, "fix_history.json");

        /// <summary>
        /// Загрузить историю примененных исправлений
        /// </summary>
        public static List<AppliedFix> Load()
        {
            try
            {
                if (!File.Exists(HistoryFilePath))
                    return new List<AppliedFix>();

                var json = File.ReadAllText(HistoryFilePath);
                return JsonSerializer.Deserialize<List<AppliedFix>>(json) ?? new List<AppliedFix>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load fix history: {ex.Message}");
                return new List<AppliedFix>();
            }
        }

        /// <summary>
        /// Сохранить историю примененных исправлений
        /// </summary>
        public static void Save(List<AppliedFix> fixes)
        {
            try
            {
                // Создать директорию если не существует
                Directory.CreateDirectory(AppDataPath);

                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(fixes, options);
                File.WriteAllText(HistoryFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save fix history: {ex.Message}");
            }
        }

        /// <summary>
        /// Добавить исправление в историю
        /// </summary>
        public static void Add(AppliedFix fix)
        {
            var fixes = Load();
            fixes.Add(fix);
            Save(fixes);
        }

        /// <summary>
        /// Удалить исправление из истории
        /// </summary>
        public static void Remove(string fixId)
        {
            var fixes = Load();
            fixes.RemoveAll(f => f.FixId == fixId);
            Save(fixes);
        }

        /// <summary>
        /// Очистить всю историю
        /// </summary>
        public static void Clear()
        {
            Save(new List<AppliedFix>());
        }
    }
}
