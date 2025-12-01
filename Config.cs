using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IspAudit
{
    /// <summary>
    /// Конфигурация приложения для GUI режима.
    /// CLI режим удалён — приложение работает только через GUI.
    /// </summary>
    public class Config
    {
        public List<string> Targets { get; set; } = new();
        public Dictionary<string, TargetDefinition> TargetMap { get; set; } = TargetCatalog.CreateDefaultTargetMap();
        
        // Управление игровыми профилями
        public static GameProfile? ActiveProfile { get; set; }
        
        // Профиль окружения: normal|vpn (влияет на классификацию/пороги)
        public string Profile { get; set; } = "normal";

        // Таймауты в секундах
        public int HttpTimeoutSeconds { get; set; } = 3;
        public int TcpTimeoutSeconds { get; set; } = 2;
        public int UdpTimeoutSeconds { get; set; } = 2;

        // Список портов для TCP проверок
        public List<int> Ports { get; set; } = TargetCatalog.CreateDefaultTcpPorts();
        public List<UdpProbeDefinition> UdpProbes { get; set; } = TargetCatalog.CreateDefaultUdpProbes();

        // Переключатели тестов (используются в GUI)
        public bool EnableDns { get; set; } = true;
        public bool EnableTcp { get; set; } = true;
        public bool EnableHttp { get; set; } = true;
        public bool EnableTrace { get; set; } = false; // Отключено по умолчанию — медленный и редко полезный для пользователей
        public bool EnableUdp { get; set; } = true;
        public bool EnableRst { get; set; } = false; // Отключено по умолчанию — сложная эвристика, мало информативна
        public bool EnableAutoBypass { get; set; } = false; // Автоматическое применение обхода блокировок
        
        // Legacy свойства (сохранены для совместимости, но не используются в GUI)
        public bool NoTrace { get; set; } = false;

        public static Config Default() => new Config();

        public List<TargetDefinition> ResolveTargets()
        {
            // Если профиль загружен, используем цели из профиля напрямую
            if (ActiveProfile?.Targets != null && ActiveProfile.Targets.Count > 0)
            {
                System.Diagnostics.Debug.WriteLine($"ResolveTargets: Using ActiveProfile targets ({ActiveProfile.Targets.Count} targets)");
                var result = new List<TargetDefinition>();
                foreach (var profileTarget in ActiveProfile.Targets)
                {
                    // Проверяем есть ли этот хост в Config.Targets (если Targets указаны явно)
                    if (Targets.Count > 0 && !Targets.Any(t => string.Equals(t, profileTarget.Host, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue; // Пропускаем цели не из списка
                    }
                    
                    result.Add(new TargetDefinition
                    {
                        Name = profileTarget.Name,
                        Host = profileTarget.Host,
                        Service = profileTarget.Service ?? "Неизвестно",
                        Critical = profileTarget.Critical,
                        FallbackIp = profileTarget.FallbackIp
                    });
                    System.Diagnostics.Debug.WriteLine($"  Added from profile: {profileTarget.Name} -> {profileTarget.Host}");
                }
                return result;
            }

            // Fallback: старая логика с TargetCatalog
            System.Diagnostics.Debug.WriteLine($"ResolveTargets: Using TargetCatalog fallback");
            var map = TargetMap.Count > 0
                ? TargetMap
                : TargetCatalog.CreateDefaultTargetMap();

            if (Targets.Count == 0)
            {
                return map.Values.Select(t => t.Copy()).ToList();
            }

            var fallbackResult = new List<TargetDefinition>();
            foreach (var host in Targets)
            {
                var matched = map.Values.FirstOrDefault(t => string.Equals(t.Host, host, StringComparison.OrdinalIgnoreCase));
                if (matched != null)
                {
                    fallbackResult.Add(matched.Copy());
                    continue;
                }

                var catalog = TargetCatalog.TryGetByHost(host);
                if (catalog != null)
                {
                    fallbackResult.Add(catalog);
                    continue;
                }

                fallbackResult.Add(new TargetDefinition
                {
                    Name = host,
                    Host = host,
                    Service = "Пользовательский"
                });
            }
            return fallbackResult;
        }

        public static void LoadGameProfile(string profileName)
        {
            try
            {
                // Сначала пробуем прямой путь (Default.json, Custom.json)
                string profilePath = Path.Combine("Profiles", $"{profileName}.json");
                
                if (!File.Exists(profilePath))
                {
                    // Если не нашли, ищем по имени профиля внутри JSON
                    var profilesDir = "Profiles";
                    if (Directory.Exists(profilesDir))
                    {
                        foreach (var file in Directory.GetFiles(profilesDir, "*.json"))
                        {
                            try
                            {
                                string json = File.ReadAllText(file);
                                var testProfile = System.Text.Json.JsonSerializer.Deserialize<GameProfile>(json);
                                if (testProfile?.Name == profileName)
                                {
                                    profilePath = file;
                                    break;
                                }
                            }
                            catch
                            {
                                // Игнорируем битые файлы
                            }
                        }
                    }
                }
                
                if (!File.Exists(profilePath))
                {
                    throw new FileNotFoundException($"Профиль '{profileName}' не найден");
                }

                string profileJson = File.ReadAllText(profilePath);
                var profile = System.Text.Json.JsonSerializer.Deserialize<GameProfile>(profileJson);
                
                if (profile == null)
                {
                    throw new InvalidOperationException($"Не удалось десериализовать профиль '{profileName}'");
                }

                ActiveProfile = profile;
            }
            catch (FileNotFoundException ex)
            {
                Console.WriteLine($"⚠️ Ошибка загрузки профиля: {ex.Message}");
                ActiveProfile = null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Ошибка при загрузке профиля '{profileName}': {ex.Message}");
                ActiveProfile = null;
            }
        }

        public static void SetActiveProfile(string profileName)
        {
            LoadGameProfile(profileName);
            
            // Обновить Program.Targets для совместимости с GUI
            if (ActiveProfile != null && ActiveProfile.Targets.Count > 0)
            {
                Program.Targets = ActiveProfile.Targets.ToDictionary(
                    t => t.Name,
                    t => new TargetDefinition
                    {
                        Name = t.Name,
                        Host = t.Host,
                        Service = t.Service,
                        Critical = t.Critical,
                        FallbackIp = t.FallbackIp
                    },
                    StringComparer.OrdinalIgnoreCase
                );
            }
        }
    }
}
