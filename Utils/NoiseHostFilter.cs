using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IspAudit.Utils
{
    /// <summary>
    /// Сервис фильтрации "шумных" хостов (CDN, телеметрия, аналитика).
    /// Загружает паттерны из JSON-файла для гибкой настройки без перекомпиляции.
    /// </summary>
    public class NoiseHostFilter
    {
        private readonly List<Regex> _patterns = new();
        private readonly List<Regex> _excludePatterns = new();
        private readonly IProgress<string>? _progress;
        
        /// <summary>
        /// Количество загруженных паттернов
        /// </summary>
        public int PatternCount => _patterns.Count;
        
        /// <summary>
        /// Количество исключений (whitelist)
        /// </summary>
        public int ExcludeCount => _excludePatterns.Count;

        public NoiseHostFilter(IProgress<string>? progress = null)
        {
            _progress = progress;
        }

        /// <summary>
        /// Загружает паттерны из JSON-файла
        /// </summary>
        /// <param name="filePath">Путь к файлу noise_hosts.json</param>
        /// <returns>true если файл загружен, false если использованы минимальные паттерны</returns>
        public bool LoadFromFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                _progress?.Report($"[NoiseFilter] ⚠ Файл {filePath} не найден! Используем только базовые фильтры (local/arpa).");
                LoadFallbackPatterns();
                return false;
            }

            try
            {
                var json = File.ReadAllText(filePath);
                var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("patterns", out var patternsElement))
                {
                    _progress?.Report("[NoiseFilter] JSON не содержит секции 'patterns'");
                    LoadFallbackPatterns();
                    return false;
                }

                foreach (var category in patternsElement.EnumerateObject())
                {
                    var categoryObj = category.Value;
                    
                    // Загружаем hosts
                    if (categoryObj.TryGetProperty("hosts", out var hostsArray))
                    {
                        foreach (var host in hostsArray.EnumerateArray())
                        {
                            var pattern = host.GetString();
                            if (!string.IsNullOrEmpty(pattern))
                            {
                                var regex = WildcardToRegex(pattern);
                                if (regex != null)
                                    _patterns.Add(regex);
                            }
                        }
                    }
                    
                    // Загружаем exclude (whitelist)
                    if (categoryObj.TryGetProperty("exclude", out var excludeArray))
                    {
                        foreach (var exclude in excludeArray.EnumerateArray())
                        {
                            var pattern = exclude.GetString();
                            if (!string.IsNullOrEmpty(pattern))
                            {
                                var regex = WildcardToRegex(pattern);
                                if (regex != null)
                                    _excludePatterns.Add(regex);
                            }
                        }
                    }
                }

                _progress?.Report($"[NoiseFilter] Загружено {_patterns.Count} паттернов, {_excludePatterns.Count} исключений из файла");
                
                // Логируем первые 5 паттернов для отладки
                if (_patterns.Count > 0)
                {
                    var sample = string.Join(", ", _patterns.Take(5).Select(p => p.ToString()));
                    _progress?.Report($"[NoiseFilter] Примеры паттернов: {sample}");
                }
                
                return true;
            }
            catch (Exception ex)
            {
                _progress?.Report($"[NoiseFilter] Ошибка загрузки: {ex.Message}");
                LoadFallbackPatterns();
                return false;
            }
        }

        /// <summary>
        /// Проверяет, является ли хост "шумным"
        /// </summary>
        public bool IsNoiseHost(string? hostname)
        {
            if (string.IsNullOrEmpty(hostname))
                return false;

            // Убираем точку в конце (FQDN), пробелы и приводим к нижнему регистру
            var lower = hostname.Trim().TrimEnd('.').ToLowerInvariant();

            // Сначала проверяем исключения (whitelist) — они имеют приоритет
            foreach (var exclude in _excludePatterns)
            {
                if (exclude.IsMatch(lower))
                    return false;
            }

            // Затем проверяем паттерны фильтрации
            foreach (var pattern in _patterns)
            {
                if (pattern.IsMatch(lower))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Метод для отладки: проверяет хост и возвращает причину
        /// </summary>
        public string DebugMatch(string? hostname)
        {
            if (string.IsNullOrEmpty(hostname))
                return "Empty hostname";

            var lower = hostname.Trim().TrimEnd('.').ToLowerInvariant();

            foreach (var exclude in _excludePatterns)
            {
                if (exclude.IsMatch(lower))
                    return $"Whitelisted by {exclude}";
            }

            foreach (var pattern in _patterns)
            {
                if (pattern.IsMatch(lower))
                    return $"Matched noise pattern {pattern}";
            }

            return "No match (Clean)";
        }

        /// <summary>
        /// Минимальные fallback-паттерны (только технические)
        /// </summary>
        private void LoadFallbackPatterns()
        {
            var fallback = new[]
            {
                "*.arpa",
                "*.local",
                "*.localdomain"
            };

            foreach (var pattern in fallback)
            {
                var regex = WildcardToRegex(pattern);
                if (regex != null)
                    _patterns.Add(regex);
            }
            
            _progress?.Report($"[NoiseFilter] Загружено {fallback.Length} базовых паттернов (fallback)");
        }

        /// <summary>
        /// Конвертирует wildcard-паттерн в Regex
        /// Поддерживает * в начале, конце и середине
        /// </summary>
        private static Regex? WildcardToRegex(string pattern)
        {
            try
            {
                // Экранируем все спецсимволы кроме *
                var escaped = Regex.Escape(pattern.ToLowerInvariant());
                
                // Заменяем \* на соответствующий regex
                var regexPattern = escaped.Replace("\\*", ".*");
                
                // Добавляем якоря для точного совпадения
                regexPattern = "^" + regexPattern + "$";
                
                return new Regex(regexPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
            }
            catch
            {
                return null;
            }
        }

        #region Singleton для удобства (опционально)
        
        private static NoiseHostFilter? _instance;
        private static readonly object _lock = new();
        
        /// <summary>
        /// Глобальный экземпляр фильтра.
        /// Используйте Initialize() для загрузки из файла.
        /// </summary>
        public static NoiseHostFilter Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new NoiseHostFilter();
                            // Если не инициализирован явно, используем fallback
                            _instance.LoadFallbackPatterns();
                        }
                    }
                }
                return _instance;
            }
        }
        
        /// <summary>
        /// Инициализирует глобальный фильтр из файла
        /// </summary>
        public static bool Initialize(string filePath, IProgress<string>? progress = null)
        {
            lock (_lock)
            {
                _instance = new NoiseHostFilter(progress);
                return _instance.LoadFromFile(filePath);
            }
        }
        
        #endregion
    }
}