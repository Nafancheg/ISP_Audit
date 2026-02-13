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
        private static readonly string[] FallbackWildcardPatterns =
        {
            "*.arpa",
            "*.local",
            "*.localdomain"
        };

        // Важно: используем copy-on-write массивы, чтобы чтение было lock-free.
        // Загрузка/перезагрузка создаёт новые массивы и атомарно подменяет ссылки.
        private Regex[] _patterns = Array.Empty<Regex>();
        private Regex[] _excludePatterns = Array.Empty<Regex>();
        private readonly IProgress<string>? _progress;
        
        /// <summary>
        /// Количество загруженных паттернов
        /// </summary>
        public int PatternCount => _patterns.Length;
        
        /// <summary>
        /// Количество исключений (whitelist)
        /// </summary>
        public int ExcludeCount => _excludePatterns.Length;

        public NoiseHostFilter(IProgress<string>? progress = null)
        {
            _progress = progress;

            // Базовые паттерны должны быть всегда, даже без noise_hosts.json.
            SetFallbackPatterns(progressOverride: null);
        }

        /// <summary>
        /// Загружает паттерны из JSON-файла
        /// </summary>
        /// <param name="filePath">Путь к файлу noise_hosts.json</param>
        /// <returns>true если файл загружен, false если использованы минимальные паттерны</returns>
        public bool LoadFromFile(string filePath, IProgress<string>? progressOverride = null)
        {
            var progress = progressOverride ?? _progress;

            if (!File.Exists(filePath))
            {
                progress?.Report($"[NoiseFilter] ⚠ Файл {filePath} не найден! Используем только базовые фильтры (local/arpa).");
                SetFallbackPatterns(progressOverride: progress);
                return false;
            }

            try
            {
                var nextPatterns = new List<Regex>();
                var nextExcludePatterns = new List<Regex>();

                // Базовые паттерны всегда включены.
                foreach (var pattern in FallbackWildcardPatterns)
                {
                    var regex = WildcardToRegex(pattern);
                    if (regex != null)
                    {
                        nextPatterns.Add(regex);
                    }
                }

                var json = File.ReadAllText(filePath);
                var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("patterns", out var patternsElement))
                {
                    progress?.Report("[NoiseFilter] JSON не содержит секции 'patterns'");
                    SetFallbackPatterns(progressOverride: progress);
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
                                    nextPatterns.Add(regex);
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
                                    nextExcludePatterns.Add(regex);
                            }
                        }
                    }
                }

                _patterns = nextPatterns.ToArray();
                _excludePatterns = nextExcludePatterns.ToArray();

                progress?.Report($"[NoiseFilter] Загружено {_patterns.Length} паттернов, {_excludePatterns.Length} исключений из файла");
                
                // Логируем первые 5 паттернов для отладки
                if (_patterns.Length > 0)
                {
                    var sample = string.Join(", ", _patterns.Take(5).Select(p => p.ToString()));
                    progress?.Report($"[NoiseFilter] Примеры паттернов: {sample}");
                }
                
                return true;
            }
            catch (Exception ex)
            {
                progress?.Report($"[NoiseFilter] Ошибка загрузки: {ex.Message}");
                SetFallbackPatterns(progressOverride: progress);
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
            var excludes = _excludePatterns;
            foreach (var exclude in excludes)
            {
                if (exclude.IsMatch(lower))
                    return false;
            }

            // Затем проверяем паттерны фильтрации
            var patterns = _patterns;
            foreach (var pattern in patterns)
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

            var excludes = _excludePatterns;
            foreach (var exclude in excludes)
            {
                if (exclude.IsMatch(lower))
                    return $"Whitelisted by {exclude}";
            }

            var patterns = _patterns;
            foreach (var pattern in patterns)
            {
                if (pattern.IsMatch(lower))
                    return $"Matched noise pattern {pattern}";
            }

            return "No match (Clean)";
        }

        /// <summary>
        /// Минимальные fallback-паттерны (только технические).
        /// Важно: этот набор должен быть всегда (даже при успешной загрузке файла).
        /// </summary>
        private void SetFallbackPatterns(IProgress<string>? progressOverride)
        {
            var patterns = new List<Regex>();
            foreach (var pattern in FallbackWildcardPatterns)
            {
                var regex = WildcardToRegex(pattern);
                if (regex != null)
                    patterns.Add(regex);
            }

            _patterns = patterns.ToArray();
            _excludePatterns = Array.Empty<Regex>();

            var progress = progressOverride ?? _progress;
            progress?.Report($"[NoiseFilter] Загружено {FallbackWildcardPatterns.Length} базовых паттернов (fallback)");
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

        // Singleton API удалён: фильтр должен приходить через DI/конструктор.
    }
}