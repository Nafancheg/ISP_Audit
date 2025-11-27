using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace IspAudit.Core.Models
{
    /// <summary>
    /// Результат диагностики конкретного хоста.
    /// Сохраняется в кэш для повторного использования.
    /// </summary>
    public class HostDiagnosisResult
    {
        /// <summary>
        /// Ключ хоста (hostname или IP:Port)
        /// </summary>
        public string HostKey { get; set; } = string.Empty;
        
        /// <summary>
        /// Обнаруженный тип блокировки (TLS_DPI, TCP_RST, DNS_FILTERED, null = нет блокировки)
        /// </summary>
        public string? BlockageType { get; set; }
        
        /// <summary>
        /// Стратегия обхода, которая сработала (TLS_FRAGMENT, TLS_DISORDER, DROP_RST, etc.)
        /// null если блокировки нет или стратегия не найдена
        /// </summary>
        public string? WorkingStrategy { get; set; }
        
        /// <summary>
        /// Дата и время последней проверки (UTC)
        /// </summary>
        public DateTime DiagnosedAt { get; set; }
        
        /// <summary>
        /// Количество успешных применений этой стратегии
        /// </summary>
        public int SuccessCount { get; set; }
        
        /// <summary>
        /// Количество неудачных применений после успешного обнаружения
        /// (если много — стратегия устарела, нужна ревалидация)
        /// </summary>
        public int FailureCount { get; set; }
        
        /// <summary>
        /// Проверяет, актуален ли результат диагностики
        /// </summary>
        public bool IsStale(TimeSpan maxAge)
        {
            return DateTime.UtcNow - DiagnosedAt > maxAge;
        }
        
        /// <summary>
        /// Проверяет, нужна ли ревалидация (много failures после успеха)
        /// </summary>
        public bool NeedsRevalidation => FailureCount >= 3;
    }
    
    /// <summary>
    /// Кэш результатов диагностики хостов.
    /// Позволяет пропустить диагностику при повторном запуске если стратегия уже известна.
    /// </summary>
    public class DiagnosisCache
    {
        private const string CacheFileName = "diagnosis_cache.json";
        private static readonly TimeSpan DefaultMaxAge = TimeSpan.FromDays(7); // Результаты актуальны 7 дней
        
        private readonly Dictionary<string, HostDiagnosisResult> _cache = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _cacheFilePath;
        private readonly object _lock = new();
        
        public DiagnosisCache(string? baseDirectory = null)
        {
            var dir = baseDirectory ?? AppContext.BaseDirectory;
            _cacheFilePath = Path.Combine(dir, CacheFileName);
            Load();
        }
        
        /// <summary>
        /// Получает кэшированный результат диагностики для хоста
        /// </summary>
        /// <param name="hostKey">Ключ хоста (hostname или IP:Port)</param>
        /// <param name="maxAge">Максимальный возраст результата (по умолчанию 7 дней)</param>
        /// <returns>Результат или null если нет в кэше/устарел</returns>
        public HostDiagnosisResult? Get(string hostKey, TimeSpan? maxAge = null)
        {
            lock (_lock)
            {
                if (_cache.TryGetValue(NormalizeKey(hostKey), out var result))
                {
                    var age = maxAge ?? DefaultMaxAge;
                    
                    // Устарел?
                    if (result.IsStale(age))
                    {
                        ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Кэш для {hostKey} устарел ({result.DiagnosedAt:u})");
                        return null;
                    }
                    
                    // Нужна ревалидация?
                    if (result.NeedsRevalidation)
                    {
                        ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Кэш для {hostKey} требует ревалидации (failures={result.FailureCount})");
                        return null;
                    }
                    
                    ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Найден кэш для {hostKey}: блокировка={result.BlockageType ?? "нет"}, стратегия={result.WorkingStrategy ?? "нет"}");
                    return result;
                }
                
                return null;
            }
        }
        
        /// <summary>
        /// Сохраняет результат успешной диагностики
        /// </summary>
        public void SaveSuccess(string hostKey, string? blockageType, string? workingStrategy)
        {
            lock (_lock)
            {
                var key = NormalizeKey(hostKey);
                
                if (_cache.TryGetValue(key, out var existing))
                {
                    // Обновляем существующую запись
                    existing.BlockageType = blockageType;
                    existing.WorkingStrategy = workingStrategy;
                    existing.DiagnosedAt = DateTime.UtcNow;
                    existing.SuccessCount++;
                    existing.FailureCount = 0; // Сбрасываем failures при успехе
                }
                else
                {
                    // Новая запись
                    _cache[key] = new HostDiagnosisResult
                    {
                        HostKey = hostKey,
                        BlockageType = blockageType,
                        WorkingStrategy = workingStrategy,
                        DiagnosedAt = DateTime.UtcNow,
                        SuccessCount = 1,
                        FailureCount = 0
                    };
                }
                
                ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Сохранено: {hostKey} → {workingStrategy ?? "без стратегии"}");
                Save();
            }
        }
        
        /// <summary>
        /// Регистрирует неудачную попытку использования кэшированной стратегии
        /// </summary>
        public void RecordFailure(string hostKey)
        {
            lock (_lock)
            {
                var key = NormalizeKey(hostKey);
                
                if (_cache.TryGetValue(key, out var existing))
                {
                    existing.FailureCount++;
                    ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Failure для {hostKey}: count={existing.FailureCount}");
                    Save();
                }
            }
        }
        
        /// <summary>
        /// Удаляет запись из кэша (для принудительной ревалидации)
        /// </summary>
        public void Invalidate(string hostKey)
        {
            lock (_lock)
            {
                var key = NormalizeKey(hostKey);
                if (_cache.Remove(key))
                {
                    ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Удалено: {hostKey}");
                    Save();
                }
            }
        }
        
        /// <summary>
        /// Очищает весь кэш
        /// </summary>
        public void Clear()
        {
            lock (_lock)
            {
                _cache.Clear();
                Save();
                ISPAudit.Utils.DebugLogger.Log("[DiagnosisCache] Кэш очищен");
            }
        }
        
        /// <summary>
        /// Возвращает все кэшированные результаты (для отладки)
        /// </summary>
        public IReadOnlyDictionary<string, HostDiagnosisResult> GetAll()
        {
            lock (_lock)
            {
                return new Dictionary<string, HostDiagnosisResult>(_cache);
            }
        }
        
        private static string NormalizeKey(string hostKey)
        {
            // Нормализуем ключ: lowercase, убираем trailing dots
            return hostKey.ToLowerInvariant().TrimEnd('.');
        }
        
        private void Load()
        {
            try
            {
                if (File.Exists(_cacheFilePath))
                {
                    var json = File.ReadAllText(_cacheFilePath);
                    var data = JsonSerializer.Deserialize<CacheData>(json);
                    
                    if (data?.Hosts != null)
                    {
                        foreach (var result in data.Hosts)
                        {
                            _cache[NormalizeKey(result.HostKey)] = result;
                        }
                        
                        ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Загружено {_cache.Count} записей из {_cacheFilePath}");
                    }
                }
            }
            catch (Exception ex)
            {
                ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Ошибка загрузки: {ex.Message}");
            }
        }
        
        private void Save()
        {
            try
            {
                var data = new CacheData
                {
                    Version = 1,
                    UpdatedAt = DateTime.UtcNow,
                    Hosts = new List<HostDiagnosisResult>(_cache.Values)
                };
                
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                };
                
                var json = JsonSerializer.Serialize(data, options);
                File.WriteAllText(_cacheFilePath, json);
            }
            catch (Exception ex)
            {
                ISPAudit.Utils.DebugLogger.Log($"[DiagnosisCache] Ошибка сохранения: {ex.Message}");
            }
        }
        
        private class CacheData
        {
            public int Version { get; set; }
            public DateTime UpdatedAt { get; set; }
            public List<HostDiagnosisResult> Hosts { get; set; } = new();
        }
    }
}
