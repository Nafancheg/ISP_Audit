using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Utils;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static Task<SmokeTestResult> Cfg_BypassProfile_Load(CancellationToken ct)
            => RunAsync("CFG-001", "Загрузка bypass_profile.json", () =>
            {
                var profile = BypassProfile.CreateDefault();
                if (profile == null)
                {
                    return new SmokeTestResult("CFG-001", "Загрузка bypass_profile.json", SmokeOutcome.Fail, TimeSpan.Zero,
                        "BypassProfile.CreateDefault вернул null");
                }

                if (profile.TlsFragmentSizes == null || profile.TlsFragmentSizes.Count == 0)
                {
                    return new SmokeTestResult("CFG-001", "Загрузка bypass_profile.json", SmokeOutcome.Fail, TimeSpan.Zero,
                        "TlsFragmentSizes пуст (ожидали хотя бы 1 размер) ");
                }

                return new SmokeTestResult("CFG-001", "Загрузка bypass_profile.json", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: Preset='{profile.FragmentPresetName}', Sizes=[{string.Join(",", profile.TlsFragmentSizes)}]");
            }, ct);

        public static Task<SmokeTestResult> Cfg_BypassProfile_SaveChanges(CancellationToken ct)
            => RunAsync("CFG-002", "Сохранение изменений в bypass_profile.json", () =>
            {
                var path = GetBypassProfilePathByRules();
                string? backup = null;
                bool hadFile = File.Exists(path);

                try
                {
                    if (hadFile)
                    {
                        backup = File.ReadAllText(path);
                    }

                    var presetName = $"SmokePreset_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
                    var sizes = new[] { 64, 64 };
                    var ok = BypassProfile.TryUpdateFragmentSettings(sizes, presetName, autoAdjustAggressive: false);
                    if (!ok)
                    {
                        return new SmokeTestResult("CFG-002", "Сохранение изменений в bypass_profile.json", SmokeOutcome.Fail, TimeSpan.Zero,
                            "TryUpdateFragmentSettings вернул false");
                    }

                    var json = File.ReadAllText(path);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    if (!root.TryGetProperty("FragmentPresetName", out var presetProp) ||
                        !string.Equals(presetProp.GetString(), presetName, StringComparison.Ordinal))
                    {
                        return new SmokeTestResult("CFG-002", "Сохранение изменений в bypass_profile.json", SmokeOutcome.Fail, TimeSpan.Zero,
                            "FragmentPresetName не обновлён в JSON");
                    }

                    if (!root.TryGetProperty("TlsFragmentSizes", out var sizesProp) || sizesProp.ValueKind != JsonValueKind.Array)
                    {
                        return new SmokeTestResult("CFG-002", "Сохранение изменений в bypass_profile.json", SmokeOutcome.Fail, TimeSpan.Zero,
                            "TlsFragmentSizes отсутствует или не массив");
                    }

                    var got = sizesProp.EnumerateArray().Select(v => v.GetInt32()).ToArray();
                    if (got.Length != 2 || got[0] != 64 || got[1] != 64)
                    {
                        return new SmokeTestResult("CFG-002", "Сохранение изменений в bypass_profile.json", SmokeOutcome.Fail, TimeSpan.Zero,
                            $"TlsFragmentSizes не совпадает. Ожидали [64,64], получили [{string.Join(",", got)}]");
                    }

                    return new SmokeTestResult("CFG-002", "Сохранение изменений в bypass_profile.json", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: значения записаны в JSON");
                }
                finally
                {
                    try
                    {
                        if (hadFile)
                        {
                            File.WriteAllText(path, backup ?? string.Empty);
                        }
                        else if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    catch
                    {
                        // Не мешаем smoke прогону: восстановление best-effort.
                    }
                }

                static string GetBypassProfilePathByRules()
                {
                    var baseCandidate = Path.Combine(AppContext.BaseDirectory, "bypass_profile.json");
                    if (File.Exists(baseCandidate)) return baseCandidate;
                    return Path.Combine(Environment.CurrentDirectory, "bypass_profile.json");
                }
            }, ct);

        public static Task<SmokeTestResult> Cfg_BypassProfile_CorruptJson_Graceful(CancellationToken ct)
            => RunAsync("CFG-003", "Обработка некорректного JSON (graceful)", () =>
            {
                var path = GetBypassProfilePathByRules();
                string? backup = null;
                bool hadFile = File.Exists(path);

                try
                {
                    if (hadFile)
                    {
                        backup = File.ReadAllText(path);
                    }

                    File.WriteAllText(path, "{ this is not valid json");

                    var ok = BypassProfile.TryUpdateFragmentSettings(new[] { 64, 64 }, "SmokeBroken", autoAdjustAggressive: false);
                    if (ok)
                    {
                        return new SmokeTestResult("CFG-003", "Обработка некорректного JSON (graceful)", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали false при битом JSON, но получили true");
                    }

                    return new SmokeTestResult("CFG-003", "Обработка некорректного JSON (graceful)", SmokeOutcome.Pass, TimeSpan.Zero,
                        "OK: битый JSON не приводит к крэшу (TryUpdateFragmentSettings вернул false)");
                }
                finally
                {
                    try
                    {
                        if (hadFile)
                        {
                            File.WriteAllText(path, backup ?? string.Empty);
                        }
                        else if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    catch
                    {
                        // best-effort
                    }
                }

                static string GetBypassProfilePathByRules()
                {
                    var baseCandidate = Path.Combine(AppContext.BaseDirectory, "bypass_profile.json");
                    if (File.Exists(baseCandidate)) return baseCandidate;
                    return Path.Combine(Environment.CurrentDirectory, "bypass_profile.json");
                }
            }, ct);

        public static Task<SmokeTestResult> Cfg_NoiseHostFilter_Singleton(CancellationToken ct)
            => RunAsync("CFG-004", "NoiseHostFilter.Instance возвращает один экземпляр", () =>
            {
                var a = NoiseHostFilter.Instance;
                var b = NoiseHostFilter.Instance;
                if (!ReferenceEquals(a, b))
                {
                    return new SmokeTestResult("CFG-004", "NoiseHostFilter.Instance возвращает один экземпляр", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Instance вернул разные объекты");
                }

                return new SmokeTestResult("CFG-004", "NoiseHostFilter.Instance возвращает один экземпляр", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: singleton работает");
            }, ct);

        public static Task<SmokeTestResult> Cfg_NoiseHostFilter_LoadAndMatch(CancellationToken ct)
            => RunAsync("CFG-005", "Загрузка noise_hosts.json + IsNoise(fonts.googleapis.com)", () =>
            {
                var noisePath = TryFindNoiseHostsJsonPath();
                if (string.IsNullOrWhiteSpace(noisePath))
                {
                    return new SmokeTestResult("CFG-005", "Загрузка noise_hosts.json + IsNoise(fonts.googleapis.com)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Не удалось найти noise_hosts.json");
                }

                NoiseHostFilter.Initialize(noisePath);

                if (!NoiseHostFilter.Instance.IsNoiseHost("fonts.googleapis.com"))
                {
                    return new SmokeTestResult("CFG-005", "Загрузка noise_hosts.json + IsNoise(fonts.googleapis.com)", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали true для fonts.googleapis.com. Debug: {NoiseHostFilter.Instance.DebugMatch("fonts.googleapis.com")}");
                }

                return new SmokeTestResult("CFG-005", "Загрузка noise_hosts.json + IsNoise(fonts.googleapis.com)", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: домен распознан как шумовой");

                static string? TryFindNoiseHostsJsonPath()
                {
                    var candidates = new List<string>
                    {
                        Path.Combine(Environment.CurrentDirectory, "noise_hosts.json"),
                        Path.Combine(AppContext.BaseDirectory, "noise_hosts.json"),
                    };

                    foreach (var start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory }.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        var dir = new DirectoryInfo(start);
                        for (int i = 0; i < 10 && dir is not null; i++)
                        {
                            candidates.Add(Path.Combine(dir.FullName, "noise_hosts.json"));
                            dir = dir.Parent;
                        }
                    }

                    foreach (var p in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        if (File.Exists(p))
                        {
                            return p;
                        }
                    }

                    return null;
                }
            }, ct);

        public static Task<SmokeTestResult> Cfg_DomainFamilies_CatalogAndThresholds(CancellationToken ct)
            => RunAsync("CFG-006", "DomainFamily: persist+reload + pinned/learned пороги", () =>
            {
                var path = DomainFamilyCatalog.CatalogFilePath;
                string? backup = null;
                bool hadFile = File.Exists(path);

                try
                {
                    if (hadFile)
                    {
                        backup = File.ReadAllText(path);
                    }

                    // 1) Round-trip persist+reload
                    var state = new DomainFamilyCatalogState
                    {
                        Version = 1,
                        PinnedDomains = new List<string> { "example.com" },
                        LearnedDomains = new Dictionary<string, LearnedDomainEntry>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["learned.test"] = new LearnedDomainEntry
                            {
                                EvidenceCount = 10,
                                EntropyEvidenceCount = 3,
                                Reason = "Smoke",
                                FirstSeenUtc = DateTime.UtcNow.AddDays(-1),
                                LastSeenUtc = DateTime.UtcNow
                            }
                        }
                    };

                    DomainFamilyCatalog.TryPersist(state);
                    var loaded = DomainFamilyCatalog.LoadOrDefault();

                    if (!loaded.PinnedDomains.Any(d => d.Equals("example.com", StringComparison.OrdinalIgnoreCase)))
                    {
                        return new SmokeTestResult("CFG-006", "DomainFamily: persist+reload + pinned/learned пороги", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PinnedDomains не сохранился/не загрузился (ожидали example.com)");
                    }

                    if (!loaded.LearnedDomains.ContainsKey("learned.test"))
                    {
                        return new SmokeTestResult("CFG-006", "DomainFamily: persist+reload + pinned/learned пороги", SmokeOutcome.Fail, TimeSpan.Zero,
                            "LearnedDomains не сохранился/не загрузился (ожидали learned.test)");
                    }

                    // 2) Порог pinned: достаточно 2 подхостов и 1 entropy.
                    var analyzerPinned = new DomainFamilyAnalyzer(loaded);
                    analyzerPinned.ObserveHost("r1---edge-12345.example.com");
                    analyzerPinned.ObserveHost("r2---edge-67890.example.com");

                    if (!string.Equals(analyzerPinned.CurrentSuggestion?.DomainSuffix, "example.com", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("CFG-006", "DomainFamily: persist+reload + pinned/learned пороги", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Pinned порог не сработал: ожидали подсказку example.com после 2 подхостов");
                    }

                    // 3) Порог learned: по умолчанию (после доработки) достаточно 3 подхостов и 1 entropy.
                    var stateLearnedOnly = new DomainFamilyCatalogState
                    {
                        Version = 1,
                        PinnedDomains = new List<string>(),
                        LearnedDomains = new Dictionary<string, LearnedDomainEntry>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["learned.test"] = new LearnedDomainEntry
                            {
                                EvidenceCount = 10,
                                EntropyEvidenceCount = 3,
                                Reason = "Smoke",
                                FirstSeenUtc = DateTime.UtcNow.AddDays(-1),
                                LastSeenUtc = DateTime.UtcNow
                            }
                        }
                    };

                    var analyzerLearned = new DomainFamilyAnalyzer(stateLearnedOnly);
                    analyzerLearned.ObserveHost("r1---edge-12345.learned.test");
                    analyzerLearned.ObserveHost("r2---edge-67890.learned.test");
                    analyzerLearned.ObserveHost("r3---edge-11111.learned.test");

                    if (!string.Equals(analyzerLearned.CurrentSuggestion?.DomainSuffix, "learned.test", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("CFG-006", "DomainFamily: persist+reload + pinned/learned пороги", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Learned порог не сработал: ожидали подсказку learned.test после 3 подхостов");
                    }

                    return new SmokeTestResult("CFG-006", "DomainFamily: persist+reload + pinned/learned пороги", SmokeOutcome.Pass, TimeSpan.Zero,
                        $"OK: pinned/learned работают, каталог: {path}");
                }
                finally
                {
                    try
                    {
                        if (hadFile)
                        {
                            File.WriteAllText(path, backup ?? string.Empty);
                        }
                        else if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    catch
                    {
                        // best-effort
                    }
                }
            }, ct);

        public static Task<SmokeTestResult> Cfg_DomainGroups_CatalogAndPinnedSuggestion(CancellationToken ct)
            => RunAsync("CFG-007", "DomainGroups: persist+reload + pinned подсказка", () =>
            {
                var path = DomainGroupCatalog.CatalogFilePath;
                string? backup = null;
                bool hadFile = File.Exists(path);

                try
                {
                    if (hadFile)
                    {
                        backup = File.ReadAllText(path);
                    }

                    var state = new DomainGroupCatalogState
                    {
                        Version = 1,
                        PinnedGroups = new List<DomainGroupEntry>
                        {
                            new DomainGroupEntry
                            {
                                Key = "group-youtube",
                                DisplayName = "YouTube",
                                Domains = new List<string> { "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com" },
                                Note = "Smoke"
                            }
                        }
                    };

                    DomainGroupCatalog.TryPersist(state);
                    var loaded = DomainGroupCatalog.LoadOrDefault();

                    var yt = loaded.PinnedGroups.FirstOrDefault(g => g.Key.Equals("group-youtube", StringComparison.OrdinalIgnoreCase));
                    if (yt == null)
                    {
                        return new SmokeTestResult("CFG-007", "DomainGroups: persist+reload + pinned подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PinnedGroups не сохранился/не загрузился (ожидали group-youtube)");
                    }

                    if (!yt.Domains.Any(d => d.Equals("googlevideo.com", StringComparison.OrdinalIgnoreCase)))
                    {
                        return new SmokeTestResult("CFG-007", "DomainGroups: persist+reload + pinned подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "PinnedGroups.Domains не содержит googlevideo.com");
                    }

                    var analyzer = new DomainGroupAnalyzer(loaded);
                    analyzer.ObserveHost("r1---edge-12345.googlevideo.com");

                    if (!string.Equals(analyzer.CurrentSuggestion?.GroupKey, "group-youtube", StringComparison.OrdinalIgnoreCase))
                    {
                        return new SmokeTestResult("CFG-007", "DomainGroups: persist+reload + pinned подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Pinned подсказка не сработала: ожидали group-youtube для host в googlevideo.com");
                    }

                    return new SmokeTestResult("CFG-007", "DomainGroups: persist+reload + pinned подсказка", SmokeOutcome.Pass, TimeSpan.Zero,
                        $"OK: pinned-группа работает, каталог: {path}");
                }
                finally
                {
                    try
                    {
                        if (hadFile)
                        {
                            File.WriteAllText(path, backup ?? string.Empty);
                        }
                        else if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    catch
                    {
                        // best-effort
                    }
                }
            }, ct);

        public static Task<SmokeTestResult> Cfg_DomainGroups_LearnedSuggestion(CancellationToken ct)
            => RunAsync("CFG-008", "DomainGroups: learned (co-occurrence) подсказка", () =>
            {
                var path = DomainGroupCatalog.CatalogFilePath;
                string? backup = null;
                bool hadFile = File.Exists(path);

                try
                {
                    if (hadFile)
                    {
                        backup = File.ReadAllText(path);
                    }

                    // Стартуем с пустого каталога без pinned-групп, чтобы проверить именно learned.
                    var state = new DomainGroupCatalogState
                    {
                        Version = 1,
                        PinnedGroups = new List<DomainGroupEntry>(),
                        LearnedGroups = new Dictionary<string, LearnedDomainGroupEntry>(StringComparer.OrdinalIgnoreCase)
                    };

                    DomainGroupCatalog.TryPersist(state);

                    // Важно: загружаем через API каталога (нормализация/пути).
                    var loaded = DomainGroupCatalog.LoadOrDefault();

                    // Порог по умолчанию 8: генерируем серию co-occurrence событий.
                    var learner = new DomainGroupLearner(loaded);
                    var now = DateTime.UtcNow;

                    for (int i = 0; i < 8; i++)
                    {
                        learner.ObserveHost("www.youtube.com", now.AddMilliseconds(i * 10));
                        learner.ObserveHost("r1---sn-a5mekned.googlevideo.com", now.AddMilliseconds(i * 10 + 1));
                    }

                    if (loaded.LearnedGroups.Count == 0)
                    {
                        return new SmokeTestResult("CFG-008", "DomainGroups: learned (co-occurrence) подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали, что learner создаст хотя бы одну learned-группу");
                    }

                    DomainGroupCatalog.TryPersist(loaded);
                    var reloaded = DomainGroupCatalog.LoadOrDefault();

                    if (reloaded.LearnedGroups.Count == 0)
                    {
                        return new SmokeTestResult("CFG-008", "DomainGroups: learned (co-occurrence) подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "LearnedGroups не сохранился/не загрузился");
                    }

                    var analyzer = new DomainGroupAnalyzer(reloaded);
                    analyzer.ObserveHost("r2---sn-a5mekned.googlevideo.com");

                    if (analyzer.CurrentSuggestion == null)
                    {
                        return new SmokeTestResult("CFG-008", "DomainGroups: learned (co-occurrence) подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Ожидали learned-подсказку для host в googlevideo.com");
                    }

                    if (!analyzer.CurrentSuggestion.Domains.Any(d => d.Equals("youtube.com", StringComparison.OrdinalIgnoreCase)))
                    {
                        return new SmokeTestResult("CFG-008", "DomainGroups: learned (co-occurrence) подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Learned-подсказка не содержит youtube.com");
                    }

                    if (!analyzer.CurrentSuggestion.Domains.Any(d => d.Equals("googlevideo.com", StringComparison.OrdinalIgnoreCase)))
                    {
                        return new SmokeTestResult("CFG-008", "DomainGroups: learned (co-occurrence) подсказка", SmokeOutcome.Fail, TimeSpan.Zero,
                            "Learned-подсказка не содержит googlevideo.com");
                    }

                    return new SmokeTestResult("CFG-008", "DomainGroups: learned (co-occurrence) подсказка", SmokeOutcome.Pass, TimeSpan.Zero,
                        $"OK: learned groups={reloaded.LearnedGroups.Count}, example={analyzer.CurrentSuggestion.GroupKey}");
                }
                finally
                {
                    try
                    {
                        if (hadFile)
                        {
                            File.WriteAllText(path, backup ?? string.Empty);
                        }
                        else if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    catch
                    {
                        // best-effort
                    }
                }
            }, ct);
    }
}
