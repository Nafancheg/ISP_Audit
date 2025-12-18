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
    }
}
