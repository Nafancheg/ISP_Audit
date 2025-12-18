using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Traffic;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static async Task<SmokeTestResult> Bypass_TlsBypassService_RegistersFilter(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Skip, sw.Elapsed,
                        "Пропуск: нет прав администратора (WinDivert требует Elevated)"
                    );
                }

                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var options = svc.GetOptionsSnapshot() with
                {
                    FragmentEnabled = true,
                    DisorderEnabled = false,
                    FakeEnabled = false,
                    DropRstEnabled = false
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(3));

                await svc.ApplyAsync(options, cts.Token).ConfigureAwait(false);

                var filters = GetEngineFiltersSnapshot(engine);
                if (!filters.Any(f => f.Name == "BypassFilter"))
                {
                    return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Fail, sw.Elapsed,
                        "BypassFilter не найден в списке фильтров TrafficEngine после ApplyAsync"
                    );
                }

                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: BypassFilter зарегистрирован"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-001", "TlsBypassService: регистрация BypassFilter", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> Bypass_TlsBypassService_RemovesFilter(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (!TrafficEngine.HasAdministratorRights)
                {
                    return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Skip, sw.Elapsed,
                        "Пропуск: нет прав администратора (WinDivert требует Elevated)"
                    );
                }

                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var enable = svc.GetOptionsSnapshot() with
                {
                    FragmentEnabled = true,
                    DisorderEnabled = false,
                    FakeEnabled = false,
                    DropRstEnabled = false
                };

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(4));

                await svc.ApplyAsync(enable, cts.Token).ConfigureAwait(false);
                await svc.DisableAsync(cts.Token).ConfigureAwait(false);

                var filters = GetEngineFiltersSnapshot(engine);
                if (filters.Any(f => f.Name == "BypassFilter"))
                {
                    return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Fail, sw.Elapsed,
                        "BypassFilter всё ещё присутствует после DisableAsync"
                    );
                }

                await engine.StopAsync().ConfigureAwait(false);

                return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: BypassFilter удалён"
                );
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("BYPASS-002", "TlsBypassService: удаление BypassFilter при отключении", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Bypass_TlsBypassService_ProfilePresetPresent(CancellationToken ct)
            => RunAsync("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", () =>
            {
                using var engine = new TrafficEngine();
                using var svc = new TlsBypassService(engine, BypassProfile.CreateDefault());

                var names = svc.FragmentPresets.Select(p => p.Name).ToList();

                if (names.Count == 0)
                {
                    return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Список пресетов пуст");
                }

                if (!names.Contains("Профиль"))
                {
                    return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Нет пресета 'Профиль' (размеры из bypass_profile.json)");
                }

                return new SmokeTestResult("BYPASS-005", "TlsBypassService: пресет 'Профиль' присутствует (bypass_profile.json)", SmokeOutcome.Pass, TimeSpan.Zero,
                    $"OK: {string.Join(", ", names)}");
            }, ct);
    }
}
