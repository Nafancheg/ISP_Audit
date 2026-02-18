using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Traffic;
using IspAudit.Models;
using IspAudit.Utils;
using IspAudit.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static async Task<SmokeTestResult> Orch_OperationsAreSerialized_RapidRetestCancel(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            using var engine = new TrafficEngine();
            using var provider = BuildIspAuditProvider();
            var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
            var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
            var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
            var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
            var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
            using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
            var orchestrator = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);
            var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
            var bypass = new BypassController(manager, autoHostlist);

            var targets = new List<Target>
            {
                new Target { Host = "203.0.113.1", Name = "test-net", Service = "443", Critical = false }
            };

            try
            {
                // Два параллельных клика по «Ретест» не должны запускать две операции.
                var t1 = orchestrator.RetestTargetsAsync(targets, bypass);
                var t2 = orchestrator.RetestTargetsAsync(targets, bypass);

                var t2Done = await Task.WhenAny(t2, Task.Delay(2000, ct)).ConfigureAwait(false);
                if (t2Done != t2)
                {
                    return new SmokeTestResult("ORCH-008", "P1.5: операции оркестратора сериализованы (rapid retest/cancel)", SmokeOutcome.Fail, sw.Elapsed,
                        "Второй параллельный ретест не завершился быстро (вероятно, запустилась вторая операция)");
                }

                // Cancel должен быть безопасен и не ронять фоновые задачи.
                orchestrator.Cancel();

                var t1Done = await Task.WhenAny(t1, Task.Delay(6000, ct)).ConfigureAwait(false);
                if (t1Done != t1)
                {
                    return new SmokeTestResult("ORCH-008", "P1.5: операции оркестратора сериализованы (rapid retest/cancel)", SmokeOutcome.Fail, sw.Elapsed,
                        "Таймаут: ретест не завершился после Cancel (ожидали быстрый выход)");
                }

                if (orchestrator.IsDiagnosticRunning)
                {
                    return new SmokeTestResult("ORCH-008", "P1.5: операции оркестратора сериализованы (rapid retest/cancel)", SmokeOutcome.Fail, sw.Elapsed,
                        "Ожидали IsDiagnosticRunning=false после отмены/завершения");
                }

                return new SmokeTestResult("ORCH-008", "P1.5: операции оркестратора сериализованы (rapid retest/cancel)", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: второй ретест не стартует, Cancel безопасно завершает операцию");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ORCH-008", "P1.5: операции оркестратора сериализованы (rapid retest/cancel)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static Task<SmokeTestResult> Orch_Pipeline_StartStop_ViaRetestTargets(CancellationToken ct)
            => RunAsync("ORCH-001", "DiagnosticOrchestrator: ретест создает/завершает pipeline", () =>
            {
                using var engine = new TrafficEngine();
                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                var orchestrator = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);
                var autoHostlist = provider.GetRequiredService<AutoHostlistService>();
                var bypass = new BypassController(manager, autoHostlist);

                // Делаем цель заведомо быструю: TCP 443 к TEST-NET (может таймаутить, но не должен падать).
                var targets = new List<Target>
                {
                    new Target { Host = "203.0.113.1", Name = "test-net", Service = "443", Critical = false }
                };

                var task = orchestrator.RetestTargetsAsync(targets, bypass);
                task.GetAwaiter().GetResult();

                if (orchestrator.IsDiagnosticRunning)
                {
                    return new SmokeTestResult("ORCH-001", "DiagnosticOrchestrator: ретест создает/завершает pipeline", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали, что после RetestTargetsAsync IsDiagnosticRunning=false");
                }

                return new SmokeTestResult("ORCH-001", "DiagnosticOrchestrator: ретест создает/завершает pipeline", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: pipeline создается и корректно освобождается");
            }, ct);

        public static async Task<SmokeTestResult> Orch_MonitoringServices_StartStop_AdminGated(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            if (!TrafficEngine.HasAdministratorRights)
            {
                return new SmokeTestResult("ORCH-002", "Orchestrator: старт/стоп мониторинговых сервисов", SmokeOutcome.Skip, sw.Elapsed,
                    "Пропуск: нет прав администратора (TrafficEngine/WinDivert требует Elevated)");
            }

            using var engine = new TrafficEngine();
            using var provider = BuildIspAuditProvider();
            var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
            var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
            var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
            var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
            var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
            using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
            var orchestrator = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

            // Готовим _cts, иначе StartMonitoringServicesAsync не запустится.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            SetPrivateField(orchestrator, "_cts", cts);

            var progress = new Progress<string>(_ => { });

            try
            {
                // StartMonitoringServicesAsync(progress, overlay=null)
                var startTask = (Task)InvokePrivateMethod(orchestrator, "StartMonitoringServicesAsync", progress, null)!;
                await startTask.ConfigureAwait(false);

                var filters = GetEngineFiltersSnapshot(engine);
                var hasMonitor = filters.Exists(f => string.Equals(f.Name, "TrafficMonitor", StringComparison.OrdinalIgnoreCase));
                if (!hasMonitor)
                {
                    return new SmokeTestResult("ORCH-002", "Orchestrator: старт/стоп мониторинговых сервисов", SmokeOutcome.Fail, sw.Elapsed,
                        "Не найден ожидаемый фильтр TrafficMonitor после старта сервисов");
                }

                var stopTask = (Task)InvokePrivateMethod(orchestrator, "StopMonitoringServicesAsync")!;
                await stopTask.ConfigureAwait(false);

                var after = GetEngineFiltersSnapshot(engine);
                var stillHas = after.Exists(f => string.Equals(f.Name, "TrafficMonitor", StringComparison.OrdinalIgnoreCase));
                if (stillHas)
                {
                    return new SmokeTestResult("ORCH-002", "Orchestrator: старт/стоп мониторинговых сервисов", SmokeOutcome.Fail, sw.Elapsed,
                        "TrafficMonitor остался зарегистрированным после StopMonitoringServicesAsync");
                }

                return new SmokeTestResult("ORCH-002", "Orchestrator: старт/стоп мониторинговых сервисов", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: сервисы стартуют и снимают фильтр при остановке");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ORCH-002", "Orchestrator: старт/стоп мониторинговых сервисов", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
            finally
            {
                try { await engine.StopAsync().ConfigureAwait(false); } catch { }
                try { cts.Cancel(); cts.Dispose(); } catch { }
            }
        }

        public static Task<SmokeTestResult> Orch_SniGating_ByPid_AllowsOnlyTracked(CancellationToken ct)
            => RunAsync("ORCH-003", "SNI гейтируется по отслеживаемому PID", () =>
            {
                using var engine = new TrafficEngine();
                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                var orchestrator = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

                var trackedPid = 111;
                var otherPid = 222;
                var pidTracker = new PidTrackerService(trackedPid);

                // Подменяем pid-tracker внутри orchestrator.
                SetPrivateField(orchestrator, "_pidTracker", pidTracker);

                var ipAllowed = IPAddress.Parse("93.184.216.34");
                var ipDenied = IPAddress.Parse("1.1.1.1");

                // Привязываем remote endpoint -> pid.
                InvokePrivateMethod(orchestrator, "TrackRemoteEndpoint", trackedPid, (byte)6, ipAllowed, (ushort)443);
                InvokePrivateMethod(orchestrator, "TrackRemoteEndpoint", otherPid, (byte)6, ipDenied, (ushort)443);

                // Дергаем обработчик SNI.
                InvokePrivateMethod(orchestrator, "HandleSniDetected", ipAllowed, 443, "allowed.example");
                InvokePrivateMethod(orchestrator, "HandleSniDetected", ipDenied, 443, "denied.example");

                var pendingHosts = GetPrivateField<ConcurrentQueue<IspAudit.Core.Models.HostDiscovered>>(orchestrator, "_pendingSniHosts");
                var pendingByEndpointObj = GetPrivateField<object>(orchestrator, "_pendingSniByEndpoint");
                var pendingByEndpointCount = (int)(pendingByEndpointObj.GetType().GetProperty("Count")?.GetValue(pendingByEndpointObj)
                    ?? throw new InvalidOperationException("Не удалось прочитать Count у _pendingSniByEndpoint"));

                // Должен пройти только один (tracked).
                if (pendingHosts.Count != 1)
                {
                    return new SmokeTestResult("ORCH-003", "SNI гейтируется по отслеживаемому PID", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 1 SNI-host в очереди, получили {pendingHosts.Count}");
                }

                if (pendingByEndpointCount != 1)
                {
                    return new SmokeTestResult("ORCH-003", "SNI гейтируется по отслеживаемому PID", SmokeOutcome.Fail, TimeSpan.Zero,
                    $"Ожидали 1 элемент в буфере ранних SNI, получили {pendingByEndpointCount}");
                }

                return new SmokeTestResult("ORCH-003", "SNI гейтируется по отслеживаемому PID", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: только tracked PID пропускает SNI в pipeline очередь");
            }, ct);

        public static Task<SmokeTestResult> Orch_EarlySniBuffered_ThenFlushed_OnPidAppear(CancellationToken ct)
            => RunAsync("ORCH-004", "Ранний SNI буферится и флашится после появления PID", () =>
            {
                using var engine = new TrafficEngine();
                using var provider = BuildIspAuditProvider();
                var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
                var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
                var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
                var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
                var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
                using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
                var orchestrator = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

                var trackedPid = 333;
                var pidTracker = new PidTrackerService(trackedPid);
                SetPrivateField(orchestrator, "_pidTracker", pidTracker);

                var ip = IPAddress.Parse("93.184.216.34");
                const int port = 443;

                // SNI пришёл до TrackRemoteEndpoint.
                InvokePrivateMethod(orchestrator, "HandleSniDetected", ip, port, "early.example");

                var pendingHosts = GetPrivateField<ConcurrentQueue<IspAudit.Core.Models.HostDiscovered>>(orchestrator, "_pendingSniHosts");
                var pendingByEndpointObj = GetPrivateField<object>(orchestrator, "_pendingSniByEndpoint");
                var pendingByEndpointCount = (int)(pendingByEndpointObj.GetType().GetProperty("Count")?.GetValue(pendingByEndpointObj)
                    ?? throw new InvalidOperationException("Не удалось прочитать Count у _pendingSniByEndpoint"));

                if (pendingByEndpointCount != 1)
                {
                    return new SmokeTestResult("ORCH-004", "Ранний SNI буферится и флашится после появления PID", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали 1 элемент в буфере ранних SNI, получили {pendingByEndpointCount}");
                }

                // Теперь появился endpoint->pid.
                InvokePrivateMethod(orchestrator, "TrackRemoteEndpoint", trackedPid, (byte)6, ip, (ushort)port);
                InvokePrivateMethod(orchestrator, "TryFlushPendingSniForEndpoint", trackedPid, (byte)6, ip, (ushort)port);

                pendingByEndpointCount = (int)(pendingByEndpointObj.GetType().GetProperty("Count")?.GetValue(pendingByEndpointObj)
                    ?? throw new InvalidOperationException("Не удалось прочитать Count у _pendingSniByEndpoint"));

                if (pendingHosts.Count != 1)
                {
                    return new SmokeTestResult("ORCH-004", "Ранний SNI буферится и флашится после появления PID", SmokeOutcome.Fail, TimeSpan.Zero,
                        $"Ожидали, что SNI будет доставлен в очередь (1), получили {pendingHosts.Count}");
                }

                if (pendingByEndpointCount != 0)
                {
                    return new SmokeTestResult("ORCH-004", "Ранний SNI буферится и флашится после появления PID", SmokeOutcome.Fail, TimeSpan.Zero,
                    $"Ожидали, что буфер ранних SNI опустеет, осталось {pendingByEndpointCount}");
                }

                return new SmokeTestResult("ORCH-004", "Ранний SNI буферится и флашится после появления PID", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: ранний SNI не теряется");
            }, ct);

        public static async Task<SmokeTestResult> Orch_ProcessExit_StopsMonitoring(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();

            using var engine = new TrafficEngine();
            using var provider = BuildIspAuditProvider();
            var noiseHostFilter = provider.GetRequiredService<NoiseHostFilter>();
            var trafficFilter = provider.GetRequiredService<ITrafficFilter>();
            var pipelineFactory = provider.GetRequiredService<ILiveTestingPipelineFactory>();
            var stateStoreFactory = provider.GetRequiredService<IBlockageStateStoreFactory>();
            var managerFactory = provider.GetRequiredService<IBypassStateManagerFactory>();
            using var manager = managerFactory.GetOrCreate(engine, baseProfile: null, log: null);
            var orchestrator = new DiagnosticOrchestrator(manager, noiseHostFilter, trafficFilter, pipelineFactory, stateStoreFactory);

            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c exit 0",
                CreateNoWindow = true,
                UseShellExecute = false
            });

            if (proc == null)
            {
                return new SmokeTestResult("ORCH-005", "Orchestrator: останавливается, когда все процессы завершились", SmokeOutcome.Fail, sw.Elapsed,
                    "Не удалось запустить cmd.exe для теста");
            }

            proc.WaitForExit(2000);

            // Пид-трекер с уже завершённым PID.
            var pidTracker = new PidTrackerService(proc.Id);
            SetPrivateField(orchestrator, "_pidTracker", pidTracker);

            // Оркестратору нужен _cts.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            SetPrivateField(orchestrator, "_cts", cts);

            try
            {
                var monitorTask = (Task)InvokePrivateMethod(orchestrator, "RunProcessMonitorAsync")!;

                // Ждём максимум 3.5 секунды (там Delay 2s).
                var done = await Task.WhenAny(monitorTask, Task.Delay(3500, ct)).ConfigureAwait(false);
                if (done != monitorTask)
                {
                    return new SmokeTestResult("ORCH-005", "Orchestrator: останавливается, когда все процессы завершились", SmokeOutcome.Fail, sw.Elapsed,
                        "Таймаут ожидания реакции на завершение процессов");
                }

                var stopReason = GetPrivateField<string?>(orchestrator, "_stopReason");
                if (!string.Equals(stopReason, "ProcessExited", StringComparison.OrdinalIgnoreCase))
                {
                    return new SmokeTestResult("ORCH-005", "Orchestrator: останавливается, когда все процессы завершились", SmokeOutcome.Fail, sw.Elapsed,
                        $"Ожидали stopReason='ProcessExited', получили '{stopReason ?? "<null>"}'");
                }

                return new SmokeTestResult("ORCH-005", "Orchestrator: останавливается, когда все процессы завершились", SmokeOutcome.Pass, sw.Elapsed,
                    "OK: завершение процессов детектится");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("ORCH-005", "Orchestrator: останавливается, когда все процессы завершились", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
            finally
            {
                try { cts.Cancel(); cts.Dispose(); } catch { }
            }
        }

        public static Task<SmokeTestResult> Orch_PidTracker_AddRemovePid(CancellationToken ct)
            => RunAsync("ORCH-006", "PidTrackerService: Add/Remove PID", () =>
            {
                var tracker = new PidTrackerService(1000);

                var added = tracker.TryAddPid(1234);
                if (!added || !tracker.IsPidTracked(1234))
                {
                    return new SmokeTestResult("ORCH-006", "PidTrackerService: Add/Remove PID", SmokeOutcome.Fail, TimeSpan.Zero,
                        "PID 1234 не добавился в TrackedPids");
                }

                var removed = tracker.TryRemovePid(1234);
                if (!removed || tracker.IsPidTracked(1234))
                {
                    return new SmokeTestResult("ORCH-006", "PidTrackerService: Add/Remove PID", SmokeOutcome.Fail, TimeSpan.Zero,
                        "PID 1234 не удалился из TrackedPids");
                }

                return new SmokeTestResult("ORCH-006", "PidTrackerService: Add/Remove PID", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK: PID добавляется и удаляется");
            }, ct);

        public static Task<SmokeTestResult> Orch_PidTracker_IsPidTracked(CancellationToken ct)
            => RunAsync("ORCH-007", "PidTrackerService: IsPidTracked возвращает корректный результат", () =>
            {
                var tracker = new PidTrackerService(2000);
                tracker.TryAddPid(2001);

                if (!tracker.IsPidTracked(2000) || !tracker.IsPidTracked(2001))
                {
                    return new SmokeTestResult("ORCH-007", "PidTrackerService: IsPidTracked возвращает корректный результат", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали true для отслеживаемых PID");
                }

                if (tracker.IsPidTracked(9999))
                {
                    return new SmokeTestResult("ORCH-007", "PidTrackerService: IsPidTracked возвращает корректный результат", SmokeOutcome.Fail, TimeSpan.Zero,
                        "Ожидали false для неотслеживаемого PID");
                }

                return new SmokeTestResult("ORCH-007", "PidTrackerService: IsPidTracked возвращает корректный результат", SmokeOutcome.Pass, TimeSpan.Zero,
                    "OK");
            }, ct);
    }
}
