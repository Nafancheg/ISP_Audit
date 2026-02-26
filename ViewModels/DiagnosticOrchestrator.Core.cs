using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Windows;
using IspAudit;
using System.Windows.Media;
using System.Net;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;

using IspAudit.Core.RuntimeAdaptation;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Оркестратор диагностики.
    /// Координирует TrafficCollector и LiveTestingPipeline.
    /// Управляет жизненным циклом мониторинговых сервисов.
    /// </summary>
    public partial class DiagnosticOrchestrator : INotifyPropertyChanged
    {
        #region Core Methods

        /// <summary>
        /// Запуск диагностики с новой архитектурой:
        /// TrafficCollector собирает хосты → LiveTestingPipeline тестирует и применяет bypass
        /// </summary>
        public async Task RunAsync(
            string targetExePath,
            BypassController bypassController,
            TestResultsManager resultsManager,
            bool enableAutoBypass = true,
            bool isSteamMode = false)
        {
            if (IsDiagnosticRunning)
            {
                Log("[Orchestrator] Диагностика уже запущена");
                return;
            }

            try
            {
                Log($"[Orchestrator] Старт диагностики: {targetExePath}");

                // Транзакционность: новый запуск должен сбрасывать pending-cancel.
                _cancelRequested = false;

                LastRunWasUserCancelled = false;

                ResetRecommendations();

                if (!OperatingSystem.IsWindows() || !IsAdministrator())
                {
                    ShowError?.Invoke(
                        "Требуются права администратора",
                        "Для захвата трафика требуются права администратора.\n\n" +
                        "Запустите приложение от имени администратора");
                    return;
                }

                // P1.5: атомарно поднимаем рантайм-структуры, чтобы:
                // - двойной Start не запускал две диагностики;
                // - Cancel не пересекался с созданием cts/pipeline.
                using (await EnterOperationGateAsync().ConfigureAwait(false))
                {
                    if (IsDiagnosticRunning)
                    {
                        Log("[Orchestrator] Диагностика уже запущена");
                        return;
                    }

                    IsDiagnosticRunning = true;
                    DiagnosticStatus = "Инициализация...";
                    FlowEventsCount = 0;
                    ConnectionsDiscovered = 0;

                    _cts = new CancellationTokenSource();

                    // Если Cancel был нажат до создания _cts — применяем отмену сразу.
                    if (_cancelRequested)
                    {
                        _stopReason = "UserCancel";
                        LastRunWasUserCancelled = true;
                        DiagnosticStatus = "Остановка...";
                        _cts.Cancel();
                    }
                }

                // Инициализируем фильтр шумных хостов
                var noiseFilterPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "noise_hosts.json");
                _noiseHostFilter.LoadFromFile(noiseFilterPath, new Progress<string>(Log));

                // Единый фильтр трафика (singleton из DI)
                var trafficFilter = _trafficFilter;

                // Сброс DNS кеша
                Log("[Orchestrator] Сброс DNS кеша...");
                await RunFlushDnsAsync();

                // Оверлей отключён (UX: не показываем отдельное сервисное окно)
                OverlayWindow? overlay = null;

                var progress = _pipelineManager.CreateUiProgress(msg =>
                {
                    DiagnosticStatus = msg;
                    TrackIntelDiagnosisSummary(msg);
                    TrackRecommendation(msg, bypassController);
                    Log($"[Pipeline] {msg}");
                    OnPipelineMessage?.Invoke(msg);
                    UpdateOverlayStatus(overlay, msg);
                });

                // 1. Запуск мониторинговых сервисов
                await StartMonitoringServicesAsync(progress, overlay);

                // 2. Запуск целевого процесса или ожидание
                int pid = 0;

                if (isSteamMode)
                {
                    var processName = Path.GetFileNameWithoutExtension(targetExePath);
                    DiagnosticStatus = $"Ожидание запуска {processName}...";
                    Log($"[Orchestrator] Режим Steam: ожидание процесса {processName}");

                    // ВАЖНО: если приложение уже запущено, мы подключаемся "поздно".
                    // В этом случае ранние TLS ClientHello могли пройти до старта перехвата,
                    // поэтому SNI может не определиться для уже существующих соединений.
                    var alreadyRunning = System.Diagnostics.Process.GetProcessesByName(processName).FirstOrDefault();
                    if (alreadyRunning != null)
                    {
                        pid = alreadyRunning.Id;
                        var warning = $"⚠ Приложение уже запущено (Steam/attach). Ранний TLS (SNI) мог пройти до старта перехвата — колонка SNI может быть пустой для части соединений. Для полного захвата запустите диагностику ДО запуска приложения или перезапустите приложение.";
                        DiagnosticStatus = warning;
                        Log($"[Orchestrator] ⚠ Процесс уже запущен: {processName} (PID={pid}). {warning}");
                    }

                    while (!_cts.Token.IsCancellationRequested)
                    {
                        if (pid != 0) break;

                        var found = System.Diagnostics.Process.GetProcessesByName(processName).FirstOrDefault();
                        if (found != null)
                        {
                            pid = found.Id;
                            Log($"[Orchestrator] Процесс обнаружен: {processName} (PID={pid})");
                            break;
                        }
                        await Task.Delay(1000, _cts.Token);
                    }
                }
                else
                {
                    DiagnosticStatus = "Запуск целевого приложения...";
                    using var process = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = targetExePath,
                            UseShellExecute = true
                        }
                    };

                    if (!process.Start())
                    {
                        throw new Exception("Не удалось запустить процесс");
                    }
                    pid = process.Id;
                    Log($"[Orchestrator] Процесс запущен: PID={pid}");
                }

                // 3. PID Tracker
                _pidTracker = new PidTrackerService(pid, progress);
                await _pidTracker.StartAsync(_cts.Token).ConfigureAwait(false);

                // Если SNI пришёл до того, как PID-tracker успел подняться (Steam/attach),
                // пытаемся добрать из буфера по уже известным remote endpoint -> pid.
                FlushPendingSniForTrackedPids();

                // 4. Pre-resolve целей (параллельно)
                _ = resultsManager.PreResolveTargetsAsync();

                DiagnosticStatus = "Анализ трафика...";

                // 5. Telemetry/UI для auto-bypass.
                // Важно: сам пайплайн не применяет обход напрямую — оркестратор решает, делать ли auto-apply.
                ResetAutoBypassUi(enableAutoBypass);
                ResetAutoApplyState();

                // 6. Создание TrafficCollector (чистый сборщик)
                _trafficCollector = new TrafficCollector(
                    _connectionMonitor!,
                    _pidTracker!,
                    _dnsParser!,
                    trafficFilter,
                    progress);

                // 7. Создание LiveTestingPipeline (тестирование + bypass)
                var latchedRunConfig = CaptureLatchedProbeRunConfig(bypassController, maxConcurrentTests: 5);
                var pipelineConfig = BuildLatchedPipelineConfig(latchedRunConfig, enableAutoBypass: enableAutoBypass);

                var stateStore = _tcpRetransmissionTracker != null
                    ? _stateStoreFactory.CreateWithTrackers(_tcpRetransmissionTracker, _httpRedirectDetector, _rstInspectionService, _udpInspectionService)
                    : null;

                _testingPipeline = _pipelineFactory.Create(
                    pipelineConfig,
                    filter: trafficFilter,
                    progress: progress,
                    trafficEngine: _trafficEngine,
                    dnsParser: _dnsParser,
                    stateStore: stateStore,
                    autoHostlist: bypassController.AutoHostlist);

                var autoApplyEnabled = enableAutoBypass;

                // Принимаем объектный план напрямую из pipeline.
                _pipelineManager.AttachPlanBuiltListener(_testingPipeline, (hostKey, plan) =>
                {
                    StorePlan(hostKey, plan, bypassController);

                    // Auto-apply: инициируем применением плана только если флаг включён пользователем.
                    // Pipeline сам по себе обход не применяет.
                    if (autoApplyEnabled)
                    {
                        TryStartAutoApplyFromPlan(hostKey, plan, bypassController);
                    }
                });

                // Повторно флешим pending SNI — на случай, если endpoint->pid уже есть, а событий соединения больше не будет.
                FlushPendingSniForTrackedPids();
                await _pipelineManager.DrainPendingHostsAsync(_pendingSniHosts, _testingPipeline).ConfigureAwait(false);
                Log("[Orchestrator] ✓ TrafficCollector + LiveTestingPipeline созданы");

                // Подписываемся на события UDP блокировок для ретеста
                if (_udpInspectionService != null)
                {
                    _udpInspectionService.OnBlockageDetected += (ip) =>
                    {
                        // UDP/QUIC блокировки часто не означают, что HTTPS по TCP не работает.
                        // Авто-ретест по каждому событию приводит к лавине перетестов и ухудшает UX.
                        Log($"[Orchestrator] UDP Blockage detected for {ip}. (no auto-retest)");

                        // Runtime Adaptation Layer: публикуем сигнал, не принимая политических решений.
                        try
                        {
                            // Важно: orchestrator передаёт только "факты" (hostKey из кешей),
                            // не включает обход и не меняет режимы/цели.
                            var primaryTarget = bypassController.GetOutcomeTargetHost();

                            string? secondaryTarget = null;
                            try
                            {
                                secondaryTarget = TryResolveHostFromIpBestEffort(ip);
                            }
                            catch (Exception ex)
                            {
                                System.Diagnostics.Debug.WriteLine($"[Orchestrator] ResolveHostFromIp: {ex.Message}");
                            }

                            var context = new ReactiveTargetSyncContext(
                                IsQuicFallbackEnabled: bypassController.IsQuicFallbackEnabled,
                                IsQuicFallbackGlobal: bypassController.IsQuicFallbackGlobal,
                                PrimaryTargetHostKey: primaryTarget,
                                SecondaryTargetHostKey: secondaryTarget);

                            _stateManager.ReactiveTargetSync.OnUdpBlockage(ip, context);
                        }
                        catch (Exception ex)
                        {
                            // Не даём вспомогательной логике ломать диагностику.
                            System.Diagnostics.Debug.WriteLine($"[Orchestrator] ReactiveTargetSync: {ex.Message}");
                        }
                    };
                }

                // 8. Запуск сбора и тестирования параллельно
                var collectorTask = RunCollectorWithPipelineAsync(overlay, progress!);
                var silenceMonitorTask = RunSilenceMonitorAsync(overlay);
                var processMonitorTask = RunProcessMonitorAsync();

                // Ждём завершения (любой таск может завершить диагностику)
                try
                {
                    await Task.WhenAny(collectorTask, silenceMonitorTask, processMonitorTask);
                }
                catch (OperationCanceledException)
                {
                    // Игнорируем здесь, обработка ниже
                }

                // Важно: остальные задачи могли продолжить работу и/или упасть.
                // Чтобы не получать TaskScheduler.UnobservedTaskException, best-effort:
                // 1) инициируем отмену
                // 2) дожидаемся завершения всех задач
                try
                {
                    _cts.Cancel();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[Orchestrator] CTS.Cancel: {ex.Message}");
                }

                try
                {
                    await Task.WhenAll(collectorTask, silenceMonitorTask, processMonitorTask).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Нормальное завершение при отмене.
                }
                catch (Exception ex)
                {
                    // Best-effort: не валим завершение диагностики из-за фоновой задачи.
                    Log($"[Orchestrator] Ошибка фоновой задачи: {ex}");
                }

                // 9. Закрываем оверлей
                Application.Current?.Dispatcher.BeginInvoke(() => overlay?.Close());

                // 10. Обработка завершения
                if (_stopReason == "UserCancel")
                {
                    Log("[Orchestrator] Отменено пользователем");
                    DiagnosticStatus = "Диагностика отменена";
                }
                else
                {
                    // ProcessExited, SilenceTimeout или другое
                    Log($"[Orchestrator] Завершение диагностики ({_stopReason ?? "Unknown"})...");

                    // Ждём завершения всех тестов в pipeline (до 30 секунд)
                    if (_testingPipeline != null)
                    {
                        Log("[Orchestrator] Ожидание завершения тестов в pipeline...");
                        await _testingPipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                    }

                    Log($"[Orchestrator] Завершено. Соединений: {_trafficCollector?.ConnectionsCount ?? 0}");

                    // Генерация и сохранение профиля (используем CancellationToken.None, чтобы сохранить даже при отмене)
                    if (_trafficCollector != null && _trafficCollector.ConnectionsCount > 0)
                    {
                        var profile = await _trafficCollector.BuildProfileAsync(
                            Path.GetFileNameWithoutExtension(targetExePath),
                            CancellationToken.None);
                        await SaveProfileAsync(targetExePath, profile);
                    }

                    DiagnosticStatus = "Диагностика завершена";
                }
            }
            catch (OperationCanceledException)
            {
                // Этот блок может быть достигнут, если исключение возникло до Task.WhenAny
                Log("[Orchestrator] Отменено пользователем (до запуска задач)");
                DiagnosticStatus = "Диагностика отменена";
            }
            catch (Exception ex)
            {
                Log($"[Orchestrator] Ошибка: {ex.Message}");
                ShowError?.Invoke("Ошибка диагностики", $"Ошибка: {ex.Message}");
                DiagnosticStatus = $"Ошибка: {ex.Message}";
            }
            finally
            {
                _cancelRequested = false;
                // P1.5: best-effort cleanup под gate (Cancel может делать dispose параллельно).
                using (await EnterOperationGateAsync().ConfigureAwait(false))
                {
                    _testingPipeline?.Dispose();
                    _testingPipeline = null;
                    _trafficCollector?.Dispose();
                    _trafficCollector = null;
                }
                DetachAutoBypassTelemetry();
                await StopMonitoringServicesAsync();
                IsDiagnosticRunning = false;
                using (await EnterOperationGateAsync().ConfigureAwait(false))
                {
                    _cts?.Dispose();
                    _cts = null;
                }
                OnDiagnosticComplete?.Invoke();
            }
        }

        /// <summary>
        /// Повторная диагностика списка целей (для проверки эффективности bypass)
        /// </summary>
        public async Task RetestTargetsAsync(
            System.Collections.Generic.IEnumerable<IspAudit.Models.Target> targets,
            BypassController bypassController,
            string? correlationId = null)
        {
            var opId = string.IsNullOrWhiteSpace(correlationId)
                ? Guid.NewGuid().ToString("N")
                : correlationId.Trim();

            try
            {
                using var op = BypassOperationContext.Enter(opId, "retest_targets");

                // P1.5: сериализуем старт ретеста (check+set под одним gate), чтобы
                // параллельные клики не запускали две операции.
                using (await EnterOperationGateAsync().ConfigureAwait(false))
                {
                    if (IsDiagnosticRunning)
                    {
                        Log("[Orchestrator] Нельзя запустить ретест во время активной диагностики");
                        return;
                    }

                    _cancelRequested = false;
                    Log($"[Orchestrator][Retest][op={opId}] Запуск ретеста проблемных целей...");

                    IsDiagnosticRunning = true;
                    DiagnosticStatus = "Ретест...";
                    _cts = new CancellationTokenSource();
                }
                DetachAutoBypassTelemetry();
                ResetAutoBypassUi(false);

                var progress = _pipelineManager.CreateUiProgress(msg =>
                {
                    DiagnosticStatus = msg;
                    TrackIntelDiagnosisSummary(msg);
                    TrackRecommendation(msg, bypassController);
                    Log($"[Retest][op={opId}] {msg}");
                    OnPipelineMessage?.Invoke(msg);
                });

                // Создаем pipeline только для тестирования (без сниффера)
                var latchedRunConfig = CaptureLatchedProbeRunConfig(bypassController, maxConcurrentTests: 5);
                var pipelineConfig = BuildLatchedPipelineConfig(latchedRunConfig, enableAutoBypass: false); // Bypass уже настроен контроллером

                // Используем существующий bypass manager из контроллера
                _testingPipeline = _pipelineFactory.Create(
                    pipelineConfig,
                    filter: _trafficFilter,
                    progress: progress,
                    trafficEngine: _trafficEngine,
                    dnsParser: _dnsParser, // Нужен для кеша SNI/DNS имён (стабильнее подписи в UI и авто-hostlist)
                    stateStore: null,
                    autoHostlist: bypassController.AutoHostlist);

                _pipelineManager.AttachPlanBuiltListener(_testingPipeline, (hostKey, plan) =>
                {
                    StorePlan(hostKey, plan, bypassController);
                });

                // Запускаем цели в pipeline
                foreach (var target in targets)
                {
                    // Пытаемся извлечь порт из Service, если там число
                    int port = 443;
                    if (int.TryParse(target.Service, out var p)) port = p;

                    if (System.Net.IPAddress.TryParse(target.Host, out var ip))
                    {
                        var key = $"{ip}:{port}:TCP";
                        var host = new HostDiscovered(key, ip, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                        {
                            Hostname = target.Name != target.Host ? target.Name : null // Если имя отличается от IP, передаем его
                        };
                        await _testingPipeline.EnqueueHostAsync(host, IspAudit.Utils.LiveTestingPipeline.HostPriority.High).ConfigureAwait(false);
                    }
                    else
                    {
                        // Если Host - это доменное имя, нужно его разрешить
                        try
                        {
                            var ips = await System.Net.Dns.GetHostAddressesAsync(target.Host);
                            if (ips.Length > 0)
                            {
                                var ipAddr = ips[0];
                                var key = $"{ipAddr}:{port}:TCP";
                                var host = new HostDiscovered(key, ipAddr, port, IspAudit.Bypass.TransportProtocol.Tcp, DateTime.UtcNow)
                                {
                                    Hostname = target.Host // Передаем оригинальный hostname
                                };
                                await _testingPipeline.EnqueueHostAsync(host, IspAudit.Utils.LiveTestingPipeline.HostPriority.High).ConfigureAwait(false);
                            }
                        }
                        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Orchestrator] Retest DNS resolve: {ex.Message}"); }
                    }
                }

                // Ждём завершения, но уважаем Cancel.
                var pipeline = _testingPipeline;
                var cts = _cts;
                if (pipeline != null)
                {
                    var drainTask = pipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(15));
                    if (cts != null)
                    {
                        try
                        {
                            await Task.WhenAny(drainTask, Task.Delay(Timeout.InfiniteTimeSpan, cts.Token)).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (cts.IsCancellationRequested)
                        {
                        }
                    }

                    // Если отменили — best-effort: быстро гасим воркеры.
                    if (cts?.IsCancellationRequested == true)
                    {
                        try { pipeline.Dispose(); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Orchestrator] Pipeline dispose: {ex.Message}"); }
                    }

                    // Дожидаемся drain (может уже завершиться после dispose).
                    try { await drainTask.ConfigureAwait(false); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Orchestrator] DrainTask: {ex.Message}"); }
                }

                Log($"[Orchestrator][Retest][op={opId}] Ретест завершен");
                DiagnosticStatus = "Ретест завершен";
            }
            catch (Exception ex)
            {
                Log($"[Orchestrator][Retest][op={opId}] Ошибка ретеста: {ex.Message}");
            }
            finally
            {
                _cancelRequested = false;
                using (await EnterOperationGateAsync().ConfigureAwait(false))
                {
                    _testingPipeline?.Dispose();
                    _testingPipeline = null;
                    IsDiagnosticRunning = false;
                    _cts?.Dispose();
                    _cts = null;
                }
                OnDiagnosticComplete?.Invoke();
            }
        }

        /// <summary>
        /// Сбор трафика и передача хостов в pipeline
        /// </summary>
        private async Task RunCollectorWithPipelineAsync(OverlayWindow? overlay, IProgress<string> progress)
        {
            if (_trafficCollector == null || _testingPipeline == null || _cts == null) return;

            try
            {
                // Если включен таймаут тишины, то ставим и глобальный лимит 10 минут.
                // Если "Без лимита времени", то глобальный лимит тоже отключаем (null).
                var captureTimeout = EnableSilenceTimeout ? TimeSpan.FromMinutes(10) : (TimeSpan?)null;

                await foreach (var host in _trafficCollector.CollectAsync(
                    captureTimeout,
                    _cts.Token).ConfigureAwait(false))
                {
                    // Обновляем UI счётчик
                    Application.Current?.Dispatcher.BeginInvoke(() =>
                    {
                        ConnectionsDiscovered = _trafficCollector.ConnectionsCount;
                        overlay?.UpdateStats(ConnectionsDiscovered, FlowEventsCount);
                    });

                    // Отправляем в pipeline на тестирование
                    await _testingPipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
        }

        /// <summary>
        /// Мониторинг тишины (отсутствие новых соединений)
        /// </summary>
        private async Task RunSilenceMonitorAsync(OverlayWindow? overlay)
        {
            if (_trafficCollector == null || _connectionMonitor == null || _cts == null) return;

            bool silenceWarningShown = false;

            try
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(1000, _cts.Token).ConfigureAwait(false);

                    // Проверяем время с момента запуска мониторинга (warmup)
                    var totalElapsed = _connectionMonitor.MonitorStartedUtc.HasValue
                        ? (DateTime.UtcNow - _connectionMonitor.MonitorStartedUtc.Value).TotalSeconds
                        : 0;

                    if (totalElapsed < WarmupSeconds || silenceWarningShown)
                        continue;

                    var silenceDuration = (DateTime.UtcNow - _trafficCollector.LastNewConnectionTime).TotalSeconds;

                    if (EnableSilenceTimeout && silenceDuration > SilenceTimeoutSeconds && overlay != null)
                    {
                        silenceWarningShown = true;
                        Log($"[Silence] Нет новых соединений более {SilenceTimeoutSeconds}с");

                        // Показываем запрос пользователю
                        bool extend;
                        try
                        {
                            var app = Application.Current;
                            if (app?.Dispatcher == null)
                            {
                                // Бывает при shutdown/тестовом контексте без UI.
                                Log("[Silence] Application.Current == null, пропускаю prompt");
                                break;
                            }

                            // Invoke: нужен результат (bool), поэтому оставляем синхронное выполнение на UI.
                            extend = await app.Dispatcher.Invoke(async () =>
                                await overlay.ShowSilencePromptAsync(SilenceTimeoutSeconds)).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            // Overlay мог быть закрыт/разрушен, или UI-поток в процессе завершения.
                            Log($"[Silence] Ошибка показа prompt: {ex.Message}");
                            break;
                        }

                        if (extend)
                        {
                            Log("[Silence] Пользователь продлил диагностику");
                            silenceWarningShown = false;
                            // Сбрасываем время последнего соединения на текущее
                            _trafficCollector.ResetSilenceTimer();
                        }
                        else
                        {
                            Log("[Silence] Авто-завершение диагностики");
                            _stopReason = "SilenceTimeout";
                            _cts.Cancel();
                            break;
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
        }

        /// <summary>
        /// Мониторинг жизни целевых процессов
        /// </summary>
        private async Task RunProcessMonitorAsync()
        {
            if (_pidTracker == null || _cts == null) return;

            try
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(2000, _cts.Token).ConfigureAwait(false);

                    bool anyAlive = false;
                    foreach (var pid in _pidTracker.TrackedPids.ToArray())
                    {
                        try
                        {
                            using var proc = System.Diagnostics.Process.GetProcessById(pid);
                            if (!proc.HasExited)
                            {
                                anyAlive = true;
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[Orchestrator] ProcessMonitor GetProcessById({pid}): {ex.Message}");
                        }
                    }

                    if (!anyAlive && _pidTracker.TrackedPids.Count > 0)
                    {
                        Log("[Orchestrator] Все отслеживаемые процессы завершились");
                        _stopReason = "ProcessExited";

                        // Закрываем входящий поток данных (это разблокирует collectorTask)
                        // DrainAndCompleteAsync будет вызван в основном потоке после WhenAny
                        _trafficCollector?.StopCollecting();

                        // НЕ отменяем и НЕ ждём здесь — основной поток сам вызовет DrainAndCompleteAsync
                        break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Нормальное завершение
            }
        }

        private string? TryResolveHostFromIpBestEffort(IPAddress ip)
        {
            try
            {
                var ipKey = ip.ToString();
                if (_dnsParser == null) return null;

                if (_dnsParser.SniCache.TryGetValue(ipKey, out var resolvedHost)
                    && !string.IsNullOrWhiteSpace(resolvedHost))
                {
                    return resolvedHost;
                }

                if (_dnsParser.DnsCache.TryGetValue(ipKey, out resolvedHost)
                    && !string.IsNullOrWhiteSpace(resolvedHost))
                {
                    return resolvedHost;
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Отмена диагностики
        /// </summary>
        public void Cancel()
        {
            var cancelledAnything = false;

            // Всегда фиксируем запрос отмены (важно для раннего окна старта).
            _cancelRequested = true;

            // Отмена ручного apply (может выполняться даже когда диагностика уже закончилась)
            if (_applyCts != null && !_applyCts.IsCancellationRequested)
            {
                Log("[Orchestrator] Отмена применения рекомендаций...");
                _applyCts.Cancel();
                cancelledAnything = true;
            }

            // Отмена диагностики
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                Log("[Orchestrator] Отмена...");
                DiagnosticStatus = "Остановка...";
                _stopReason = "UserCancel";
                LastRunWasUserCancelled = true;

                // Сначала отменяем токен — это прервёт await foreach в CollectAsync
                _cts.Cancel();

                // Потом best-effort останавливаем компоненты под gate (не блокируя UI)
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using (await EnterOperationGateAsync().ConfigureAwait(false))
                        {
                            _testingPipeline?.Dispose();
                            _testingPipeline = null;
                            _trafficCollector?.Dispose();
                            _trafficCollector = null;
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[Orchestrator] Cancel cleanup: {ex.Message}");
                    }
                });
                cancelledAnything = true;
            }
            else if (IsDiagnosticRunning)
            {
                // Раннее окно: диагностика уже помечена как запущенная, но _cts ещё не создан.
                // Не теряем отмену — RunAsync применит её сразу после создания _cts.
                Log("[Orchestrator] Отмена запрошена (ожидание инициализации)...");
                DiagnosticStatus = "Остановка...";
                _stopReason = "UserCancel";
                LastRunWasUserCancelled = true;
                cancelledAnything = true;
            }

            if (!cancelledAnything)
            {
                Log("[Orchestrator] Уже отменено или не запущено");
            }
        }

        #endregion
    }
}
