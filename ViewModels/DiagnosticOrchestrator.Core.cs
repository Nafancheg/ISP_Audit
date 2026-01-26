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
using IspAudit.Core.IntelligenceV2.Contracts;
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
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
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
                    MessageBox.Show(
                        "Для захвата трафика требуются права администратора.\n\n" +
                        "Запустите приложение от имени администратора",
                        "Требуются права администратора",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
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

                // Инициализируем фильтр шумных хостов
                var noiseFilterPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "noise_hosts.json");
                NoiseHostFilter.Initialize(noiseFilterPath, new Progress<string>(Log));

                // Создаем единый фильтр трафика (для дедупликации и фильтрации)
                var trafficFilter = new UnifiedTrafficFilter();

                // Сброс DNS кеша
                Log("[Orchestrator] Сброс DNS кеша...");
                await RunFlushDnsAsync();

                // Оверлей отключён (UX: не показываем отдельное сервисное окно)
                OverlayWindow? overlay = null;

                var progress = new Progress<string>(msg =>
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        DiagnosticStatus = msg;
                        TrackV2DiagnosisSummary(msg);
                        TrackRecommendation(msg, bypassController);
                        Log($"[Pipeline] {msg}");
                        OnPipelineMessage?.Invoke(msg);
                        UpdateOverlayStatus(overlay, msg);
                    });
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

                // 5. Преимптивный bypass (через сервис, с телеметрией в UI)
                // Важно: в текущем MVP auto-apply запрещён. Даже если флаг включён в UI,
                // мы не применяем техники автоматически.
                if (enableAutoBypass)
                {
                    Log("[Orchestrator] ⚠ Auto-bypass запрошен, но отключён политикой (auto-apply запрещён)");
                    ((IProgress<string>?)progress)?.Report("⚠ Auto-bypass отключён: авто-применение обхода запрещено");
                }

                enableAutoBypass = false;
                ResetAutoBypassUi(enableAutoBypass);

                // 6. Создание TrafficCollector (чистый сборщик)
                _trafficCollector = new TrafficCollector(
                    _connectionMonitor!,
                    _pidTracker!,
                    _dnsParser!,
                    progress,
                    trafficFilter);

                // 7. Создание LiveTestingPipeline (тестирование + bypass)
                var effectiveTestTimeout = bypassController.IsVpnDetected
                    ? TimeSpan.FromSeconds(8)
                    : TimeSpan.FromSeconds(3);

                var pipelineConfig = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = enableAutoBypass,
                    MaxConcurrentTests = 5,
                    TestTimeout = effectiveTestTimeout
                };

                _testingPipeline = new LiveTestingPipeline(
                    pipelineConfig,
                    progress,
                    _trafficEngine,
                    _dnsParser,
                    trafficFilter,
                    _tcpRetransmissionTracker != null
                        ? new InMemoryBlockageStateStore(_tcpRetransmissionTracker, _httpRedirectDetector, _rstInspectionService, _udpInspectionService)
                        : null,
                    bypassController.AutoHostlist);

                // v2: принимаем объектный план напрямую из pipeline (auto-apply запрещён).
                _testingPipeline.OnV2PlanBuilt += (hostKey, plan) =>
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        StoreV2Plan(hostKey, plan, bypassController);
                    });
                };

                // Повторно флешим pending SNI — на случай, если endpoint->pid уже есть, а событий соединения больше не будет.
                FlushPendingSniForTrackedPids();
                while (_pendingSniHosts.TryDequeue(out var sniHost))
                {
                    await _testingPipeline.EnqueueHostAsync(sniHost).ConfigureAwait(false);
                }
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
                            var context = new ReactiveTargetSyncContext(
                                IsQuicFallbackEnabled: bypassController.IsQuicFallbackEnabled,
                                IsQuicFallbackGlobal: bypassController.IsQuicFallbackGlobal,
                                CurrentOutcomeTargetHost: bypassController.GetOutcomeTargetHost(),
                                TryResolveHostFromIp: TryResolveHostFromIpBestEffort,
                                SetOutcomeTargetHost: bypassController.SetOutcomeTargetHost);

                            _reactiveTargetSync?.OnUdpBlockage(ip, context);
                        }
                        catch
                        {
                            // Не даём вспомогательной логике ломать диагностику.
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

                // 9. Закрываем оверлей
                Application.Current?.Dispatcher.Invoke(() => overlay?.Close());

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
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка диагностики",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                DiagnosticStatus = $"Ошибка: {ex.Message}";
            }
            finally
            {
                _cancelRequested = false;
                _testingPipeline?.Dispose();
                _trafficCollector?.Dispose();
                DetachAutoBypassTelemetry();
                await StopMonitoringServicesAsync();
                IsDiagnosticRunning = false;
                _cts?.Dispose();
                _cts = null;
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
            if (IsDiagnosticRunning)
            {
                Log("[Orchestrator] Нельзя запустить ретест во время активной диагностики");
                return;
            }

            var opId = string.IsNullOrWhiteSpace(correlationId)
                ? Guid.NewGuid().ToString("N")
                : correlationId.Trim();

            try
            {
                using var op = BypassOperationContext.Enter(opId, "retest_targets");
                _cancelRequested = false;
                Log($"[Orchestrator][Retest][op={opId}] Запуск ретеста проблемных целей...");
                IsDiagnosticRunning = true;
                DiagnosticStatus = "Ретест...";
                _cts = new CancellationTokenSource();
                DetachAutoBypassTelemetry();
                ResetAutoBypassUi(false);

                var progress = new Progress<string>(msg =>
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        DiagnosticStatus = msg;
                        TrackV2DiagnosisSummary(msg);
                        TrackRecommendation(msg, bypassController);
                        Log($"[Retest][op={opId}] {msg}");
                        OnPipelineMessage?.Invoke(msg);
                    });
                });

                // Создаем pipeline только для тестирования (без сниффера)
                var effectiveTestTimeout = bypassController.IsVpnDetected
                    ? TimeSpan.FromSeconds(8)
                    : TimeSpan.FromSeconds(3);

                var pipelineConfig = new PipelineConfig
                {
                    EnableLiveTesting = true,
                    EnableAutoBypass = false, // Bypass уже настроен контроллером
                    MaxConcurrentTests = 5,
                    TestTimeout = effectiveTestTimeout
                };

                // Используем существующий bypass manager из контроллера
                _testingPipeline = new LiveTestingPipeline(
                    pipelineConfig,
                    progress,
                    _trafficEngine,
                    _dnsParser, // Нужен для кеша SNI/DNS имён (стабильнее подписи в UI и авто-hostlist)
                    new UnifiedTrafficFilter(),
                    null, // State store новый
                    bypassController.AutoHostlist);

                _testingPipeline.OnV2PlanBuilt += (hostKey, plan) =>
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        StoreV2Plan(hostKey, plan, bypassController);
                    });
                };

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
                        await _testingPipeline.EnqueueHostAsync(host).ConfigureAwait(false);
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
                                await _testingPipeline.EnqueueHostAsync(host).ConfigureAwait(false);
                            }
                        }
                        catch { }
                    }
                }

                // Ждем завершения
                await _testingPipeline.DrainAndCompleteAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);

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
                _testingPipeline?.Dispose();
                _testingPipeline = null;
                IsDiagnosticRunning = false;
                _cts?.Dispose();
                _cts = null;
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
                    Application.Current?.Dispatcher.Invoke(() =>
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
                        var extend = await Application.Current!.Dispatcher.Invoke(async () =>
                            await overlay.ShowSilencePromptAsync(SilenceTimeoutSeconds));

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
                        catch { }
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

                // Потом останавливаем компоненты
                _testingPipeline?.Dispose();
                _trafficCollector?.Dispose();
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
