using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Utils;
using IspAudit.Wpf;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region Constructor

        private readonly IspAudit.Core.Traffic.TrafficEngine _trafficEngine;
        private readonly BypassStateManager _bypassState;

        private readonly NetworkChangeMonitor? _networkChangeMonitor;
        private volatile bool _pendingNetworkChangePrompt;

        private volatile bool _pendingRetestAfterRun;
        private string _pendingRetestReason = "";

        private readonly System.Collections.Generic.HashSet<string> _pendingManualRetestHostKeys = new(StringComparer.OrdinalIgnoreCase);

        // P0.1 Step 14: единый источник истины для group participation / pinning / merge состояния группы.
        private readonly GroupBypassAttachmentStore _groupBypassAttachmentStore = new();

        public MainViewModel()
        {
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log("MainViewModel: Инициализация");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Create TrafficEngine
            var progress = new Progress<string>(msg => Log(msg));
            _trafficEngine = new IspAudit.Core.Traffic.TrafficEngine(progress);

            _trafficEngine.OnPerformanceUpdate += ms =>
            {
                Application.Current?.Dispatcher.Invoke(() => TrafficEngineLatency = ms);
            };

            // Единый владелец bypass/TrafficEngine
            _bypassState = BypassStateManager.GetOrCreate(_trafficEngine, baseProfile: null, log: Log);

            // Создаём контроллеры
            Bypass = new BypassController(_bypassState);
            Orchestrator = new DiagnosticOrchestrator(_bypassState);
            Results = new TestResultsManager();

            // Подписываемся на события
            Bypass.OnLog += Log;
            Bypass.PropertyChanged += (s, e) =>
            {
                OnPropertyChanged(e.PropertyName ?? "");
                CheckAndRetestFailedTargets(e.PropertyName);
                if (e.PropertyName == nameof(Bypass.IsBypassActive))
                {
                    CheckTrafficEngineState();
                    if (!Bypass.IsBypassActive)
                    {
                        ClearAppliedBypassMarkers();
                    }
                }

                if (e.PropertyName == nameof(BypassController.OutcomeTargetHost))
                {
                    OnPropertyChanged(nameof(ActiveApplyGroupKey));
                }
            };

            Orchestrator.OnLog += Log;
            Orchestrator.OnPipelineMessage += msg =>
            {
                CurrentAction = msg;
                Results.ParsePipelineMessage(msg);
                UpdateUserMessage(msg);
            };
            Orchestrator.OnDiagnosticComplete += () =>
            {
                ScreenState = "done";
                CommandManager.InvalidateRequerySuggested();

                if (_pendingRetestAfterRun)
                {
                    _pendingRetestAfterRun = false;
                    if (!Orchestrator.LastRunWasUserCancelled)
                    {
                        _ = RunPendingRetestAfterRunAsync();
                    }
                    else
                    {
                        Log($"[AutoRetest] Skip scheduled retest after cancel (reason={_pendingRetestReason})");
                        _pendingRetestReason = "";
                    }
                }

                if (_pendingNetworkChangePrompt)
                {
                    _pendingNetworkChangePrompt = false;
                    ShowNetworkChangePrompt();
                }

                // Per-card ручные ретесты, запрошенные во время диагностики.
                if (_pendingManualRetestHostKeys.Count > 0)
                {
                    if (!Orchestrator.LastRunWasUserCancelled)
                    {
                        _ = RunPendingManualRetestsAfterRunAsync();
                    }
                    else
                    {
                        lock (_pendingManualRetestHostKeys)
                        {
                            _pendingManualRetestHostKeys.Clear();
                        }
                        Log("[PerCardRetest] Skip queued retests after user cancel");
                    }
                }
            };
            Orchestrator.PropertyChanged += (s, e) =>
            {
                OnPropertyChanged(e.PropertyName ?? "");
                if (e.PropertyName == nameof(Orchestrator.IsDiagnosticRunning))
                {
                    OnPropertyChanged(nameof(IsRunning));
                    OnPropertyChanged(nameof(StartButtonText));
                    CheckTrafficEngineState();

                    if (Orchestrator.IsDiagnosticRunning)
                    {
                        if (!IsLeftPanelPinned)
                        {
                            IsLeftPanelOpen = false;
                        }
                    }
                    else
                    {
                        // После остановки НЕ открываем панель автоматически.
                        // Состоянием панели управляет только пользователь (и флаг закрепления).
                        if (IsLeftPanelPinned)
                        {
                            IsLeftPanelOpen = true;
                        }
                    }
                }
                if (e.PropertyName == nameof(Orchestrator.HasRecommendations))
                {
                    CommandManager.InvalidateRequerySuggested();
                }

                if (e.PropertyName == nameof(Orchestrator.IsPostApplyRetestRunning)
                    || e.PropertyName == nameof(Orchestrator.PostApplyRetestStatus)
                    || e.PropertyName == nameof(Orchestrator.EndpointBlockStatus)
                    || e.PropertyName == nameof(Orchestrator.IsApplyRunning)
                    || e.PropertyName == nameof(Orchestrator.ApplyStatusText))
                {
                    OnPropertyChanged(nameof(IsPostApplyRetestRunning));
                    OnPropertyChanged(nameof(PostApplyRetestStatus));
                    OnPropertyChanged(nameof(EndpointBlockStatus));
                    OnPropertyChanged(nameof(IsApplyRunning));
                    OnPropertyChanged(nameof(ApplyStatusText));
                }
            };

            Results.OnLog += Log;
            Results.PropertyChanged += (s, e) =>
            {
                OnPropertyChanged(e.PropertyName ?? "");
                OnPropertyChanged(nameof(RunningStatusText));

                if (e.PropertyName == nameof(TestResultsManager.SuggestedDomainSuffix) ||
                    e.PropertyName == nameof(TestResultsManager.SuggestedDomainSubhostCount) ||
                    e.PropertyName == nameof(TestResultsManager.CanSuggestDomainAggregation))
                {
                    OnPropertyChanged(nameof(HasDomainSuggestion));
                    OnPropertyChanged(nameof(ApplyDomainButtonText));
                    OnPropertyChanged(nameof(DomainSuggestionHintText));
                    OnPropertyChanged(nameof(ActiveApplyGroupKey));
                    RefreshManualParticipationMarkersBestEffort();
                    CommandManager.InvalidateRequerySuggested();
                }
            };

            // Инициализация результатов
            Results.Initialize();

            // Команды
            StartLiveTestingCommand = new RelayCommand(async _ => await StartOrCancelAsync(), _ => true);
            StartCommand = StartLiveTestingCommand;
            CancelCommand = new RelayCommand(_ => Orchestrator.Cancel(), _ => IsRunning || IsApplyingRecommendations);
            SetStateCommand = new RelayCommand(state => ScreenState = state?.ToString() ?? "start");
            ReportCommand = new RelayCommand(_ => GenerateReport(), _ => IsDone);
            DetailsCommand = new RelayCommand(param => ShowDetailsDialog(param as IspAudit.Models.TestResult), _ => true);
            BrowseExeCommand = new RelayCommand(_ => BrowseExe(), _ => !IsRunning);
            ToggleThemeCommand = new RelayCommand(_ => IsDarkTheme = !IsDarkTheme);

            ToggleLeftPanelCommand = new RelayCommand(_ => IsLeftPanelOpen = !IsLeftPanelOpen, _ => true);

            // Bypass Commands
            ToggleFragmentCommand = new RelayCommand(_ => Bypass.IsFragmentEnabled = !Bypass.IsFragmentEnabled, _ => ShowBypassPanel);
            ToggleDisorderCommand = new RelayCommand(_ => Bypass.IsDisorderEnabled = !Bypass.IsDisorderEnabled, _ => ShowBypassPanel);
            ToggleFakeCommand = new RelayCommand(_ => Bypass.IsFakeEnabled = !Bypass.IsFakeEnabled, _ => ShowBypassPanel);
            ToggleDropRstCommand = new RelayCommand(_ => Bypass.IsDropRstEnabled = !Bypass.IsDropRstEnabled, _ => ShowBypassPanel);
            ToggleDoHCommand = new RelayCommand(_ => Bypass.IsDoHEnabled = !Bypass.IsDoHEnabled, _ => ShowBypassPanel);
            DisableAllBypassCommand = new RelayCommand(async _ =>
            {
                await Bypass.DisableAllAsync();
                EnableAutoBypass = false; // Также отключаем авто-включение при следующем старте
                ClearAppliedBypassMarkers();
            },
                _ => ShowBypassPanel && (IsFragmentEnabled || IsDisorderEnabled || IsFakeEnabled || IsDropRstEnabled));

            ApplyRecommendationsCommand = new RelayCommand(async _ => await ApplyRecommendationsAsync(), _ => HasRecommendations && !IsApplyingRecommendations);
            ApplyDomainRecommendationsCommand = new RelayCommand(async _ => await ApplyDomainRecommendationsAsync(), _ => HasDomainSuggestion && !IsApplyingRecommendations);

            RestartConnectionCommand = new RelayCommand(async _ => await RestartConnectionAsync(), _ => ShowBypassPanel && !IsApplyingRecommendations);

            // Применение стратегии/плана из конкретной строки результата ("карточки").
            // UX: пользователь видит стратегию рядом с целью и нажимает "Подключить" именно для неё.
            ConnectFromResultCommand = new RelayCommand(async param => await ConnectFromResultAsync(param as IspAudit.Models.TestResult),
                param => ShowBypassPanel && !IsApplyingRecommendations);

            // Доменное применение v2 плана из конкретной строки результата.
            // UX: если строка относится к SuggestedDomainSuffix, даём кнопку "Подключить домен" прямо в таблице.
            ConnectDomainFromResultCommand = new RelayCommand(async param => await ConnectDomainFromResultAsync(param as IspAudit.Models.TestResult),
                param => ShowBypassPanel && !IsApplyingRecommendations);

            RetestFromResultCommand = new RelayCommand(async param => await RetestFromResultAsync(param as IspAudit.Models.TestResult),
                _ => true);

            ReconnectFromResultCommand = new RelayCommand(async param => await ReconnectFromResultAsync(param as IspAudit.Models.TestResult),
                _ => ShowBypassPanel);

            ToggleParticipationFromResultCommand = new RelayCommand(param => ToggleParticipationFromResult(param as IspAudit.Models.TestResult),
                _ => true);

            CopySelectedResultApplyTransactionJsonCommand = new RelayCommand(_ => CopySelectedResultApplyTransactionJson(),
                _ => !string.IsNullOrWhiteSpace(SelectedResultApplyTransactionJson));

            NetworkRevalidateCommand = new RelayCommand(async _ => await RunNetworkRevalidationAsync(), _ => ShowBypassPanel && IsNetworkChangePromptVisible);
            NetworkDisableBypassCommand = new RelayCommand(async _ => await DisableBypassFromNetworkPromptAsync(), _ => ShowBypassPanel && IsNetworkChangePromptVisible);
            NetworkIgnoreCommand = new RelayCommand(_ => HideNetworkChangePrompt(), _ => IsNetworkChangePromptVisible);

            // NetworkChange monitor (P0.6): запускаем только когда есть WPF Application.
            // В smoke/console окружении Application.Current обычно null, и мы избегаем подписок на системные события.
            if (Application.Current != null)
            {
                _networkChangeMonitor = new NetworkChangeMonitor(Log);
                _networkChangeMonitor.NetworkChanged += _ =>
                {
                    try
                    {
                        Application.Current?.Dispatcher.Invoke(() => OnNetworkChanged());
                    }
                    catch
                    {
                        // ignore
                    }
                };
                _networkChangeMonitor.Start();
            }

            // Step 7/9: авто-обновление per-card статусов/деталей.
            try
            {
                Results.TestResults.CollectionChanged += (_, e) =>
                {
                    try
                    {
                        if (e == null) return;
                        if (e.Action != NotifyCollectionChangedAction.Add) return;
                        if (e.NewItems == null || e.NewItems.Count == 0) return;

                        foreach (var item in e.NewItems)
                        {
                            if (item is not IspAudit.Models.TestResult test) continue;
                            var hostKey = GetPreferredHostKey(test);
                            if (string.IsNullOrWhiteSpace(hostKey)) continue;

                            var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                            if (string.IsNullOrWhiteSpace(groupKey)) continue;

                            UpdateLastApplyTransactionTextForGroupKey(groupKey);
                            UpdateManualParticipationMarkersForGroupKey(groupKey);
                        }
                    }
                    catch
                    {
                        // ignore
                    }
                };
            }
            catch
            {
                // ignore
            }

            try
            {
                Bypass.ApplyTransactions.CollectionChanged += (_, e) =>
                {
                    try
                    {
                        if (e == null) return;
                        if (e.Action != NotifyCollectionChangedAction.Add) return;
                        if (e.NewItems == null || e.NewItems.Count == 0) return;

                        foreach (var item in e.NewItems)
                        {
                            if (item is not IspAudit.Bypass.BypassApplyTransaction tx) continue;
                            if (!string.IsNullOrWhiteSpace(tx.GroupKey))
                            {
                                UpdateLastApplyTransactionTextForGroupKey(tx.GroupKey);
                                UpdateManualParticipationMarkersForGroupKey(tx.GroupKey);
                            }
                        }

                        // Если выбранная строка относится к этой же группе — обновим панель деталей.
                        UpdateSelectedResultApplyTransactionDetails();
                    }
                    catch
                    {
                        // ignore
                    }
                };
            }
            catch
            {
                // ignore
            }

            // Автозагрузка manual participation (best-effort).
            LoadManualParticipationFromDiskBestEffort();

            Log("✓ MainViewModel инициализирован");
        }

        private void PersistManualParticipationBestEffort()
        {
            _ = Task.Run(() =>
            {
                try
                {
                    _groupBypassAttachmentStore.PersistToDiskBestEffort();
                }
                catch
                {
                    // ignore
                }
            });
        }

        private void LoadManualParticipationFromDiskBestEffort()
        {
            _ = Task.Run(() =>
            {
                try
                {
                    _groupBypassAttachmentStore.LoadFromDiskBestEffort();

                    // Обновим UI best-effort.
                    try
                    {
                        foreach (var r in Results.TestResults)
                        {
                            var hostKey = GetPreferredHostKey(r);
                            if (string.IsNullOrWhiteSpace(hostKey)) continue;
                            var groupKey = GetStableApplyGroupKeyForHostKey(hostKey);
                            if (string.IsNullOrWhiteSpace(groupKey)) continue;
                            UpdateManualParticipationMarkersForGroupKey(groupKey);
                        }
                    }
                    catch
                    {
                        // ignore
                    }
                }
                catch
                {
                    // ignore
                }
            });
        }

        public async Task InitializeAsync()
        {
            // Инициализация bypass при старте
            await Bypass.InitializeOnStartupAsync();
        }

        public async Task ShutdownAsync()
        {
            // 1) Останавливаем диагностику/применение рекомендаций, если они идут.
            try
            {
                Orchestrator.Cancel();
            }
            catch
            {
                // ignore
            }

            // 2) Отключаем bypass (WinDivert/фильтры) и восстанавливаем DNS, если мы его меняли.
            try
            {
                if (ShowBypassPanel)
                {
                    await Bypass.DisableAllAsync().ConfigureAwait(false);

                    // Критично: если DoH/DNS фикс включался через FixService, после выхода нужно вернуть исходные DNS.
                    // Иначе пользователь может остаться на DNS провайдера, который у него не работает.
                    if (FixService.HasBackupFile)
                    {
                        await Bypass.RestoreDoHAsync().ConfigureAwait(false);
                    }
                }
            }
            catch
            {
                // ignore
            }

            // 3) Отмечаем корректное завершение сессии bypass.
            try
            {
                _bypassState.MarkCleanShutdown();
                Log("[Bypass][Watchdog] Clean shutdown отмечен");
            }
            catch
            {
                // ignore
            }

            // 4) Чистим монитор смены сети.
            try
            {
                _networkChangeMonitor?.Dispose();
            }
            catch
            {
                // ignore
            }
        }

        public void OnAppExit()
        {
            try
            {
                _bypassState.MarkCleanShutdown();
                Log("[Bypass][Watchdog] Clean shutdown отмечен");
            }
            catch
            {
                // ignore
            }

            try
            {
                _networkChangeMonitor?.Dispose();
            }
            catch
            {
                // ignore
            }
        }

        private void OnNetworkChanged()
        {
            Log("[P0.6][NET] Событие смены сети");

            // UX: если обход не включён (нет опций) — уведомление не нужно.
            var snapshot = _bypassState.GetOptionsSnapshot();
            if (!snapshot.IsAnyEnabled())
            {
                Log("[P0.6][NET] Skip: bypass options not enabled");
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[P0.6][NET] Skip: bypass panel hidden (no admin rights)");
                return;
            }

            // Если сейчас идёт диагностика — откладываем UX до завершения.
            if (IsRunning || IsApplyingRecommendations)
            {
                _pendingNetworkChangePrompt = true;
                Log("[P0.6][NET] Defer prompt: diagnostic/apply in progress");
                return;
            }

            ShowNetworkChangePrompt();
        }

        private void ShowNetworkChangePrompt()
        {
            IsNetworkChangePromptVisible = true;
            NetworkChangePromptText =
                "Обнаружена смена сети.\n" +
                "Рекомендуется перепроверить состояние обхода.\n" +
                "Действия: «Проверить», «Отключить», «Игнорировать».";
        }

        private void HideNetworkChangePrompt()
        {
            try
            {
                _networkRevalidateCts?.Cancel();
                _networkRevalidateCts?.Dispose();
            }
            catch
            {
                // ignore
            }
            finally
            {
                _networkRevalidateCts = null;
            }

            IsNetworkChangePromptVisible = false;
        }

        private async Task DisableBypassFromNetworkPromptAsync()
        {
            try
            {
                await Bypass.DisableAllAsync();
                EnableAutoBypass = false;

                NetworkChangePromptText =
                    "Bypass отключён.\n" +
                    "Если проблема осталась — запустите полную диагностику.";
            }
            catch (Exception ex)
            {
                NetworkChangePromptText = $"Ошибка отключения bypass: {ex.Message}";
            }
        }

        private async Task RunNetworkRevalidationAsync()
        {
            if (_isNetworkRevalidating)
            {
                return;
            }

            _isNetworkRevalidating = true;
            try
            {
                _networkRevalidateCts?.Cancel();
                _networkRevalidateCts?.Dispose();
                _networkRevalidateCts = new CancellationTokenSource();
                var ct = _networkRevalidateCts.Token;

                NetworkChangePromptText = "Проверяю состояние обхода…";

                // Stage 1: health/activation (быстро)
                var activation = _bypassState.GetActivationStatusSnapshot();
                Log($"[P0.6][STAGE1] ACT={activation.Text}; {activation.Details}");

                // Stage 2: outcome check (активный probe)
                var host = _bypassState.GetOutcomeTargetHost();
                if (string.IsNullOrWhiteSpace(host))
                {
                    Log("[P0.6][STAGE2] OUT=UNKNOWN: no target host");
                }

                var outcome = await _bypassState.RunOutcomeProbeNowAsync(cancellationToken: ct);
                Log($"[P0.6][STAGE2] OUT={outcome.Text}; {outcome.Details}");

                // Stage 3: предложение запустить полную диагностику
                NetworkChangePromptText =
                    "Проверка завершена.\n" +
                    $"Stage 1: ACT: {activation.Text}.\n" +
                    $"Stage 2: OUT: {outcome.Text}.\n" +
                    "Stage 3: если проблема осталась — нажмите «Начать диагностику» для полного прогона.";
            }
            catch (OperationCanceledException)
            {
                NetworkChangePromptText = "Проверка отменена.";
            }
            catch (Exception ex)
            {
                NetworkChangePromptText = $"Ошибка проверки: {ex.Message}";
            }
            finally
            {
                _isNetworkRevalidating = false;
            }
        }

        #endregion
    }
}
