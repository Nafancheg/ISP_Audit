using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Bypass;
using IspAudit.Utils;
using IspAudit.Wpf;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        public sealed class ApplyTransactionRow
        {
            public ApplyTransactionRow(string dedupKey, int repeatCount, BypassApplyTransaction latest, IReadOnlyList<BypassApplyTransaction> transactions)
            {
                DedupKey = dedupKey ?? string.Empty;
                RepeatCount = repeatCount <= 0 ? 1 : repeatCount;
                Latest = latest;
                Transactions = transactions ?? Array.Empty<BypassApplyTransaction>();
            }

            public string DedupKey { get; }

            public int RepeatCount { get; }

            public string RepeatCountText => RepeatCount <= 1 ? string.Empty : $"×{RepeatCount}";

            public BypassApplyTransaction Latest { get; }

            /// <summary>
            /// Полный список транзакций для этой агрегированной строки (в пределах текущего буфера/персиста).
            /// Новые обычно идут первыми.
            /// </summary>
            public IReadOnlyList<BypassApplyTransaction> Transactions { get; }

            // Проксируем поля для DataGrid (совместимость с существующими биндингами).
            public string CreatedAtUtc => Latest.CreatedAtUtc;
            public string InitiatorHostKey => Latest.InitiatorHostKey;
            public string GroupKey => Latest.GroupKey;
            public IReadOnlyList<string> CandidateIpEndpoints => Latest.CandidateIpEndpoints;
            public string AppliedStrategyText => Latest.AppliedStrategyText;
            public string PlanText => Latest.PlanText;
            public string ActivationStatusText => Latest.ActivationStatusText;
        }

        private const int ApplyTransactionsCapacity = 50;
        private const int ApplyTransactionsPersistCount = 10;
        private const int ApplyTransactionsPersistMaxBytes = 2 * 1024 * 1024;

        private readonly BypassApplyTransactionJournal _applyTransactionsJournal = new(ApplyTransactionsCapacity);

        private string _applyTransactionsExportStatusText = string.Empty;
        private ApplyTransactionRow? _selectedApplyTransaction;
        private string _selectedApplyTransactionJson = string.Empty;

        public ICommand ExportSelectedApplyTransactionCommand { get; private set; } = null!;
        public ICommand ClearApplyTransactionsCommand { get; private set; } = null!;

        public ObservableCollection<ApplyTransactionRow> ApplyTransactions { get; } = new();

        public BypassApplyTransaction? TryGetLatestApplyTransactionForGroupKey(string? groupKey)
        {
            try
            {
                var key = (groupKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(key)) return null;

                // Важно: ObservableCollection может быть не отсортирована (например при загрузке с диска),
                // а также может не обновиться (если UiInvoke попал в неготовый Dispatcher в smoke/strict).
                // Поэтому выбираем «последнюю» транзакцию устойчиво: объединяем кандидатов из UI и журнала
                // и берём максимальный CreatedAtUtc.
                var candidates = new List<BypassApplyTransaction>();

                try
                {
                    candidates.AddRange(ApplyTransactions
                        .Select(r => r.Latest)
                        .Where(t => string.Equals((t.GroupKey ?? string.Empty).Trim().Trim('.'), key, StringComparison.OrdinalIgnoreCase)));
                }
                catch
                {
                    // ignore
                }

                try
                {
                    candidates.AddRange(_applyTransactionsJournal.Snapshot().Where(t =>
                        string.Equals((t.GroupKey ?? string.Empty).Trim().Trim('.'), key, StringComparison.OrdinalIgnoreCase)));
                }
                catch
                {
                    // ignore
                }

                return candidates
                    .OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc))
                    .FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        public string GetApplyTransactionJson(BypassApplyTransaction? tx)
        {
            if (tx == null) return string.Empty;
            return BuildApplyTransactionJson(tx);
        }

        public string TryGetLatestApplyTransactionJsonForGroupKey(string? groupKey)
        {
            try
            {
                var tx = TryGetLatestApplyTransactionForGroupKey(groupKey);
                return tx == null ? string.Empty : BuildApplyTransactionJson(tx);
            }
            catch
            {
                return string.Empty;
            }
        }

        public string ApplyTransactionsExportStatusText
        {
            get => _applyTransactionsExportStatusText;
            private set
            {
                if (_applyTransactionsExportStatusText == value) return;
                _applyTransactionsExportStatusText = value;
                OnPropertyChanged(nameof(ApplyTransactionsExportStatusText));
            }
        }

        public ApplyTransactionRow? SelectedApplyTransaction
        {
            get => _selectedApplyTransaction;
            set
            {
                if (ReferenceEquals(_selectedApplyTransaction, value)) return;
                _selectedApplyTransaction = value;
                OnPropertyChanged(nameof(SelectedApplyTransaction));

                SelectedApplyTransactionJson = value == null ? string.Empty : BuildApplyTransactionRowJson(value);
            }
        }

        public string SelectedApplyTransactionJson
        {
            get => _selectedApplyTransactionJson;
            private set
            {
                if (_selectedApplyTransactionJson == value) return;
                _selectedApplyTransactionJson = value;
                OnPropertyChanged(nameof(SelectedApplyTransactionJson));
            }
        }

        private void InitApplyTransactionsCommands()
        {
            ExportSelectedApplyTransactionCommand = new RelayCommand(_ =>
            {
                ExportSelectedApplyTransaction();
            }, _ => true);

            ClearApplyTransactionsCommand = new RelayCommand(_ =>
            {
                _applyTransactionsJournal.Clear();
                UiInvoke(() =>
                {
                    ApplyTransactions.Clear();
                    SelectedApplyTransaction = null;
                    ApplyTransactionsExportStatusText = "";
                });

                TryDeleteApplyTransactionsPersistedFile();
            }, _ => true);

            // Автозагрузка сохранённых транзакций (best-effort).
            LoadApplyTransactionsFromDiskBestEffort();
        }

        public void RecordApplyTransaction(
            string initiatorHostKey,
            string groupKey,
            System.Collections.Generic.IReadOnlyList<string>? candidateIpEndpoints,
            string appliedStrategyText,
            string planText,
            string? reasoning,
            string? transactionIdOverride = null,
            string? resultStatus = null,
            string? error = null,
            string? rollbackStatus = null,
            string? cancelReason = null,
            string? applyCurrentPhase = null,
            long? applyTotalElapsedMs = null,
            IReadOnlyList<BypassApplyPhaseTiming>? applyPhases = null)
        {
            try
            {
                var activation = _stateManager.GetActivationStatusSnapshot();
                var outcome = _stateManager.GetOutcomeStatusSnapshot();
                var optionsSnapshot = _stateManager.GetOptionsSnapshot();
                var udp443TargetCount = _stateManager.GetUdp443DropTargetIpCountSnapshot();
                BypassStateManager.ActiveTargetPolicy[] activeTargetPolicies = Array.Empty<BypassStateManager.ActiveTargetPolicy>();
                try
                {
                    // internal API (P0.1 Step 1): фиксируем «активные цели» как часть snapshot.
                    activeTargetPolicies = _stateManager.GetActiveTargetPoliciesSnapshot(initiatorHostKey);
                }
                catch
                {
                    activeTargetPolicies = Array.Empty<BypassStateManager.ActiveTargetPolicy>();
                }

                var candidateIps = candidateIpEndpoints?.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
                    ?? Array.Empty<string>();

                // P0.2 Stage 5.4 (интеграция с P0.1): используем candidate endpoints как seed
                // для observed IPv4 целей. Это помогает policy-driven per-target веткам работать сразу.
                try
                {
                    _stateManager.SeedObservedIpv4TargetsFromCandidateEndpointsBestEffort(initiatorHostKey ?? string.Empty, candidateIps);
                }
                catch
                {
                    // best-effort
                }

                // Практическая стабилизация: сохраняем candidate endpoints в ActiveTargetPolicy,
                // чтобы per-target политики могли компилироваться без DNS в последующих apply.
                try
                {
                    _stateManager.UpdateActiveTargetCandidateEndpointsBestEffort(initiatorHostKey ?? string.Empty, candidateIps);
                }
                catch
                {
                    // best-effort
                }

                var expected = BuildExpectedEffects(planText ?? string.Empty, candidateIps);
                var warnings = BuildWarnings(planText ?? string.Empty, candidateIps, activation.Text, ActivePolicies.Count);

                var safeInitiator = initiatorHostKey ?? string.Empty;
                var safeGroup = groupKey ?? string.Empty;
                var safePlanText = planText ?? string.Empty;
                var safeReasoning = reasoning ?? string.Empty;

                var request = new BypassApplyRequest
                {
                    InitiatorHostKey = safeInitiator,
                    GroupKey = safeGroup,
                    CandidateIpEndpoints = candidateIps,
                    PlanText = safePlanText,
                    Reasoning = safeReasoning
                };

                var snapshot = new BypassApplySnapshot
                {
                    ActivationStatusText = activation.Text,
                    ActivationStatusDetails = activation.Details,
                    OptionsSnapshot = optionsSnapshot,
                    DoHEnabled = _isDoHEnabled,
                    SelectedDnsPreset = SelectedDnsPreset,
                    Udp443DropTargetIpCount = udp443TargetCount,
                    ActiveTargetPolicies = activeTargetPolicies,
                    ActivePolicies = ActivePolicies.ToList(),
                    PolicySnapshotJson = _lastPolicySnapshotJson
                };

                var result = new BypassApplyResult
                {
                    Status = string.IsNullOrWhiteSpace(resultStatus) ? "RECORDED" : resultStatus.Trim(),
                    Error = string.IsNullOrWhiteSpace(error) ? string.Empty : error.Trim(),
                    RollbackStatus = string.IsNullOrWhiteSpace(rollbackStatus) ? string.Empty : rollbackStatus.Trim(),
                    CancelReason = string.IsNullOrWhiteSpace(cancelReason) ? string.Empty : cancelReason.Trim(),
                    ApplyCurrentPhase = string.IsNullOrWhiteSpace(applyCurrentPhase) ? string.Empty : applyCurrentPhase.Trim(),
                    ApplyTotalElapsedMs = applyTotalElapsedMs.GetValueOrDefault(0),
                    ApplyPhases = applyPhases ?? Array.Empty<BypassApplyPhaseTiming>(),
                    AppliedStrategyText = appliedStrategyText ?? string.Empty,
                    PlanText = safePlanText,
                    Reasoning = safeReasoning,
                    OutcomeTargetHost = _stateManager.GetOutcomeTargetHost(),
                    OutcomeStatus = outcome
                };

                var contributions = BuildContributions(safePlanText, safeInitiator, activeTargetPolicies, optionsSnapshot, _isDoHEnabled);

                var tx = new BypassApplyTransaction
                {
                    Version = "intel",

                    TransactionId = string.IsNullOrWhiteSpace(transactionIdOverride)
                        ? Guid.NewGuid().ToString("N")
                        : transactionIdOverride.Trim(),

                    InitiatorHostKey = safeInitiator,
                    GroupKey = safeGroup,
                    CandidateIpEndpoints = candidateIps,
                    ExpectedEffects = expected,
                    Warnings = warnings,
                    AppliedStrategyText = appliedStrategyText ?? string.Empty,
                    PlanText = safePlanText,
                    Reasoning = safeReasoning,
                    ActivationStatusText = activation.Text,
                    ActivationStatusDetails = activation.Details,
                    ActivePolicies = ActivePolicies.ToList(),
                    PolicySnapshotJson = _lastPolicySnapshotJson,

                    Request = request,
                    Snapshot = snapshot,
                    Result = result,
                    Contributions = contributions
                };

                _applyTransactionsJournal.Add(tx);

                UiInvoke(() =>
                {
                    RebuildApplyTransactionsUiFromJournal();
                });

                Log($"[P0.1][APPLY_TX] tx={tx.TransactionId}; host={tx.InitiatorHostKey}; group={tx.GroupKey}; ip={tx.CandidateIpEndpoints.Count}; applied={tx.AppliedStrategyText}; act={tx.ActivationStatusText}");

                PersistApplyTransactionsBestEffort();
            }
            catch (Exception ex)
            {
                Log($"[P0.1][APPLY_TX] Ошибка записи транзакции: {ex.Message}");
            }
        }

        private sealed record ApplyTransactionAggregateInfo
        {
            public string DedupKey { get; init; } = string.Empty;
            public string GroupKey { get; init; } = string.Empty;
            public string PlanText { get; init; } = string.Empty;
            public int RepeatCount { get; init; }
            public string LatestTransactionId { get; init; } = string.Empty;
            public string LatestCreatedAtUtc { get; init; } = string.Empty;
        }

        private sealed record ApplyTransactionsPersistedStateV2
        {
            public string Version { get; init; } = "v2";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();
            public IReadOnlyList<BypassApplyTransaction> Transactions { get; init; } = Array.Empty<BypassApplyTransaction>();
            public IReadOnlyList<ApplyTransactionAggregateInfo> Aggregates { get; init; } = Array.Empty<ApplyTransactionAggregateInfo>();
        }

        private sealed record ApplyTransactionsPersistedStateV1
        {
            public string Version { get; init; } = "v1";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();
            public IReadOnlyList<BypassApplyTransaction> Transactions { get; init; } = Array.Empty<BypassApplyTransaction>();
        }

        private static string GetApplyTransactionsPersistPath()
        {
            var overridePath = EnvVar.GetTrimmedNonEmpty(EnvKeys.ApplyTransactionsPath);
            if (!string.IsNullOrWhiteSpace(overridePath))
            {
                return overridePath;
            }

            return AppPaths.GetStateFilePath("apply_transactions.json");
        }

        private void PersistApplyTransactionsBestEffort()
        {
            _ = Task.Run(() =>
            {
                try
                {
                    var path = GetApplyTransactionsPersistPath();
                    var dir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrWhiteSpace(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    // Берём последние K транзакций из журнала (raw), а агрегаты восстанавливаем детерминированно.
                    var list = _applyTransactionsJournal.Snapshot().Take(ApplyTransactionsPersistCount).ToList();

                    var aggregates = BuildAggregateInfos(list);

                    var payload = new ApplyTransactionsPersistedStateV2
                    {
                        Transactions = list,
                        Aggregates = aggregates
                    };

                    var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

                    if (json.Length > ApplyTransactionsPersistMaxBytes)
                    {
                        // Не пишем слишком большие файлы (best-effort защита от раздувания snapshot-ов).
                        return;
                    }

                    File.WriteAllText(path, json, System.Text.Encoding.UTF8);
                }
                catch
                {
                    // ignore
                }
            });
        }

        private void TryDeleteApplyTransactionsPersistedFile()
        {
            try
            {
                var path = GetApplyTransactionsPersistPath();
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // ignore
            }
        }

        private void LoadApplyTransactionsFromDiskBestEffort()
        {
            _ = Task.Run(() =>
            {
                try
                {
                    var path = GetApplyTransactionsPersistPath();
                    if (!File.Exists(path)) return;

                    var json = File.ReadAllText(path);
                    if (string.IsNullOrWhiteSpace(json)) return;
                    if (json.Length > ApplyTransactionsPersistMaxBytes) return;

                    IReadOnlyList<BypassApplyTransaction>? list = null;

                    // v2 (dedup metadata + raw)
                    try
                    {
                        var state2 = JsonSerializer.Deserialize<ApplyTransactionsPersistedStateV2>(json);
                        if (state2?.Transactions != null && state2.Transactions.Count > 0)
                        {
                            list = state2.Transactions;
                        }
                    }
                    catch
                    {
                        // ignore
                    }

                    // v1 (raw only)
                    if (list == null)
                    {
                        var state1 = JsonSerializer.Deserialize<ApplyTransactionsPersistedStateV1>(json);
                        list = state1?.Transactions;
                    }

                    if (list == null || list.Count == 0) return;

                    // Стабильно сортируем: новые сверху. CreatedAtUtc у нас строкой в формате "u".
                    var ordered = list
                        .OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc))
                        .Take(ApplyTransactionsCapacity)
                        .ToList();

                    UiInvoke(() =>
                    {
                        try
                        {
                            ApplyTransactions.Clear();
                            _applyTransactionsJournal.Clear();

                            foreach (var tx in ordered)
                            {
                                _applyTransactionsJournal.Add(tx);
                            }

                            RebuildApplyTransactionsUiFromJournal();

                            if (SelectedApplyTransaction == null)
                            {
                                SelectedApplyTransaction = ApplyTransactions.FirstOrDefault();
                            }
                        }
                        catch
                        {
                            // ignore
                        }
                    });
                }
                catch
                {
                    // ignore
                }
            });
        }

        private void RebuildApplyTransactionsUiFromJournal()
        {
            try
            {
                var raw = _applyTransactionsJournal.Snapshot();
                if (raw.Count == 0)
                {
                    ApplyTransactions.Clear();
                    SelectedApplyTransaction = null;
                    return;
                }

                var groups = raw
                    .GroupBy(t => BuildApplyDedupKey(t.GroupKey, t.PlanText), StringComparer.OrdinalIgnoreCase)
                    .Select(g =>
                    {
                        var ordered = g.OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc)).ToList();
                        var latest = ordered.First();
                        return new ApplyTransactionRow(g.Key, ordered.Count, latest, ordered);
                    })
                    .OrderByDescending(r => ParseCreatedAtUtcOrMin(r.CreatedAtUtc))
                    .Take(ApplyTransactionsCapacity)
                    .ToList();

                var previouslySelectedKey = SelectedApplyTransaction?.DedupKey;

                ApplyTransactions.Clear();
                foreach (var row in groups)
                {
                    ApplyTransactions.Add(row);
                }

                if (!string.IsNullOrWhiteSpace(previouslySelectedKey))
                {
                    SelectedApplyTransaction = ApplyTransactions.FirstOrDefault(r =>
                        string.Equals(r.DedupKey, previouslySelectedKey, StringComparison.OrdinalIgnoreCase))
                        ?? ApplyTransactions.FirstOrDefault();
                }
                else
                {
                    SelectedApplyTransaction = SelectedApplyTransaction ?? ApplyTransactions.FirstOrDefault();
                }
            }
            catch
            {
                // ignore
            }
        }

        private static string BuildApplyDedupKey(string? groupKey, string? planText)
        {
            var g = (groupKey ?? string.Empty).Trim().Trim('.');
            var p = (planText ?? string.Empty).Trim();

            // План может быть длинным, но это лучший детерминированный ключ для дедупликации.
            // Нормализуем регистр и whitespace для устойчивости.
            g = g.ToLowerInvariant();
            p = string.Join(' ', p.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)).ToLowerInvariant();

            return $"{g}||{p}";
        }

        private static IReadOnlyList<ApplyTransactionAggregateInfo> BuildAggregateInfos(IReadOnlyList<BypassApplyTransaction> raw)
        {
            try
            {
                return raw
                    .GroupBy(t => BuildApplyDedupKey(t.GroupKey, t.PlanText), StringComparer.OrdinalIgnoreCase)
                    .Select(g =>
                    {
                        var ordered = g.OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc)).ToList();
                        var latest = ordered.First();
                        return new ApplyTransactionAggregateInfo
                        {
                            DedupKey = g.Key,
                            GroupKey = latest.GroupKey,
                            PlanText = latest.PlanText,
                            RepeatCount = ordered.Count,
                            LatestTransactionId = latest.TransactionId,
                            LatestCreatedAtUtc = latest.CreatedAtUtc
                        };
                    })
                    .OrderByDescending(a => ParseCreatedAtUtcOrMin(a.LatestCreatedAtUtc))
                    .ToList();
            }
            catch
            {
                return Array.Empty<ApplyTransactionAggregateInfo>();
            }
        }

        private static void UiInvoke(Action action)
        {
            try
            {
                var dispatcher = Application.Current?.Dispatcher;
                if (dispatcher == null)
                {
                    action();
                    return;
                }

                if (dispatcher.CheckAccess())
                {
                    action();
                }
                else
                {
                    dispatcher.Invoke(action);
                }
            }
            catch
            {
                // ignore
            }
        }

        private static DateTimeOffset ParseCreatedAtUtcOrMin(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return DateTimeOffset.MinValue;
            return DateTimeOffset.TryParse(value, out var dt) ? dt : DateTimeOffset.MinValue;
        }

        private void ExportSelectedApplyTransaction()
        {
            try
            {
                var tx = SelectedApplyTransaction ?? ApplyTransactions.FirstOrDefault();
                if (tx == null)
                {
                    ApplyTransactionsExportStatusText = "Экспорт: нет транзакций";
                    return;
                }

                var json = BuildApplyTransactionRowJson(tx);
                if (string.IsNullOrWhiteSpace(json))
                {
                    ApplyTransactionsExportStatusText = "Экспорт: JSON пуст";
                    return;
                }

                var artifactsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "artifacts");
                Directory.CreateDirectory(artifactsDir);

                var shortId = tx.Latest.TransactionId.Length >= 8 ? tx.Latest.TransactionId.Substring(0, 8) : tx.Latest.TransactionId;
                var filename = $"apply_transaction_{DateTime.Now:yyyyMMdd_HHmmss}_{shortId}.json";
                var path = Path.Combine(artifactsDir, filename);

                File.WriteAllText(path, json, System.Text.Encoding.UTF8);

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    try
                    {
                        System.Windows.Clipboard.SetText(json);
                    }
                    catch
                    {
                        // ignore
                    }
                });

                ApplyTransactionsExportStatusText = $"Экспорт: сохранено {filename} (и скопировано в буфер)";
                try
                {
                    System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
                }
                catch
                {
                }
            }
            catch (Exception ex)
            {
                ApplyTransactionsExportStatusText = $"Экспорт: ошибка ({ex.Message})";
            }
        }

        private static string BuildApplyTransactionRowJson(ApplyTransactionRow row)
        {
            try
            {
                var jsonOpts = new JsonSerializerOptions { WriteIndented = true };

                var root = new JsonObject
                {
                    ["dedup"] = new JsonObject
                    {
                        ["dedupKey"] = row.DedupKey,
                        ["repeatCount"] = row.RepeatCount,
                        ["repeatCountText"] = row.RepeatCountText
                    }
                };

                // Полный JSON последней транзакции как основная секция (чтобы не ломать привычные ожидания).
                var latestJson = BuildApplyTransactionJson(row.Latest);
                if (!string.IsNullOrWhiteSpace(latestJson))
                {
                    try
                    {
                        root["latest"] = JsonNode.Parse(latestJson);
                    }
                    catch
                    {
                        root["latestJson"] = latestJson;
                    }
                }

                // Короткий список всех транзакций группы (для аудита) без тяжелых снапшотов.
                var items = new JsonArray();
                foreach (var tx in row.Transactions)
                {
                    items.Add(new JsonObject
                    {
                        ["transactionId"] = tx.TransactionId,
                        ["createdAtUtc"] = tx.CreatedAtUtc,
                        ["initiatorHostKey"] = tx.InitiatorHostKey,
                        ["groupKey"] = tx.GroupKey,
                        ["candidateIpCount"] = tx.CandidateIpEndpoints?.Count ?? 0,
                        ["appliedStrategyText"] = tx.AppliedStrategyText,
                        ["planText"] = tx.PlanText,
                        ["activationStatusText"] = tx.ActivationStatusText,
                        ["resultStatus"] = tx.Result?.Status ?? string.Empty,
                        ["resultError"] = tx.Result?.Error ?? string.Empty
                    });
                }

                root["transactions"] = items;

                return root.ToJsonString(jsonOpts);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string BuildApplyTransactionJson(BypassApplyTransaction tx)
        {
            try
            {
                var jsonOpts = new JsonSerializerOptions { WriteIndented = true };

                var node = new JsonObject
                {
                    ["version"] = tx.Version,
                    ["transactionId"] = tx.TransactionId,
                    ["createdAtUtc"] = tx.CreatedAtUtc,
                    ["initiatorHostKey"] = tx.InitiatorHostKey,
                    ["groupKey"] = tx.GroupKey,
                    ["candidateIpEndpoints"] = JsonSerializer.SerializeToNode(tx.CandidateIpEndpoints, jsonOpts),
                    ["expectedEffects"] = JsonSerializer.SerializeToNode(tx.ExpectedEffects, jsonOpts),
                    ["warnings"] = JsonSerializer.SerializeToNode(tx.Warnings, jsonOpts),
                    ["appliedStrategyText"] = tx.AppliedStrategyText,
                    ["planText"] = tx.PlanText,
                    ["reasoning"] = tx.Reasoning,
                    ["activationStatus"] = new JsonObject
                    {
                        ["text"] = tx.ActivationStatusText,
                        ["details"] = tx.ActivationStatusDetails
                    }
                };

                // ActivePolicies
                node["activePolicies"] = JsonSerializer.SerializeToNode(tx.ActivePolicies, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                // PolicySnapshotJson: пытаемся встроить как JSON, чтобы не было экранирования.
                if (!string.IsNullOrWhiteSpace(tx.PolicySnapshotJson))
                {
                    try
                    {
                        node["policySnapshot"] = JsonNode.Parse(tx.PolicySnapshotJson);
                    }
                    catch
                    {
                        node["policySnapshotJson"] = tx.PolicySnapshotJson;
                    }
                }

                // P0.1 Step 2: секции плана (контракт), плюс contributions.
                if (tx.Request != null)
                {
                    node["request"] = JsonSerializer.SerializeToNode(tx.Request, jsonOpts);
                }

                if (tx.Result != null)
                {
                    node["result"] = JsonSerializer.SerializeToNode(tx.Result, jsonOpts);
                }

                if (tx.Contributions != null && tx.Contributions.Count > 0)
                {
                    node["contributions"] = JsonSerializer.SerializeToNode(tx.Contributions, jsonOpts);
                }

                if (tx.Snapshot != null)
                {
                    var snap = new JsonObject
                    {
                        ["activationStatus"] = new JsonObject
                        {
                            ["text"] = tx.Snapshot.ActivationStatusText,
                            ["details"] = tx.Snapshot.ActivationStatusDetails
                        },
                        ["optionsSnapshot"] = JsonSerializer.SerializeToNode(tx.Snapshot.OptionsSnapshot, jsonOpts),
                        ["doHEnabled"] = tx.Snapshot.DoHEnabled,
                        ["selectedDnsPreset"] = tx.Snapshot.SelectedDnsPreset,
                        ["udp443DropTargetIpCount"] = tx.Snapshot.Udp443DropTargetIpCount,
                        ["activeTargetPolicies"] = JsonSerializer.SerializeToNode(tx.Snapshot.ActiveTargetPolicies, jsonOpts),
                        ["activePolicies"] = JsonSerializer.SerializeToNode(tx.Snapshot.ActivePolicies, jsonOpts)
                    };

                    // Встроим policy snapshot как JSON, если возможно.
                    if (!string.IsNullOrWhiteSpace(tx.Snapshot.PolicySnapshotJson))
                    {
                        try
                        {
                            snap["policySnapshot"] = JsonNode.Parse(tx.Snapshot.PolicySnapshotJson);
                        }
                        catch
                        {
                            snap["policySnapshotJson"] = tx.Snapshot.PolicySnapshotJson;
                        }
                    }

                    node["snapshot"] = snap;
                }

                return node.ToJsonString(new JsonSerializerOptions
                {
                    WriteIndented = true
                });
            }
            catch
            {
                return string.Empty;
            }
        }

        private static BypassApplyContribution[] BuildContributions(
            string planText,
            string initiatorHostKey,
            IReadOnlyList<BypassStateManager.ActiveTargetPolicy> activeTargetPolicies,
            TlsBypassOptions optionsSnapshot,
            bool doHEnabled)
        {
            try
            {
                var list = new List<BypassApplyContribution>();
                var tokens = SplitPlanTokens(planText);

                // Плановые «вклады» (по токенам плана).
                if (tokens.Contains("DROP_UDP_443")) list.Add(BypassApplyContribution.Create("assist", "drop_udp_443", "true", "QUIC→TCP"));
                if (tokens.Contains("ALLOW_NO_SNI")) list.Add(BypassApplyContribution.Create("assist", "allow_no_sni", "true", "No SNI"));
                if (tokens.Contains("DROP_RST")) list.Add(BypassApplyContribution.Create("capability", "drop_rst", "true"));
                if (tokens.Contains("TLS_FRAGMENT")) list.Add(BypassApplyContribution.Create("capability", "tls_fragment", "true"));
                if (tokens.Contains("TLS_DISORDER")) list.Add(BypassApplyContribution.Create("capability", "tls_disorder", "true"));
                if (tokens.Contains("TLS_FAKE")) list.Add(BypassApplyContribution.Create("capability", "tls_fake", "true"));

                // Состояние на момент записи.
                if (doHEnabled) list.Add(BypassApplyContribution.Create("state", "doh_enabled", "true"));
                if (!string.IsNullOrWhiteSpace(optionsSnapshot.PresetName))
                {
                    list.Add(BypassApplyContribution.Create("state", "tls_preset", optionsSnapshot.PresetName));
                }

                // Вклад «активной цели» (P0.1 Step 1).
                if (!string.IsNullOrWhiteSpace(initiatorHostKey) && activeTargetPolicies != null && activeTargetPolicies.Count > 0)
                {
                    var p = activeTargetPolicies.FirstOrDefault(v => string.Equals(v.HostKey, initiatorHostKey, StringComparison.OrdinalIgnoreCase));
                    if (p != null)
                    {
                        list.Add(BypassApplyContribution.Create("target_policy", "host", p.HostKey));
                        list.Add(BypassApplyContribution.Create("target_policy", "tls_strategy", p.TlsStrategy.ToString()));
                        if (p.DropUdp443) list.Add(BypassApplyContribution.Create("target_policy", "drop_udp_443", "true"));
                        if (p.AllowNoSni) list.Add(BypassApplyContribution.Create("target_policy", "allow_no_sni", "true"));
                        if (p.HttpHostTricksEnabled) list.Add(BypassApplyContribution.Create("target_policy", "http_host_tricks", "true"));
                    }
                }

                return list.ToArray();
            }
            catch
            {
                return Array.Empty<BypassApplyContribution>();
            }
        }

        private static string[] BuildExpectedEffects(string planText, IReadOnlyList<string> candidateIps)
        {
            var list = new System.Collections.Generic.List<string>();

            var tokens = SplitPlanTokens(planText);
            var hasTlsBypass = tokens.Contains("TLS_FRAGMENT") || tokens.Contains("TLS_DISORDER") || tokens.Contains("TLS_FAKE") || tokens.Contains("DROP_RST");

            if (tokens.Contains("DROP_UDP_443"))
            {
                // Режим GLOBAL/селективный в транзакции не фиксируем (это опция), но эффект описываем универсально.
                var scopeHint = candidateIps.Count == 0
                    ? "(селективный режим требует endpoints)"
                    : $"(IPs={candidateIps.Count})";
                list.Add($"QUIC→TCP: при QUIC/HTTP3 трафике должен расти счётчик Udp443Dropped {scopeHint}");
            }

            if (hasTlsBypass)
            {
                list.Add("TLS bypass: при наличии TLS@443 (ClientHello@443) ожидается статус ACTIVATED и рост метрик обработки");
            }

            if (tokens.Contains("ALLOW_NO_SNI"))
            {
                list.Add("No SNI: обход должен применяться даже без распознанного SNI (ECH/ESNI/фрагментация)");
            }

            if (list.Count == 0)
            {
                list.Add("Ожидаемый эффект не определён: транзакция не содержит явных стратегий/assist-флагов");
            }

            return list.ToArray();
        }

        private static string[] BuildWarnings(string planText, IReadOnlyList<string> candidateIps, string activationText, int activePoliciesCount)
        {
            var list = new System.Collections.Generic.List<string>();

            var tokens = SplitPlanTokens(planText);

            if (tokens.Contains("DROP_UDP_443") && candidateIps.Count == 0)
            {
                list.Add("QUIC→TCP (селективно): endpoints пусты — UDP/443 может не глушиться, если цель не задана/не resolved");
            }

            if (string.Equals(activationText, "ENGINE_DEAD", StringComparison.OrdinalIgnoreCase))
            {
                list.Add("ENGINE_DEAD: TrafficEngine не запущен или метрики не обновляются — нужен запуск от администратора/проверка WinDivert");
            }
            else if (string.Equals(activationText, "BYPASS OFF", StringComparison.OrdinalIgnoreCase))
            {
                list.Add("BYPASS OFF: обход выключен — транзакция не может дать эффект");
            }
            else if (string.Equals(activationText, "NO_TRAFFIC", StringComparison.OrdinalIgnoreCase))
            {
                list.Add("NO_TRAFFIC: нет TLS@443 трафика — откройте HTTPS/игру, иначе метрики/эффект не проявятся");
            }
            else if (string.Equals(activationText, "NOT_ACTIVATED", StringComparison.OrdinalIgnoreCase))
            {
                list.Add("NOT_ACTIVATED: трафик есть, но эффекта по метрикам нет (возможна несовместимость стратегии или неверная цель)");
            }

            if (activePoliciesCount == 0)
            {
                list.Add("Policy-driven snapshot пуст: не видно активных FlowPolicy (возможно, ветка policy-driven не активна для текущего трафика)");
            }

            return list.ToArray();
        }

        private static System.Collections.Generic.HashSet<string> SplitPlanTokens(string planText)
        {
            var set = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(planText)) return set;

            var parts = planText.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var p in parts)
            {
                var token = p.Trim();
                if (token.Length == 0) continue;
                set.Add(token);
            }

            return set;
        }
    }
}
