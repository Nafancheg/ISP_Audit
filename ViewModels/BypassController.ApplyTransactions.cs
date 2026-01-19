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
using IspAudit.Wpf;

// Явно указываем WPF Application вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        private const int ApplyTransactionsCapacity = 50;
        private const int ApplyTransactionsPersistCount = 10;
        private const int ApplyTransactionsPersistMaxBytes = 2 * 1024 * 1024;

        private readonly BypassApplyTransactionJournal _applyTransactionsJournal = new(ApplyTransactionsCapacity);

        private string _applyTransactionsExportStatusText = string.Empty;
        private BypassApplyTransaction? _selectedApplyTransaction;
        private string _selectedApplyTransactionJson = string.Empty;

        public ICommand ExportSelectedApplyTransactionCommand { get; private set; } = null!;
        public ICommand ClearApplyTransactionsCommand { get; private set; } = null!;

        public ObservableCollection<BypassApplyTransaction> ApplyTransactions { get; } = new();

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

        public BypassApplyTransaction? SelectedApplyTransaction
        {
            get => _selectedApplyTransaction;
            set
            {
                if (ReferenceEquals(_selectedApplyTransaction, value)) return;
                _selectedApplyTransaction = value;
                OnPropertyChanged(nameof(SelectedApplyTransaction));

                SelectedApplyTransactionJson = value == null ? string.Empty : BuildApplyTransactionJson(value);
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
                Application.Current?.Dispatcher.Invoke(() =>
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
            string? reasoning)
        {
            try
            {
                var activation = _stateManager.GetActivationStatusSnapshot();

                var tx = new BypassApplyTransaction
                {
                    InitiatorHostKey = initiatorHostKey ?? string.Empty,
                    GroupKey = groupKey ?? string.Empty,
                    CandidateIpEndpoints = candidateIpEndpoints?.ToArray() ?? Array.Empty<string>(),
                    AppliedStrategyText = appliedStrategyText ?? string.Empty,
                    PlanText = planText ?? string.Empty,
                    Reasoning = reasoning ?? string.Empty,
                    ActivationStatusText = activation.Text,
                    ActivationStatusDetails = activation.Details,
                    ActivePolicies = ActivePolicies.ToList(),
                    PolicySnapshotJson = _lastPolicySnapshotJson
                };

                _applyTransactionsJournal.Add(tx);

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    ApplyTransactions.Insert(0, tx);
                    while (ApplyTransactions.Count > ApplyTransactionsCapacity)
                    {
                        ApplyTransactions.RemoveAt(ApplyTransactions.Count - 1);
                    }

                    if (SelectedApplyTransaction == null)
                    {
                        SelectedApplyTransaction = tx;
                    }
                });

                Log($"[P0.1][APPLY_TX] tx={tx.TransactionId}; host={tx.InitiatorHostKey}; group={tx.GroupKey}; ip={tx.CandidateIpEndpoints.Count}; applied={tx.AppliedStrategyText}; act={tx.ActivationStatusText}");

                PersistApplyTransactionsBestEffort();
            }
            catch (Exception ex)
            {
                Log($"[P0.1][APPLY_TX] Ошибка записи транзакции: {ex.Message}");
            }
        }

        private sealed record ApplyTransactionsPersistedStateV1
        {
            public string Version { get; init; } = "v1";
            public string SavedAtUtc { get; init; } = DateTimeOffset.UtcNow.ToString("u").TrimEnd();
            public IReadOnlyList<BypassApplyTransaction> Transactions { get; init; } = Array.Empty<BypassApplyTransaction>();
        }

        private static string GetApplyTransactionsPersistPath()
        {
            var overridePath = Environment.GetEnvironmentVariable("ISP_AUDIT_APPLY_TRANSACTIONS_PATH");
            if (!string.IsNullOrWhiteSpace(overridePath))
            {
                return overridePath;
            }

            var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var dir = Path.Combine(baseDir, "ISP_Audit");
            return Path.Combine(dir, "apply_transactions.json");
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

                    // Берём последние K транзакций из UI коллекции (новые в начале).
                    // Если UI ещё не успел обновиться, fallback на snapshot из журнала.
                    List<BypassApplyTransaction> list;
                    try
                    {
                        list = ApplyTransactions.Take(ApplyTransactionsPersistCount).ToList();
                    }
                    catch
                    {
                        list = _applyTransactionsJournal.Snapshot().Take(ApplyTransactionsPersistCount).ToList();
                    }

                    var payload = new ApplyTransactionsPersistedStateV1
                    {
                        Transactions = list
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

                    var state = JsonSerializer.Deserialize<ApplyTransactionsPersistedStateV1>(json);
                    var list = state?.Transactions;
                    if (list == null || list.Count == 0) return;

                    // Стабильно сортируем: новые сверху. CreatedAtUtc у нас строкой в формате "u".
                    var ordered = list
                        .OrderByDescending(t => ParseCreatedAtUtcOrMin(t.CreatedAtUtc))
                        .Take(ApplyTransactionsCapacity)
                        .ToList();

                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        try
                        {
                            ApplyTransactions.Clear();
                            _applyTransactionsJournal.Clear();

                            foreach (var tx in ordered)
                            {
                                ApplyTransactions.Add(tx);
                                _applyTransactionsJournal.Add(tx);
                            }

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

                var json = BuildApplyTransactionJson(tx);
                if (string.IsNullOrWhiteSpace(json))
                {
                    ApplyTransactionsExportStatusText = "Экспорт: JSON пуст";
                    return;
                }

                var artifactsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "artifacts");
                Directory.CreateDirectory(artifactsDir);

                var shortId = tx.TransactionId.Length >= 8 ? tx.TransactionId.Substring(0, 8) : tx.TransactionId;
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

        private static string BuildApplyTransactionJson(BypassApplyTransaction tx)
        {
            try
            {
                var node = new JsonObject
                {
                    ["version"] = tx.Version,
                    ["transactionId"] = tx.TransactionId,
                    ["createdAtUtc"] = tx.CreatedAtUtc,
                    ["initiatorHostKey"] = tx.InitiatorHostKey,
                    ["groupKey"] = tx.GroupKey,
                    ["candidateIpEndpoints"] = JsonSerializer.SerializeToNode(tx.CandidateIpEndpoints, new JsonSerializerOptions
                    {
                        WriteIndented = true
                    }),
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
    }
}
