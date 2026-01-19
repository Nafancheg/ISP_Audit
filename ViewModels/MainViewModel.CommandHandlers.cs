using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Models;
using IspAudit.Utils;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region Command Handlers

        private async Task ApplyRecommendationsAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
                var outcome = await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey).ConfigureAwait(false);

                // Практический UX: сразу запускаем короткий пост-Apply ретест по цели.
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    ClearAppliedBypassMarkers();
                    ApplyAppliedStrategyToResults(outcome.HostKey, outcome.AppliedStrategyText);
                    MarkAppliedBypassTarget(SelectedTestResult);

                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения рекомендаций");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения рекомендаций: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ApplyDomainRecommendationsAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[V2][APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            if (!HasDomainSuggestion)
            {
                Log("[V2][APPLY] Доменная подсказка недоступна для текущей цели");
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                var domain = Results.SuggestedDomainSuffix;
                if (string.IsNullOrWhiteSpace(domain))
                {
                    Log("[V2][APPLY] Доменная цель не определена");
                    return;
                }

                var outcome = await Orchestrator.ApplyRecommendationsForDomainAsync(Bypass, domain).ConfigureAwait(false);

                // Практический UX: ретестим доменную цель.
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, domain);

                if (Bypass.IsBypassActive && SelectedTestResult != null && outcome != null)
                {
                    ClearAppliedBypassMarkers();
                    ApplyAppliedStrategyToResults(outcome.HostKey, outcome.AppliedStrategyText);
                    MarkAppliedBypassTarget(SelectedTestResult);

                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения доменной стратегии");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения доменной стратегии: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private async Task ConnectFromResultAsync(TestResult? test)
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[V2][APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            if (test == null)
            {
                return;
            }

            IsApplyingRecommendations = true;
            try
            {
                // Подсветим выбранную цель + выставим OutcomeTargetHost (селективный QUIC→TCP зависит от этого).
                SelectedTestResult = test;

                var preferredHostKey = GetPreferredHostKey(test);
                if (string.IsNullOrWhiteSpace(preferredHostKey))
                {
                    Log("[V2][APPLY] Нет hostKey для выбранной строки (SNI/Host/Name пуст)");
                    return;
                }

                // Если для этой цели есть v2 план — применяем его.
                // Если плана нет, ApplyRecommendationsAsync просто ничего не сделает (и это лучше, чем включать тумблеры вслепую).
                var outcome = await Orchestrator.ApplyRecommendationsAsync(Bypass, preferredHostKey).ConfigureAwait(false);

                // Практический UX: ретестим именно выбранную цель.
                _ = Orchestrator.StartPostApplyRetestAsync(Bypass, preferredHostKey);

                if (Bypass.IsBypassActive && outcome != null)
                {
                    ClearAppliedBypassMarkers();
                    ApplyAppliedStrategyToResults(outcome.HostKey, outcome.AppliedStrategyText);
                    MarkAppliedBypassTarget(test);

                    var groupKey = ComputeApplyGroupKey(outcome.HostKey, Results.SuggestedDomainSuffix);
                    var endpoints = Orchestrator.GetCachedCandidateIpEndpointsSnapshot(outcome.HostKey);
                    if (endpoints.Count == 0)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(900));
                        endpoints = await Orchestrator.ResolveCandidateIpEndpointsSnapshotAsync(outcome.HostKey, cts.Token).ConfigureAwait(false);
                    }

                    Bypass.RecordApplyTransaction(outcome.HostKey, groupKey, endpoints, outcome.AppliedStrategyText, outcome.PlanText, outcome.Reasoning);
                }
            }
            catch (OperationCanceledException)
            {
                Log("[V2][APPLY] Отмена применения стратегии из карточки");
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка применения стратегии из карточки: {ex.Message}");
            }
            finally
            {
                IsApplyingRecommendations = false;
            }
        }

        private static string? GetPreferredHostKey(TestResult? test)
        {
            try
            {
                if (test?.Target == null) return null;

                // Важно: "шумовые" домены (например, *.1e100.net) часто появляются как late-resolve/rDNS.
                // Для применения обхода они бесполезны и могут приводить к впечатлению, что кнопка "Подключить" ничего не делает.
                var candidates = new[]
                {
                    test.Target.SniHost,
                    test.Target.Host,
                    test.Target.Name,
                    test.Target.FallbackIp
                };

                foreach (var c in candidates)
                {
                    if (string.IsNullOrWhiteSpace(c)) continue;
                    var trimmed = c.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;

                    if (System.Net.IPAddress.TryParse(trimmed, out _))
                    {
                        return trimmed;
                    }

                    if (!NoiseHostFilter.Instance.IsNoiseHost(trimmed))
                    {
                        return trimmed;
                    }
                }

                // Если все кандидаты оказались шумом — возвращаем хотя бы первый непустой,
                // чтобы UI/лог явно показали, что именно выбрано.
                return candidates.FirstOrDefault(s => !string.IsNullOrWhiteSpace(s))?.Trim();
            }
            catch
            {
                return null;
            }
        }

        private static string ComputeApplyGroupKey(string hostKey, string? suggestedDomainSuffix)
        {
            try
            {
                hostKey = (hostKey ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(hostKey)) return string.Empty;

                // IP адрес не агрегируем.
                if (IPAddress.TryParse(hostKey, out _)) return hostKey;

                var suffix = (suggestedDomainSuffix ?? string.Empty).Trim().Trim('.');
                if (suffix.Length == 0) return hostKey;

                if (hostKey.Equals(suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                if (hostKey.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)) return suffix;
                return hostKey;
            }
            catch
            {
                return hostKey ?? string.Empty;
            }
        }

        private async Task RestartConnectionAsync()
        {
            if (IsApplyingRecommendations)
            {
                return;
            }

            if (!ShowBypassPanel)
            {
                Log("[V2][APPLY] Bypass недоступен (нужны права администратора)");
                return;
            }

            var preferredHostKey = GetPreferredHostKey(SelectedTestResult);
            try
            {
                await Orchestrator.NudgeReconnectAsync(Bypass, preferredHostKey).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log($"[V2][APPLY] Ошибка рестарта коннекта: {ex.Message}");
            }
        }

        private static void UiBeginInvoke(Action action)
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
                    dispatcher.BeginInvoke(action);
                }
            }
            catch
            {
                // ignore
            }
        }

        private void ClearAppliedBypassMarkers()
        {
            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    if (r.IsAppliedBypassTarget)
                    {
                        r.IsAppliedBypassTarget = false;
                    }

                    if (!string.IsNullOrWhiteSpace(r.AppliedBypassStrategy))
                    {
                        r.AppliedBypassStrategy = null;
                    }
                }
            });
        }

        private void ApplyAppliedStrategyToResults(string hostKey, string appliedStrategyText)
        {
            if (string.IsNullOrWhiteSpace(hostKey)) return;
            if (string.IsNullOrWhiteSpace(appliedStrategyText)) return;

            var key = hostKey.Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(key)) return;

            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    if (r?.Target == null) continue;

                    var candidates = new[]
                    {
                        r.Target.SniHost,
                        r.Target.Host,
                        r.Target.Name,
                        r.Target.FallbackIp
                    };

                    foreach (var c in candidates)
                    {
                        if (string.IsNullOrWhiteSpace(c)) continue;
                        var cc = c.Trim().Trim('.');
                        if (string.IsNullOrWhiteSpace(cc)) continue;

                        if (System.Net.IPAddress.TryParse(key, out _))
                        {
                            if (string.Equals(cc, key, StringComparison.OrdinalIgnoreCase))
                            {
                                r.AppliedBypassStrategy = appliedStrategyText;
                                break;
                            }
                        }
                        else
                        {
                            if (string.Equals(cc, key, StringComparison.OrdinalIgnoreCase)
                                || cc.EndsWith("." + key, StringComparison.OrdinalIgnoreCase))
                            {
                                r.AppliedBypassStrategy = appliedStrategyText;
                                break;
                            }
                        }
                    }
                }
            });
        }

        private void MarkAppliedBypassTarget(TestResult applied)
        {
            UiBeginInvoke(() =>
            {
                foreach (var r in Results.TestResults)
                {
                    r.IsAppliedBypassTarget = ReferenceEquals(r, applied);
                }
            });
        }

        private async Task StartOrCancelAsync()
        {
            if (IsRunning)
            {
                Log("→ Cancelling diagnostic");
                Orchestrator.Cancel();
            }
            else
            {
                await StartDiagnosticAsync();
            }
        }

        private async Task StartDiagnosticAsync()
        {
            string targetExePath;

            if (IsBasicTestMode)
            {
                targetExePath = GetTestNetworkAppPath() ?? "";
                if (string.IsNullOrEmpty(targetExePath))
                {
                    MessageBox.Show("Не удалось найти TestNetworkApp.exe", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                Log($"[Mode] Basic Test: {targetExePath}");
            }
            else
            {
                if (string.IsNullOrEmpty(ExePath) || !File.Exists(ExePath))
                {
                    MessageBox.Show("Файл не найден.", "Ошибка",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                targetExePath = ExePath;
                Log($"[Mode] Normal: {targetExePath}");
            }

            ScreenState = "running";
            Results.Clear();

            Orchestrator.EnableSilenceTimeout = !IsUnlimitedTime;
            await Orchestrator.RunAsync(targetExePath, Bypass, Results, EnableAutoBypass, IsSteamMode);
        }

        private void BrowseExe()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*",
                Title = "Выберите exe файл приложения"
            };

            if (dialog.ShowDialog() == true)
            {
                ExePath = dialog.FileName;
                Log($"[BrowseExe] Selected: {ExePath}");
            }
        }

        private void GenerateReport()
        {
            try
            {
                var report = new
                {
                    Date = DateTime.Now,
                    ExePath = ExePath,
                    Summary = new
                    {
                        Total = TotalTargets,
                        Passed = PassCount,
                        Failed = FailCount,
                        Warnings = WarnCount
                    },
                    Results = TestResults.Select(t => new
                    {
                        Host = t.Target.Host,
                        Name = t.Target.Name,
                        Service = t.Target.Service,
                        Status = t.Status.ToString(),
                        Details = t.Details,
                        Error = t.Error,
                        BypassStrategy = t.BypassStrategy,
                        Flags = new
                        {
                            t.IsRstInjection,
                            t.IsHttpRedirect,
                            t.IsRetransmissionHeavy,
                            t.IsUdpBlockage
                        }
                    }).ToList()
                };

                var json = System.Text.Json.JsonSerializer.Serialize(report,
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                var filename = $"isp_audit_report_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, filename);

                File.WriteAllText(path, json);
                Log($"[Report] Saved: {path}");

                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
            }
            catch (Exception ex)
            {
                Log($"[Report] Error: {ex.Message}");
                MessageBox.Show($"Ошибка создания отчета: {ex.Message}", "Ошибка",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowDetailsDialog(TestResult? result)
        {
            if (result == null) return;

            try
            {
                var window = new IspAudit.Windows.TestDetailsWindow(result)
                {
                    Owner = Application.Current.MainWindow
                };
                window.ShowDialog();
            }
            catch (Exception ex)
            {
                Log($"[ShowDetails] Error: {ex.Message}");
            }
        }

        #endregion
    }
}
