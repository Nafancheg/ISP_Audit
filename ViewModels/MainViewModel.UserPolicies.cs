using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using IspAudit.Core.Bypass;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Wpf;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        private const int UserFlowPoliciesCap = 200;

        private bool _isUserFlowPoliciesBusy;
        private string _userFlowPoliciesStatusText = string.Empty;
        private UserFlowPolicyRow? _selectedUserFlowPolicy;

        public ObservableCollection<UserFlowPolicyRow> UserFlowPolicies { get; } = new();

        public UserFlowPolicyRow? SelectedUserFlowPolicy
        {
            get => _selectedUserFlowPolicy;
            set
            {
                if (_selectedUserFlowPolicy == value) return;
                _selectedUserFlowPolicy = value;
                OnPropertyChanged(nameof(SelectedUserFlowPolicy));
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            }
        }

        public bool IsUserFlowPoliciesBusy
        {
            get => _isUserFlowPoliciesBusy;
            private set
            {
                if (_isUserFlowPoliciesBusy == value) return;
                _isUserFlowPoliciesBusy = value;
                OnPropertyChanged(nameof(IsUserFlowPoliciesBusy));
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            }
        }

        public string UserFlowPoliciesStatusText
        {
            get => _userFlowPoliciesStatusText;
            private set
            {
                if (string.Equals(_userFlowPoliciesStatusText, value, StringComparison.Ordinal)) return;
                _userFlowPoliciesStatusText = value;
                OnPropertyChanged(nameof(UserFlowPoliciesStatusText));
            }
        }

        private void InitializeUserFlowPoliciesUi()
        {
            try
            {
                ReloadUserFlowPoliciesBestEffort();
            }
            catch
            {
                // ignore
            }
        }

        private void AddUserFlowPolicyRow()
        {
            try
            {
                UserFlowPolicies.Add(UserFlowPolicyRow.CreateDefault());
                SelectedUserFlowPolicy = UserFlowPolicies.LastOrDefault();
                UserFlowPoliciesStatusText = "Добавлена новая политика (не забудьте нажать 'Сохранить').";
            }
            catch
            {
                // ignore
            }
        }

        private void DeleteSelectedUserFlowPolicyRow()
        {
            try
            {
                if (SelectedUserFlowPolicy == null) return;
                _ = UserFlowPolicies.Remove(SelectedUserFlowPolicy);
                SelectedUserFlowPolicy = null;
                UserFlowPoliciesStatusText = "Политика удалена (не забудьте нажать 'Сохранить').";
            }
            catch
            {
                // ignore
            }
        }

        private void ReloadUserFlowPoliciesBestEffort()
        {
            try
            {
                var loaded = UserFlowPolicyStore.LoadOrEmpty();

                UiBeginInvoke(() =>
                {
                    UserFlowPolicies.Clear();
                    foreach (var p in loaded)
                    {
                        UserFlowPolicies.Add(MapToRow(p));
                    }

                    SelectedUserFlowPolicy = UserFlowPolicies.FirstOrDefault();
                    UserFlowPoliciesStatusText = loaded.Count == 0
                        ? "Пользовательские политики не заданы."
                        : $"Загружено пользовательских политик: {loaded.Count}.";
                });

                // Прокидываем в core слой, чтобы snapshot мог собраться при следующем Apply.
                try
                {
                    _bypassState.SetUserFlowPoliciesForManager(loaded);
                }
                catch
                {
                    // ignore
                }
            }
            catch
            {
                UiBeginInvoke(() => UserFlowPoliciesStatusText = "Не удалось загрузить политики (best-effort).");
            }
        }

        private async Task SaveUserFlowPoliciesAsync()
        {
            if (IsUserFlowPoliciesBusy) return;
            IsUserFlowPoliciesBusy = true;

            try
            {
                UserFlowPoliciesStatusText = "Сохранение политик…";

                var rows = UserFlowPolicies.ToArray();
                if (rows.Length > UserFlowPoliciesCap)
                {
                    UserFlowPoliciesStatusText = $"⚠️ Политик слишком много: {rows.Length} > {UserFlowPoliciesCap}. Сохранение отклонено.";
                    return;
                }

                var policies = new List<FlowPolicy>(rows.Length);
                var errors = new List<string>();
                var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var row in rows)
                {
                    if (!TryBuildPolicy(row, out var policy, out var error))
                    {
                        errors.Add(error);
                        continue;
                    }

                    if (!ids.Add(policy.Id))
                    {
                        errors.Add($"Id должен быть уникальным: '{policy.Id}'");
                        continue;
                    }

                    policies.Add(policy);
                }

                if (errors.Count > 0)
                {
                    UserFlowPoliciesStatusText = "⚠️ Валидация не прошла: " + errors.First();
                    return;
                }

                // Компилируем (hard-conflict detection) — на фоне.
                await Task.Run(() =>
                {
                    _ = policies.Count == 0 ? null : PolicySetCompiler.CompileOrThrow(policies);
                });

                // Персист.
                UserFlowPolicyStore.SaveBestEffort(policies);

                // Применяем в runtime: set + re-apply текущих опций (фон).
                await Bypass.SetUserFlowPoliciesAndRecompileAsync(policies, CancellationToken.None);

                UiBeginInvoke(() =>
                {
                    UserFlowPoliciesStatusText = policies.Count == 0
                        ? "Политики очищены и применены."
                        : $"Политики сохранены и применены: {policies.Count}.";
                });
            }
            catch (Exception ex)
            {
                UiBeginInvoke(() =>
                {
                    UserFlowPoliciesStatusText = $"⚠️ Не удалось сохранить/применить: {ex.Message}";
                });
            }
            finally
            {
                IsUserFlowPoliciesBusy = false;
            }
        }

        private static UserFlowPolicyRow MapToRow(FlowPolicy p)
        {
            var row = UserFlowPolicyRow.CreateDefault();

            try
            {
                row.Id = p.Id ?? string.Empty;
                row.Scope = p.Scope.ToString();
                row.Priority = p.Priority;

                row.Proto = p.Match.Proto?.ToString() ?? string.Empty;
                row.Port = p.Match.Port?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
                row.TlsStage = p.Match.TlsStage?.ToString() ?? string.Empty;
                row.SniPattern = p.Match.SniPattern ?? string.Empty;

                // Action → компактный UI формат.
                if (p.Action.Kind == PolicyActionKind.Pass) row.Action = "PASS";
                else if (p.Action.Kind == PolicyActionKind.Block) row.Action = "BLOCK";
                else if (string.Equals(p.Action.StrategyId, PolicyAction.StrategyIdDropUdp443, StringComparison.OrdinalIgnoreCase)) row.Action = "DropUdp443";
                else if (string.Equals(p.Action.StrategyId, PolicyAction.StrategyIdHttpHostTricks, StringComparison.OrdinalIgnoreCase)) row.Action = "HttpHostTricks";
                else if (string.Equals(p.Action.StrategyId, PolicyAction.StrategyIdTlsBypassStrategy, StringComparison.OrdinalIgnoreCase))
                {
                    row.Action = "TlsBypassStrategy";
                    if (p.Action.Parameters.TryGetValue(PolicyAction.ParameterKeyTlsStrategy, out var s))
                    {
                        row.TlsStrategy = s;
                    }
                }
                else
                {
                    row.Action = "PASS";
                }
            }
            catch
            {
                // ignore
            }

            return row;
        }

        private static bool TryBuildPolicy(UserFlowPolicyRow row, out FlowPolicy policy, out string error)
        {
            policy = null!;
            error = string.Empty;

            if (row == null)
            {
                error = "Пустая строка политики";
                return false;
            }

            var id = (row.Id ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(id))
            {
                error = "Id обязателен";
                return false;
            }

            if (!TryParseScope(row.Scope, out var scope, out error))
            {
                error = $"{id}: {error}";
                return false;
            }

            if (!TryParseProto(row.Proto, out var proto, out error))
            {
                error = $"{id}: {error}";
                return false;
            }

            if (!TryParseNullablePort(row.Port, out var port, out error))
            {
                error = $"{id}: {error}";
                return false;
            }

            if (!TryParseTlsStage(row.TlsStage, out var tlsStage, out error))
            {
                error = $"{id}: {error}";
                return false;
            }

            var sni = (row.SniPattern ?? string.Empty).Trim();
            if (!IsValidSniPattern(sni, out var sniError))
            {
                error = $"{id}: {sniError}";
                return false;
            }

            if (!TryParseAction(row.Action, row.TlsStrategy, out var action, out error))
            {
                error = $"{id}: {error}";
                return false;
            }

            policy = new FlowPolicy
            {
                Id = id,
                Priority = row.Priority,
                Scope = scope,
                Match = new MatchCondition
                {
                    Proto = proto,
                    Port = port,
                    TlsStage = tlsStage,
                    SniPattern = string.IsNullOrWhiteSpace(sni) ? null : sni
                },
                Action = action
            };

            return true;
        }

        private static bool TryParseScope(string scopeText, out PolicyScope scope, out string error)
        {
            error = string.Empty;
            var s = (scopeText ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(s))
            {
                scope = PolicyScope.Local;
                return true;
            }

            if (Enum.TryParse<PolicyScope>(s, ignoreCase: true, out var parsed))
            {
                scope = parsed;
                return true;
            }

            scope = PolicyScope.Local;
            error = "Scope: ожидается Local/Global";
            return false;
        }

        private static bool TryParseProto(string protoText, out FlowTransportProtocol? proto, out string error)
        {
            error = string.Empty;
            var s = (protoText ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(s))
            {
                proto = null;
                return true;
            }

            if (Enum.TryParse<FlowTransportProtocol>(s, ignoreCase: true, out var parsed))
            {
                proto = parsed;
                return true;
            }

            proto = null;
            error = "Proto: ожидается Tcp/Udp или пусто";
            return false;
        }

        private static bool TryParseNullablePort(string portText, out int? port, out string error)
        {
            error = string.Empty;
            var s = (portText ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(s))
            {
                port = null;
                return true;
            }

            if (!int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p))
            {
                port = null;
                error = "Port: ожидается число 1..65535 или пусто";
                return false;
            }

            if (p < 1 || p > 65535)
            {
                port = null;
                error = "Port: ожидается число 1..65535";
                return false;
            }

            port = p;
            return true;
        }

        private static bool TryParseTlsStage(string tlsText, out TlsStage? tlsStage, out string error)
        {
            error = string.Empty;
            var s = (tlsText ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(s))
            {
                tlsStage = null;
                return true;
            }

            if (Enum.TryParse<TlsStage>(s, ignoreCase: true, out var parsed))
            {
                tlsStage = parsed;
                return true;
            }

            tlsStage = null;
            error = "TlsStage: ожидается ClientHello/Handshake/ApplicationData/NoSni или пусто";
            return false;
        }

        private static bool TryParseAction(string actionText, string tlsStrategyText, out PolicyAction action, out string error)
        {
            error = string.Empty;
            action = PolicyAction.Pass;

            var s = (actionText ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(s))
            {
                error = "Action обязателен";
                return false;
            }

            if (string.Equals(s, "PASS", StringComparison.OrdinalIgnoreCase))
            {
                action = PolicyAction.Pass;
                return true;
            }

            if (string.Equals(s, "BLOCK", StringComparison.OrdinalIgnoreCase))
            {
                action = PolicyAction.Block;
                return true;
            }

            if (string.Equals(s, "DropUdp443", StringComparison.OrdinalIgnoreCase))
            {
                action = PolicyAction.DropUdp443;
                return true;
            }

            if (string.Equals(s, "HttpHostTricks", StringComparison.OrdinalIgnoreCase))
            {
                action = PolicyAction.HttpHostTricks;
                return true;
            }

            if (string.Equals(s, "TlsBypassStrategy", StringComparison.OrdinalIgnoreCase))
            {
                var tls = (tlsStrategyText ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(tls))
                {
                    error = "TlsStrategy обязателен для Action=TlsBypassStrategy";
                    return false;
                }

                action = PolicyAction.TlsBypassStrategy(tls);
                return true;
            }

            error = "Action: ожидается PASS/BLOCK/DropUdp443/HttpHostTricks/TlsBypassStrategy";
            return false;
        }

        private static bool IsValidSniPattern(string sni, out string error)
        {
            error = string.Empty;
            if (string.IsNullOrWhiteSpace(sni)) return true;
            if (!sni.Contains('*', StringComparison.Ordinal)) return true;

            // Разрешаем только "*" и "*.suffix".
            if (sni == "*") return true;
            if (sni.StartsWith("*.", StringComparison.Ordinal) && sni.Length > 2) return true;

            error = "SniPattern: wildcard поддерживается только как '*' или '*.example.com'";
            return false;
        }
    }
}
