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

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Оркестратор диагностики.
    /// Координирует TrafficCollector и LiveTestingPipeline.
    /// Управляет жизненным циклом мониторинговых сервисов.
    /// </summary>
    public partial class DiagnosticOrchestrator : INotifyPropertyChanged
    {
        #region Recommendations

        private void TrackRecommendation(string msg, BypassController bypassController)
        {
            if (string.IsNullOrWhiteSpace(msg)) return;

            // v2 — главный источник рекомендаций. Legacy сохраняем только как справочное.
            var isV2 = msg.TrimStart().StartsWith("[V2]", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("v2:", StringComparison.OrdinalIgnoreCase);

            // B5: v2 — единственный источник рекомендаций.
            // Legacy строки допускаются в логах, но не должны влиять на UI рекомендации.
            if (!isV2)
            {
                return;
            }

            // Нас интересуют строки вида "💡 Рекомендация: TLS_FRAGMENT" или "→ Стратегия: DROP_RST".
            // Не используем Split(':'), потому что в сообщении может быть host:port или другие двоеточия.
            var raw = TryExtractAfterMarker(msg, "Рекомендация:")
                ?? TryExtractAfterMarker(msg, "Стратегия:");

            if (string.IsNullOrWhiteSpace(raw)) return;

            raw = raw.Trim();
            var paren = raw.IndexOf('(');
            if (paren > 0)
            {
                raw = raw.Substring(0, paren).Trim();
            }

            if (string.IsNullOrWhiteSpace(raw)) return;

            // Поддержка списка стратегий в одной строке (v2 формат, чтобы не убивать UI шумом).
            // Пример: "[V2] 💡 Рекомендация: TLS_FRAGMENT, DROP_RST"
            // Пример: "💡 Рекомендация: v2:TlsFragment + DropRst (conf=78)"
            var normalized = raw;
            if (normalized.StartsWith("v2:", StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized.Substring(3);
            }

            var tokens = normalized
                .Split(new[] { ',', '+', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(MapStrategyToken)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (tokens.Count == 0) return;

            foreach (var token in tokens)
            {
                if (IsStrategyActive(token, bypassController))
                {
                    // Уже включено вручную — считаем это ручным применением,
                    // чтобы панель рекомендаций была видима и не исчезала.
                    _recommendedStrategies.Remove(token);
                    _legacyRecommendedStrategies.Remove(token);
                    _manualRecommendations.Add(token);
                    continue;
                }

                if (ServiceStrategies.Contains(token))
                {
                    _recommendedStrategies.Add(token);
                }
                else
                {
                    _manualRecommendations.Add(token);
                }
            }

            UpdateRecommendationTexts(bypassController);
        }

        private void StoreV2Plan(string hostKey, BypassPlan plan, BypassController bypassController)
        {
            if (NoiseHostFilter.Instance.IsNoiseHost(hostKey))
            {
                // Шум не должен перетирать «активный» план рекомендаций и засорять Apply.
                return;
            }

            _v2PlansByHost[hostKey] = plan;

            _lastV2Plan = plan;
            _lastV2PlanHostKey = hostKey;

            // План сформирован для конкретной цели — «прикалываем» v2-цель к hostKey плана,
            // чтобы последующие сообщения по другим хостам не ломали Apply (и UX панели рекомендаций).
            _lastV2DiagnosisHostKey = hostKey;

            // Токены нужны только для текста панели. Реальное применение идёт по объектному plan.
            _recommendedStrategies.Clear();

            foreach (var strategy in plan.Strategies)
            {
                var token = strategy.Id switch
                {
                    StrategyId.TlsFragment => "TLS_FRAGMENT",
                    StrategyId.TlsDisorder => "TLS_DISORDER",
                    StrategyId.TlsFakeTtl => "TLS_FAKE",
                    StrategyId.DropRst => "DROP_RST",
                    StrategyId.UseDoh => "DOH",
                    _ => string.Empty
                };

                if (string.IsNullOrWhiteSpace(token))
                {
                    continue;
                }

                if (!IsStrategyActive(token, bypassController))
                {
                    _recommendedStrategies.Add(token);
                }
            }

            if (plan.DropUdp443)
            {
                var token = "DROP_UDP_443";
                if (!IsStrategyActive(token, bypassController))
                {
                    _recommendedStrategies.Add(token);
                }
            }

            if (plan.AllowNoSni)
            {
                var token = "ALLOW_NO_SNI";
                if (!IsStrategyActive(token, bypassController))
                {
                    _recommendedStrategies.Add(token);
                }
            }

            _lastV2DiagnosisSummary = string.IsNullOrWhiteSpace(hostKey)
                ? $"([V2] диагноз={plan.ForDiagnosis} уверенность={plan.PlanConfidence}%: {plan.Reasoning})"
                : $"([V2] диагноз={plan.ForDiagnosis} уверенность={plan.PlanConfidence}%: {plan.Reasoning}) (цель: {hostKey})";

            UpdateRecommendationTexts(bypassController);
        }

        private static string? TryExtractAfterMarker(string msg, string marker)
        {
            var idx = msg.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            idx += marker.Length;
            if (idx >= msg.Length) return null;

            return msg.Substring(idx);
        }

        private void TrackV2DiagnosisSummary(string msg)
        {
            // Берём v2 диагноз из строки карточки: "❌ ... ( [V2] диагноз=SilentDrop уверенность=78%: ... )"
            if (string.IsNullOrWhiteSpace(msg)) return;
            if (!msg.StartsWith("❌ ", StringComparison.Ordinal)) return;
            if (!msg.Contains("[V2]", StringComparison.OrdinalIgnoreCase) && !msg.Contains("v2:", StringComparison.OrdinalIgnoreCase)) return;

            try
            {
                // Ключ цели: предпочитаем SNI (человеко‑понятный), иначе берём IP из "host:port".
                var candidateHostKey = string.Empty;
                var sni = TryExtractInlineToken(msg, "SNI");
                if (!string.IsNullOrWhiteSpace(sni) && sni != "-")
                {
                    candidateHostKey = sni;
                }
                else
                {
                    var afterPrefix = msg.Substring(2).TrimStart();
                    var firstToken = afterPrefix.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(firstToken))
                    {
                        candidateHostKey = firstToken.Split(':').FirstOrDefault() ?? "";
                    }
                }

                // Если план уже построен, не позволяем сообщениям по другим хостам «перетереть» цель,
                // иначе кнопка Apply может начать вести себя как "ничего не происходит".
                if (_lastV2Plan != null
                    && !string.IsNullOrWhiteSpace(_lastV2PlanHostKey)
                    && !string.IsNullOrWhiteSpace(candidateHostKey)
                    && !string.Equals(candidateHostKey, _lastV2PlanHostKey, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                if (!string.IsNullOrWhiteSpace(candidateHostKey))
                {
                    _lastV2DiagnosisHostKey = candidateHostKey;
                }

                // Вытаскиваем компактный текст v2 в скобках (он уже пользовательский)
                var m = Regex.Match(msg, @"\(\s*\[V2\][^\)]*\)", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var tail = m.Value.Trim();
                    _lastV2DiagnosisSummary = string.IsNullOrWhiteSpace(_lastV2DiagnosisHostKey)
                        ? $"{tail}"
                        : $"{tail} (цель: {_lastV2DiagnosisHostKey})";
                }
            }
            catch
            {
                // Игнорируем ошибки парсинга
            }
        }

        private static string? TryExtractInlineToken(string msg, string token)
        {
            try
            {
                var m = Regex.Match(msg, $@"\b{Regex.Escape(token)}=([^\s\|]+)", RegexOptions.IgnoreCase);
                return m.Success ? m.Groups[1].Value.Trim() : null;
            }
            catch
            {
                return null;
            }
        }

        private static string FormatStrategyTokenForUi(string token)
        {
            // Должно совпадать с текстами тумблеров в MainWindow.xaml.
            return token.ToUpperInvariant() switch
            {
                "TLS_FRAGMENT" => "Frag",
                "TLS_DISORDER" => "Frag+Rev",
                "TLS_FAKE" => "TLS Fake",
                "DROP_RST" => "Drop RST",
                "DROP_UDP_443" => "QUIC→TCP",
                "ALLOW_NO_SNI" => "No SNI",
                // Back-compat
                "QUIC_TO_TCP" => "QUIC→TCP",
                "NO_SNI" => "No SNI",
                "DOH" => "🔒 DoH",
                _ => token
            };
        }

        private static string MapStrategyToken(string token)
        {
            var t = token.Trim();
            if (string.IsNullOrWhiteSpace(t)) return string.Empty;

            // Поддерживаем как legacy-строки, так и enum-названия v2.
            return t switch
            {
                "TlsFragment" => "TLS_FRAGMENT",
                "TlsDisorder" => "TLS_DISORDER",
                "TlsFakeTtl" => "TLS_FAKE",
                "DropRst" => "DROP_RST",
                "UseDoh" => "DOH",
                "DropUdp443" => "DROP_UDP_443",
                "AllowNoSni" => "ALLOW_NO_SNI",

                // Back-compat
                "QUIC_TO_TCP" => "DROP_UDP_443",
                "NO_SNI" => "ALLOW_NO_SNI",
                _ => t.ToUpperInvariant()
            };
        }

        #endregion
    }
}
