using System;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Intelligence.Execution;

namespace IspAudit.Utils
{
    public partial class LiveTestingPipeline
    {
        private static string NormalizeHostnameForDedup(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;

            var s = value.Trim();

            // Срезаем хвост на первом невалидном символе (по аналогии с UI-слоем).
            // Разрешаем только ASCII hostname: a-z, 0-9, '.', '-'
            int end = 0;
            for (; end < s.Length; end++)
            {
                char c = s[end];
                bool ok =
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '.' || c == '-';

                if (!ok) break;
            }

            var cleaned = end == s.Length ? s : s.Substring(0, end);
            cleaned = cleaned.Trim('.');

            if (cleaned.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(4);
            }

            return string.IsNullOrWhiteSpace(cleaned) ? s : cleaned;
        }

        /// <summary>
        /// Worker 3: Обновление UI (bypass применяется отдельно, не во время диагностики)
        /// </summary>
        private async Task UiWorker(CancellationToken ct)
        {
            await foreach (var blocked in _bypassQueue.Reader.ReadAllAsync(ct))
            {
                try
                {
                    var host = blocked.TestResult.Host.RemoteIp.ToString();
                    var port = blocked.TestResult.Host.RemotePort;

                    var sni = blocked.TestResult.SniHostname;
                    if (string.IsNullOrWhiteSpace(sni) && _dnsParser != null)
                    {
                        _dnsParser.SniCache.TryGetValue(host, out sni);
                    }
                    var rdns = blocked.TestResult.ReverseDnsHostname;
                    var namesSuffix = $" SNI={(string.IsNullOrWhiteSpace(sni) ? "-" : sni)} RDNS={(string.IsNullOrWhiteSpace(rdns) ? "-" : rdns)}";

                    // Формируем детальное сообщение
                    var details = $"{host}:{port}{namesSuffix}";
                    if (blocked.TestResult.TcpLatencyMs > 0)
                    {
                        details += $" ({blocked.TestResult.TcpLatencyMs}ms)";
                    }

                    // Статус проверок
                    var h3Mark = blocked.TestResult.Http3Ok == true
                        ? "✓"
                        : blocked.TestResult.Http3Ok == false
                            ? "✗"
                            : "-";

                    var h3Tail = string.IsNullOrWhiteSpace(blocked.TestResult.Http3Status)
                        ? string.Empty
                        : blocked.TestResult.Http3Status == "H3_OK" || blocked.TestResult.Http3Status == "H3_NOT_ATTEMPTED"
                            ? string.Empty
                            : $"({blocked.TestResult.Http3Status})";

                    var checks = $"DNS:{(blocked.TestResult.DnsOk ? "✓" : "✗")} TCP:{(blocked.TestResult.TcpOk ? "✓" : "✗")} TLS:{(blocked.TestResult.TlsOk ? "✓" : "✗")} H3:{h3Mark}{h3Tail}";

                    var blockage = string.IsNullOrEmpty(blocked.TestResult.BlockageType)
                        ? PipelineContract.BypassUnknown
                        : blocked.TestResult.BlockageType;

                    // Краткий хвост из текста рекомендации (там уже зашиты счётчики фейлов и ретрансмиссий)
                    string? suffix = null;
                    if (!string.IsNullOrWhiteSpace(blocked.RecommendedAction))
                    {
                        // Ищем первую открывающую скобку – туда мы дописываем агрегированные сигналы,
                        // например: "(diag:...; ... )".
                        var idx = blocked.RecommendedAction.IndexOf('(');
                        if (idx >= 0 && blocked.RecommendedAction.EndsWith(")", StringComparison.Ordinal))
                        {
                            var tail = blocked.RecommendedAction.Substring(idx).Trim();
                            if (!string.IsNullOrEmpty(tail))
                            {
                                if (_executor.TryFormatDiagnosisSuffix(tail, out var formattedTail))
                                {
                                    suffix = formattedTail;
                                }
                                else
                                {
                                    suffix = tail;
                                }
                            }
                        }
                    }

                    var uiLine = suffix is null
                        ? $"❌ {details} | {checks} | {blockage}"
                        : $"❌ {details} | {checks} | {blockage} {suffix}";

                    _progress?.Report(uiLine);

                    // Показываем рекомендацию, но НЕ применяем bypass автоматически
                    // Bypass должен применяться отдельной командой после завершения диагностики
                    if (blocked.BypassStrategy != PipelineContract.BypassNone && blocked.BypassStrategy != PipelineContract.BypassUnknown)
                    {
                        // Дедуп по SNI (если есть), иначе по IP.
                        // Это уменьшает шум в логах при множественных IP одного домена.
                        var dedupKeyRaw = !string.IsNullOrWhiteSpace(sni) && sni != "-" ? sni : host;
                        var dedupKey = dedupKeyRaw == host ? host : NormalizeHostnameForDedup(dedupKeyRaw);

                        // Контекст цели для детерминированной привязки рекомендации к карточке (UI не должен полагаться на LastUpdatedHost).
                        var context = $"host={host}:{port} SNI={(string.IsNullOrWhiteSpace(sni) ? "-" : sni)} RDNS={(string.IsNullOrWhiteSpace(rdns) ? "-" : rdns)}";

                        // Auto-hostlist: если хост попал в кандидаты, помечаем это рядом с рекомендацией.
                        // Ранее это было видно только в intel-хвосте диагноза.
                        if (!string.IsNullOrWhiteSpace(blocked.RecommendedAction)
                            && blocked.RecommendedAction.Contains("autoHL hits=", StringComparison.OrdinalIgnoreCase))
                        {
                            context += " hostlist=auto";
                        }

                        if (_executor.TryBuildRecommendationLine(dedupKey, blocked.BypassStrategy, context, out var recommendationLine))
                        {
                            _progress?.Report(recommendationLine);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _progress?.Report($"[UI] Ошибка обработки: {ex.Message}");
                }
            }
        }
    }
}
