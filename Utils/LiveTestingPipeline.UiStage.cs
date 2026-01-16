using System;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.IntelligenceV2.Execution;

namespace IspAudit.Utils
{
    public partial class LiveTestingPipeline
    {
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
                    var checks = $"DNS:{(blocked.TestResult.DnsOk ? "✓" : "✗")} TCP:{(blocked.TestResult.TcpOk ? "✓" : "✗")} TLS:{(blocked.TestResult.TlsOk ? "✓" : "✗")}";

                    var blockage = string.IsNullOrEmpty(blocked.TestResult.BlockageType)
                        ? PipelineContract.BypassUnknown
                        : blocked.TestResult.BlockageType;

                    // Краткий хвост из текста рекомендации (там уже зашиты счётчики фейлов и ретрансмиссий)
                    string? suffix = null;
                    if (!string.IsNullOrWhiteSpace(blocked.RecommendedAction))
                    {
                        // Ищем первую открывающую скобку – именно там StandardBlockageClassifier
                        // дописывает агрегированные сигналы: "(фейлов за Ns: N, ретрансмиссий: M, ...)".
                        var idx = blocked.RecommendedAction.IndexOf('(');
                        if (idx >= 0 && blocked.RecommendedAction.EndsWith(")", StringComparison.Ordinal))
                        {
                            var tail = blocked.RecommendedAction.Substring(idx).Trim();
                            if (!string.IsNullOrEmpty(tail))
                            {
                                if (_executorV2.TryFormatDiagnosisSuffix(tail, out var formattedTail))
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
                        if (_executorV2.TryBuildRecommendationLine(host, blocked.BypassStrategy, out var recommendationLine))
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
