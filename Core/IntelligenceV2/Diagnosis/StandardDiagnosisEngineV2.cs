using System;
using System.Collections.Generic;
using IspAudit.Core.IntelligenceV2.Contracts;

namespace IspAudit.Core.IntelligenceV2.Diagnosis;

/// <summary>
/// Минимальный Diagnosis Engine v2.
/// Важно: работает только по <see cref="BlockageSignalsV2"/> и не знает ничего про стратегии/обход.
/// </summary>
public sealed class StandardDiagnosisEngineV2
{
    public DiagnosisResult Diagnose(BlockageSignalsV2 signals)
    {
        if (signals is null) throw new ArgumentNullException(nameof(signals));

        var notes = new List<string>();
        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["hostKey"] = signals.HostKey,
            ["windowSec"] = ((int)signals.AggregationWindow.TotalSeconds).ToString(),
            ["sampleSize"] = signals.SampleSize.ToString(),
            ["unreliable"] = signals.IsUnreliable ? "1" : "0"
        };

        // Assist-ориентированные факты (для QA/логов). Сами по себе диагноз не определяют.
        if (signals.UdpUnansweredHandshakes > 0)
        {
            notes.Add($"UDP: безответных рукопожатий={signals.UdpUnansweredHandshakes}");
            evidence["udpUnanswered"] = signals.UdpUnansweredHandshakes.ToString();
        }

        if (signals.HostTestedCount > 0)
        {
            evidence["hostTestedCount"] = signals.HostTestedCount.ToString();
            evidence["hostTestedNoSni"] = signals.HostTestedNoSniCount.ToString();

            if (signals.HostTestedNoSniCount > 0)
            {
                notes.Add($"SNI: отсутствует в {signals.HostTestedNoSniCount}/{signals.HostTestedCount} тестах");
            }
        }

        // Факты (без предположений)
        if (signals.HasDnsFailure)
        {
            notes.Add("DNS: ошибка/статус != OK");
            evidence["dnsFailure"] = "1";
        }
        if (signals.HasFakeIp)
        {
            notes.Add("IP: служебный/подозрительный диапазон (fake IP)");
            evidence["fakeIp"] = "1";
        }
        if (signals.HasHttpRedirect)
        {
            notes.Add("HTTP: обнаружен редирект/заглушка");
            evidence["httpRedirect"] = "1";
        }
        if (signals.HasTcpTimeout)
        {
            notes.Add("TCP: timeout");
            evidence["tcpTimeout"] = "1";
        }
        if (signals.HasTcpReset)
        {
            notes.Add("TCP: RST наблюдался");
            evidence["tcpReset"] = "1";
        }
        if (signals.RstTtlDelta is int ttlDelta)
        {
            notes.Add($"TCP: rst-ttl-delta={ttlDelta}");
            evidence["rstTtlDelta"] = ttlDelta.ToString();
        }
        if (signals.RstIpIdDelta is int ipIdDelta)
        {
            notes.Add($"TCP: rst-ipid-delta={ipIdDelta}");
            evidence["rstIpIdDelta"] = ipIdDelta.ToString();
        }
        if (signals.SuspiciousRstCount > 0)
        {
            notes.Add($"TCP: suspicious-rst-count={signals.SuspiciousRstCount}");
            evidence["suspiciousRstCount"] = signals.SuspiciousRstCount.ToString();
        }
        if (signals.RstLatency is TimeSpan rstLatency)
        {
            var ms = (int)Math.Max(0, Math.Round(rstLatency.TotalMilliseconds, MidpointRounding.AwayFromZero));
            notes.Add($"TCP: rst-latency-ms={ms}");
            evidence["rstLatencyMs"] = ms.ToString();
        }
        if (signals.HasTlsTimeout)
        {
            notes.Add("TLS: timeout");
            evidence["tlsTimeout"] = "1";
        }
        if (signals.HasTlsAuthFailure)
        {
            notes.Add("TLS: auth failure");
            evidence["tlsAuthFailure"] = "1";
        }
        if (signals.HasTlsReset)
        {
            notes.Add("TLS: reset наблюдался");
            evidence["tlsReset"] = "1";
        }
        if (signals.RetransmissionRate is double r)
        {
            var rr = Math.Clamp(r, 0.0, 1.0);
            notes.Add($"TCP: retx-rate={rr:0.00}");
            evidence["retxRate"] = rr.ToString("0.00");
        }
        else
        {
            evidence["retxRate"] = "n/a";
        }

        // 1) Качество данных
        // Важно: "мало событий" не должно превращать диагностику в тупик без рекомендаций.
        // Если иных фактов нет — помечаем как Unknown, но даём возможность UI показать консервативный план (fallback).
        if (signals.IsUnreliable)
        {
            notes.Insert(0, "Недостаточно данных: мало событий в окне (вывод может быть неточным)");
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.Unknown,
                Confidence = 50,
                MatchedRuleName = "unreliable-sample",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 2) Очевидно «всё чисто» по флагам
        if (!signals.HasDnsFailure && !signals.HasFakeIp && !signals.HasHttpRedirect &&
            !signals.HasTcpTimeout && !signals.HasTcpReset && !signals.HasTlsTimeout && !signals.HasTlsAuthFailure && !signals.HasTlsReset)
        {
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.NoBlockage,
                Confidence = 80,
                MatchedRuleName = "no-flags",
                ExplanationNotes = Array.Empty<string>(),
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 3) Мульти-слой: DNS + что-то ещё
        var hasTransportOrAppIssue = signals.HasTcpTimeout || signals.HasTcpReset || signals.HasTlsTimeout || signals.HasTlsAuthFailure || signals.HasTlsReset || signals.HasHttpRedirect;
        if (signals.HasDnsFailure && hasTransportOrAppIssue)
        {
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.MultiLayerBlock,
                Confidence = 70,
                MatchedRuleName = "dns+transport",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 4) HTTP редирект как наблюдаемый факт
        if (signals.HasHttpRedirect)
        {
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.HttpRedirect,
                Confidence = 75,
                MatchedRuleName = "http-redirect",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 5) DNS проблемы
        if (signals.HasDnsFailure || signals.HasFakeIp)
        {
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.DnsHijack,
                Confidence = signals.HasFakeIp ? 75 : 55,
                MatchedRuleName = signals.HasFakeIp ? "dns-fake-ip" : "dns-failure",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 6) Таймаут + высокая доля ретрансмиссий
        if (signals.HasTcpTimeout)
        {
            if (signals.RetransmissionRate is double rr && rr >= 0.20)
            {
                return new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.SilentDrop,
                    Confidence = 80,
                    MatchedRuleName = "tcp-timeout+high-retx",
                    ExplanationNotes = notes,
                    Evidence = evidence,
                    InputSignals = signals,
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };
            }

            // Timeout сам по себе уже сильный симптом, но без ретранс-метрики мы не уверены.
            // Важно: ставим диагноз "SilentDrop" с умеренной уверенностью < 50,
            // чтобы StrategySelector не предлагал обход автоматически.
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.SilentDrop,
                Confidence = 45,
                MatchedRuleName = "tcp-timeout-only",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 7) RST: при наличии TTL delta (и желательно latency) можем различить active edge vs stateful DPI.
        if (signals.HasTcpReset)
        {
            var hasTtlAnomaly = signals.RstTtlDelta is int ttl && ttl >= 6;
            var hasIpIdAnomaly = signals.RstIpIdDelta is int ipidDelta && ipidDelta >= 1000;
            var hasStrongAnomaly = hasTtlAnomaly || hasIpIdAnomaly;

            // Устойчивость: не ставим уверенный DPI-диагноз по единичному событию.
            // Считаем, что 2+ попадания в окне — минимально приемлемый признак повторяемости.
            var isStable = signals.SuspiciousRstCount >= 2;

            if (hasStrongAnomaly && isStable)
            {
                // Порог latency: быстрый RST чаще характерен для "edge" (активная инъекция ближе к клиенту).
                // Медленный RST — скорее stateful инспекция (ожидает контент/паттерн).
                if (signals.RstLatency is TimeSpan l)
                {
                    var ms = l.TotalMilliseconds;
                    if (ms <= 250)
                    {
                        return new DiagnosisResult
                        {
                            DiagnosisId = DiagnosisId.ActiveDpiEdge,
                            Confidence = 80,
                            MatchedRuleName = "tcp-rst+stable-anomaly+fast",
                            ExplanationNotes = notes,
                            Evidence = evidence,
                            InputSignals = signals,
                            DiagnosedAtUtc = DateTimeOffset.UtcNow
                        };
                    }

                    if (ms >= 500)
                    {
                        return new DiagnosisResult
                        {
                            DiagnosisId = DiagnosisId.StatefulDpi,
                            Confidence = 75,
                            MatchedRuleName = "tcp-rst+stable-anomaly+slow",
                            ExplanationNotes = notes,
                            Evidence = evidence,
                            InputSignals = signals,
                            DiagnosedAtUtc = DateTimeOffset.UtcNow
                        };
                    }
                }

                return new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.ActiveDpiEdge,
                    Confidence = 65,
                    MatchedRuleName = "tcp-rst+stable-anomaly",
                    ExplanationNotes = notes,
                    Evidence = evidence,
                    InputSignals = signals,
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };
            }

            if (hasStrongAnomaly && !isStable)
            {
                // Есть подозрительный RST, но нет устойчивости улик в окне.
                // Возвращаем Unknown (без DPI-id), чтобы не создавать ложную уверенность на “рабочих” целях.
                return new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.Unknown,
                    Confidence = 55,
                    MatchedRuleName = "tcp-rst+single-anomaly",
                    ExplanationNotes = notes,
                    Evidence = evidence,
                    InputSignals = signals,
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };
            }

            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.Unknown,
                Confidence = 45,
                MatchedRuleName = "tcp-rst-only",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 8) TLS timeout без дополнительных улик
        if (signals.HasTlsTimeout || signals.HasTlsAuthFailure || signals.HasTlsReset)
        {
            var confidence = 50;
            if (signals.HasTlsTimeout) confidence = 55;
            if (signals.HasTlsReset) confidence = 60;

            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.TlsInterference,
                Confidence = signals.HasTlsAuthFailure ? Math.Min(50, confidence) : confidence,
                MatchedRuleName = signals.HasTlsAuthFailure ? "tls-auth-failure" : "tls-interference",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        return new DiagnosisResult
        {
            DiagnosisId = DiagnosisId.Unknown,
            Confidence = 40,
            MatchedRuleName = "fallback",
            ExplanationNotes = notes,
            Evidence = evidence,
            InputSignals = signals,
            DiagnosedAtUtc = DateTimeOffset.UtcNow
        };
    }
}
