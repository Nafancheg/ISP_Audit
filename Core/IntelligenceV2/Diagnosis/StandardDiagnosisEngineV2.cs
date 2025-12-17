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
        if (signals.IsUnreliable)
        {
            notes.Insert(0, "Недостаточно данных: мало событий в окне");
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.Unknown,
                Confidence = 25,
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

        // 7) RST без метрик TTL/latency — данных недостаточно, чтобы уверенно интерпретировать
        if (signals.HasTcpReset)
        {
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
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.Unknown,
                Confidence = signals.HasTlsAuthFailure ? 45 : 50,
                MatchedRuleName = signals.HasTlsAuthFailure ? "tls-auth-failure-only" : "tls-issue-only",
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
