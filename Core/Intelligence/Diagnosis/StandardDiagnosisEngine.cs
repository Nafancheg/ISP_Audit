using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Utils;

namespace IspAudit.Core.Intelligence.Diagnosis;

/// <summary>
/// Минимальный Diagnosis Engine INTEL.
/// Важно: работает только по <see cref="BlockageSignals"/> и не знает ничего про стратегии/обход.
/// </summary>
public sealed class StandardDiagnosisEngine
{
    public DiagnosisResult Diagnose(BlockageSignals signals)
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

        if (signals.Http3AttemptCount > 0)
        {
            notes.Add($"H3: attempts={signals.Http3AttemptCount} ok={signals.Http3SuccessCount} fail={signals.Http3FailureCount} timeout={signals.Http3TimeoutCount} notSupported={signals.Http3NotSupportedCount}");
            evidence["h3Attempts"] = signals.Http3AttemptCount.ToString();
            evidence["h3Ok"] = signals.Http3SuccessCount.ToString();
            evidence["h3Fail"] = signals.Http3FailureCount.ToString();
            evidence["h3Timeout"] = signals.Http3TimeoutCount.ToString();
            evidence["h3NotSupported"] = signals.Http3NotSupportedCount.ToString();
        }

        if (signals.HostTestedCount > 0)
        {
            evidence["hostTestedCount"] = signals.HostTestedCount.ToString();
            evidence["hostTestedNoSni"] = signals.HostTestedNoSniCount.ToString();
            evidence["hostVerdictUnknownCount"] = signals.HostVerdictUnknownCount.ToString();

            if (!string.IsNullOrWhiteSpace(signals.LastUnknownReason))
            {
                evidence["lastUnknownReason"] = signals.LastUnknownReason;
            }

            if (signals.HostTestedNoSniCount > 0)
            {
                notes.Add($"SNI: отсутствует в {signals.HostTestedNoSniCount}/{signals.HostTestedCount} тестах");
            }

            if (signals.HostVerdictUnknownCount > 0)
            {
                notes.Add($"Health: unknown verdicts={signals.HostVerdictUnknownCount}");
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
            evidence["httpRedirect"] = "1";

            var redirectHost = string.IsNullOrWhiteSpace(signals.RedirectToHost) ? null : signals.RedirectToHost;
            if (redirectHost != null)
            {
                var isLikelyBlockpage = IsLikelyProviderBlockpageHost(redirectHost);
                notes.Add(isLikelyBlockpage
                    ? $"HTTP: редирект на заглушку ({redirectHost})"
                    : $"HTTP: редирект (Location host={redirectHost})");

                evidence["redirectToHost"] = redirectHost;
                evidence["redirectKind"] = isLikelyBlockpage ? "blockpage" : "unknown";
            }
            else
            {
                notes.Add("HTTP: обнаружен редирект/заглушка");
            }
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

        // 1.1) Unknown-first guard: если healthcheck уже пометил часть проверок как Unknown,
        // не деградируем в NoBlockage (S0) при отсутствии других флагов.
        var hasConcreteBlockageFacts =
            signals.HasDnsFailure || signals.HasFakeIp || signals.HasHttpRedirect ||
            signals.HasTcpTimeout || signals.HasTcpReset ||
            signals.HasTlsTimeout || signals.HasTlsAuthFailure || signals.HasTlsReset ||
            signals.Http3FailureCount > 0;

        if (signals.HostVerdictUnknownCount > 0 && !hasConcreteBlockageFacts)
        {
            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.Unknown,
                Confidence = 55,
                MatchedRuleName = "health-unknown",
                ExplanationNotes = notes,
                Evidence = evidence,
                InputSignals = signals,
                DiagnosedAtUtc = DateTimeOffset.UtcNow
            };
        }

        // 2) Очевидно «всё чисто» по флагам
        if (!signals.HasDnsFailure && !signals.HasFakeIp && !signals.HasHttpRedirect &&
            !signals.HasTcpTimeout && !signals.HasTcpReset && !signals.HasTlsTimeout && !signals.HasTlsAuthFailure && !signals.HasTlsReset &&
            signals.Http3FailureCount == 0)
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
            var redirectHost = string.IsNullOrWhiteSpace(signals.RedirectToHost) ? null : signals.RedirectToHost;
            var isLikelyBlockpage = BlockpageHostCatalog.IsLikelyProviderBlockpageHost(redirectHost);
            var sourceHost = TryExtractHostFromHostKey(signals.HostKey);

            var suspiciousFlags = new List<string>();
            if (isLikelyBlockpage)
            {
                suspiciousFlags.Add("blockpage-host");
            }

            if (IsLiteralIpOrPrivateNetworkHost(redirectHost))
            {
                suspiciousFlags.Add("literal-ip-or-private");
            }

            if (IsLocalHost(redirectHost))
            {
                suspiciousFlags.Add("local-host");
            }

            if (IsEtldPlusOneChanged(sourceHost, redirectHost))
            {
                suspiciousFlags.Add("etld-plus-one-changed");
            }

            var redirectClass = suspiciousFlags.Count > 0 ? "suspicious" : "normal";
            evidence["redirectClass"] = redirectClass;
            if (!string.IsNullOrWhiteSpace(sourceHost))
            {
                evidence["sourceHost"] = sourceHost!;
            }
            if (suspiciousFlags.Count > 0)
            {
                evidence["redirectSuspiciousFlags"] = string.Join(',', suspiciousFlags);
            }

            notes.Add(redirectClass == "suspicious"
                ? $"HTTP: redirect suspicious ({string.Join(", ", suspiciousFlags)})"
                : "HTTP: redirect observed (normal anomaly, no hard suspicious flags)");

            return new DiagnosisResult
            {
                DiagnosisId = DiagnosisId.HttpRedirect,
                Confidence = redirectClass == "suspicious" ? (isLikelyBlockpage ? 80 : 70) : 45,
                MatchedRuleName = redirectClass == "suspicious" ? "http-redirect-suspicious" : "http-redirect-normal",
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

        // 5.1) QUIC/HTTP/3 проблема (без явных TCP/TLS проблем)
        // Важно: диагностируем только если реально были попытки H3 и нет успехов.
        // Если H3 не поддерживается платформой — это не блокировка.
        if (signals.Http3AttemptCount > 0 && signals.Http3SuccessCount == 0 && signals.Http3FailureCount > 0 && signals.Http3NotSupportedCount == 0)
        {
            var hasOtherIssues =
                signals.HasHttpRedirect ||
                signals.HasTcpTimeout || signals.HasTcpReset ||
                signals.HasTlsTimeout || signals.HasTlsAuthFailure || signals.HasTlsReset;

            if (!hasOtherIssues)
            {
                // Таймауты считаем более сильным признаком, чем "failed".
                var confidence = signals.Http3TimeoutCount > 0 ? 65 : 55;

                return new DiagnosisResult
                {
                    DiagnosisId = DiagnosisId.QuicInterference,
                    Confidence = confidence,
                    MatchedRuleName = "h3-fail-without-tcp-tls",
                    ExplanationNotes = notes,
                    Evidence = evidence,
                    InputSignals = signals,
                    DiagnosedAtUtc = DateTimeOffset.UtcNow
                };
            }
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

    private static string? TryExtractHostFromHostKey(string? hostKey)
    {
        if (string.IsNullOrWhiteSpace(hostKey))
        {
            return null;
        }

        var key = hostKey.Trim();
        var idx = key.IndexOf(':');
        var host = idx > 0 ? key[..idx] : key;
        host = NormalizeHost(host) ?? host;

        return string.IsNullOrWhiteSpace(host) || IPAddress.TryParse(host, out _) ? null : host;
    }

    private static bool IsLiteralIpOrPrivateNetworkHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var normalized = NormalizeHost(host);
        if (normalized is null || !IPAddress.TryParse(normalized, out var ip))
        {
            return false;
        }

        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            // RFC1918: 10/8, 172.16/12, 192.168/16.
            if (bytes[0] == 10)
            {
                return true;
            }

            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return true;
            }

            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsLocalHost(string? host)
    {
        var normalized = NormalizeHost(host);
        return normalized is not null
            && (normalized.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                || string.Equals(normalized, "localhost", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsEtldPlusOneChanged(string? sourceHost, string? redirectHost)
    {
        var src = GetEtldPlusOne(sourceHost);
        var dst = GetEtldPlusOne(redirectHost);
        return src is not null && dst is not null && !string.Equals(src, dst, StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetEtldPlusOne(string? host)
    {
        var normalized = NormalizeHost(host);
        if (string.IsNullOrWhiteSpace(normalized) || IPAddress.TryParse(normalized, out _))
        {
            return null;
        }

        var parts = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2)
        {
            return null;
        }

        return $"{parts[^2]}.{parts[^1]}";
    }

    private static string? NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return null;
        }

        var trimmed = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (trimmed.Length == 0)
        {
            return null;
        }

        try
        {
            var idn = new IdnMapping();
            return idn.GetAscii(trimmed);
        }
        catch
        {
            return trimmed;
        }
    }

    private static bool IsLikelyProviderBlockpageHost(string? host)
        => BlockpageHostCatalog.IsLikelyProviderBlockpageHost(host);
}
