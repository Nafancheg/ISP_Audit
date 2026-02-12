using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Intelligence.Feedback;

namespace IspAudit.Core.Intelligence.Strategies;

/// <summary>
/// Минимальный селектор стратегий INTEL (MVP).
/// ВАЖНО: решение принимает строго по <see cref="DiagnosisResult"/> (id + confidence),
/// но может использовать минимальные факты из InputSignals для assist-рекомендаций (QUIC fallback / allow-no-SNI).
/// </summary>
public sealed class StandardStrategySelector
{
    private readonly IFeedbackStore? _feedbackStore;
    private readonly FeedbackStoreOptions _feedbackOptions;

    public StandardStrategySelector()
        : this(feedbackStore: null, feedbackOptions: null)
    {
    }

    public StandardStrategySelector(IFeedbackStore? feedbackStore, FeedbackStoreOptions? feedbackOptions = null)
    {
        _feedbackStore = feedbackStore;
        _feedbackOptions = feedbackOptions ?? new FeedbackStoreOptions();
    }

    private static readonly HashSet<StrategyId> ImplementedStrategies =
    [
        StrategyId.TlsDisorder,
        StrategyId.TlsFragment,
        StrategyId.DropRst,
        StrategyId.UseDoh,
        StrategyId.HttpHostTricks,
        StrategyId.BadChecksum,
    ];

    private static readonly HashSet<StrategyId> DeferredStrategies =
    [
    ];

    /// <summary>
    /// Построить план рекомендаций.
    /// Жёсткие защиты:
    /// - confidence &lt; 50 → пустой план
    /// - RiskLevel.High запрещён при confidence &lt; 70
    /// - нереализованные стратегии: warning + skip (без исключений)
    /// </summary>
    public BypassPlan Select(DiagnosisResult diagnosis, Action<string>? warningLog = null)
    {
        if (diagnosis is null) throw new ArgumentNullException(nameof(diagnosis));

        var confidence = Math.Clamp(diagnosis.Confidence, 0, 100);

        if (confidence < 50)
        {
            return CreateEmptyPlan(diagnosis.DiagnosisId, confidence, "confidence < 50");
        }

        var candidates = BuildCandidates(diagnosis.DiagnosisId);

        var filtered = new List<BypassStrategy>(capacity: candidates.Count);
        var deferred = new List<DeferredBypassStrategy>(capacity: 3);

        foreach (var candidate in candidates)
        {
            if (candidate.Risk == RiskLevel.High && confidence < StrategyContractConstraints.MinConfidenceForHighRiskStrategies)
            {
                continue;
            }

            if (!ImplementedStrategies.Contains(candidate.Id))
            {
                // Отложенные стратегии не должны попадать в применяемый список, но должны быть видны в UI/логах.
                if (DeferredStrategies.Contains(candidate.Id))
                {
                    deferred.Add(new DeferredBypassStrategy
                    {
                        Id = candidate.Id,
                        Risk = candidate.Risk,
                        Reason = "отложено: техника помечена как deferred (не применяется автоматически)"
                    });
                    continue;
                }

                EmitWarning(warningLog, $"[INTEL][Selector] Стратегия {candidate.Id} не реализована — пропуск.");
                continue;
            }

            filtered.Add(new BypassStrategy
            {
                Id = candidate.Id,
                BasePriority = candidate.BasePriority,
                Risk = candidate.Risk,
                Parameters = candidate.Parameters
            });
        }

        // Важно: допускаем assist-only план даже без стратегий.
        // Например, для QUIC/HTTP3 иногда достаточно DropUdp443 (принудить H3→H2).

        var forDiagnosisId = diagnosis.DiagnosisId;

        // P1.14: сортировка по PlanWeight:
        // weight = strength × confidence / cost
        // где:
        // - strength: BasePriority (таблица маппинга)
        // - confidence: уверенность диагноза
        // - cost: оценка цены/риска (Low=1, Medium=2, High=3)
        // Дополнительно: feedback boost по win-rate:
        // - WinRate > 70% → ×1.5
        // - WinRate < 30% → ×0.5
        var ranked = filtered
            .Select(s =>
            {
                var cost = GetStrategyCost(s.Risk);
                var strength = s.BasePriority;
                var weight = (strength * confidence) / (double)cost;

                var feedbackMultiplier = TryGetFeedbackMultiplier(forDiagnosisId, s.Id);
                weight *= feedbackMultiplier;

                return new RankedStrategy(s, weight, feedbackMultiplier);
            })
            .ToList();

        var ordered = ranked
            .OrderByDescending(s => s.PlanWeight)
            .ThenByDescending(s => s.BasePriority)
            .ThenBy(s => s.Risk)
            .ThenBy(s => s.Id)
            .Select(s => s.Strategy)
            .ToList();

        // Важное правило UX/исполнения: одновременно должен применяться только один режим TLS-обхода.
        // Иначе селектор может выдать противоречивые рекомендации (например, Disorder + Fragment),
        // а исполнитель всё равно вынужден выбрать одну (см. профиль TLS strategy).
        ordered = KeepOnlyOneTlsModeStrategy(ordered);

        // Assist-рекомендации (MVP):
        // - DropUdp443: если есть признаки проблем QUIC/HTTP3.
        //   Приоритет: реальные HTTP/3 пробы (HostTester) > эвристика "безответные UDP рукопожатия".
        //   ВАЖНО: если уже есть TLS timeout на TCP/443, то QUIC→TCP не является приоритетным лечением
        //   (это не устраняет TLS проблему) — тогда не навязываем DropUdp443, чтобы не путать пользователя.
        // - AllowNoSni: если SNI часто отсутствует в HostTested, а мы рекомендуем TLS-обход.
        var hasTlsBypassStrategy = ordered.Any(s => s.Id is StrategyId.TlsFragment or StrategyId.TlsDisorder or StrategyId.AggressiveFragment or StrategyId.TlsFakeTtl);

        var signals = diagnosis.InputSignals;

        var hasHttp3Evidence = signals.Http3AttemptCount > 0;
        var hasHttp3FailureOnly = hasHttp3Evidence
            && signals.Http3NotSupportedCount == 0
            && signals.Http3SuccessCount == 0
            && signals.Http3FailureCount > 0;

        var hasUdpHeuristic = signals.UdpUnansweredHandshakes >= 2;
        var hasQuicEvidence = hasHttp3Evidence ? hasHttp3FailureOnly : hasUdpHeuristic;

        // QUIC fallback SSoT: DropUdp443 — единственный канонический action в плане.
        // Не дублируем StrategyId.QuicObfuscation в plan.Strategies.
        // Правило: не навязываем QUIC→TCP, если уже есть TLS timeout на TCP/443.
        var recommendDropUdp443 = false;
        if (!signals.HasTlsTimeout)
        {
            // Для диагнозов DPI (ActiveDpiEdge/StatefulDpi) допускаем assist без доп. evidence:
            // QUIC часто мешает увидеть эффект TLS-обхода.
            if (forDiagnosisId is DiagnosisId.ActiveDpiEdge or DiagnosisId.StatefulDpi)
            {
                recommendDropUdp443 = true;
            }
            else if (forDiagnosisId == DiagnosisId.QuicInterference)
            {
                recommendDropUdp443 = hasQuicEvidence;
            }
            else if (hasHttp3Evidence && hasHttp3FailureOnly)
            {
                // Реальные H3 пробы: если H3 только падает, QUIC→TCP часто помогает.
                recommendDropUdp443 = true;
            }
        }

        // DNS-only кейс: QUIC fallback не является приоритетным лечением.
        if (forDiagnosisId == DiagnosisId.DnsHijack)
        {
            recommendDropUdp443 = false;
        }

        var recommendAllowNoSni = false;
        if (hasTlsBypassStrategy && signals.HostTestedCount >= 2)
        {
            var ratio = (double)signals.HostTestedNoSniCount / Math.Max(1, signals.HostTestedCount);
            recommendAllowNoSni = signals.HostTestedNoSniCount >= 2 && ratio >= 0.70;
        }

        var anyFeedbackApplied = ranked.Any(r => Math.Abs(r.FeedbackMultiplier - 1.0) > 0.0001);

        var reasoning = anyFeedbackApplied
            ? "план сформирован по диагнозу INTEL (feedback)"
            : "план сформирован по диагнозу INTEL (MVP)";

        if (candidates.Count == 0)
        {
            reasoning += "; нет маппинга стратегий для диагноза";
        }

        if (recommendDropUdp443)
        {
            reasoning += "; assist: QUIC→TCP";
        }
        if (recommendAllowNoSni)
        {
            reasoning += "; assist: No SNI";
        }

        if (forDiagnosisId == DiagnosisId.HttpRedirect && !string.IsNullOrWhiteSpace(signals.RedirectToHost))
        {
            reasoning += $"; redirectHost={signals.RedirectToHost}";
            if (confidence < 70)
            {
                reasoning += "; возможно captive portal/роутер (проверь сеть/авторизацию)";
            }
        }

        if (deferred.Count > 0)
        {
            reasoning += "; deferred: " + string.Join(", ", deferred.Select(d => d.Id));
        }

        if (ordered.Count == 0 && deferred.Count == 0 && !recommendDropUdp443 && !recommendAllowNoSni)
        {
            return CreateEmptyPlan(diagnosis.DiagnosisId, confidence,
                candidates.Count == 0
                    ? "нет маппинга для диагноза"
                    : "все стратегии отфильтрованы по риску/реализации");
        }

        return new BypassPlan
        {
            ForDiagnosis = forDiagnosisId,
            PlanConfidence = confidence,
            PlannedAtUtc = DateTimeOffset.UtcNow,
            Reasoning = reasoning,
            DropUdp443 = recommendDropUdp443,
            AllowNoSni = recommendAllowNoSni,
            Strategies = ordered,
            DeferredStrategies = deferred
        };
    }

    private static List<BypassStrategy> KeepOnlyOneTlsModeStrategy(List<BypassStrategy> strategies)
    {
        // Группа взаимоисключающих стратегий. Оставляем первую по ранжированию.
        var tlsModeGroup = new HashSet<StrategyId>
        {
            StrategyId.TlsDisorder,
            StrategyId.TlsFragment,
            StrategyId.AggressiveFragment,
        };

        var result = new List<BypassStrategy>(strategies.Count);
        var tlsModeAlreadyAdded = false;

        foreach (var strategy in strategies)
        {
            if (!tlsModeGroup.Contains(strategy.Id))
            {
                result.Add(strategy);
                continue;
            }

            if (tlsModeAlreadyAdded)
            {
                continue;
            }

            result.Add(strategy);
            tlsModeAlreadyAdded = true;
        }

        return result;
    }

    private double TryGetFeedbackMultiplier(DiagnosisId diagnosisId, StrategyId strategyId)
    {
        if (_feedbackStore == null)
        {
            return 1.0;
        }

        if (!_feedbackStore.TryGetStats(new FeedbackKey(diagnosisId, strategyId), out var stats))
        {
            return 1.0;
        }

        if (stats.TotalCount < _feedbackOptions.MinSamplesToAffectRanking)
        {
            return 1.0;
        }

        // P1.14: пороговая схема.
        if (stats.SuccessRate > 0.70)
        {
            return 1.5;
        }
        if (stats.SuccessRate < 0.30)
        {
            return 0.5;
        }

        return 1.0;
    }

    private static int GetStrategyCost(RiskLevel risk)
    {
        return risk switch
        {
            RiskLevel.Low => 1,
            RiskLevel.Medium => 2,
            RiskLevel.High => 3,
            _ => 2,
        };
    }

    private static BypassPlan CreateEmptyPlan(DiagnosisId diagnosisId, int confidence, string reason)
    {
        return new BypassPlan
        {
            ForDiagnosis = diagnosisId,
            PlanConfidence = confidence,
            PlannedAtUtc = DateTimeOffset.UtcNow,
            Reasoning = reason,
            Strategies = new List<BypassStrategy>()
        };
    }

    private static void EmitWarning(Action<string>? warningLog, string message)
    {
        if (warningLog != null)
        {
            warningLog(message);
            return;
        }

        Trace.WriteLine(message);
    }

    private static List<StrategyTemplate> BuildCandidates(DiagnosisId diagnosisId)
    {
        // MVP: маппинг небольшой и консервативный.
        // ВАЖНО: не читаем diagnosis.InputSignals / метрики — только DiagnosisId.
        return diagnosisId switch
        {
            // Fallback: если данных мало и диагноз остался Unknown, всё равно полезно предложить
            // самый базовый и относительно безопасный TLS-обход. Это помогает восстановить
            // поведение "хотя бы не хуже" legacy без возврата legacy-классификатора.
            DiagnosisId.Unknown =>
            [
                new StrategyTemplate(
                    StrategyId.TlsFragment,
                    BasePriority: 60,
                    Risk: RiskLevel.Medium,
                    Parameters: new Dictionary<string, object?>
                    {
                        ["PresetName"] = "Стандарт",
                        ["TlsFragmentSizes"] = new[] { 64 },
                        ["AutoAdjustAggressive"] = false
                    })
            ],

            // MVP/практика: при "чисто DNS" диагнозе даём низкорисковую рекомендацию DoH.
            // Это не авто-применение: пользователь включает DoH вручную или через Apply INTEL.
            DiagnosisId.DnsHijack =>
            [
                new StrategyTemplate(StrategyId.UseDoh, BasePriority: 80, Risk: RiskLevel.Low, Parameters: new Dictionary<string, object?>()),
            ],

            DiagnosisId.SilentDrop =>
            [
                new StrategyTemplate(
                    StrategyId.TlsFragment,
                    BasePriority: 90,
                    Risk: RiskLevel.Medium,
                    Parameters: new Dictionary<string, object?>
                    {
                        // Явно задаём параметры, чтобы план был детерминированным.
                        // Иначе executor оставит текущий пресет пользователя, и результат будет зависеть от UI-состояния.
                        ["PresetName"] = "Стандарт",
                        ["TlsFragmentSizes"] = new[] { 64 },
                        ["AutoAdjustAggressive"] = false
                    }),
                new StrategyTemplate(StrategyId.DropRst, BasePriority: 50, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
            ],

            DiagnosisId.MultiLayerBlock =>
            [
                new StrategyTemplate(StrategyId.UseDoh, BasePriority: 100, Risk: RiskLevel.Low, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(StrategyId.TlsDisorder, BasePriority: 90, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(StrategyId.DropRst, BasePriority: 50, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
            ],

            DiagnosisId.TlsInterference =>
            [
                // Консервативно: предлагаем TLS-обход, но без high-risk. Параметры по умолчанию.
                new StrategyTemplate(StrategyId.TlsDisorder, BasePriority: 90, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(
                    StrategyId.TlsFragment,
                    BasePriority: 80,
                    Risk: RiskLevel.Medium,
                    Parameters: new Dictionary<string, object?>
                    {
                        ["PresetName"] = "Стандарт",
                        ["TlsFragmentSizes"] = new[] { 64 },
                        ["AutoAdjustAggressive"] = false
                    }),
                new StrategyTemplate(StrategyId.DropRst, BasePriority: 30, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
            ],

            // HTTP редирект (заглушка/подмена ответа). В MVP реагируем консервативно: HTTP Host tricks (TCP/80).
            DiagnosisId.HttpRedirect =>
            [
                new StrategyTemplate(StrategyId.HttpHostTricks, BasePriority: 85, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
            ],

            // Будущие диагнозы (может появиться в следующих итерациях diagnosis engine)
            DiagnosisId.ActiveDpiEdge or DiagnosisId.StatefulDpi =>
            [
                new StrategyTemplate(StrategyId.TlsDisorder, BasePriority: 90, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(
                    StrategyId.TlsFragment,
                    BasePriority: 80,
                    Risk: RiskLevel.Medium,
                    Parameters: new Dictionary<string, object?>
                    {
                        ["PresetName"] = "Стандарт",
                        ["TlsFragmentSizes"] = new[] { 64 },
                        ["AutoAdjustAggressive"] = false
                    }),
                new StrategyTemplate(StrategyId.DropRst, BasePriority: 50, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),

                // Phase 3 техники (implemented): попадают в plan.Strategies и применяются при ручном ApplyIntelPlanAsync.
                // Примечания:
                // - QUIC→TCP fallback реализован через assist-флаг DropUdp443 (SSoT, без StrategyId.QuicObfuscation в списке).
                // - BadChecksum влияет только на фейковые пакеты.
                new StrategyTemplate(StrategyId.HttpHostTricks, BasePriority: 10, Risk: RiskLevel.Medium, Parameters: new Dictionary<string, object?>()),
                new StrategyTemplate(StrategyId.BadChecksum, BasePriority: 1, Risk: RiskLevel.High, Parameters: new Dictionary<string, object?>()),

                // High-risk стратегия: разрешена только при confidence >= 70.
                new StrategyTemplate(StrategyId.AggressiveFragment, BasePriority: 20, Risk: RiskLevel.High, Parameters: new Dictionary<string, object?>())
            ],

            _ => new List<StrategyTemplate>()
        };
    }

    private sealed record StrategyTemplate(
        StrategyId Id,
        int BasePriority,
        RiskLevel Risk,
        Dictionary<string, object?> Parameters)
    {
    }

    private readonly record struct RankedStrategy(BypassStrategy Strategy, double PlanWeight, double FeedbackMultiplier)
    {
        public StrategyId Id => Strategy.Id;
        public int BasePriority => Strategy.BasePriority;
        public RiskLevel Risk => Strategy.Risk;
    }
}
