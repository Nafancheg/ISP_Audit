using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;

namespace IspAudit.Bypass
{
    public partial class TlsBypassService
    {
        /// <summary>
        /// Текущий снимок опций (без повторного построения профиля).
        /// </summary>
        public TlsBypassOptions GetOptionsSnapshot()
        {
            lock (_sync)
            {
                return _options;
            }
        }

        /// <summary>
        /// Применить новый набор опций TLS bypass.
        /// </summary>
        public async Task ApplyAsync(TlsBypassOptions options, CancellationToken cancellationToken = default)
        {
            BypassStateManagerGuard.WarnIfBypassed(_log, "TlsBypassService.ApplyAsync");

            lock (_sync)
            {
                _options = options.Normalize();
            }

            await ApplyInternalAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Применить преподготовленный профиль (используется для преимптивного включения).
        /// </summary>
        public Task ApplyPreemptiveAsync(CancellationToken cancellationToken = default)
        {
            var preset = _options with
            {
                FragmentEnabled = false,
                DisorderEnabled = true,
                FakeEnabled = false,
                DropRstEnabled = true
            };

            return ApplyAsync(preset, cancellationToken);
        }

        /// <summary>
        /// Отключить bypass и удалить фильтр.
        /// </summary>
        public Task DisableAsync(CancellationToken cancellationToken = default)
        {
            BypassStateManagerGuard.WarnIfBypassed(_log, "TlsBypassService.DisableAsync");
            return ApplyAsync(_options with
            {
                FragmentEnabled = false,
                DisorderEnabled = false,
                FakeEnabled = false,
                DropRstEnabled = false,
                AllowNoSni = false,
                DropUdp443 = false,
                // Важно: DisableAsync должен полностью выключать bypass.
                // Иначе TtlTrickEnabled из профиля может оставить IsAnyEnabled()==true
                // и фильтр будет пересоздан/останется в TrafficEngine.
                TtlTrickEnabled = false,
                AutoTtlEnabled = false
            }, cancellationToken);
        }

        private async Task ApplyInternalAsync(CancellationToken cancellationToken)
        {
            var totalSw = Stopwatch.StartNew();
            var currentPhase = "enter";

            // Снимок корреляции: помогает сопоставить зависание/таймаут apply с транзакцией UI.
            var opSnapshot = BypassOperationContext.Snapshot();
            var corr = opSnapshot?.CorrelationId;
            var corrText = string.IsNullOrWhiteSpace(corr) ? "-" : corr;

            void LogPhase(string phase, long elapsedMs, long warnThresholdMs, string details = "")
            {
                try
                {
                    var warn = elapsedMs >= warnThresholdMs ? "WARN" : "OK";
                    var safeDetails = string.IsNullOrWhiteSpace(details) ? string.Empty : "; " + details;
                    _log?.Invoke($"[Bypass][ApplyInternal] {warn}: phase={phase}; ms={elapsedMs}; corr={corrText}{safeDetails}");
                }
                catch
                {
                    // best-effort
                }
            }

            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                // P0.1 observability: привязываем мутации TrafficEngine к корреляционному контексту операции.
                // Это помогает расследовать редкие падения loop (например, "Collection was modified") без репро.
                try
                {
                    var op = BypassOperationContext.Snapshot();
                    if (op != null)
                    {
                        TlsBypassOptions optionsSnapshotForDiag;
                        lock (_sync)
                        {
                            optionsSnapshotForDiag = _options;
                        }

                        var details = $"host={op.HostKey}; group={op.GroupKey}; options={optionsSnapshotForDiag.ToReadableStrategy()}";
                        _trafficEngine.SetLastMutationContext(op.CorrelationId, op.Operation, details);
                    }
                }
                catch
                {
                    // best-effort
                }

                // Smoke-режим (без TrafficEngine) выполняется почти синхронно.
                // Добавляем небольшую отменяемую задержку, чтобы детерминированно тестировать
                // таймаут/Cancel и безопасный откат на верхнем уровне.
                if (!_useTrafficEngine)
                {
                    currentPhase = "smoke_delay";
                    await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken).ConfigureAwait(false);
                }

                if (_useTrafficEngine)
                {
                    currentPhase = "engine_remove_filter";
                    var sw = Stopwatch.StartNew();
                    _trafficEngine.RemoveFilter("BypassFilter");
                    sw.Stop();
                    LogPhase("engine_remove_filter", sw.ElapsedMilliseconds, warnThresholdMs: 250, "name=BypassFilter");
                }

                TlsBypassOptions optionsSnapshot;
                lock (_sync)
                {
                    optionsSnapshot = _options;
                }

                if (!optionsSnapshot.IsAnyEnabled())
                {
                    currentPhase = "disabled";
                    _filter = null;
                    _metricsSince = DateTime.MinValue;
                    StateChanged?.Invoke(new TlsBypassState(false, "-", "-"));
                    MetricsUpdated?.Invoke(TlsBypassMetrics.Empty);
                    VerdictChanged?.Invoke(TlsBypassVerdict.CreateInactive());
                    _log?.Invoke("[Bypass] Все опции отключены");
                    return;
                }

                currentPhase = "build_profile";
                var profileSw = Stopwatch.StartNew();
                var profile = BuildProfile(optionsSnapshot);
                profileSw.Stop();
                LogPhase("build_profile", profileSw.ElapsedMilliseconds, warnThresholdMs: 250, $"preset={optionsSnapshot.PresetName}");

                currentPhase = "build_filter";
                var filterSw = Stopwatch.StartNew();
                var filter = new BypassFilter(profile, _log, optionsSnapshot.PresetName);
                filterSw.Stop();
                LogPhase("build_filter", filterSw.ElapsedMilliseconds, warnThresholdMs: 250, $"preset={optionsSnapshot.PresetName}");

                // Важно: фильтр пересоздаётся при каждом Apply. Пробрасываем runtime-настройки,
                // которые хранятся в сервисе и должны переживать пересоздание.
                uint[] udp443TargetsSnapshot;
                IspAudit.Core.Models.DecisionGraphSnapshot? decisionSnapshot;
                lock (_sync)
                {
                    udp443TargetsSnapshot = _udp443DropTargetIps.Length == 0 ? Array.Empty<uint>() : _udp443DropTargetIps.ToArray();
                    decisionSnapshot = _decisionGraphSnapshot;
                }
                currentPhase = "configure_filter";
                var cfgSw = Stopwatch.StartNew();
                filter.SetUdp443DropTargetIps(udp443TargetsSnapshot);
                filter.SetDecisionGraphSnapshot(decisionSnapshot);
                cfgSw.Stop();
                LogPhase("configure_filter", cfgSw.ElapsedMilliseconds, warnThresholdMs: 250, $"udp443Targets={udp443TargetsSnapshot.Length}; hasPolicySnapshot={(decisionSnapshot != null ? "yes" : "no")}");

                if (_useTrafficEngine)
                {
                    currentPhase = "engine_register_filter";
                    var regSw = Stopwatch.StartNew();
                    _trafficEngine.RegisterFilter(filter);
                    regSw.Stop();
                    LogPhase("engine_register_filter", regSw.ElapsedMilliseconds, warnThresholdMs: 250, "type=BypassFilter");

                    if (!_trafficEngine.IsRunning)
                    {
                        currentPhase = "engine_start";
                        var startSw = Stopwatch.StartNew();
                        await _trafficEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                        startSw.Stop();
                        LogPhase("engine_start", startSw.ElapsedMilliseconds, warnThresholdMs: 1500);
                    }
                }

                lock (_sync)
                {
                    _filter = filter;
                    _metricsSince = _now();
                }

                currentPhase = "finalize";
                StateChanged?.Invoke(new TlsBypassState(true, "-", _metricsSince.ToString("HH:mm:ss")));
                _log?.Invoke($"[Bypass] Применены опции: {optionsSnapshot.ToReadableStrategy()} | TLS chunks: {optionsSnapshot.FragmentSizesAsText()}, threshold: {profile.TlsFragmentThreshold}");

                totalSw.Stop();
                LogPhase("total", totalSw.ElapsedMilliseconds, warnThresholdMs: 3000);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    totalSw.Stop();
                    LogPhase("canceled", totalSw.ElapsedMilliseconds, warnThresholdMs: 0, $"at={currentPhase}");
                }
                catch
                {
                    // best-effort
                }

                _log?.Invoke("[Bypass] Применение отменено");
                throw;
            }
            catch (Exception ex)
            {
                try
                {
                    totalSw.Stop();
                    LogPhase("failed", totalSw.ElapsedMilliseconds, warnThresholdMs: 0, $"at={currentPhase}; error={ex.Message}");
                }
                catch
                {
                    // best-effort
                }

                _log?.Invoke($"[Bypass] Ошибка применения опций: {ex}");
            }
        }

        private BypassProfile BuildProfile(TlsBypassOptions options)
        {
            var tlsStrategy = TlsBypassStrategy.None;

            if (options.DisorderEnabled && options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.FakeDisorder;
            else if (options.FragmentEnabled && options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.FakeFragment;
            else if (options.DisorderEnabled)
                tlsStrategy = TlsBypassStrategy.Disorder;
            else if (options.FakeEnabled)
                tlsStrategy = TlsBypassStrategy.Fake;
            else if (options.FragmentEnabled)
                tlsStrategy = TlsBypassStrategy.Fragment;

            // Делаем обход более "липким" при включённом AllowNoSni:
            // - ClientHello часто сегментируется на несколько TCP пакетов
            // - порог 128 может не дать шанса стратегии сработать
            // В этом режиме мы не зависим от успешного парсинга SNI.
            var tlsThreshold = options.AllowNoSni ? 1 : _baseProfile.TlsFragmentThreshold;

            return new BypassProfile
            {
                DropTcpRst = options.DropRstEnabled,
                FragmentTlsClientHello = options.FragmentEnabled || options.DisorderEnabled || options.FakeEnabled,
                TlsStrategy = tlsStrategy,
                TlsFirstFragmentSize = _baseProfile.TlsFirstFragmentSize,
                TlsFragmentThreshold = tlsThreshold,
                TlsFragmentSizes = options.FragmentSizes,
                TtlTrick = options.TtlTrickEnabled,
                TtlTrickValue = options.TtlTrickValue,
                AutoTtl = options.AutoTtlEnabled,
                AllowNoSni = options.AllowNoSni,
                DropUdp443 = options.DropUdp443,
                DropUdp443Global = options.DropUdp443 && options.DropUdp443Global,
                HttpHostTricks = options.HttpHostTricksEnabled,
                BadChecksum = options.BadChecksumEnabled,
                RedirectRules = _baseProfile.RedirectRules
            };
        }

        private static IReadOnlyList<TlsFragmentPreset> BuildPresets(BypassProfile baseProfile)
        {
            var profileSizes = baseProfile.TlsFragmentSizes ?? new List<int> { baseProfile.TlsFirstFragmentSize };
            var safeProfileSizes = profileSizes.Select(v => Math.Max(4, v)).ToList();

            return new List<TlsFragmentPreset>
            {
                new("Стандарт", new List<int> { 64 }, "Баланс: один фрагмент 64 байта"),
                new("Умеренный", new List<int> { 96 }, "Чуть крупнее фрагмент для совместимости"),
                new("Агрессивный", new List<int> { 32, 32 }.Select(v => Math.Max(4, v)).ToList(), "Два мелких фрагмента для сложных DPI"),
                new("Профиль", safeProfileSizes, "Размеры из bypass_profile.json")
            };
        }
    }
}
