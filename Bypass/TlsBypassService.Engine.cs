using System;
using System.Collections.Generic;
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
                    await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken).ConfigureAwait(false);
                }

                if (_useTrafficEngine)
                {
                    _trafficEngine.RemoveFilter("BypassFilter");
                }

                TlsBypassOptions optionsSnapshot;
                lock (_sync)
                {
                    optionsSnapshot = _options;
                }

                if (!optionsSnapshot.IsAnyEnabled())
                {
                    _filter = null;
                    _metricsSince = DateTime.MinValue;
                    StateChanged?.Invoke(new TlsBypassState(false, "-", "-"));
                    MetricsUpdated?.Invoke(TlsBypassMetrics.Empty);
                    VerdictChanged?.Invoke(TlsBypassVerdict.CreateInactive());
                    _log?.Invoke("[Bypass] Все опции отключены");
                    return;
                }

                var profile = BuildProfile(optionsSnapshot);
                var filter = new BypassFilter(profile, _log, optionsSnapshot.PresetName);

                // Важно: фильтр пересоздаётся при каждом Apply. Пробрасываем runtime-настройки,
                // которые хранятся в сервисе и должны переживать пересоздание.
                uint[] udp443TargetsSnapshot;
                IspAudit.Core.Models.DecisionGraphSnapshot? decisionSnapshot;
                lock (_sync)
                {
                    udp443TargetsSnapshot = _udp443DropTargetIps.Length == 0 ? Array.Empty<uint>() : _udp443DropTargetIps.ToArray();
                    decisionSnapshot = _decisionGraphSnapshot;
                }
                filter.SetUdp443DropTargetIps(udp443TargetsSnapshot);
                filter.SetDecisionGraphSnapshot(decisionSnapshot);

                if (_useTrafficEngine)
                {
                    _trafficEngine.RegisterFilter(filter);

                    if (!_trafficEngine.IsRunning)
                    {
                        await _trafficEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                    }
                }

                lock (_sync)
                {
                    _filter = filter;
                    _metricsSince = _now();
                }

                StateChanged?.Invoke(new TlsBypassState(true, "-", _metricsSince.ToString("HH:mm:ss")));
                _log?.Invoke($"[Bypass] Применены опции: {optionsSnapshot.ToReadableStrategy()} | TLS chunks: {optionsSnapshot.FragmentSizesAsText()}, threshold: {profile.TlsFragmentThreshold}");
            }
            catch (OperationCanceledException)
            {
                _log?.Invoke("[Bypass] Применение отменено");
                throw;
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass] Ошибка применения опций: {ex.Message}");
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
