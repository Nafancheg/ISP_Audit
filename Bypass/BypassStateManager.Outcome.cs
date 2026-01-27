using System;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Bypass
{
    public sealed partial class BypassStateManager
    {
        private static readonly TimeSpan OutcomeDefaultDelay = TimeSpan.FromSeconds(12);
        private static readonly TimeSpan OutcomeDefaultTimeout = TimeSpan.FromSeconds(6);
        private static readonly TimeSpan OutcomeProbeFlowTtl = TimeSpan.FromSeconds(30);

        private string _outcomeTargetHost = string.Empty;
        private OutcomeStatusSnapshot _lastOutcomeSnapshot = new(OutcomeStatus.Unknown, "UNKNOWN", "нет данных");
        private CancellationTokenSource? _outcomeCts;
        private Func<string, CancellationToken, Task<OutcomeStatusSnapshot>>? _outcomeProbeOverrideForSmoke;

        /// <summary>
        /// Задать цель для outcome-check (обычно — hostKey последнего INTEL-плана/диагноза).
        /// Если цель не задана, outcome остаётся UNKNOWN.
        /// </summary>
        public void SetOutcomeTargetHost(string? host)
        {
            _outcomeTargetHost = (host ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(_outcomeTargetHost))
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "нет цели для outcome-check");
            }
        }

        public string GetOutcomeTargetHost() => _outcomeTargetHost;

        public OutcomeStatusSnapshot GetOutcomeStatusSnapshot()
        {
            var options = _tlsService.GetOptionsSnapshot();
            if (!options.IsAnyEnabled())
            {
                return new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "bypass отключён");
            }

            return _lastOutcomeSnapshot;
        }

        /// <summary>
        /// Немедленно выполняет outcome-probe (без delay), чтобы переоценить доступность цели.
        /// Используется для staged revalidation при смене сети.
        /// </summary>
        public async Task<OutcomeStatusSnapshot> RunOutcomeProbeNowAsync(
            string? hostOverride = null,
            TimeSpan? timeoutOverride = null,
            CancellationToken cancellationToken = default)
        {
            var options = _tlsService.GetOptionsSnapshot();
            if (!options.IsAnyEnabled())
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "bypass отключён");
                return _lastOutcomeSnapshot;
            }

            var host = string.IsNullOrWhiteSpace(hostOverride)
                ? _outcomeTargetHost
                : (hostOverride ?? string.Empty).Trim();

            if (string.IsNullOrWhiteSpace(host))
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "нет цели для outcome-check");
                return _lastOutcomeSnapshot;
            }

            // Отменяем отложенную проверку (если была запланирована), и выполняем probe прямо сейчас.
            CancelOutcomeProbe();

            var timeoutMs = ReadMsEnvAllowZero("ISP_AUDIT_OUTCOME_TIMEOUT_MS", (int)OutcomeDefaultTimeout.TotalMilliseconds);
            var timeout = timeoutOverride ?? TimeSpan.FromMilliseconds(timeoutMs);

            _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "выполняю outcome-probe");

            try
            {
                var snapshot = await RunOutcomeProbeAsync(host, timeout, cancellationToken).ConfigureAwait(false);
                _lastOutcomeSnapshot = snapshot;
                return snapshot;
            }
            catch (OperationCanceledException)
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "outcome-probe отменён");
                return _lastOutcomeSnapshot;
            }
            catch (Exception ex)
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"outcome-probe error: {ex.Message}");
                return _lastOutcomeSnapshot;
            }
        }

        internal void SetOutcomeProbeForSmoke(Func<string, CancellationToken, Task<OutcomeStatusSnapshot>> probe)
        {
            _outcomeProbeOverrideForSmoke = probe;
        }

        private void CancelOutcomeProbe()
        {
            try
            {
                _outcomeCts?.Cancel();
                _outcomeCts?.Dispose();
            }
            catch
            {
                // ignore
            }
            finally
            {
                _outcomeCts = null;
            }
        }

        private void ScheduleOutcomeProbeIfPossible()
        {
            var host = _outcomeTargetHost;
            if (string.IsNullOrWhiteSpace(host))
            {
                _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "нет цели для outcome-check");
                return;
            }

            CancelOutcomeProbe();
            _outcomeCts = new CancellationTokenSource();
            var ct = _outcomeCts.Token;

            var delayMs = ReadMsEnvAllowZero("ISP_AUDIT_OUTCOME_DELAY_MS", (int)OutcomeDefaultDelay.TotalMilliseconds);
            var timeoutMs = ReadMsEnvAllowZero("ISP_AUDIT_OUTCOME_TIMEOUT_MS", (int)OutcomeDefaultTimeout.TotalMilliseconds);

            var delay = TimeSpan.FromMilliseconds(delayMs);
            var timeout = TimeSpan.FromMilliseconds(timeoutMs);

            _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "ожидание outcome-probe");

            _ = Task.Run(async () =>
            {
                try
                {
                    if (delay > TimeSpan.Zero)
                    {
                        await Task.Delay(delay, ct).ConfigureAwait(false);
                    }

                    var snapshot = await RunOutcomeProbeAsync(host, timeout, ct).ConfigureAwait(false);
                    _lastOutcomeSnapshot = snapshot;
                }
                catch (OperationCanceledException)
                {
                    _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Unknown, "UNKNOWN", "outcome-probe отменён");
                }
                catch (Exception ex)
                {
                    _lastOutcomeSnapshot = new OutcomeStatusSnapshot(OutcomeStatus.Failed, "FAILED", $"outcome-probe error: {ex.Message}");
                }
            }, CancellationToken.None);
        }

        private async Task<OutcomeStatusSnapshot> RunOutcomeProbeAsync(string host, TimeSpan timeout, CancellationToken cancellationToken)
        {
            // Smoke-хук: детерминированная подмена, без реальной сети.
            if (_outcomeProbeOverrideForSmoke != null)
            {
                return await _outcomeProbeOverrideForSmoke(host, cancellationToken).ConfigureAwait(false);
            }

            return await HttpsOutcomeProbe.RunAsync(
                host,
                onConnected: (local, remote) =>
                {
                    // Регистрируем flow в фильтре, чтобы probe не попадал в пользовательские метрики.
                    _tlsService.RegisterOutcomeProbeFlow(local, remote, OutcomeProbeFlowTtl);
                },
                timeout: timeout,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }
}
