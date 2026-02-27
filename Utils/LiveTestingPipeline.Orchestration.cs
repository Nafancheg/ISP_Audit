using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    public partial class LiveTestingPipeline
    {
        private async Task HealthLoop(CancellationToken ct)
        {
            // Держим локальные снапшоты, чтобы писать только дельты.
            long prevEnq = 0;
            long prevSnifferDrop = 0;
            long prevTesterDeq = 0;
            long prevTesterDrop = 0;
            long prevTesterOk = 0;
            long prevTesterErr = 0;
            long prevClassifierDeq = 0;
            long prevUiIssues = 0;
            long prevUiLogOnly = 0;
            long prevUiDropped = 0;

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);

                    var enq = Interlocked.Read(ref _statHostsEnqueued);
                    var snifferDrop = Interlocked.Read(ref _statSnifferDropped);
                    var testerDeq = Interlocked.Read(ref _statTesterDequeued);
                    var testerDrop = Interlocked.Read(ref _statTesterDropped);
                    var testerOk = Interlocked.Read(ref _statTesterCompleted);
                    var testerErr = Interlocked.Read(ref _statTesterErrors);
                    var classifierDeq = Interlocked.Read(ref _statClassifierDequeued);
                    var uiIssues = Interlocked.Read(ref _statUiIssuesEnqueued);
                    var uiLogOnly = Interlocked.Read(ref _statUiLogOnly);
                    var uiDropped = Interlocked.Read(ref _statUiDropped);

                    var delta = (enq - prevEnq) + (testerDeq - prevTesterDeq) + (classifierDeq - prevClassifierDeq) + (uiIssues - prevUiIssues);
                    var pending = PendingCount;

                    // P1.5: degrade mode — если очередь стабильно растёт, ускоряем low (timeout/2).
                    try
                    {
                        if (pending > 20)
                        {
                            _degradePendingTicks++;
                        }
                        else
                        {
                            _degradePendingTicks = 0;
                            if (_isDegradeMode && pending < 10)
                            {
                                _isDegradeMode = false;
                                _progress?.Report("[PipelineHealth] degrade=OFF (pending<10)");
                            }
                        }

                        if (!_isDegradeMode && _degradePendingTicks >= 3)
                        {
                            _isDegradeMode = true;
                            _progress?.Report("[PipelineHealth] degrade=ON (pending>20 for 3 ticks)");
                        }
                    }
                    catch
                    {
                        // ignore
                    }

                    // P1.5: QueueAge p95
                    int? queueAgeP95 = null;
                    try
                    {
                        if (_queueAgeWindow.TryGetP95(out var p95))
                        {
                            queueAgeP95 = p95;
                            Interlocked.Exchange(ref _statQueueAgeP95ms, p95);
                        }
                    }
                    catch
                    {
                        // ignore
                    }

                    // Не спамим: если конвейер стоит и очереди пусты — молчим.
                    if (delta == 0 && pending == 0)
                    {
                        continue;
                    }

                    // Если очередь раздувается — это сигнал потерь/узких мест.
                    if (pending >= 200 || delta > 0)
                    {
                        var qAgeText = queueAgeP95.HasValue ? $" qAgeP95={queueAgeP95.Value}ms" : string.Empty;
                        var degradeText = _isDegradeMode ? " degrade=ON" : string.Empty;
                        _progress?.Report(
                            $"[PipelineHealth] pending={pending} | enq={enq}(+{enq - prevEnq}) " +
                            $"snifferDrop={snifferDrop}(+{snifferDrop - prevSnifferDrop}) " +
                            $"tester=deq:{testerDeq}(+{testerDeq - prevTesterDeq}) drop:{testerDrop}(+{testerDrop - prevTesterDrop}) ok:{testerOk}(+{testerOk - prevTesterOk}) err:{testerErr}(+{testerErr - prevTesterErr}) " +
                            $"classifier=deq:{classifierDeq}(+{classifierDeq - prevClassifierDeq}) " +
                            $"ui=issues:{uiIssues}(+{uiIssues - prevUiIssues}) logOnly:{uiLogOnly}(+{uiLogOnly - prevUiLogOnly}) drop:{uiDropped}(+{uiDropped - prevUiDropped})" +
                            degradeText + qAgeText);
                    }

                    prevEnq = enq;
                    prevSnifferDrop = snifferDrop;
                    prevTesterDeq = testerDeq;
                    prevTesterDrop = testerDrop;
                    prevTesterOk = testerOk;
                    prevTesterErr = testerErr;
                    prevClassifierDeq = classifierDeq;
                    prevUiIssues = uiIssues;
                    prevUiLogOnly = uiLogOnly;
                    prevUiDropped = uiDropped;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
            }
            catch
            {
                // Health-лог не должен валить pipeline
            }
        }

        /// <summary>
        /// Завершает приём новых хостов и ожидает обработки всех в очереди
        /// </summary>
        /// <param name="timeout">Максимальное время ожидания</param>
        /// <returns>true если все хосты обработаны, false если таймаут</returns>
        public async Task<bool> DrainAndCompleteAsync(TimeSpan timeout)
        {
            // Закрываем входную очередь - больше хостов не будет.
            // ВАЖНО: завершение делаем по цепочке (tester→classifier→ui), иначе возможна гонка:
            // PendingCount не учитывает элементы, уже лежащие в Channel, и ранний TryComplete может
            // закрыть _bypassQueue до того, как ClassifierWorker успеет написать туда элемент.
            _snifferHighQueue.Writer.TryComplete();
            _snifferLowQueue.Writer.TryComplete();

            _progress?.Report($"[Pipeline] Ожидание завершения тестов... (pending: {PendingCount})");

            var deadline = DateTime.UtcNow + timeout;

            async Task<bool> WaitTaskWithDeadlineAsync(Task task)
            {
                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero) return false;
                var completedTask = await Task.WhenAny(task, Task.Delay(remaining)).ConfigureAwait(false);
                return completedTask == task;
            }

            // 1) Ждём, пока тестер дочитает sniffer-очередь и допишет всё в tester-очередь.
            if (_workers.Length >= 1)
            {
                if (!await WaitTaskWithDeadlineAsync(_workers[0]).ConfigureAwait(false))
                {
                    _progress?.Report("[Pipeline] ⚠ Таймаут на завершении TesterWorker");
                    return false;
                }
            }
            _testerQueue.Writer.TryComplete();

            // 2) Ждём, пока классификатор дочитает tester-очередь и допишет всё в bypass-очередь.
            if (_workers.Length >= 2)
            {
                if (!await WaitTaskWithDeadlineAsync(_workers[1]).ConfigureAwait(false))
                {
                    _progress?.Report("[Pipeline] ⚠ Таймаут на завершении ClassifierWorker");
                    return false;
                }
            }
            _bypassQueue.Writer.TryComplete();

            // 3) Ждём, пока UI воркер дочитает bypass-очередь и выплюнет все строки.
            if (_workers.Length >= 3)
            {
                if (!await WaitTaskWithDeadlineAsync(_workers[2]).ConfigureAwait(false))
                {
                    _progress?.Report("[Pipeline] ⚠ Таймаут на завершении UiWorker");
                    return false;
                }
            }

            _progress?.Report("[Pipeline] ✓ Все тесты завершены");
            return true;
        }

        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            try
            {
                _cts.Cancel();
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN][SNIFFER][END] Pipeline CTS cancel failed: action=continue; type={ex.GetType().Name}; msg={ex.Message}; hresult={ex.HResult}");
            }

            _snifferHighQueue.Writer.TryComplete();
            _snifferLowQueue.Writer.TryComplete();
            _testerQueue.Writer.TryComplete();
            _bypassQueue.Writer.TryComplete();

            try
            {
                // P2.RUNTIME.1: не блокируем Dispose через Wait/Result.
                var workersTask = _healthTask != null
                    ? Task.WhenAny(Task.WhenAll(_workers.Append(_healthTask)), Task.Delay(3000))
                    : Task.WhenAny(Task.WhenAll(_workers), Task.Delay(3000));

                _ = workersTask.ContinueWith(t =>
                {
                    if (t.Exception != null)
                    {
                        _progress?.Report($"[Pipeline] WARN dispose async wait failed: {t.Exception.GetBaseException().Message}");
                    }

                    try
                    {
                        _cts.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _progress?.Report($"[WARN][SNIFFER][END] Pipeline CTS dispose failed (continuation): action=continue; type={ex.GetType().Name}; msg={ex.Message}; hresult={ex.HResult}");
                    }
                }, TaskScheduler.Default);
            }
            catch (Exception ex)
            {
                _progress?.Report($"[WARN][SNIFFER][END] Pipeline dispose continuation setup failed: action=fallback_dispose; type={ex.GetType().Name}; msg={ex.Message}; hresult={ex.HResult}");
                try
                {
                    _cts.Dispose();
                }
                catch (Exception disposeEx)
                {
                    _progress?.Report($"[WARN][SNIFFER][END] Pipeline CTS dispose failed (fallback): action=continue; type={disposeEx.GetType().Name}; msg={disposeEx.Message}; hresult={disposeEx.HResult}");
                }
            }
        }
    }
}
