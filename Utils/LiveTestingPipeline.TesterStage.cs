using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using IspAudit.Core.Models;

namespace IspAudit.Utils
{
    public partial class LiveTestingPipeline
    {
        /// <summary>
        /// Worker 1: Тестирование хостов
        /// </summary>
        private async Task TesterWorker(CancellationToken ct)
        {
            // Раньше тестер был строго последовательным, из-за чего при активном браузере очередь могла
            // расти быстрее, чем успевал работать тест (DNS/TCP/TLS). У нас уже есть конфиг,
            // но он не использовался: PipelineConfig.MaxConcurrentTests.
            //
            // Здесь используем его как реальный лимит параллелизма тестов.
            var maxConcurrency = _config?.MaxConcurrentTests ?? 1;
            if (maxConcurrency < 1) maxConcurrency = 1;
            if (maxConcurrency > 32) maxConcurrency = 32;

            using var gate = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var inFlight = new HashSet<Task>();
            var maxTracked = Math.Max(64, maxConcurrency * 16);

            var highReader = _snifferHighQueue.Reader;
            var lowReader = _snifferLowQueue.Reader;
            var highCompleted = false;
            var lowCompleted = false;

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    // ВАЖНО (P1.5): берём permit до dequeue.
                    // Иначе при maxConcurrency=1 можно «забрать» low из очереди и не дать high приоритет.
                    await gate.WaitAsync(ct).ConfigureAwait(false);

                    QueuedHost queued;
                    try
                    {
                        var (hasItem, item, highDone, lowDone) = await TryDequeueNextAsync(highReader, lowReader, highCompleted, lowCompleted, ct)
                            .ConfigureAwait(false);
                        highCompleted = highDone;
                        lowCompleted = lowDone;
                        if (!hasItem)
                        {
                            gate.Release();
                            break;
                        }
                        queued = item;
                    }
                    catch
                    {
                        gate.Release();
                        throw;
                    }

                    if (queued.IsHighPriority)
                    {
                        Interlocked.Decrement(ref _pendingInSnifferHigh);
                    }
                    else
                    {
                        Interlocked.Decrement(ref _pendingInSnifferLow);
                    }

                    Interlocked.Increment(ref _statTesterDequeued);

                    // P1.5: метрика QueueAgeMs
                    try
                    {
                        var ageMs = (int)(((Stopwatch.GetTimestamp() - queued.EnqueuedTimestamp) * 1000L) / Stopwatch.Frequency);
                        _queueAgeWindow.Add(ageMs);
                        Interlocked.Increment(ref _statQueueAgeSamples);
                    }
                    catch
                    {
                        // ignore
                    }

                    var task = Task.Run(async () =>
                    {
                        try
                        {
                            await ProcessHostTestAsync(queued.Host, queued.IsHighPriority, ct).ConfigureAwait(false);
                        }
                        finally
                        {
                            gate.Release();
                        }
                    }, ct);

                    inFlight.Add(task);

                    if (inFlight.Count >= maxTracked)
                    {
                        var done = await Task.WhenAny(inFlight).ConfigureAwait(false);
                        inFlight.Remove(done);
                        inFlight.RemoveWhere(t => t.IsCompleted);
                    }
                }

                // Нормальное завершение: дождаться всех незавершённых тестов.
                if (inFlight.Count > 0)
                {
                    await Task.WhenAll(inFlight).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // При отмене не блокируем shutdown ожиданием всех in-flight задач.
            }
        }

        private static async Task<(bool HasItem, QueuedHost Item, bool HighCompleted, bool LowCompleted)> TryDequeueNextAsync(
            ChannelReader<QueuedHost> high,
            ChannelReader<QueuedHost> low,
            bool highCompleted,
            bool lowCompleted,
            CancellationToken ct)
        {
            while (true)
            {
                if (high.TryRead(out var qh)) return (true, qh, highCompleted, lowCompleted);
                if (low.TryRead(out qh)) return (true, qh, highCompleted, lowCompleted);

                if (highCompleted && lowCompleted) return (false, default, true, true);

                Task<bool>? highWait = null;
                Task<bool>? lowWait = null;

                if (!highCompleted)
                {
                    highWait = high.WaitToReadAsync(ct).AsTask();
                }
                if (!lowCompleted)
                {
                    lowWait = low.WaitToReadAsync(ct).AsTask();
                }

                if (highWait == null && lowWait == null) return (false, default, highCompleted, lowCompleted);

                var completed = lowWait == null
                    ? await Task.WhenAny(highWait!).ConfigureAwait(false)
                    : highWait == null
                        ? await Task.WhenAny(lowWait).ConfigureAwait(false)
                        : await Task.WhenAny(highWait, lowWait).ConfigureAwait(false);

                if (completed == highWait)
                {
                    if (!await highWait!.ConfigureAwait(false)) highCompleted = true;
                }
                else
                {
                    if (!await lowWait!.ConfigureAwait(false)) lowCompleted = true;
                }
            }
        }

        private async Task ProcessHostTestAsync(HostDiscovered host, bool isHighPriority, CancellationToken ct)
        {
            // Получаем hostname из объекта или кеша (если есть) для более умной дедупликации
            var hostname = host.SniHostname ?? host.Hostname;
            if (string.IsNullOrEmpty(hostname))
            {
                hostname = _dnsParser?.DnsCache.TryGetValue(host.RemoteIp.ToString(), out var name) == true
                    ? name : null;
            }
            if (string.IsNullOrEmpty(hostname))
            {
                hostname = _dnsParser?.SniCache.TryGetValue(host.RemoteIp.ToString(), out var sniName) == true
                    ? sniName : null;
            }

            // Проверяем через единый фильтр (дедупликация + шум)
            var decision = _filter.ShouldTest(host, hostname);
            if (decision.Action == FilterAction.Drop)
            {
                Interlocked.Increment(ref _statTesterDropped);
                return;
            }

            // Дедупликация на уровне "сессии тестирования":
            // если цель уже была поставлена на тест — повторные события не должны доходить до тестера.
            if (!_stateStore.TryBeginHostTest(host, hostname))
            {
                Interlocked.Increment(ref _statTesterDropped);
                return;
            }

            Interlocked.Increment(ref _pendingInTester);
            try
            {
                // Тестируем хост (DNS, TCP, TLS)
                var testerToUse = _tester;
                if (!isHighPriority && _isDegradeMode && _degradedTester != null)
                {
                    testerToUse = _degradedTester;
                }

                var result = await testerToUse.TestHostAsync(host, ct).ConfigureAwait(false);

                // P1.5: помечаем проблемные IP, чтобы новые события поднимались в high.
                try
                {
                    var ip = host.RemoteIp.ToString();
                    var hasProblem = !result.DnsOk || !result.TcpOk || !result.TlsOk || (result.Http3Ok.HasValue && !result.Http3Ok.Value);
                    if (hasProblem)
                    {
                        _recentProblemIps[ip] = 1;
                    }
                    else
                    {
                        _recentProblemIps.TryRemove(ip, out _);
                    }
                }
                catch
                {
                    // ignore
                }

                await _testerQueue.Writer.WriteAsync(result, ct).ConfigureAwait(false);
                Interlocked.Increment(ref _statTesterCompleted);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Не логируем при отмене
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _statTesterErrors);
                _progress?.Report($"[TESTER] Ошибка тестирования {host.RemoteIp}: {ex.Message}");
            }
            finally
            {
                Interlocked.Decrement(ref _pendingInTester);
            }
        }
    }
}
