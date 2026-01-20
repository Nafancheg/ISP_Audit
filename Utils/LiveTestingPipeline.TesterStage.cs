using System;
using System.Collections.Generic;
using System.Threading;
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

            try
            {
                await foreach (var host in _snifferQueue.Reader.ReadAllAsync(ct))
                {
                    Interlocked.Decrement(ref _pendingInSniffer);
                    Interlocked.Increment(ref _statTesterDequeued);

                    await gate.WaitAsync(ct).ConfigureAwait(false);

                    // Запускаем тест асинхронно, сохраняя лимит по параллелизму.
                    var task = Task.Run(async () =>
                    {
                        try
                        {
                            await ProcessHostTestAsync(host, ct).ConfigureAwait(false);
                        }
                        finally
                        {
                            gate.Release();
                        }
                    }, ct);

                    inFlight.Add(task);

                    // Не даём коллекции задач расти без ограничений.
                    if (inFlight.Count >= maxTracked)
                    {
                        var done = await Task.WhenAny(inFlight).ConfigureAwait(false);
                        inFlight.Remove(done);

                        // Дочищаем всё, что уже завершилось.
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

        private async Task ProcessHostTestAsync(HostDiscovered host, CancellationToken ct)
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
                var result = await _tester.TestHostAsync(host, ct).ConfigureAwait(false);
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
