using System;
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
            await foreach (var host in _snifferQueue.Reader.ReadAllAsync(ct))
            {
                Interlocked.Decrement(ref _pendingInSniffer);
                Interlocked.Increment(ref _statTesterDequeued);

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
                    continue;
                }

                // Дедупликация на уровне "сессии тестирования":
                // если цель уже была поставлена на тест — повторные события не должны доходить до тестера.
                if (!_stateStore.TryBeginHostTest(host, hostname))
                {
                    Interlocked.Increment(ref _statTesterDropped);
                    continue;
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
}
