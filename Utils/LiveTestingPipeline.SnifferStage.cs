using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using BypassTransportProtocol = IspAudit.Bypass.TransportProtocol;
using IspAudit.Core.Models;

namespace IspAudit.Utils
{
    public partial class LiveTestingPipeline
    {
        public enum HostPriority
        {
            Low = 0,
            High = 1
        }

        /// <summary>
        /// Добавляет обнаруженный хост в очередь на тестирование
        /// </summary>
        public ValueTask EnqueueHostAsync(HostDiscovered host, HostPriority priority = HostPriority.Low)
        {
            Interlocked.Increment(ref _statHostsEnqueued);

            // P1.5: повторные фейлы — если по этому IP уже видели проблему, поднимаем приоритет.
            if (priority == HostPriority.Low)
            {
                try
                {
                    if (_recentProblemIps.ContainsKey(host.RemoteIp.ToString()))
                    {
                        priority = HostPriority.High;
                    }
                }
                catch
                {
                    // ignore
                }
            }

            if (priority == HostPriority.High)
            {
                Interlocked.Increment(ref _pendingInSnifferHigh);
            }
            else
            {
                Interlocked.Increment(ref _pendingInSnifferLow);
            }

            // ВАЖНО: события могут прийти поздно (например, SNI после остановки пайплайна).
            // Для таких случаев enqueue должен быть безопасным и не создавать «ложные ошибки».
            var enqueued = false;
            try
            {
                var q = new QueuedHost(host, Stopwatch.GetTimestamp(), priority == HostPriority.High);

                // С DropOldest TryWrite обычно успешен даже при заполненной очереди; false чаще означает, что writer уже завершён.
                var writer = priority == HostPriority.High ? _snifferHighQueue.Writer : _snifferLowQueue.Writer;
                if (writer.TryWrite(q))
                {
                    enqueued = true;
                    return ValueTask.CompletedTask;
                }

                Interlocked.Increment(ref _statSnifferDropped);
            }
            catch (ChannelClosedException)
            {
                Interlocked.Increment(ref _statSnifferDropped);
            }
            finally
            {
                // Если enqueue не состоялся, pending не будет уменьшен воркером.
                // При успешном enqueue pending уменьшается в TesterWorker.
                if (!enqueued)
                {
                    if (priority == HostPriority.High)
                    {
                        Interlocked.Decrement(ref _pendingInSnifferHigh);
                    }
                    else
                    {
                        Interlocked.Decrement(ref _pendingInSnifferLow);
                    }
                }
            }

            return ValueTask.CompletedTask;
        }

        /// <summary>
        /// Принудительно запускает повторное тестирование указанного IP.
        /// Используется, когда пассивные анализаторы (UDP/RST) обнаруживают проблему постфактум.
        /// </summary>
        public void ForceRetest(IPAddress ip)
        {
            if (_disposed) return;

            // 1. Сбрасываем фильтр для этого IP, чтобы он не был отброшен как дубликат
            _filter.Invalidate(ip.ToString());

            // 2. Создаем искусственное событие обнаружения хоста
            // Предполагаем порт 443, так как это наиболее вероятно для QUIC/Web
            var key = $"{ip}:443:UDP";
            var host = new HostDiscovered(
                key,
                ip,
                443,
                BypassTransportProtocol.Udp,
                DateTime.UtcNow);

            // 3. Отправляем в очередь на обработку
            _ = EnqueueHostAsync(host, HostPriority.High);
        }
    }
}
