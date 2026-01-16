using System;
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
        /// <summary>
        /// Добавляет обнаруженный хост в очередь на тестирование
        /// </summary>
        public ValueTask EnqueueHostAsync(HostDiscovered host)
        {
            Interlocked.Increment(ref _statHostsEnqueued);
            Interlocked.Increment(ref _pendingInSniffer);

            // ВАЖНО: события могут прийти поздно (например, SNI после остановки пайплайна).
            // Для таких случаев enqueue должен быть безопасным и не создавать «ложные ошибки».
            var enqueued = false;
            try
            {
                // С DropOldest TryWrite обычно успешен даже при заполненной очереди; false чаще означает, что writer уже завершён.
                if (_snifferQueue.Writer.TryWrite(host))
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
                    Interlocked.Decrement(ref _pendingInSniffer);
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
            _snifferQueue.Writer.TryWrite(host);
        }
    }
}
