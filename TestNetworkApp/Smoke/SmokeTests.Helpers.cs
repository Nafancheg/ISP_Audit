using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Traffic;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        private sealed class DummyPacketFilter : IPacketFilter
        {
            public string Name { get; }
            public int Priority { get; }

            public DummyPacketFilter(string name, int priority)
            {
                Name = name;
                Priority = priority;
            }

            public bool Process(InterceptedPacket packet, PacketContext ctx, IPacketSender sender)
            {
                return true;
            }
        }

        private static async Task MakeTcpAttemptAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
        {
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            try
            {
                await tcp.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            }
            catch
            {
                // Нам не важен успех рукопожатия, важен факт попытки соединения в TCP таблице.
            }
        }

        private static List<IPacketFilter> GetEngineFiltersSnapshot(TrafficEngine engine)
        {
            // Smoke-тест: используем reflection, чтобы проверить реальный порядок после сортировки.
            var fields = typeof(TrafficEngine)
                .GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);

            var listField = fields.FirstOrDefault(f => typeof(List<IPacketFilter>).IsAssignableFrom(f.FieldType));
            if (listField == null)
            {
                return new List<IPacketFilter>();
            }

            var value = listField.GetValue(engine) as List<IPacketFilter>;
            if (value == null)
            {
                return new List<IPacketFilter>();
            }

            lock (value)
            {
                return value.ToList();
            }
        }

        private static Task<SmokeTestResult> RunAsync(string id, string name, Func<SmokeTestResult> body, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                ct.ThrowIfCancellationRequested();
                var result = body();
                sw.Stop();
                return Task.FromResult(result with { Duration = sw.Elapsed });
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                return Task.FromResult(new SmokeTestResult(id, name, SmokeOutcome.Skip, sw.Elapsed, "Отменено"));
            }
            catch (Exception ex)
            {
                sw.Stop();
                return Task.FromResult(new SmokeTestResult(id, name, SmokeOutcome.Fail, sw.Elapsed, ex.Message));
            }
        }
    }
}
