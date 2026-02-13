using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using IspAudit.Core.Traffic;
using IspAudit.Utils;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        private static ServiceProvider BuildIspAuditProvider()
        {
            var services = new ServiceCollection();
            services.AddIspAuditServices();
            return services.BuildServiceProvider();
        }

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
                .GetFields(BindingFlags.Instance | BindingFlags.NonPublic);

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

        private static async Task<SmokeTestResult> RunAsyncAwait(string id, string name, Func<CancellationToken, Task<SmokeTestResult>> body, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                ct.ThrowIfCancellationRequested();
                var result = await body(ct).ConfigureAwait(false);
                sw.Stop();
                return result with { Duration = sw.Elapsed };
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                return new SmokeTestResult(id, name, SmokeOutcome.Skip, sw.Elapsed, "Отменено");
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new SmokeTestResult(id, name, SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        private static T GetPrivateField<T>(object instance, string fieldName)
        {
            var field = instance.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic);
            if (field == null)
            {
                throw new MissingFieldException(instance.GetType().FullName, fieldName);
            }

            var value = field.GetValue(instance);

            // Если поле null, то для ссылочных/Nullable<T> типов это допустимо.
            // Иначе (для не-nullable value-type) это ошибка.
            if (value is null)
            {
                var t = typeof(T);
                var allowsNull = !t.IsValueType || Nullable.GetUnderlyingType(t) != null;
                if (allowsNull)
                {
                    return default!;
                }

                throw new InvalidCastException($"Поле '{fieldName}' имеет тип 'null', ожидали '{typeof(T).FullName}'");
            }

            if (value is not T typed)
            {
                throw new InvalidCastException($"Поле '{fieldName}' имеет тип '{value?.GetType().FullName ?? "null"}', ожидали '{typeof(T).FullName}'");
            }

            return typed;
        }

        private static void SetPrivateField(object instance, string fieldName, object? value)
        {
            var field = instance.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic);
            if (field == null)
            {
                throw new MissingFieldException(instance.GetType().FullName, fieldName);
            }

            field.SetValue(instance, value);
        }

        private static object? InvokePrivateMethod(object instance, string methodName, params object?[] args)
        {
            var method = instance.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic);
            if (method == null)
            {
                throw new MissingMethodException(instance.GetType().FullName, methodName);
            }

            return method.Invoke(instance, args);
        }
    }
}
