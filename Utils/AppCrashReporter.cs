using System;
using System.IO;
using System.Security.Principal;
using System.Text.Json;

namespace IspAudit.Utils;

internal static class AppCrashReporter
{
    internal static void TryWrite(Exception exception, string source, bool? isTerminating)
    {
        try
        {
            var dir = Path.Combine(AppPaths.StateDirectory, "crash_reports", "app");
            Directory.CreateDirectory(dir);

            var ts = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff");
            var pid = Environment.ProcessId;
            var path = Path.Combine(dir, $"app_crash_{ts}_pid{pid}.json");

            var payload = new
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Source = source,
                IsTerminating = isTerminating,
                ProcessId = pid,
                ThreadId = Environment.CurrentManagedThreadId,
                IsAdmin = IsAdministratorSafe(),
                ExceptionType = exception.GetType().FullName,
                ExceptionMessage = exception.Message,
                Exception = exception.ToString()
            };

            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(path, json, System.Text.Encoding.UTF8);
        }
        catch
        {
            // best-effort: crash-report не должен усугублять падение
        }
    }

    private static bool IsAdministratorSafe()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
