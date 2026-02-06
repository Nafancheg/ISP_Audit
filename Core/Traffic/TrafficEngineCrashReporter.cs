using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using IspAudit.Utils;

namespace IspAudit.Core.Traffic;

internal static class TrafficEngineCrashReporter
{
    private const string EnvVarCrashDir = IspAudit.Utils.EnvKeys.TrafficEngineCrashDir;

    internal static void TryWrite(Exception exception, string? lastMutationForLog)
    {
        try
        {
            var dir = GetCrashReportsDirectory();
            Directory.CreateDirectory(dir);

            var ts = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff");
            var pid = Environment.ProcessId;
            var path = Path.Combine(dir, $"traffic_engine_crash_{ts}_pid{pid}.json");

            var payload = new
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                ProcessId = pid,
                ThreadId = Environment.CurrentManagedThreadId,
                IsAdmin = IsAdministratorSafe(),
                ExceptionType = exception.GetType().FullName,
                ExceptionMessage = exception.Message,
                Exception = exception.ToString(),
                LastMutation = lastMutationForLog
            };

            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(path, json, System.Text.Encoding.UTF8);
        }
        catch
        {
            // best-effort: crash-report не должен ломать shutdown/обход
        }
    }

    private static string GetCrashReportsDirectory()
    {
        var overrideDir = EnvVar.GetTrimmedNonEmpty(EnvVarCrashDir);
        if (!string.IsNullOrWhiteSpace(overrideDir))
        {
            return overrideDir;
        }

        return Path.Combine(AppPaths.StateDirectory, "crash_reports", "traffic_engine");
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
