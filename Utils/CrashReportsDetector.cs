using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace IspAudit.Utils
{
    internal sealed class CrashReportsDetectionResult
    {
        public int NewAppCount { get; init; }
        public int NewTrafficEngineCount { get; init; }
        public DateTimeOffset? LatestNewUtc { get; init; }

        public bool HasNew => NewAppCount > 0 || NewTrafficEngineCount > 0;

        public string AppCrashDir { get; init; } = string.Empty;
        public string TrafficEngineCrashDir { get; init; } = string.Empty;
        public string CrashRootDir { get; init; } = string.Empty;
    }

    internal static class CrashReportsDetector
    {
        internal static CrashReportsDetectionResult DetectNewSince(DateTimeOffset lastSeenUtc)
        {
            var appDir = Path.Combine(AppPaths.StateDirectory, "crash_reports", "app");
            var trafficDir = GetTrafficEngineCrashDir();
            var rootDir = Path.Combine(AppPaths.StateDirectory, "crash_reports");

            var lastSeen = lastSeenUtc.UtcDateTime;

            var (newApp, latestAppUtc) = CountNewJsonReports(appDir, lastSeen);
            var (newTraffic, latestTrafficUtc) = CountNewJsonReports(trafficDir, lastSeen);

            DateTimeOffset? latestNewUtc = null;
            var latestUtc = MaxUtc(latestAppUtc, latestTrafficUtc);
            if (latestUtc != null)
            {
                latestNewUtc = new DateTimeOffset(latestUtc.Value, TimeSpan.Zero);
            }

            return new CrashReportsDetectionResult
            {
                NewAppCount = newApp,
                NewTrafficEngineCount = newTraffic,
                LatestNewUtc = latestNewUtc,
                AppCrashDir = appDir,
                TrafficEngineCrashDir = trafficDir,
                CrashRootDir = rootDir
            };
        }

        internal static void OpenCrashReportFoldersBestEffort(CrashReportsDetectionResult? detection)
        {
            try
            {
                if (!OperatingSystem.IsWindows())
                {
                    return;
                }

                var appDir = detection?.AppCrashDir;
                var trafficDir = detection?.TrafficEngineCrashDir;
                var rootDir = detection?.CrashRootDir;

                // 1) Общая папка (рядом с приложением)
                if (!string.IsNullOrWhiteSpace(rootDir))
                {
                    Directory.CreateDirectory(rootDir);
                    TryOpenFolder(rootDir);
                }

                // 2) Папка app crash-reports
                if (!string.IsNullOrWhiteSpace(appDir))
                {
                    Directory.CreateDirectory(appDir);
                    TryOpenFolder(appDir);
                }

                // 3) Папка traffic_engine crash-reports (может быть override)
                if (!string.IsNullOrWhiteSpace(trafficDir))
                {
                    Directory.CreateDirectory(trafficDir);
                    TryOpenFolder(trafficDir);
                }
            }
            catch
            {
                // ignore
            }
        }

        private static string GetTrafficEngineCrashDir()
        {
            var overrideDir = EnvVar.GetTrimmedNonEmpty(EnvKeys.TrafficEngineCrashDir);
            if (!string.IsNullOrWhiteSpace(overrideDir))
            {
                return overrideDir;
            }

            return Path.Combine(AppPaths.StateDirectory, "crash_reports", "traffic_engine");
        }

        private static (int NewCount, DateTime? LatestNewUtc) CountNewJsonReports(string dir, DateTime lastSeenUtc)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(dir)) return (0, null);
                if (!Directory.Exists(dir)) return (0, null);

                var newCount = 0;
                DateTime? latestUtc = null;

                foreach (var file in Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly))
                {
                    DateTime writeUtc;
                    try
                    {
                        writeUtc = File.GetLastWriteTimeUtc(file);
                    }
                    catch
                    {
                        continue;
                    }

                    if (writeUtc <= lastSeenUtc) continue;

                    newCount++;
                    latestUtc = MaxUtc(latestUtc, writeUtc);
                }

                return (newCount, latestUtc);
            }
            catch
            {
                return (0, null);
            }
        }

        private static DateTime? MaxUtc(DateTime? a, DateTime? b)
        {
            if (a == null) return b;
            if (b == null) return a;
            return a.Value >= b.Value ? a : b;
        }

        private static void TryOpenFolder(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path)) return;

                var psi = new ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true
                };

                Process.Start(psi);
            }
            catch
            {
                // ignore
            }
        }
    }
}
