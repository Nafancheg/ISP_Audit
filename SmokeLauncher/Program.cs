using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace SmokeLauncher;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            // Требование проекта: строгий прогон smoke без ручного "запусти от админа".
            // Единственное действие пользователя — подтверждение UAC (иначе WinDivert не запустить).

            if (!IsAdministrator())
            {
                return RelaunchElevated(args);
            }

            var repoRoot = FindRepoRoot();
            if (repoRoot is null)
            {
                Console.Error.WriteLine("[SmokeLauncher] Не удалось найти корень репозитория (ISP_Audit.sln). Запусти из папки проекта.");
                return 2;
            }

            var testAppCsproj = Path.Combine(repoRoot, "TestNetworkApp", "TestNetworkApp.csproj");
            if (!File.Exists(testAppCsproj))
            {
                Console.Error.WriteLine($"[SmokeLauncher] Не найден проект TestNetworkApp: {testAppCsproj}");
                return 2;
            }

            var artifactsDir = Path.Combine(repoRoot, "artifacts");
            Directory.CreateDirectory(artifactsDir);

            var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var jsonPath = Path.Combine(artifactsDir, $"smoke_strict_{ts}.json");

            Console.WriteLine("=== SmokeLauncher (Admin) ===");
            Console.WriteLine($"Repo: {repoRoot}");
            Console.WriteLine($"Project: {testAppCsproj}");
            Console.WriteLine($"JSON: {jsonPath}");
            Console.WriteLine();

            var exitCode = RunDotNetSmoke(testAppCsproj, jsonPath);

            Console.WriteLine();
            Console.WriteLine($"[SmokeLauncher] ExitCode: {exitCode}");
            Console.WriteLine($"[SmokeLauncher] Report: {jsonPath}");

            return exitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[SmokeLauncher] Непредвиденная ошибка:");
            Console.Error.WriteLine(ex);
            return 99;
        }
    }

    private static int RunDotNetSmoke(string testAppCsproj, string jsonPath)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        // dotnet run -c Debug --project ... -- --smoke all --no-skip --json ...
        psi.ArgumentList.Add("run");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("Debug");
        psi.ArgumentList.Add("--project");
        psi.ArgumentList.Add(testAppCsproj);
        psi.ArgumentList.Add("--");
        psi.ArgumentList.Add("--smoke");
        psi.ArgumentList.Add("all");
        psi.ArgumentList.Add("--no-skip");
        psi.ArgumentList.Add("--json");
        psi.ArgumentList.Add(jsonPath);

        using var p = Process.Start(psi);
        if (p is null)
        {
            Console.Error.WriteLine("[SmokeLauncher] Не удалось запустить dotnet process.");
            return 3;
        }

        p.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                Console.WriteLine(e.Data);
            }
        };
        p.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                Console.Error.WriteLine(e.Data);
            }
        };

        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        p.WaitForExit();

        return p.ExitCode;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int RelaunchElevated(string[] args)
    {
        // При elevate нельзя редиректить STDOUT/STDERR. Мы просто ждём завершения.
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath))
        {
            Console.Error.WriteLine("[SmokeLauncher] Не удалось определить путь к текущему процессу.");
            return 2;
        }

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true,
            Verb = "runas"
        };

        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        Console.WriteLine("[SmokeLauncher] Требуются права администратора. Запрашиваю UAC...");

        try
        {
            using var p = Process.Start(psi);
            if (p is null)
            {
                Console.Error.WriteLine("[SmokeLauncher] Не удалось запустить elevated процесс.");
                return 3;
            }

            p.WaitForExit();
            return p.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // 1223 = The operation was canceled by the user.
            Console.Error.WriteLine("[SmokeLauncher] UAC отклонён пользователем.");
            return 1223;
        }
    }

    private static string? FindRepoRoot()
    {
        // Ищем ISP_Audit.sln вверх от текущей директории и от AppContext.BaseDirectory.
        var candidates = new List<string>
        {
            Environment.CurrentDirectory,
            AppContext.BaseDirectory
        };

        foreach (var start in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var dir = new DirectoryInfo(start);
            for (int i = 0; i < 10 && dir is not null; i++)
            {
                var sln = Path.Combine(dir.FullName, "ISP_Audit.sln");
                if (File.Exists(sln))
                {
                    return dir.FullName;
                }

                dir = dir.Parent;
            }
        }

        return null;
    }
}
