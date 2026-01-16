using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Reflection;
using System.Text;

namespace SmokeLauncher;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            // Важно: фиксируем кодировку консоли, иначе кириллица в PowerShell/ConsoleHost часто превращается в кракозябры.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Console.InputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            Console.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

            // Требование проекта: строгий прогон smoke без ручного "запусти от админа".
            // Единственное действие пользователя — подтверждение UAC (иначе WinDivert не запустить).

            // Внутренние аргументы (передаются при relaunch elevated), чтобы не зависеть от
            // WorkingDirectory/контекста и гарантировать запись JSON в artifacts.
            const string RepoRootArg = "--_repoRoot";
            const string JsonPathArg = "--_jsonPath";
            const string LogPathArg = "--_logPath";

            // 1) Определяем корень репозитория заранее (даже в non-admin),
            // чтобы можно было предсказуемо сформировать путь отчёта.
            var repoRoot = TryGetArgValue(args, RepoRootArg) ?? FindRepoRoot();
            if (repoRoot is null)
            {
                Console.Error.WriteLine("[SmokeLauncher] Не удалось найти корень репозитория (ISP_Audit.sln). Запусти из папки проекта.");
                return 2;
            }

            var artifactsDir = Path.Combine(repoRoot, "artifacts");
            Directory.CreateDirectory(artifactsDir);

            var jsonPath = TryGetArgValue(args, JsonPathArg);
            if (string.IsNullOrWhiteSpace(jsonPath))
            {
                var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                jsonPath = Path.Combine(artifactsDir, $"smoke_strict_{ts}.json");
            }

            var logPath = TryGetArgValue(args, LogPathArg);
            if (string.IsNullOrWhiteSpace(logPath))
            {
                // Лог всегда рядом с JSON, чтобы проще было искать.
                logPath = Path.ChangeExtension(jsonPath, ".log.txt");
            }

            if (!IsAdministrator())
            {
                Console.WriteLine("=== SmokeLauncher (Non-Admin) ===");
                Console.WriteLine($"Repo: {repoRoot}");
                Console.WriteLine($"JSON (planned): {jsonPath}");
                Console.WriteLine($"LOG (planned): {logPath}");
                Console.WriteLine();

                var relaunchExitCode = RelaunchElevated(args, repoRoot, jsonPath, logPath);

                // Если elevated успел что-то записать в лог — покажем его хвост, чтобы не было ощущения "ничего не происходит".
                TryPrintLogTail(logPath);

                return relaunchExitCode;
            }

            var testAppCsproj = Path.Combine(repoRoot, "TestNetworkApp", "TestNetworkApp.csproj");
            if (!File.Exists(testAppCsproj))
            {
                Console.Error.WriteLine($"[SmokeLauncher] Не найден проект TestNetworkApp: {testAppCsproj}");
                return 2;
            }

            Console.WriteLine("=== SmokeLauncher (Admin) ===");
            Console.WriteLine($"Repo: {repoRoot}");
            Console.WriteLine($"Project: {testAppCsproj}");
            Console.WriteLine($"JSON: {jsonPath}");
            Console.WriteLine($"LOG: {logPath}");
            Console.WriteLine();

            // Маркер того, что elevated стадия реально стартовала (помогает отлаживать UAC/релонч).
            TryWriteAdminStartedMarker(jsonPath);
            TryAppendToLog(logPath, $"[SmokeLauncher][ADMIN] Started at {DateTime.Now:O}{Environment.NewLine}");

            var smokeExitCode = RunDotNetSmoke(testAppCsproj, jsonPath, logPath);

            Console.WriteLine();
            Console.WriteLine($"[SmokeLauncher] ExitCode: {smokeExitCode}");
            Console.WriteLine($"[SmokeLauncher] Report: {jsonPath}");
            Console.WriteLine($"[SmokeLauncher] Log: {logPath}");

            return smokeExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[SmokeLauncher] Непредвиденная ошибка:");
            Console.Error.WriteLine(ex);
            return 99;
        }
    }

    private static int RunDotNetSmoke(string testAppCsproj, string jsonPath, string logPath)
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
            TryAppendToLog(logPath, "[SmokeLauncher][ADMIN] Не удалось запустить dotnet process." + Environment.NewLine);
            return 3;
        }

        p.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                Console.WriteLine(e.Data);
                TryAppendToLog(logPath, e.Data + Environment.NewLine);
            }
        };
        p.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                Console.Error.WriteLine(e.Data);
                TryAppendToLog(logPath, "[stderr] " + e.Data + Environment.NewLine);
            }
        };

        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        p.WaitForExit();

        TryAppendToLog(logPath, $"[SmokeLauncher][ADMIN] dotnet ExitCode={p.ExitCode}{Environment.NewLine}");
        return p.ExitCode;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int RelaunchElevated(string[] args, string repoRoot, string jsonPath, string logPath)
    {
        // При elevate нельзя редиректить STDOUT/STDERR. Мы просто ждём завершения.
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            Console.Error.WriteLine("[SmokeLauncher] Не удалось определить путь к текущему процессу.");
            return 2;
        }

        var baseDir = AppContext.BaseDirectory;
        var selfExeCandidate = Path.Combine(baseDir, "SmokeLauncher.exe");

        // ВАЖНО: если SmokeLauncher запущен через `dotnet run`, то ProcessPath указывает на dotnet.exe.
        // В этом случае elevated-процесс должен запустить dotnet с путём к нашей сборке (dll), иначе
        // dotnet получит неизвестные аргументы (--_repoRoot/--_jsonPath) и завершится с ошибкой.
        var isDotnetHost = string.Equals(Path.GetFileName(processPath), "dotnet.exe", StringComparison.OrdinalIgnoreCase);
        var selfAssemblyPath = Assembly.GetExecutingAssembly().Location;
        if (isDotnetHost && string.IsNullOrWhiteSpace(selfAssemblyPath))
        {
            Console.Error.WriteLine("[SmokeLauncher] Не удалось определить путь к SmokeLauncher.dll для elevate.");
            return 2;
        }

        // Предпочитаем запускать SmokeLauncher.exe напрямую (самый надёжный вариант под Windows).
        // Это важно, потому что `dotnet run` запускает через dotnet-host, и relaunch может быть нестабильным.
        var launchFileName = File.Exists(selfExeCandidate) ? selfExeCandidate : processPath;

        // Собираем аргументы в строку (UseShellExecute=true может игнорировать ArgumentList).
        var elevatedArgs = new List<string>();
        if (!File.Exists(selfExeCandidate) && isDotnetHost)
        {
            // dotnet <SmokeLauncher.dll> ...
            elevatedArgs.Add(selfAssemblyPath);
        }

        elevatedArgs.Add("--_repoRoot");
        elevatedArgs.Add(repoRoot);
        elevatedArgs.Add("--_jsonPath");
        elevatedArgs.Add(jsonPath);
        elevatedArgs.Add("--_logPath");
        elevatedArgs.Add(logPath);

        foreach (var a in args)
        {
            // Внутренние аргументы не прокидываем повторно.
            if (string.Equals(a, "--_repoRoot", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(a, "--_jsonPath", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            elevatedArgs.Add(a);
        }

        var debugPath = Path.Combine(repoRoot, "artifacts", "smoke_elevate_debug.txt");
        TryWriteElevateDebug(debugPath, launchFileName, elevatedArgs);

        var psi = new ProcessStartInfo
        {
            FileName = launchFileName,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = repoRoot,
            Arguments = string.Join(" ", elevatedArgs.Select(QuoteWindowsCommandLineArg))
        };

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
        catch (System.ComponentModel.Win32Exception ex)
        {
            Console.Error.WriteLine($"[SmokeLauncher] Ошибка запуска elevated процесса: NativeErrorCode={ex.NativeErrorCode}, Message={ex.Message}");
            Console.Error.WriteLine("[SmokeLauncher] Проверь: UAC не отключён, нет групповой политики запрета elevate, VS Code запущен не из sandbox.");
            return ex.NativeErrorCode != 0 ? ex.NativeErrorCode : 4;
        }
    }

    private static void TryWriteElevateDebug(string debugPath, string fileName, List<string> args)
    {
        try
        {
            var lines = new List<string>
            {
                $"Time: {DateTime.Now:O}",
                $"FileName: {fileName}",
                $"Args: {string.Join(" ", args.Select(QuoteWindowsCommandLineArg))}",
            };
            File.WriteAllLines(debugPath, lines);
        }
        catch
        {
            // Это диагностический файл, падать из-за него не нужно.
        }
    }

    private static void TryWriteAdminStartedMarker(string jsonPath)
    {
        try
        {
            var markerPath = Path.ChangeExtension(jsonPath, ".admin_started.txt");
            File.WriteAllText(markerPath, $"Started: {DateTime.Now:O}");
        }
        catch
        {
            // Маркер вспомогательный.
        }
    }

    private static void TryAppendToLog(string logPath, string text)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? ".");
            File.AppendAllText(logPath, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        catch
        {
            // Лог вспомогательный.
        }
    }

    private static void TryPrintLogTail(string logPath)
    {
        try
        {
            if (!File.Exists(logPath))
            {
                return;
            }

            var lines = File.ReadAllLines(logPath);
            var tail = lines.Skip(Math.Max(0, lines.Length - 25)).ToArray();

            Console.WriteLine();
            Console.WriteLine("=== SmokeLauncher log tail ===");
            foreach (var line in tail)
            {
                Console.WriteLine(line);
            }
        }
        catch
        {
            // Не критично.
        }
    }

    private static string QuoteWindowsCommandLineArg(string arg)
    {
        if (arg.Length == 0)
        {
            return "\"\"";
        }

        var needsQuotes = arg.Any(char.IsWhiteSpace) || arg.Contains('"');
        if (!needsQuotes)
        {
            return arg;
        }

        var sb = new StringBuilder();
        sb.Append('"');

        var backslashCount = 0;
        foreach (var ch in arg)
        {
            if (ch == '\\')
            {
                backslashCount++;
                continue;
            }

            if (ch == '"')
            {
                sb.Append(new string('\\', backslashCount * 2 + 1));
                sb.Append('"');
                backslashCount = 0;
                continue;
            }

            if (backslashCount > 0)
            {
                sb.Append(new string('\\', backslashCount));
                backslashCount = 0;
            }

            sb.Append(ch);
        }

        if (backslashCount > 0)
        {
            sb.Append(new string('\\', backslashCount * 2));
        }

        sb.Append('"');
        return sb.ToString();
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

    private static string? TryGetArgValue(string[] args, string key)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], key, StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length)
                {
                    return args[i + 1];
                }

                return null;
            }
        }

        return null;
    }
}
