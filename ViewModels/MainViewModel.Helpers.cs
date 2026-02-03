using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MaterialDesignThemes.Wpf;
using IspAudit.Models;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region Helper Methods

        private string? GetTestNetworkAppPath()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // 1) Самый простой вариант: TestNetworkApp.exe лежит рядом с основным exe.
            var path = Path.Combine(baseDir, "TestNetworkApp.exe");
            if (File.Exists(path)) return path;

            // 2) Вариант для publish-скриптов: подпапка рядом с основным exe.
            path = Path.Combine(baseDir, "TestNetworkApp", "bin", "Publish", "TestNetworkApp.exe");
            if (File.Exists(path)) return path;

            // 3) Dev-расклад: основной exe лежит в bin/Debug|Release/...,
            // а TestNetworkApp публикуется в <repoRoot>/TestNetworkApp/bin/Publish/.
            var repoRoot = TryFindRepoRoot(Environment.CurrentDirectory) ?? TryFindRepoRoot(baseDir);
            if (!string.IsNullOrWhiteSpace(repoRoot))
            {
                path = Path.Combine(repoRoot, "TestNetworkApp", "bin", "Publish", "TestNetworkApp.exe");
                if (File.Exists(path)) return path;
            }

            // 4) Фолбэк: идём вверх от baseDir и пытаемся найти стандартный путь, даже если sln не найден.
            var dir = new DirectoryInfo(baseDir);
            for (var i = 0; i < 10 && dir is not null; i++)
            {
                path = Path.Combine(dir.FullName, "TestNetworkApp", "bin", "Publish", "TestNetworkApp.exe");
                if (File.Exists(path)) return path;
                dir = dir.Parent;
            }

            return null;
        }

        private static string? TryFindRepoRoot(string startDir)
        {
            if (string.IsNullOrWhiteSpace(startDir)) return null;

            var dir = new DirectoryInfo(startDir);
            for (int i = 0; i < 10 && dir is not null; i++)
            {
                var sln = Path.Combine(dir.FullName, "ISP_Audit.sln");
                if (File.Exists(sln))
                {
                    return dir.FullName;
                }

                dir = dir.Parent;
            }

            return null;
        }

        private void UpdateUserMessage(string msg)
        {
            var cleanMsg = msg;

            if (cleanMsg.StartsWith("["))
            {
                var closeBracket = cleanMsg.IndexOf(']');
                if (closeBracket > 0)
                {
                    cleanMsg = cleanMsg.Substring(closeBracket + 1).Trim();
                }
            }

            if (cleanMsg.Contains("ConnectionMonitor")) cleanMsg = "Анализ сетевых соединений...";
            if (cleanMsg.Contains("WinDivert")) cleanMsg = "Инициализация драйвера перехвата...";
            if (cleanMsg.Contains("DNS")) cleanMsg = "Проверка DNS запросов...";

            if (System.Text.RegularExpressions.Regex.IsMatch(cleanMsg, @"\d+\.\d+\.\d+\.\d+:\d+"))
            {
                cleanMsg = "Обнаружено соединение с сервером...";
            }

            UserMessage = cleanMsg;
        }

        private async void CheckAndRetestFailedTargets(string? propertyName)
        {
            if (string.IsNullOrEmpty(propertyName)) return;

            // Важно: это не auto-bypass, но это авто-действие (ретест). По умолчанию отключаем,
            // чтобы не размывать наблюдаемость и причинно-следственные связи.
            if (!IspAudit.Config.RuntimeFlags.EnableAutoRetestOnBypassChange) return;

            // Проверяем, что изменилось именно свойство bypass
            if (propertyName != nameof(Bypass.IsFragmentEnabled) &&
                propertyName != nameof(Bypass.IsDisorderEnabled) &&
                propertyName != nameof(Bypass.IsFakeEnabled) &&
                propertyName != nameof(Bypass.IsDropRstEnabled) &&
                propertyName != nameof(Bypass.IsQuicFallbackEnabled) &&
                propertyName != nameof(Bypass.IsAllowNoSniEnabled) &&
                propertyName != nameof(Bypass.IsDoHEnabled))
            {
                return;
            }

            // Во время активной диагностики Orchestrator.RetestTargetsAsync запрещён.
            // Поэтому откладываем ретест до завершения (done).
            if (IsRunning)
            {
                _pendingRetestAfterRun = true;
                _pendingRetestReason = propertyName;
                Log($"[AutoRetest] Bypass option changed ({propertyName}) during running. Retest scheduled after diagnostic ends.");
                return;
            }

            // Если диагностика ещё не завершена — ничего не делаем.
            if (!IsDone) return;

            // Находим проблемные цели (не OK)
            var failedTargets = Results.TestResults
                .Where(r => r.Status != TestStatus.Pass)
                .Select(r => r.Target)
                .ToList();

            if (failedTargets.Count == 0) return;

            Log($"[AutoRetest] Bypass option changed ({propertyName}). Retesting {failedTargets.Count} failed targets...");

            // Запускаем ретест
            var opId = Guid.NewGuid().ToString("N");
            await Orchestrator.RetestTargetsAsync(failedTargets, Bypass, opId);
        }

        private async Task RunPendingRetestAfterRunAsync()
        {
            try
            {
                if (!IspAudit.Config.RuntimeFlags.EnableAutoRetestOnBypassChange)
                {
                    _pendingRetestAfterRun = false;
                    _pendingRetestReason = "";
                    return;
                }

                if (!IsDone) return;

                var failedTargets = Results.TestResults
                    .Where(r => r.Status != TestStatus.Pass)
                    .Select(r => r.Target)
                    .ToList();

                if (failedTargets.Count == 0) return;

                Log($"[AutoRetest] Running scheduled retest after run (reason={_pendingRetestReason}). Targets={failedTargets.Count}");
                var opId = Guid.NewGuid().ToString("N");
                await Orchestrator.RetestTargetsAsync(failedTargets, Bypass, opId);
            }
            catch (Exception ex)
            {
                Log($"[AutoRetest] Error: {ex.Message}");
            }
            finally
            {
                _pendingRetestReason = "";
            }
        }

        private void ApplyTheme(bool isDark)
        {
            var paletteHelper = new PaletteHelper();
            var theme = paletteHelper.GetTheme();
            theme.SetBaseTheme(isDark ? BaseTheme.Dark : BaseTheme.Light);
            paletteHelper.SetTheme(theme);
        }

        private void CheckTrafficEngineState()
        {
            if (!Bypass.IsBypassActive && !Orchestrator.IsDiagnosticRunning)
            {
                if (_trafficEngine.IsRunning)
                {
                    Log("[Main] Stopping TrafficEngine (no active consumers)...");
                    _ = _bypassState.StopEngineAsync();
                }
            }
        }

        #endregion
    }
}
