using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Bypass;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;
using IspAudit.Core.Traffic.Filters;
using IspAudit.Windows;
using IspAudit;
using System.Windows.Media;
using System.Net;

// Явно указываем WPF вместо WinForms
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace IspAudit.ViewModels
{
    /// <summary>
    /// Оркестратор диагностики.
    /// Координирует TrafficCollector и LiveTestingPipeline.
    /// Управляет жизненным циклом мониторинговых сервисов.
    /// </summary>
    public partial class DiagnosticOrchestrator : INotifyPropertyChanged
    {
        #region System Helpers

        private async Task SaveProfileAsync(string targetExePath, DiagnosticProfile profile)
        {
            try
            {
                var profilesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Profiles");
                Directory.CreateDirectory(profilesDir);

                var exeName = Path.GetFileNameWithoutExtension(targetExePath);
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var profilePath = Path.Combine(profilesDir, $"{exeName}_{timestamp}.json");

                profile.ExePath = targetExePath;
                profile.Name = $"{exeName} (Captured {DateTime.Now:g})";

                var jsonOptions = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
                var json = System.Text.Json.JsonSerializer.Serialize(profile, jsonOptions);

                await File.WriteAllTextAsync(profilePath, json);
                Log($"[Orchestrator] Профиль сохранен: {profilePath}");

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    DiagnosticStatus = $"Профиль сохранен: {Path.GetFileName(profilePath)}";
                });
            }
            catch (Exception ex)
            {
                Log($"[Orchestrator] Ошибка сохранения профиля: {ex.Message}");
            }
        }

        private async Task RunFlushDnsAsync()
        {
            try
            {
                // ipconfig /flushdns на русской Windows часто пишет OEM866
                var oem866 = System.Text.Encoding.GetEncoding(866);
                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = oem866,
                    StandardErrorEncoding = oem866
                };

                using var process = System.Diagnostics.Process.Start(startInfo);
                if (process != null)
                {
                    var stdoutTask = process.StandardOutput.ReadToEndAsync();
                    var stderrTask = process.StandardError.ReadToEndAsync();
                    await process.WaitForExitAsync().ConfigureAwait(false);

                    var output = (await stdoutTask.ConfigureAwait(false)).Trim();
                    var error = (await stderrTask.ConfigureAwait(false)).Trim();

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        Log($"[DNS] Flush result: {output}");
                    }
                    else if (!string.IsNullOrWhiteSpace(error))
                    {
                        Log($"[DNS] Flush error: {error}");
                    }
                    else
                    {
                        Log("[DNS] Flush completed");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[DNS] Flush failed: {ex.Message}");
            }
        }

        [SupportedOSPlatform("windows")]
        private static bool IsAdministrator()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void Log(string message)
        {
            OnLog?.Invoke(message);
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
