using System;
using System.IO;
using System.Linq;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region Logging

        private static readonly string LogsDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
        private static readonly string LogFilePath = InitializeLogFilePath();

        private static string InitializeLogFilePath()
        {
            try
            {
                Directory.CreateDirectory(LogsDirectory);

                var existingLogs = Directory.GetFiles(LogsDirectory, "isp_audit_vm_*.log")
                    .OrderBy(File.GetCreationTimeUtc)
                    .ToList();

                while (existingLogs.Count > 9)
                {
                    var toDelete = existingLogs[0];
                    existingLogs.RemoveAt(0);
                    try { File.Delete(toDelete); }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Log] Delete old log failed: {ex.Message}"); }
                }

                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                return Path.Combine(LogsDirectory, $"isp_audit_vm_{timestamp}.log");
            }
            catch
            {
                return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "isp_audit_vm_fallback.log");
            }
        }

        private static void Log(string message)
        {
            try
            {
                File.AppendAllText(LogFilePath, $"[{DateTime.Now:HH:mm:ss.fff}] {message}\n");
                System.Diagnostics.Debug.WriteLine(message);
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Log] Write failed: {ex.Message}"); }
        }

        #endregion
    }
}
