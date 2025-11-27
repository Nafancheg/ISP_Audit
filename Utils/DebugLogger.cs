using System;
using System.IO;
using System.Linq;

namespace ISPAudit.Utils
{
    /// <summary>
    /// Единый логгер для всего приложения.
    /// Пишет в Logs/isp_audit_vm_*.log — тот же файл что и MainViewModel.
    /// </summary>
    public static class DebugLogger
    {
        private static readonly object _lock = new object();
        private static readonly string _logPath;

        static DebugLogger()
        {
            // Используем ту же директорию и паттерн что MainViewModel
            var logsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
            
            try
            {
                Directory.CreateDirectory(logsDir);

                // Ищем существующий лог текущей сессии (последний по времени создания)
                var existingLogs = Directory.GetFiles(logsDir, "isp_audit_vm_*.log");
                if (existingLogs.Length > 0)
                {
                    // Используем самый новый существующий файл
                    _logPath = existingLogs
                        .OrderByDescending(File.GetCreationTimeUtc)
                        .First();
                }
                else
                {
                    // Создаём новый файл если нет существующих
                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    _logPath = Path.Combine(logsDir, $"isp_audit_vm_{timestamp}.log");
                }
            }
            catch
            {
                // Фолбэк
                _logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "debug_trace.log");
            }
        }

        public static void Log(string message)
        {
            try
            {
                lock (_lock)
                {
                    var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                    var threadId = System.Threading.Thread.CurrentThread.ManagedThreadId;
                    var line = $"[{timestamp}][T{threadId}] {message}\n";
                    
                    File.AppendAllText(_logPath, line);
                    System.Diagnostics.Debug.WriteLine(message);
                }
            }
            catch { /* Игнорируем ошибки */ }
        }
        
        /// <summary>
        /// Путь к текущему файлу логов.
        /// </summary>
        public static string CurrentLogPath => _logPath;
    }
}
