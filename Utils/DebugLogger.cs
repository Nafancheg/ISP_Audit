using System;
using System.IO;

namespace IspAudit.Utils
{
    public static class DebugLogger
    {
        private static readonly object _lock = new object();
        private static readonly string _logPath;

        static DebugLogger()
        {
            _logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "debug_trace.log");
            
            // Очистка файла при старте
            try
            {
                File.WriteAllText(_logPath, $"=== DEBUG TRACE START: {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} ===\n");
            }
            catch { /* Игнорируем ошибки */ }
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
    }
}
