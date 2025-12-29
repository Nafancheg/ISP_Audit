using System;
using System.IO;
using System.Text.Json;

namespace IspAudit.Bypass
{
    internal sealed class BypassSessionJournal
    {
        private sealed class SessionState
        {
            public int Version { get; set; } = 1;
            public bool CleanShutdown { get; set; }
            public bool WasBypassActive { get; set; }
            public DateTimeOffset UpdatedAtUtc { get; set; }
            public string? LastReason { get; set; }
        }

        private readonly string _path;
        private readonly Action<string>? _log;
        private readonly object _sync = new();

        // Снимок, прочитанный на старте (нужен для crash-recovery решения).
        public bool StartupWasUncleanAndBypassActive { get; private set; }

        public BypassSessionJournal(string path, Action<string>? log)
        {
            _path = path ?? throw new ArgumentNullException(nameof(path));
            _log = log;

            var loaded = TryLoad();
            if (loaded != null)
            {
                StartupWasUncleanAndBypassActive = loaded.WasBypassActive && !loaded.CleanShutdown;
            }
        }

        public static string GetDefaultPath()
        {
            var overridePath = Environment.GetEnvironmentVariable("ISP_AUDIT_BYPASS_SESSION_PATH");
            if (!string.IsNullOrWhiteSpace(overridePath))
            {
                return overridePath;
            }

            var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var dir = Path.Combine(baseDir, "ISP_Audit");
            return Path.Combine(dir, "bypass_session.json");
        }

        public void MarkSessionStarted()
        {
            // При старте считаем shutdown "грязным" до тех пор, пока не отметили clean.
            Update(state =>
            {
                state.CleanShutdown = false;
                state.UpdatedAtUtc = DateTimeOffset.UtcNow;
                state.LastReason = "session_start";
            });
        }

        public void SetBypassActive(bool active, string reason)
        {
            Update(state =>
            {
                state.WasBypassActive = active;
                state.UpdatedAtUtc = DateTimeOffset.UtcNow;
                state.LastReason = reason;

                // Пока приложение работает, всегда считаем shutdown "грязным".
                // CleanShutdown отмечается отдельно на выходе.
                state.CleanShutdown = false;
            });
        }

        public void TouchHeartbeat(string reason)
        {
            Update(state =>
            {
                state.UpdatedAtUtc = DateTimeOffset.UtcNow;
                state.LastReason = reason;
            });
        }

        public void MarkCleanShutdown(string reason)
        {
            Update(state =>
            {
                state.CleanShutdown = true;
                state.UpdatedAtUtc = DateTimeOffset.UtcNow;
                state.LastReason = reason;
            });
        }

        private void Update(Action<SessionState> mutate)
        {
            lock (_sync)
            {
                var state = TryLoad() ?? new SessionState
                {
                    CleanShutdown = true,
                    WasBypassActive = false,
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                    LastReason = "init"
                };

                mutate(state);
                TrySave(state);
            }
        }

        private SessionState? TryLoad()
        {
            try
            {
                if (!File.Exists(_path)) return null;

                var json = File.ReadAllText(_path);
                return JsonSerializer.Deserialize<SessionState>(json);
            }
            catch
            {
                return null;
            }
        }

        private void TrySave(SessionState state)
        {
            try
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var json = JsonSerializer.Serialize(state, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(_path, json);
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[Bypass][WARN] Не удалось записать журнал сессии: {ex.Message}");
            }
        }
    }
}
