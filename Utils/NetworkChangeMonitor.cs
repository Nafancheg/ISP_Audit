using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    /// <summary>
    /// Отслеживает смену сети (debounce) и публикует событие при изменении "сетевого отпечатка".
    /// Используется для UX: при смене сети предложить revalidation обхода.
    /// </summary>
    internal sealed class NetworkChangeMonitor : IDisposable
    {
        private readonly Action<string>? _log;
        private readonly object _sync = new();
        private CancellationTokenSource? _debounceCts;

        private string _lastFingerprint = string.Empty;
        private volatile bool _started;

        public event Action<string /*fingerprint*/>? NetworkChanged;

        public NetworkChangeMonitor(Action<string>? log = null)
        {
            _log = log;
        }

        public void Start()
        {
            if (_started) return;
            _started = true;

            _lastFingerprint = BuildFingerprintSafe();

            NetworkChange.NetworkAddressChanged += OnNetworkEvent;
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;

            _log?.Invoke($"[NET] NetworkChangeMonitor started: fp='{_lastFingerprint}'");
        }

        private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
        {
            _log?.Invoke($"[NET] availability changed: IsAvailable={e.IsAvailable}");
            OnNetworkEvent(sender, EventArgs.Empty);
        }

        private void OnNetworkEvent(object? sender, EventArgs e)
        {
            // NetworkChange часто шлёт пачки событий (особенно при DHCP/VPN).
            // Делаем debounce, и только затем сравниваем "отпечаток".
            CancellationTokenSource cts;
            lock (_sync)
            {
                _debounceCts?.Cancel();
                _debounceCts?.Dispose();
                _debounceCts = new CancellationTokenSource();
                cts = _debounceCts;
            }

            _ = DebouncedCheckAsync(cts.Token);
        }

        private async Task DebouncedCheckAsync(CancellationToken ct)
        {
            try
            {
                await Task.Delay(800, ct).ConfigureAwait(false);

                var fp = BuildFingerprintSafe();
                if (string.IsNullOrWhiteSpace(fp))
                {
                    return;
                }

                var changed = false;
                lock (_sync)
                {
                    if (!string.Equals(_lastFingerprint, fp, StringComparison.Ordinal))
                    {
                        _lastFingerprint = fp;
                        changed = true;
                    }
                }

                if (!changed)
                {
                    return;
                }

                _log?.Invoke($"[NET] fingerprint changed: fp='{fp}'");
                NetworkChanged?.Invoke(fp);
            }
            catch (OperationCanceledException)
            {
                // ignore
            }
            catch (Exception ex)
            {
                _log?.Invoke($"[NET] NetworkChangeMonitor error: {ex.Message}");
            }
        }

        private static string BuildFingerprintSafe()
        {
            try
            {
                var available = NetworkInterface.GetIsNetworkAvailable();

                var parts = new List<string>
                {
                    available ? "avail=1" : "avail=0"
                };

                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni == null) continue;

                    // Берём только UP интерфейсы: это снижает шум от отключенных адаптеров.
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;

                    var ip = ni.GetIPProperties();
                    var v4 = ip.UnicastAddresses
                        .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(a => a.Address.ToString())
                        .OrderBy(s => s, StringComparer.Ordinal)
                        .ToArray();

                    var gw = ip.GatewayAddresses
                        .Select(g => g.Address?.ToString() ?? string.Empty)
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .OrderBy(s => s, StringComparer.Ordinal)
                        .ToArray();

                    var sb = new StringBuilder();
                    sb.Append("if=").Append(ni.Id);
                    if (v4.Length > 0) sb.Append(";v4=").Append(string.Join(",", v4));
                    if (gw.Length > 0) sb.Append(";gw=").Append(string.Join(",", gw));

                    parts.Add(sb.ToString());
                }

                parts.Sort(StringComparer.Ordinal);
                return string.Join("|", parts);
            }
            catch
            {
                return string.Empty;
            }
        }

        public void Dispose()
        {
            try
            {
                NetworkChange.NetworkAddressChanged -= OnNetworkEvent;
                NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
            }
            catch
            {
                // ignore
            }

            lock (_sync)
            {
                try
                {
                    _debounceCts?.Cancel();
                    _debounceCts?.Dispose();
                }
                catch
                {
                    // ignore
                }
                finally
                {
                    _debounceCts = null;
                }
            }
        }
    }
}
