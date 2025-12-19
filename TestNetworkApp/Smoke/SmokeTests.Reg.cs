using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IspAudit.Utils;
using IspAudit.ViewModels;

namespace TestNetworkApp.Smoke
{
    internal static partial class SmokeTests
    {
        public static async Task<SmokeTestResult> REG_Tracert_Cp866_NoMojibake(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                var cp866 = Encoding.GetEncoding(866);

                var psi = new ProcessStartInfo
                {
                    FileName = "tracert.exe",
                    Arguments = "-h 1 127.0.0.1",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = cp866,
                    StandardErrorEncoding = cp866
                };

                using var p = Process.Start(psi);
                if (p == null)
                {
                    return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Fail, sw.Elapsed,
                        "Не удалось запустить tracert.exe");
                }

                var outputTask = p.StandardOutput.ReadToEndAsync();
                var errTask = p.StandardError.ReadToEndAsync();

                await Task.WhenAny(Task.WhenAll(outputTask, errTask), Task.Delay(5000, ct)).ConfigureAwait(false);

                try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }

                var output = (await outputTask.ConfigureAwait(false)) + "\n" + (await errTask.ConfigureAwait(false));

                // Простейший критерий: отсутствие replacement char.
                if (output.Contains('�'))
                {
                    return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Fail, sw.Elapsed,
                        "В выводе обнаружен символ замены '�' (возможна проблема с кодировкой)" );
                }

                return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Pass, sw.Elapsed, "OK");
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("REG-001", "REG: tracert CP866 без кракозябр", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }

        public static async Task<SmokeTestResult> REG_VpnWarning_WhenVpnDetected(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var prev = NetUtils.LikelyVpnActiveOverrideForSmoke;
                NetUtils.LikelyVpnActiveOverrideForSmoke = () => true;

                try
                {
                    using var engine = new IspAudit.Core.Traffic.TrafficEngine();
                    var bypass = new BypassController(engine);

                    await bypass.InitializeOnStartupAsync().ConfigureAwait(false);

                    if (!bypass.IsVpnDetected)
                    {
                        return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Fail, sw.Elapsed,
                            "Ожидали IsVpnDetected=true при принудительном override" );
                    }

                    if (string.IsNullOrWhiteSpace(bypass.VpnWarningText))
                    {
                        return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Fail, sw.Elapsed,
                            "Ожидали непустой VpnWarningText при детекте VPN" );
                    }

                    return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Pass, sw.Elapsed, "OK");
                }
                finally
                {
                    NetUtils.LikelyVpnActiveOverrideForSmoke = prev;
                }
            }
            catch (Exception ex)
            {
                return new SmokeTestResult("REG-002", "REG: VPN warning (детект)", SmokeOutcome.Fail, sw.Elapsed, ex.Message);
            }
        }
    }
}
