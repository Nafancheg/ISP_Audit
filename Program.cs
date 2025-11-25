using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using IspAudit.Output;
using IspAudit.Tests;
using IspAudit.Utils;
using ISPAudit;

namespace IspAudit
{
    internal static class Program
    {
        // Retained for GUI compatibility: name -> target definition
        public static Dictionary<string, TargetDefinition> Targets { get; set; } = TargetCatalog.CreateDefaultTargetMap();

        [STAThread]
        private static int Main(string[] args)
        {
            // DEBUG: Логируем в файл
            var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "isp_audit_debug.txt");
            File.WriteAllText(logPath, $"Program.Main STARTED at {DateTime.Now}\n");
            File.AppendAllText(logPath, $"Args count: {args.Length}\n");
            
            try
            {
                File.AppendAllText(logPath, "Setting Console.OutputEncoding...\n");
                Console.OutputEncoding = System.Text.Encoding.UTF8;
                File.AppendAllText(logPath, "Console.OutputEncoding set\n");
                
                File.AppendAllText(logPath, "Setting Console.Title...\n");
                Console.Title = "ISP Audit - standalone exe";
                File.AppendAllText(logPath, "Console.Title set\n");
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, $"Console setup failed: {ex.Message}\n");
                // Ignore console errors in GUI mode
            }

            File.AppendAllText(logPath, "Console configured\n");

            // Load default profile
            Config.SetActiveProfile("Default");
            
            File.AppendAllText(logPath, "Profile loaded\n");

            // GUI mode: явный параметр или запуск без аргументов
            if (args.Length == 0 || (args.Length > 0 && args[0].Equals("gui", StringComparison.OrdinalIgnoreCase)))
            {
                File.AppendAllText(logPath, "Entering GUI mode\n");
                
                // Скрыть консоль при GUI-запуске
                TryHideConsoleWindow();

                File.AppendAllText(logPath, "Console hidden\n");

                try
                {
                    File.AppendAllText(logPath, "Creating App...\n");
                    var app = new App();
                    
                    File.AppendAllText(logPath, "Calling app.InitializeComponent()...\n");
                    // FIXME: InitializeComponent() not visible - namespace issue?
                    // app.InitializeComponent();
                    
                    File.AppendAllText(logPath, "App initialized, calling Run()\n");
                    app.Run();
                    
                    File.AppendAllText(logPath, "App.Run() returned\n");
                }
                catch (Exception ex)
                {
                    File.AppendAllText(logPath, $"EXCEPTION in GUI mode:\n{ex}\n");
                    throw;
                }
                
                return 0;
            }

            // CLI mode - run async logic
            return RunCliAsync(args).GetAwaiter().GetResult();
        }

        private static async Task<int> RunCliAsync(string[] args)
        {

            // Parse CLI
            var (config, parseError, helpText) = Config.ParseArgs(args);
            if (!string.IsNullOrEmpty(parseError))
            {
                Console.WriteLine(parseError);
                if (!string.IsNullOrEmpty(helpText)) Console.WriteLine(helpText);
                return 2;
            }
            if (config.ShowHelp)
            {
                Console.WriteLine(helpText);
                return 0;
            }

            // Auto-detect VPN in CLI mode
            if (NetUtils.LikelyVpnActive())
            {
                config.Profile = "vpn";
                config.HttpTimeoutSeconds = 12;
                config.TcpTimeoutSeconds = 8;
                config.UdpTimeoutSeconds = 4;
                if (config.Verbose)
                {
                    Console.WriteLine("VPN detected - using adaptive timeouts (HTTP: 12s, TCP: 8s, UDP: 4s)");
                }
            }

            // Build targets list
            var targetDefinitions = config.ResolveTargets();
            var targets = targetDefinitions.Select(t => t.Host).Distinct().ToList();

            // Human header
            PrettyHeader("ISP Audit – Network Diagnostics");
            Console.WriteLine($"Targets: {string.Join(", ", targetDefinitions.Select(t => $"{t.Name} ({t.Host})"))}");
            Console.WriteLine($"Timeouts: http={config.HttpTimeoutSeconds}s tcp={config.TcpTimeoutSeconds}s udp={config.UdpTimeoutSeconds}s");
            Console.WriteLine();

            // External IP (no upload; local only)
            string extIp = await NetUtils.TryGetExternalIpAsync().ConfigureAwait(false);
            Console.WriteLine($"External IP: {extIp}");
            Console.WriteLine();

            // Run tests via audit runner
            IspAudit.Bypass.WinDivertBypassManager? bypassManager = null;
            if (config.EnableAutoBypass)
            {
                bypassManager = new IspAudit.Bypass.WinDivertBypassManager();
            }

            var run = await AuditRunner.RunAsync(new Config
            {
                Targets = targets,
                TargetMap = config.TargetMap.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.OrdinalIgnoreCase),
                ReportPath = config.ReportPath,
                Verbose = config.Verbose,
                PrintJson = config.PrintJson,
                NoTrace = config.NoTrace,
                HttpTimeoutSeconds = config.HttpTimeoutSeconds,
                TcpTimeoutSeconds = config.TcpTimeoutSeconds,
                UdpTimeoutSeconds = config.UdpTimeoutSeconds,
                Ports = new List<int>(config.Ports),
                UdpProbes = config.UdpProbes.Select(p => p.Copy()).ToList(),
                EnableAutoBypass = config.EnableAutoBypass
            }, null, default, bypassManager).ConfigureAwait(false);
            run.cli = string.Join(' ', args);
            run.ext_ip = extIp;

            if (bypassManager != null)
            {
                await bypassManager.DisableAsync();
            }

            // Console pretty output
            ReportWriter.PrintHuman(run, config);

            // Save JSON report
            string outPath = string.IsNullOrWhiteSpace(config.ReportPath) ? Path.Combine(Directory.GetCurrentDirectory(), "isp_report.json") : config.ReportPath;
            await ReportWriter.SaveJsonAsync(run, outPath).ConfigureAwait(false);
            Console.WriteLine($"Saved JSON report: {outPath}");

            // Optional short JSON to stdout
            if (config.PrintJson)
            {
                Console.WriteLine(ReportWriter.BuildShortSummaryJson(run));
            }

            return 0;
        }

        // For GUI: run with current Program.Targets
        public static async Task RunAllChecksAsync()
        {
            var config = Config.Default();
            config.TargetMap = Targets.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.OrdinalIgnoreCase);
            config.Targets = config.TargetMap.Values.Select(t => t.Host).Distinct().ToList();
            await RunCliAsync(config.ToArgsArray());
        }

        private static void PrettyHeader(string text)
        {
            string line = new string('=', Math.Min(80, Math.Max(10, text.Length + 8)));
            Console.WriteLine(line);
            Console.WriteLine($"  {text}");
            Console.WriteLine(line);
        }

        private static void TryHideConsoleWindow()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    var hWnd = NativeMethods.GetConsoleWindow();
                    if (hWnd != IntPtr.Zero)
                    {
                        NativeMethods.ShowWindow(hWnd, 0); // SW_HIDE
                    }
                }
            }
            catch { }
        }

        private static class NativeMethods
        {
            [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
            [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        }
    }
}
