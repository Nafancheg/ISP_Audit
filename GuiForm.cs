using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace IspAudit
{
    public class GuiForm : Form
    {
        private readonly Button btnRun;
        private readonly Button btnCancel;
        private readonly Button btnSaveJson;
        private readonly Button btnShowReport;
        private readonly CheckBox chkDns;
        private readonly CheckBox chkTcp;
        private readonly CheckBox chkHttp;
        private readonly CheckBox chkTrace;
        private readonly CheckBox chkUdp;
        private readonly CheckBox chkRst;
        private readonly TextBox txtTimeout;
        private readonly Label lblExtIp;
        private readonly ListView lvTargets;
        private readonly ListView lvSteps;
        private readonly TextBox txtName;
        private readonly TextBox txtHost;
        private readonly Button btnAdd;
        private readonly Button btnRemove;
        private readonly TextBox txtLog;
        private readonly TextBox txtAnalysis;
        private readonly ProgressBar pbOverall;
        private readonly Label lblStatus;

        private readonly StringBuilder _logBuffer = new();
        private Output.RunReport? _lastRun;
        private Config _lastConfig = Config.Default();
        private CancellationTokenSource? _cts;

        public GuiForm()
        {
            this.Font = new System.Drawing.Font("Segoe UI", 9F);
            Text = "ISP Audit";
            Width = 1100;
            Height = 720;

            btnRun = new Button { Text = "Запустить" };
            btnRun.Click += BtnRun_Click;
            btnCancel = new Button { Text = "Отмена", Enabled = false };
            btnCancel.Click += BtnCancel_Click;

            btnSaveJson = new Button { Text = "Сохранить JSON" };
            btnSaveJson.Click += BtnSaveJson_Click;

            btnShowReport = new Button { Text = "Показать отчёт" };
            btnShowReport.Click += BtnShowReport_Click;
            chkDns = new CheckBox { AutoSize = true, Text = "DNS", Checked = true };
            chkTcp = new CheckBox { AutoSize = true, Text = "TCP", Checked = true };
            chkHttp = new CheckBox { AutoSize = true, Text = "HTTP", Checked = true };
            chkTrace = new CheckBox { AutoSize = true, Text = "Traceroute", Checked = true };
            chkUdp = new CheckBox { AutoSize = true, Text = "UDP", Checked = true };
            chkRst = new CheckBox { AutoSize = true, Text = "RST", Checked = true };
            txtTimeout = new TextBox { Width = 50, Text = "12" };
            var lblTimeout = new Label { AutoSize = true, Text = "Таймаут, с" };
            lblExtIp = new Label { AutoSize = true, Text = string.Empty };

            // Автосайзинг тулбара
            var topBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = false,
                Padding = new Padding(8, 8, 8, 4)
            };
            foreach (var c in new Control[] { btnRun, btnCancel, btnSaveJson, btnShowReport, chkDns, chkTcp, chkHttp, chkTrace, chkUdp, chkRst, txtTimeout, lblTimeout, lblExtIp })
            {
                if (c is Button b) { b.AutoSize = true; b.AutoSizeMode = AutoSizeMode.GrowAndShrink; b.Margin = new Padding(6, 2, 6, 2); }
                else if (c is CheckBox cb) { cb.Margin = new Padding(12, 6, 0, 2); }
                else if (c is TextBox tb) { tb.Margin = new Padding(12, 2, 6, 2); }
                else if (c is Label l) { l.Margin = new Padding(6, 6, 6, 2); }
                topBar.Controls.Add(c);
            }
            var tips = new ToolTip();
            tips.SetToolTip(btnRun, "Запустить выбранные тесты");
            tips.SetToolTip(btnCancel, "Остановить текущую проверку");
            tips.SetToolTip(btnSaveJson, "Сохранить полный JSON отчёт");
            tips.SetToolTip(btnShowReport, "Показать краткие выводы и советы");
            tips.SetToolTip(chkDns, "Сравнение системного DNS и DoH (Cloudflare)");
            tips.SetToolTip(chkTcp, "Проверка TCP-портов (80/443)");
            tips.SetToolTip(chkHttp, "HTTP(S) запросы с SNI и чтением сертификата");
            tips.SetToolTip(chkTrace, "tracert -d (без DNS-имен), до 30 хопов");
            tips.SetToolTip(chkUdp, "UDP DNS запрос к 1.1.1.1:53 (проверка UDP/QUIC)");
            tips.SetToolTip(chkRst, "Эвристика RST-инжекции (подозрение по таймингам)");
            tips.SetToolTip(txtTimeout, "Глобальный таймаут для сетевых операций, с");

            lvTargets = new ListView { Left = 10, Top = 45, Width = 320, Height = 450, View = View.Details, FullRowSelect = true, Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left };
            lvTargets.Columns.Add("Name", 140);
            lvTargets.Columns.Add("Host", 160);

            txtName = new TextBox { Left = 10, Top = 505, Width = 150 };
            txtHost = new TextBox { Left = 170, Top = 505, Width = 160 };
            btnAdd = new Button { Text = "Add / Update", Left = 10, Top = 535, Width = 120 };
            btnRemove = new Button { Text = "Remove", Left = 140, Top = 535, Width = 80 };
            btnAdd.Click += BtnAdd_Click;
            btnRemove.Click += BtnRemove_Click;

            lvSteps = new ListView { Left = 340, Top = 45, Width = 620, Height = 200, View = View.Details, FullRowSelect = true, GridLines = true, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            lvSteps.Columns.Add("Тест", 160);
            lvSteps.Columns.Add("Статус", 120);
            lvSteps.Columns.Add("Детали", 320);

            pbOverall = new ProgressBar { Left = 340, Top = 250, Width = 620, Height = 14, Style = ProgressBarStyle.Blocks, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            lblStatus = new Label { Left = 340, Top = 268, Width = 620, Height = 18, Text = "Готов", Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };

            txtLog = new TextBox { Left = 340, Top = 290, Width = 730, Height = 205, Multiline = true, ScrollBars = ScrollBars.Both, ReadOnly = true, Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right, Font = new System.Drawing.Font("Consolas", 10) };

            txtAnalysis = new TextBox { Left = 10, Top = 580, Width = 1050, Height = 80, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };

            Controls.AddRange(new Control[]
            {
                topBar,
                lvTargets, lvSteps,
                txtName, txtHost, btnAdd, btnRemove,
                pbOverall, lblStatus,
                txtLog, txtAnalysis
            });

            LoadTargetsToListView();
            lvTargets.SelectedIndexChanged += LvTargets_SelectedIndexChanged;
        }

        private void LvTargets_SelectedIndexChanged(object? sender, EventArgs e)
        {
            if (lvTargets.SelectedItems.Count == 0) return;
            var it = lvTargets.SelectedItems[0];
            txtName.Text = it.SubItems[0].Text;
            txtHost.Text = it.SubItems[1].Text;
        }

        private void BtnAdd_Click(object? sender, EventArgs e)
        {
            string name = txtName.Text.Trim();
            string host = txtHost.Text.Trim();
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(host)) return;

            foreach (ListViewItem it in lvTargets.Items)
            {
                if (it.SubItems[0].Text.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    it.SubItems[1].Text = host;
                    return;
                }
            }
            lvTargets.Items.Add(new ListViewItem(new[] { name, host }));
        }

        private void BtnRemove_Click(object? sender, EventArgs e)
        {
            if (lvTargets.SelectedItems.Count == 0) return;
            lvTargets.Items.Remove(lvTargets.SelectedItems[0]);
        }

        private void LoadTargetsToListView()
        {
            lvTargets.Items.Clear();
            foreach (var kv in Program.Targets)
            {
                lvTargets.Items.Add(new ListViewItem(new[] { kv.Key, kv.Value }));
            }
        }

        private void SaveListViewToProgramTargets()
        {
            Program.Targets.Clear();
            foreach (ListViewItem it in lvTargets.Items)
            {
                var name = it.SubItems[0].Text;
                var host = it.SubItems[1].Text;
                if (!Program.Targets.ContainsKey(name)) Program.Targets.Add(name, host);
            }
        }

        private async void BtnRun_Click(object? sender, EventArgs e)
        {
            btnRun.Enabled = false;
            btnCancel.Enabled = true;
            pbOverall.Style = ProgressBarStyle.Marquee;
            lblStatus.Text = "Выполняется…";
            txtLog.Clear();
            txtAnalysis.Clear();
            _logBuffer.Clear();

            SaveListViewToProgramTargets();

            try
            {
                var cfg = Config.Default();
                cfg.Targets = Program.Targets.Values.ToList();
                cfg.NoTrace = !chkTrace.Checked;
                cfg.EnableDns = chkDns.Checked;
                cfg.EnableTcp = chkTcp.Checked;
                cfg.EnableHttp = chkHttp.Checked;
                cfg.EnableTrace = chkTrace.Checked;
                cfg.EnableUdp = chkUdp.Checked;
                cfg.EnableRst = chkRst.Checked;
                if (int.TryParse(txtTimeout.Text.Trim(), out int t) && t > 0)
                {
                    cfg.HttpTimeoutSeconds = t;
                    cfg.TcpTimeoutSeconds = Math.Min(10, t);
                    cfg.UdpTimeoutSeconds = Math.Min(10, t);
                }

                InitSteps();
                var progress = new Progress<IspAudit.Tests.TestProgress>(UpdateStepUI);
                _cts = new CancellationTokenSource();
                var run = await AuditRunner.RunAsync(cfg, progress, _cts.Token).ConfigureAwait(false);
                _lastRun = run;
                _lastConfig = cfg;

                BeginInvoke(new Action(() =>
                {
                    lblExtIp.Text = "Внешний IP: " + (run.ext_ip ?? "—");
                    txtLog.Text = Output.ReportWriter.BuildHumanText(run, cfg);
                    var advice = Output.ReportWriter.BuildAdviceText(run);
                    txtAnalysis.Text = BuildGuiSummary(run) + Environment.NewLine + "Рекомендации:" + Environment.NewLine + advice;
                }));
            }
            catch (OperationCanceledException)
            {
                lblStatus.Text = "Отменено";
            }
            catch (Exception ex)
            {
                AppendText($"Exception: {ex}\r\n");
            }
            finally
            {
                pbOverall.Style = ProgressBarStyle.Blocks;
                lblStatus.Text = "Готов";
                btnRun.Enabled = true;
                btnCancel.Enabled = false;
            }
        }

        private void BtnCancel_Click(object? sender, EventArgs e)
        {
            _cts?.Cancel();
        }

        private async void BtnSaveJson_Click(object? sender, EventArgs e)
        {
            if (_lastRun == null)
            {
                MessageBox.Show(this, "Сначала запустите тесты.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            using var sfd = new SaveFileDialog { Filter = "JSON (*.json)|*.json", FileName = "isp_report.json" };
            if (sfd.ShowDialog(this) == DialogResult.OK)
            {
                try
                {
                    UseWaitCursor = true;
                    btnSaveJson.Enabled = false;
                    await Output.ReportWriter.SaveJsonAsync(_lastRun, sfd.FileName).ConfigureAwait(true);
                    MessageBox.Show(this, "Отчёт сохранён:\r\n" + sfd.FileName, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Не удалось сохранить отчёт:\r\n" + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally
                {
                    btnSaveJson.Enabled = true;
                    UseWaitCursor = false;
                }
            }
        }

        private void BtnShowReport_Click(object? sender, EventArgs e)
        {
            if (_lastRun == null)
            {
                MessageBox.Show(this, "Сначала запустите тесты.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var txt = Output.ReportWriter.BuildAdviceText(_lastRun);
            ShowTextWindow("Человеческий отчёт", txt);
        }

        private void AppendText(string s)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(() => AppendText(s)));
                return;
            }
            txtLog.AppendText(s);
        }

        private string BuildGuiSummary(Output.RunReport run)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Итог: DNS={run.summary.dns} TCP={run.summary.tcp} UDP={run.summary.udp} TLS={run.summary.tls}");
            sb.AppendLine();
            foreach (var kv in run.targets)
            {
                var t = kv.Value;
                bool anyOpen = t.tcp.Exists(r => r.open);
                bool httpOk = t.http.Exists(h => h.success && h.status is >= 200 and < 400);
                sb.AppendLine($"— {kv.Key}: DNS={t.dns_status}; Порты={(anyOpen ? "есть" : "нет")}; HTTPS={(httpOk ? "ОК" : "нет")}");
            }
            if (run.udp_test != null)
            {
                sb.AppendLine();
                sb.AppendLine($"UDP DNS {run.udp_test.target}: {(run.udp_test.reply ? "ответ" : "нет ответа")}, RTT={run.udp_test.rtt_ms?.ToString() ?? "-"}мс");
            }
            return sb.ToString();
        }

        private void InitSteps()
        {
            if (InvokeRequired) { BeginInvoke(new Action(InitSteps)); return; }
            lvSteps.Items.Clear();
            if (chkDns.Checked) AddStepRow("DNS", "ожидание");
            if (chkTcp.Checked) AddStepRow("TCP", "ожидание");
            if (chkHttp.Checked) AddStepRow("HTTP", "ожидание");
            if (chkTrace.Checked) AddStepRow("Traceroute", "ожидание");
            if (chkUdp.Checked) AddStepRow("UDP", "ожидание");
            if (chkRst.Checked) AddStepRow("RST", "ожидание");
        }

        private void AddStepRow(string name, string status)
        {
            var it = new ListViewItem(new[] { name, status, string.Empty });
            lvSteps.Items.Add(it);
        }

        private void UpdateStepUI(IspAudit.Tests.TestProgress p)
        {
            if (InvokeRequired) { BeginInvoke(new Action<IspAudit.Tests.TestProgress>(UpdateStepUI), p); return; }
            string name = p.Kind switch
            {
                IspAudit.Tests.TestKind.DNS => "DNS",
                IspAudit.Tests.TestKind.TCP => "TCP",
                IspAudit.Tests.TestKind.HTTP => "HTTP",
                IspAudit.Tests.TestKind.TRACEROUTE => "Traceroute",
                IspAudit.Tests.TestKind.UDP => "UDP",
                IspAudit.Tests.TestKind.RST => "RST",
                _ => p.Kind.ToString()
            };
            foreach (ListViewItem it in lvSteps.Items)
            {
                if (it.SubItems[0].Text.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    it.SubItems[1].Text = p.Success == null ? "выполняется…" : (p.Success.Value ? "пройден" : "не пройден");
                    it.SubItems[2].Text = p.Message ?? string.Empty;
                    it.ForeColor = p.Success == null ? System.Drawing.Color.DodgerBlue : (p.Success.Value ? System.Drawing.Color.ForestGreen : System.Drawing.Color.Crimson);
                    if (p.Success == null)
                        lblStatus.Text = $"{name}: {p.Status}";
                    else
                        lblStatus.Text = $"{name}: {(p.Success.Value ? "OK" : "ошибка")}";
                    if (p.Kind == IspAudit.Tests.TestKind.TRACEROUTE && !string.IsNullOrWhiteSpace(p.Message))
                    {
                        txtLog.AppendText(p.Message + Environment.NewLine);
                    }
                    break;
                }
            }
        }

        private void ShowTextWindow(string title, string text)
        {
            var win = new Form { Text = title, Width = 900, Height = 650, StartPosition = FormStartPosition.CenterParent };
            var tb = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new System.Drawing.Font("Consolas", 10) };
            tb.Text = text;
            win.Controls.Add(tb);
            win.Show(this); // немодально, форма не блокируется
        }
    }
}
