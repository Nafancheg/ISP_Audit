using System;
using System.IO;
using System.Text;
using System.Linq;
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
        private readonly Button btnSummaryActions;
        private readonly Button btnCopyReport;
        private readonly CheckBox chkDns;
        private readonly CheckBox chkTcp;
        private readonly CheckBox chkHttp;
        private readonly CheckBox chkTrace;
        private readonly CheckBox chkUdp;
        private readonly CheckBox chkRst;
        private readonly CheckBox chkAdvanced;
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
        private readonly Label lblSummaryStatus;
        private readonly Label lblSummaryIssues;
        private readonly Label lblSummaryRecommendations;
        private readonly Panel pnlAdvanced;

        private readonly StringBuilder _logBuffer = new();
        private Output.RunReport? _lastRun;
        private Config _lastConfig = Config.Default();
        private CancellationTokenSource? _cts;
        private string _lastAdviceText = string.Empty;
        private string _lastSummaryPlainText = string.Empty;
        private Form? _summaryPopup;
        private bool _summaryReady;

        public GuiForm()
        {
            this.Font = new System.Drawing.Font("Segoe UI", 9F);
            Text = "ISP Audit";
            Width = 1100;
            Height = 720;

            btnRun = new Button { Text = "Проверить", AutoSize = true };
            btnRun.Click += BtnRun_Click;
            btnCancel = new Button { Text = "Остановить", Enabled = false, AutoSize = true, Visible = false };
            btnCancel.Click += BtnCancel_Click;

            btnSaveJson = new Button { Text = "Сохранить JSON", AutoSize = true };
            btnSaveJson.Click += BtnSaveJson_Click;

            btnShowReport = new Button { Text = "Подробный отчёт", AutoSize = true };
            btnShowReport.Click += BtnShowReport_Click;

            btnSummaryActions = new Button { Text = "Что делать?", AutoSize = true };
            btnSummaryActions.Click += BtnSummaryActions_Click;
            btnCopyReport = new Button { Text = "Скопировать отчёт", AutoSize = true };
            btnCopyReport.Click += BtnCopyReport_Click;
            btnSummaryActions.Enabled = false;
            btnCopyReport.Enabled = false;

            chkDns = new CheckBox { AutoSize = true, Text = "DNS", Checked = true };
            chkTcp = new CheckBox { AutoSize = true, Text = "TCP", Checked = true };
            chkHttp = new CheckBox { AutoSize = true, Text = "HTTP", Checked = true };
            chkTrace = new CheckBox { AutoSize = true, Text = "Traceroute", Checked = true };
            chkUdp = new CheckBox { AutoSize = true, Text = "UDP", Checked = true };
            chkRst = new CheckBox { AutoSize = true, Text = "RST", Checked = true };
            chkAdvanced = new CheckBox { AutoSize = true, Text = "Расширенный режим" };

            txtTimeout = new TextBox { Width = 50, Text = "12" };
            var lblTimeout = new Label { AutoSize = true, Text = "Таймаут, с" };
            lblExtIp = new Label { AutoSize = true, Text = string.Empty };

            var tips = new ToolTip();
            tips.SetToolTip(btnRun, "Запустить быструю проверку");
            tips.SetToolTip(btnCancel, "Остановить текущую проверку");
            tips.SetToolTip(btnSaveJson, "Сохранить полный JSON отчёт");
            tips.SetToolTip(btnShowReport, "Открыть подробные результаты");
            tips.SetToolTip(chkDns, "Сравнить системный DNS и Cloudflare DoH");
            tips.SetToolTip(chkTcp, "Попробовать подключиться к портам 80/443");
            tips.SetToolTip(chkHttp, "Сделать HTTPS-запросы и проверить сертификаты");
            tips.SetToolTip(chkTrace, "Выполнить трассировку до цели");
            tips.SetToolTip(chkUdp, "Отправить UDP-запрос на 1.1.1.1:53");
            tips.SetToolTip(chkRst, "Проверить подозрение на RST-блокировку");
            tips.SetToolTip(txtTimeout, "Максимальное время ожидания сетевых операций, с");

            lvTargets = new ListView { View = View.Details, FullRowSelect = true, Dock = DockStyle.Fill };
            lvTargets.Columns.Add("Название", 160);
            lvTargets.Columns.Add("Адрес", 180);

            txtName = new TextBox { Dock = DockStyle.Fill };
            txtHost = new TextBox { Dock = DockStyle.Fill };
            btnAdd = new Button { Text = "Добавить / Обновить", AutoSize = true };
            btnRemove = new Button { Text = "Удалить", AutoSize = true };
            btnAdd.Click += BtnAdd_Click;
            btnRemove.Click += BtnRemove_Click;

            lvSteps = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill };
            lvSteps.Columns.Add("Тест", 160);
            lvSteps.Columns.Add("Статус", 150);
            lvSteps.Columns.Add("Комментарий", 320);

            pbOverall = new ProgressBar { Style = ProgressBarStyle.Blocks, Dock = DockStyle.Fill };
            lblStatus = new Label { AutoSize = true, Text = "Ожидание запуска" };

            txtLog = new TextBox { Multiline = true, ScrollBars = ScrollBars.Both, ReadOnly = true, Dock = DockStyle.Fill, Font = new System.Drawing.Font("Consolas", 10) };
            txtAnalysis = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };

            lblSummaryStatus = new Label
            {
                Text = "Проверка ещё не запускалась",
                AutoSize = false,
                Dock = DockStyle.Fill,
                Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold),
                ForeColor = System.Drawing.Color.DimGray,
                Margin = new Padding(0, 0, 12, 6)
            };

            lblSummaryIssues = new Label
            {
                Text = "Проблемы будут показаны здесь после проверки.",
                AutoSize = true,
                MaximumSize = new System.Drawing.Size(650, 0),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                Margin = new Padding(0, 8, 12, 4),
                Font = new System.Drawing.Font("Segoe UI", 9.5F),
                ForeColor = System.Drawing.Color.Black
            };

            lblSummaryRecommendations = new Label
            {
                Text = "Рекомендации появятся после анализа.",
                AutoSize = true,
                MaximumSize = new System.Drawing.Size(650, 0),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                Margin = new Padding(0, 4, 12, 4),
                Font = new System.Drawing.Font("Segoe UI", 9F),
                ForeColor = System.Drawing.Color.Black
            };

            var summaryLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                AutoSize = true
            };
            summaryLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 65));
            summaryLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
            summaryLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            summaryLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            summaryLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var summaryPanel = new Panel
            {
                Dock = DockStyle.Top,
                Padding = new Padding(12),
                BackColor = System.Drawing.Color.FromArgb(240, 248, 255),
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink
            };

            summaryLayout.Controls.Add(lblSummaryStatus, 0, 0);
            summaryLayout.Controls.Add(lblSummaryIssues, 0, 1);
            summaryLayout.Controls.Add(lblSummaryRecommendations, 0, 2);

            var actionPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false
            };
            actionPanel.Controls.Add(btnSummaryActions);
            actionPanel.Controls.Add(btnCopyReport);

            summaryLayout.Controls.Add(actionPanel, 1, 0);
            summaryLayout.SetRowSpan(actionPanel, 3);

            summaryPanel.Controls.Add(summaryLayout);

            var runPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(12, 6, 12, 0)
            };
            runPanel.Controls.Add(btnRun);
            runPanel.Controls.Add(btnCancel);
            btnCancel.Margin = new Padding(12, 3, 0, 3);
            runPanel.Controls.Add(chkAdvanced);
            chkAdvanced.Margin = new Padding(20, 6, 0, 3);

            var progressPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(12, 6, 12, 6),
                ColumnCount = 1
            };
            progressPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            progressPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            progressPanel.Controls.Add(pbOverall, 0, 0);
            progressPanel.Controls.Add(lblStatus, 0, 1);

            pnlAdvanced = new Panel { Dock = DockStyle.Fill, Visible = false };

            var advancedContainer = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2
            };
            advancedContainer.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            advancedContainer.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var advancedToolbar = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = false,
                Padding = new Padding(8, 8, 8, 4)
            };
            foreach (var c in new Control[]
            {
                btnSaveJson,
                btnShowReport,
                chkDns,
                chkTcp,
                chkHttp,
                chkTrace,
                chkUdp,
                chkRst,
                txtTimeout,
                lblTimeout,
                lblExtIp
            })
            {
                if (c is Button b) { b.Margin = new Padding(6, 2, 6, 2); }
                else if (c is CheckBox cb) { cb.Margin = new Padding(12, 6, 0, 2); }
                else if (c is TextBox tb) { tb.Margin = new Padding(12, 2, 6, 2); }
                else if (c is Label l) { l.Margin = new Padding(6, 6, 6, 2); }
                advancedToolbar.Controls.Add(c);
            }

            advancedContainer.Controls.Add(advancedToolbar, 0, 0);

            var advancedLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2
            };
            advancedLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 360));
            advancedLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var targetsLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(0, 0, 8, 0)
            };
            targetsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            targetsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            targetsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            targetsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            targetsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            targetsLayout.Controls.Add(lvTargets, 0, 0);

            var nameLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
            nameLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            nameLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            nameLayout.Controls.Add(new Label { Text = "Название", Dock = DockStyle.Fill, TextAlign = System.Drawing.ContentAlignment.MiddleLeft }, 0, 0);
            nameLayout.Controls.Add(txtName, 1, 0);
            targetsLayout.Controls.Add(nameLayout, 0, 1);

            var hostLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
            hostLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            hostLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            hostLayout.Controls.Add(new Label { Text = "Адрес", Dock = DockStyle.Fill, TextAlign = System.Drawing.ContentAlignment.MiddleLeft }, 0, 0);
            hostLayout.Controls.Add(txtHost, 1, 0);
            targetsLayout.Controls.Add(hostLayout, 0, 2);

            var targetButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
            targetButtons.Controls.Add(btnAdd);
            targetButtons.Controls.Add(btnRemove);
            targetsLayout.Controls.Add(targetButtons, 0, 3);

            advancedLayout.Controls.Add(targetsLayout, 0, 0);

            var resultsLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3
            };
            resultsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 200));
            resultsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            resultsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 45));
            resultsLayout.Controls.Add(lvSteps, 0, 0);
            resultsLayout.Controls.Add(txtLog, 0, 1);
            resultsLayout.Controls.Add(txtAnalysis, 0, 2);

            advancedLayout.Controls.Add(resultsLayout, 1, 0);

            advancedContainer.Controls.Add(advancedLayout, 0, 1);
            pnlAdvanced.Controls.Add(advancedContainer);

            var rootLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4
            };
            rootLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rootLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rootLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rootLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            rootLayout.Controls.Add(summaryPanel, 0, 0);
            rootLayout.Controls.Add(runPanel, 0, 1);
            rootLayout.Controls.Add(progressPanel, 0, 2);
            rootLayout.Controls.Add(pnlAdvanced, 0, 3);

            Controls.Add(rootLayout);

            LoadTargetsToListView();
            lvTargets.SelectedIndexChanged += LvTargets_SelectedIndexChanged;
            chkAdvanced.CheckedChanged += ChkAdvanced_CheckedChanged;
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
            btnCancel.Visible = true;
            pbOverall.Style = ProgressBarStyle.Marquee;
            lblStatus.Text = "Проверка выполняется…";
            txtLog.Clear();
            txtAnalysis.Clear();
            _logBuffer.Clear();
            lblSummaryStatus.Text = "Идёт проверка…";
            lblSummaryStatus.ForeColor = System.Drawing.Color.DodgerBlue;
            lblSummaryIssues.Text = "Пожалуйста, дождитесь результатов.";
            lblSummaryRecommendations.Text = string.Empty;
            _lastAdviceText = string.Empty;
            _lastSummaryPlainText = string.Empty;
            _summaryReady = false;
            UpdateSummaryActionsState();
            CloseSummaryPopup();

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
                    _lastAdviceText = advice;
                    txtAnalysis.Text = BuildGuiSummary(run) + Environment.NewLine + "Рекомендации:" + Environment.NewLine + advice;
                    UpdateSummaryBlock(run, advice);
                }));
            }
            catch (OperationCanceledException)
            {
                lblStatus.Text = "Проверка остановлена";
                lblSummaryStatus.Text = "Проверка остановлена";
                lblSummaryStatus.ForeColor = System.Drawing.Color.DimGray;
                lblSummaryRecommendations.Text = string.Empty;
                _summaryReady = false;
                UpdateSummaryActionsState();
            }
            catch (Exception ex)
            {
                AppendText($"Exception: {ex}\r\n");
                lblSummaryStatus.Text = "Произошла ошибка";
                lblSummaryStatus.ForeColor = System.Drawing.Color.Crimson;
                lblSummaryIssues.Text = ex.Message;
                lblSummaryRecommendations.Text = string.Empty;
                _summaryReady = false;
                UpdateSummaryActionsState();
            }
            finally
            {
                pbOverall.Style = ProgressBarStyle.Blocks;
                lblStatus.Text = "Готово";
                btnRun.Enabled = true;
                btnCancel.Enabled = false;
                btnCancel.Visible = chkAdvanced.Checked;
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
            _lastAdviceText = txt;
            ShowTextWindow("Человеческий отчёт", txt);
        }

        private void BtnSummaryActions_Click(object? sender, EventArgs e)
        {
            if (!_summaryReady || _lastRun == null)
            {
                MessageBox.Show(this, "Сначала выполните проверку.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (string.IsNullOrWhiteSpace(_lastAdviceText))
            {
                _lastAdviceText = Output.ReportWriter.BuildAdviceText(_lastRun);
            }
            ShowTextWindow("Что делать дальше", _lastAdviceText);
        }

        private void BtnCopyReport_Click(object? sender, EventArgs e)
        {
            if (!_summaryReady || string.IsNullOrWhiteSpace(_lastSummaryPlainText))
            {
                MessageBox.Show(this, "Отчёт появится после завершения проверки.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                Clipboard.SetText(_lastSummaryPlainText);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Не удалось скопировать отчёт: " + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ChkAdvanced_CheckedChanged(object? sender, EventArgs e)
        {
            pnlAdvanced.Visible = chkAdvanced.Checked;
            btnCancel.Visible = chkAdvanced.Checked || btnCancel.Enabled;
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
            sb.AppendLine("Общий итог:");
            sb.AppendLine($"DNS: {FormatStatus(run.summary.dns)}");
            sb.AppendLine($"TCP: {FormatStatus(run.summary.tcp)}");
            sb.AppendLine($"UDP: {FormatStatus(run.summary.udp)}");
            sb.AppendLine($"TLS: {FormatStatus(run.summary.tls)}");
            sb.AppendLine();
            foreach (var kv in run.targets)
            {
                var t = kv.Value;
                bool anyOpen = t.tcp.Exists(r => r.open);
                bool httpOk = t.http.Exists(h => h.success && h.status is >= 200 and < 400);
                sb.AppendLine($"— {kv.Key}: DNS {FormatStatus(t.dns_status)}, порты {(anyOpen ? "доступны" : "закрыты")}, HTTPS {(httpOk ? "отвечает" : "не отвечает")}");
            }
            if (run.udp_test != null)
            {
                sb.AppendLine();
                sb.AppendLine($"UDP DNS {run.udp_test.target}: {(run.udp_test.reply ? "есть ответ" : "нет ответа")}, задержка {run.udp_test.rtt_ms?.ToString() ?? "-"} мс");
            }
            return sb.ToString();
        }

        private void InitSteps()
        {
            if (InvokeRequired) { BeginInvoke(new Action(InitSteps)); return; }
            lvSteps.Items.Clear();
            if (chkDns.Checked) AddStepRow("DNS", "в очереди");
            if (chkTcp.Checked) AddStepRow("TCP", "в очереди");
            if (chkHttp.Checked) AddStepRow("HTTP", "в очереди");
            if (chkTrace.Checked) AddStepRow("Traceroute", "в очереди");
            if (chkUdp.Checked) AddStepRow("UDP", "в очереди");
            if (chkRst.Checked) AddStepRow("RST", "в очереди");
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
                    it.SubItems[1].Text = p.Success == null ? "идёт проверка" : (p.Success.Value ? "успешно" : "ошибка");
                    it.SubItems[2].Text = p.Message ?? string.Empty;
                    it.ForeColor = p.Success == null ? System.Drawing.Color.DodgerBlue : (p.Success.Value ? System.Drawing.Color.ForestGreen : System.Drawing.Color.Crimson);
                    if (p.Success == null)
                        lblStatus.Text = $"{name}: {p.Status}";
                    else
                        lblStatus.Text = $"{name}: {(p.Success.Value ? "успешно" : "ошибка")}";
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

        private void UpdateSummaryBlock(Output.RunReport run, string advice)
        {
            bool hasIssues = HasIssues(run);
            lblSummaryStatus.Text = hasIssues ? "Проблемы обнаружены" : "Проблемы не обнаружены";
            lblSummaryStatus.ForeColor = hasIssues ? System.Drawing.Color.Crimson : System.Drawing.Color.ForestGreen;

            lblSummaryIssues.Text = BuildIssuesText(run);
            lblSummaryRecommendations.Text = advice;

            _lastSummaryPlainText = $"Статус: {lblSummaryStatus.Text}{Environment.NewLine}{Environment.NewLine}Проблемы:{Environment.NewLine}{lblSummaryIssues.Text}{Environment.NewLine}{Environment.NewLine}Рекомендации:{Environment.NewLine}{advice}";
            _summaryReady = true;
            UpdateSummaryActionsState();
            ShowSummaryPopup(lblSummaryStatus.Text, lblSummaryIssues.Text, advice, hasIssues);
        }

        private static bool HasIssues(Output.RunReport run)
        {
            return run.summary.dns != "OK" && run.summary.dns != "UNKNOWN"
                   || run.summary.tcp == "FAIL"
                   || run.summary.udp == "FAIL"
                   || run.summary.tls == "FAIL"
                   || run.summary.tls == "SUSPECT";
        }

        private static string BuildIssuesText(Output.RunReport run)
        {
            var issues = new StringBuilder();

            void AddIssue(string text)
            {
                if (issues.Length > 0) issues.AppendLine();
                issues.Append("• ");
                issues.Append(text);
            }

            switch (run.summary.dns)
            {
                case "DNS_BOGUS":
                    AddIssue("DNS возвращает недействительные ответы.");
                    break;
                case "DNS_FILTERED":
                    AddIssue("Похоже на фильтрацию или подмену DNS.");
                    break;
                case "WARN":
                    AddIssue("Ответы системного DNS и DoH не совпадают.");
                    break;
            }

            if (run.summary.tcp == "FAIL")
                AddIssue("Не получилось подключиться к проверенным TCP-портам.");

            if (run.summary.udp == "FAIL")
                AddIssue("Нет ответа на UDP-запрос к 1.1.1.1:53.");

            if (run.summary.tls == "FAIL")
                AddIssue("HTTPS-сервисы не ответили на запросы.");
            else if (run.summary.tls == "SUSPECT")
                AddIssue("Есть подозрение на блокировку HTTPS по SNI.");

            if (issues.Length == 0)
                issues.Append("Явных проблем не найдено.");

            return issues.ToString();
        }

        private static string FormatStatus(string status)
        {
            return status switch
            {
                "OK" => "норма",
                "WARN" => "есть предупреждения",
                "FAIL" => "не пройдено",
                "SUSPECT" => "подозрение на блокировку",
                "DNS_BOGUS" => "ошибочные ответы",
                "DNS_FILTERED" => "возможна фильтрация",
                "UNKNOWN" => "нет данных",
                _ => status
            };
        }

        private void UpdateSummaryActionsState()
        {
            btnSummaryActions.Enabled = _summaryReady;
            btnCopyReport.Enabled = _summaryReady;
        }

        private void CloseSummaryPopup()
        {
            if (_summaryPopup != null)
            {
                if (!_summaryPopup.IsDisposed)
                {
                    _summaryPopup.Close();
                }
                _summaryPopup = null;
            }
        }

        private void ShowSummaryPopup(string status, string issues, string advice, bool hasIssues)
        {
            CloseSummaryPopup();

            var popup = new Form
            {
                Text = "Итоги проверки",
                Width = 540,
                Height = 420,
                StartPosition = FormStartPosition.CenterParent,
                MinimizeBox = false,
                MaximizeBox = false
            };

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(12)
            };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var statusLabel = new Label
            {
                Text = status,
                AutoSize = true,
                Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold),
                ForeColor = hasIssues ? System.Drawing.Color.Crimson : System.Drawing.Color.ForestGreen,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 8)
            };

            var issuesBox = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                Text = issues,
                Font = new System.Drawing.Font("Segoe UI", 9F)
            };

            var adviceBox = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                Text = advice,
                Font = new System.Drawing.Font("Segoe UI", 9F)
            };

            var buttonsPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink
            };

            var btnClose = new Button { Text = "Закрыть", AutoSize = true };
            btnClose.Click += (_, _) => popup.Close();

            var btnCopy = new Button { Text = "Скопировать отчёт", AutoSize = true };
            btnCopy.Click += (_, _) =>
            {
                try
                {
                    Clipboard.SetText(_lastSummaryPlainText);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(popup, "Не удалось скопировать отчёт: " + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            var btnDetails = new Button { Text = "Что делать?", AutoSize = true };
            btnDetails.Click += (_, _) => BtnSummaryActions_Click(btnDetails, EventArgs.Empty);

            buttonsPanel.Controls.Add(btnClose);
            buttonsPanel.Controls.Add(btnCopy);
            buttonsPanel.Controls.Add(btnDetails);

            layout.Controls.Add(statusLabel, 0, 0);
            layout.Controls.Add(issuesBox, 0, 1);
            layout.Controls.Add(adviceBox, 0, 2);
            layout.Controls.Add(buttonsPanel, 0, 3);

            popup.Controls.Add(layout);

            popup.FormClosed += (_, _) =>
            {
                if (_summaryPopup == popup)
                {
                    _summaryPopup = null;
                }
            };

            _summaryPopup = popup;
            popup.Show(this);
        }
    }
}
