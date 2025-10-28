using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using IspAudit.Bypass;
using IspAudit.Utils;

namespace IspAudit
{
    public class GuiForm : Form
    {
        private readonly Button btnRun;
        private readonly Button btnCancel;
        private readonly Button btnSaveJson;
        private readonly Button btnShowReport;
        private readonly Button btnSummaryActions;
        private readonly Button btnCopySummary;
        private readonly Button btnCopyReport;
        private readonly Button btnExportReport;
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
        private readonly ComboBox cmbService;
        private readonly Button btnAdd;
        private readonly Button btnRemove;
        private readonly Button btnSaveProfile;
        private readonly Button btnLoadProfile;
        private readonly TextBox txtLog;
        private readonly TextBox txtAnalysis;
        private readonly TextBox txtPorts;
        private readonly Label lblPorts;
        private readonly ProgressBar pbOverall;
        private readonly Label lblStatus;
        private readonly Label lblSummaryStatus;
        private readonly Label lblSummaryIssues;
        private readonly Label lblSummaryRecommendations;
        private readonly Panel pnlAdvanced;
        private readonly Panel pnlBypass;
        private readonly Label lblBypassTitle;
        private readonly Label lblBypassHint;
        private readonly Label lblBypassStatus;
        private readonly Button btnBypassToggle;

        private readonly StringBuilder _logBuffer = new();
        private Output.RunReport? _lastRun;
        private Config _lastConfig = Config.Default();
        private CancellationTokenSource? _cts;
        private string _lastAdviceText = string.Empty;
        private string _lastSummaryPlainText = string.Empty;
        private string _lastSummaryCompactText = string.Empty;
        private Form? _summaryPopup;
        private bool _summaryReady;
        private readonly WinDivertBypassManager _bypassManager;
        private bool _bypassActivationAllowed;
        private const string ProfileFileFilter = "Профиль ISP Audit (*.iaprofile)|*.iaprofile|JSON (*.json)|*.json";
        private const string ProfileDefaultFileName = "isp_profile.iaprofile";

        public GuiForm()
        {
            this.Font = new System.Drawing.Font("Segoe UI", 9F);
            Text = "ISP Audit";
            Width = 1100;
            Height = 720;

            _bypassManager = new WinDivertBypassManager();
            _bypassManager.StateChanged += BypassManager_StateChanged;
            _bypassActivationAllowed = false;

            btnRun = new Button { Text = "Проверить", AutoSize = true };
            btnRun.Click += BtnRun_Click;
            btnCancel = new Button { Text = "Остановить", Enabled = false, AutoSize = true, Visible = false };
            btnCancel.Click += BtnCancel_Click;

            btnSaveJson = new Button { Text = "Сохранить JSON", AutoSize = true };
            btnSaveJson.Click += BtnSaveJson_Click;

            btnExportReport = new Button { Text = "Экспорт HTML/PDF", AutoSize = true, Enabled = false };
            btnExportReport.Click += BtnExportReport_Click;

            btnShowReport = new Button { Text = "Подробный отчёт", AutoSize = true };
            btnShowReport.Click += BtnShowReport_Click;

            btnSummaryActions = new Button { Text = "Что делать?", AutoSize = true, Enabled = false };
            btnSummaryActions.Click += BtnSummaryActions_Click;
            btnCopySummary = new Button { Text = "Скопировать итог", AutoSize = true, Enabled = false };
            btnCopySummary.Click += BtnCopySummary_Click;
            btnCopyReport = new Button { Text = "Скопировать отчёт", AutoSize = true, Enabled = false };
            btnCopyReport.Click += BtnCopyReport_Click;

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

            lvTargets = new ListView { View = View.Details, FullRowSelect = true, Dock = DockStyle.Fill };
            lvTargets.Columns.Add("Название", 160);
            lvTargets.Columns.Add("Адрес", 180);

            txtName = new TextBox { Dock = DockStyle.Fill };
            txtHost = new TextBox { Dock = DockStyle.Fill };
            cmbService = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDown };
            cmbService.Items.AddRange(new object[] { "Портал", "Лаунчер", "CDN", "Игровые сервера", "Прочее" });
            cmbService.SelectedIndex = cmbService.Items.Count - 1;
            btnAdd = new Button { Text = "Добавить / Обновить", AutoSize = true };
            btnRemove = new Button { Text = "Удалить", AutoSize = true };
            btnAdd.Click += BtnAdd_Click;
            btnRemove.Click += BtnRemove_Click;

            btnSaveProfile = new Button { Text = "Сохранить профиль", AutoSize = true };
            btnSaveProfile.Click += BtnSaveProfile_Click;
            btnLoadProfile = new Button { Text = "Загрузить профиль", AutoSize = true };
            btnLoadProfile.Click += BtnLoadProfile_Click;

            lvSteps = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill };
            lvSteps.Columns.Add("Тест", 160);
            lvSteps.Columns.Add("Статус", 150);
            lvSteps.Columns.Add("Комментарий", 320);

            pbOverall = new ProgressBar { Style = ProgressBarStyle.Blocks, Dock = DockStyle.Fill };
            lblStatus = new Label { AutoSize = true, Text = "Ожидание запуска" };

            txtLog = new TextBox { Multiline = true, ScrollBars = ScrollBars.Both, ReadOnly = true, Dock = DockStyle.Fill, Font = new System.Drawing.Font("Consolas", 10) };
            txtAnalysis = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };

            txtPorts = new TextBox { Width = 160, Text = Output.ReportWriter.FormatPortList(Config.Default().Ports) };
            lblPorts = new Label { AutoSize = true, Text = "Порты" };

            var tips = new ToolTip();
            tips.SetToolTip(btnRun, "Запустить быструю проверку");
            tips.SetToolTip(btnCancel, "Остановить текущую проверку");
            tips.SetToolTip(btnSaveJson, "Сохранить полный JSON отчёт");
            tips.SetToolTip(btnExportReport, "Сохранить HTML или PDF отчёт");
            tips.SetToolTip(btnShowReport, "Открыть подробные результаты");
            tips.SetToolTip(btnCopySummary, "Скопировать краткий итог для поддержки");
            tips.SetToolTip(btnCopyReport, "Скопировать подробный текстовый отчёт");
            tips.SetToolTip(btnSaveProfile, "Сохранить цели, порты и включённые тесты в файл профиля");
            tips.SetToolTip(btnLoadProfile, "Загрузить профиль проверки из файла");
            tips.SetToolTip(chkDns, "Сравнить системный DNS и Cloudflare DoH");
            tips.SetToolTip(chkTcp, "Попробовать подключиться к портам 80/443");
            tips.SetToolTip(chkHttp, "Сделать HTTPS-запросы и проверить сертификаты");
            tips.SetToolTip(chkTrace, "Выполнить трассировку до цели");
            tips.SetToolTip(chkUdp, "Отправить UDP-запрос на 1.1.1.1:53");
            tips.SetToolTip(chkRst, "Проверить подозрение на RST-блокировку");
            tips.SetToolTip(txtTimeout, "Максимальное время ожидания сетевых операций, с");
            tips.SetToolTip(txtPorts, "Список TCP-портов через запятую, поддерживаются диапазоны (например 8000-8020)");

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

            lblBypassTitle = new Label
            {
                Text = "Обход блокировок",
                AutoSize = true,
                Font = new System.Drawing.Font("Segoe UI", 10F, System.Drawing.FontStyle.Bold),
                Margin = new Padding(0, 0, 0, 4)
            };

            lblBypassHint = new Label
            {
                Text = "WinDivert требует запуск программы от имени администратора. Модуль фильтрует TCP RST, " +
                       "фрагментирует TLS ClientHello и может переадресовывать трафик Star Citizen.",
                AutoSize = true,
                MaximumSize = new Size(640, 0),
                ForeColor = Color.DimGray,
                Margin = new Padding(0, 0, 0, 4)
            };

            lblBypassStatus = new Label
            {
                Text = "WinDivert не активен",
                AutoSize = true,
                ForeColor = Color.DimGray,
                Margin = new Padding(0, 0, 0, 4)
            };

            btnBypassToggle = new Button
            {
                Text = "Включить обход",
                AutoSize = true,
                Enabled = false
            };
            btnBypassToggle.Click += BtnBypassToggle_Click;

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
            actionPanel.Controls.Add(btnCopySummary);
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
                btnExportReport,
                btnShowReport,
                btnSaveProfile,
                btnLoadProfile,
                chkDns,
                chkTcp,
                chkHttp,
                chkTrace,
                chkUdp,
                chkRst,
                lblPorts,
                txtPorts,
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
                RowCount = 5,
                Padding = new Padding(0, 0, 8, 0)
            };
            targetsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            targetsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            targetsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
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

            var serviceLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
            serviceLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            serviceLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            serviceLayout.Controls.Add(new Label { Text = "Сервис", Dock = DockStyle.Fill, TextAlign = System.Drawing.ContentAlignment.MiddleLeft }, 0, 0);
            serviceLayout.Controls.Add(cmbService, 1, 0);
            targetsLayout.Controls.Add(serviceLayout, 0, 3);

            var targetButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
            targetButtons.Controls.Add(btnAdd);
            targetButtons.Controls.Add(btnRemove);
            targetButtons.Controls.Add(btnSaveProfile);
            targetButtons.Controls.Add(btnLoadProfile);
            targetsLayout.Controls.Add(targetButtons, 0, 4);

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
                RowCount = 5
            };
            rootLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rootLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rootLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rootLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rootLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            pnlBypass = BuildBypassPanel();

            rootLayout.Controls.Add(summaryPanel, 0, 0);
            rootLayout.Controls.Add(pnlBypass, 0, 1);
            rootLayout.Controls.Add(runPanel, 0, 2);
            rootLayout.Controls.Add(progressPanel, 0, 3);
            rootLayout.Controls.Add(pnlAdvanced, 0, 4);

            Controls.Add(rootLayout);

            LoadTargetsToListView();
            lvTargets.SelectedIndexChanged += LvTargets_SelectedIndexChanged;
            chkAdvanced.CheckedChanged += ChkAdvanced_CheckedChanged;
            UpdateBypassUi();
        }

        private void LvTargets_SelectedIndexChanged(object? sender, EventArgs e)
        {
            if (lvTargets.SelectedItems.Count == 0) return;
            var it = lvTargets.SelectedItems[0];
            txtName.Text = it.SubItems[0].Text;
            txtHost.Text = it.SubItems[1].Text;
            cmbService.Text = it.SubItems.Count > 2 ? it.SubItems[2].Text : string.Empty;
        }

        private void BtnAdd_Click(object? sender, EventArgs e)
        {
            string name = txtName.Text.Trim();
            string host = txtHost.Text.Trim();
            string service = cmbService.Text.Trim();
            if (string.IsNullOrEmpty(service)) service = "Прочее";
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(host)) return;

            for (int i = 0; i < lvTargets.Items.Count; i++)
            {
                if (lvTargets.Items[i] is ListViewItem it &&
                    it.SubItems[0].Text.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    it.SubItems[1].Text = host;
                    if (it.SubItems.Count < 3) it.SubItems.Add(service);
                    else it.SubItems[2].Text = service;
                    return;
                }
            }
            lvTargets.Items.Add(new ListViewItem(new[] { name, host, service }));
        }

        private void BtnRemove_Click(object? sender, EventArgs e)
        {
            if (lvTargets.SelectedItems.Count == 0) return;
            lvTargets.Items.Remove(lvTargets.SelectedItems[0]);
        }

        private async void BtnSaveProfile_Click(object? sender, EventArgs e)
        {
            if (!TryGetPorts(out var ports, true)) return;
            int timeout = GetTimeoutSeconds();
            var profile = BuildProfileData(ports, timeout);

            using var sfd = new SaveFileDialog { Filter = ProfileFileFilter, FileName = ProfileDefaultFileName };
            if (sfd.ShowDialog(this) == DialogResult.OK)
            {
                try
                {
                    UseWaitCursor = true;
                    await GuiProfileStorage.SaveAsync(profile, sfd.FileName).ConfigureAwait(true);
                    MessageBox.Show(this, "Профиль сохранён:\r\n" + sfd.FileName, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Не удалось сохранить профиль:\r\n" + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally
                {
                    UseWaitCursor = false;
                }
            }
        }

        private async void BtnLoadProfile_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog { Filter = ProfileFileFilter };
            if (ofd.ShowDialog(this) == DialogResult.OK)
            {
                try
                {
                    UseWaitCursor = true;
                    var profile = await GuiProfileStorage.LoadAsync(ofd.FileName).ConfigureAwait(true);
                    ApplyProfile(profile);
                    MessageBox.Show(this, "Профиль загружен:\r\n" + ofd.FileName, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Не удалось загрузить профиль:\r\n" + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally
                {
                    UseWaitCursor = false;
                }
            }
        }

        private async void BtnBypassToggle_Click(object? sender, EventArgs e)
        {
            if (!WinDivertBypassManager.IsPlatformSupported)
            {
                MessageBox.Show(this, "WinDivert доступен только в Windows.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (!WinDivertBypassManager.HasAdministratorRights)
            {
                MessageBox.Show(this, "Запустите программу от имени администратора для включения обхода.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            btnBypassToggle.Enabled = false;
            try
            {
                if (_bypassManager.State == BypassState.Enabled || _bypassManager.State == BypassState.Enabling)
                {
                    await _bypassManager.DisableAsync();
                }
                else
                {
                    await _bypassManager.EnableAsync();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Не удалось переключить WinDivert: " + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                UpdateBypassUi();
            }
        }

        private void BypassManager_StateChanged(object? sender, EventArgs e)
        {
            if (!IsHandleCreated || IsDisposed) return;
            try
            {
                BeginInvoke(new Action(UpdateBypassUi));
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private void UpdateBypassUi()
        {
            if (lblBypassStatus == null || btnBypassToggle == null) return;

            if (!WinDivertBypassManager.IsPlatformSupported)
            {
                lblBypassStatus.Text = "WinDivert доступен только в Windows.";
                lblBypassStatus.ForeColor = Color.Crimson;
                lblBypassHint.ForeColor = Color.DimGray;
                btnBypassToggle.Text = "Включить обход";
                btnBypassToggle.Enabled = false;
                return;
            }

            if (!WinDivertBypassManager.HasAdministratorRights)
            {
                lblBypassStatus.Text = "Запустите программу от имени администратора, чтобы активировать WinDivert.";
                lblBypassStatus.ForeColor = Color.DarkOrange;
                lblBypassHint.ForeColor = Color.DarkOrange;
                btnBypassToggle.Text = "Включить обход";
                btnBypassToggle.Enabled = false;
                return;
            }

            lblBypassHint.ForeColor = Color.DimGray;

            switch (_bypassManager.State)
            {
                case BypassState.Disabled:
                    lblBypassStatus.Text = "WinDivert выключен. Фильтрация не выполняется.";
                    lblBypassStatus.ForeColor = Color.DimGray;
                    btnBypassToggle.Text = "Включить обход";
                    btnBypassToggle.Enabled = _bypassActivationAllowed;
                    break;
                case BypassState.Enabling:
                    lblBypassStatus.Text = "WinDivert запускается…";
                    lblBypassStatus.ForeColor = Color.DodgerBlue;
                    btnBypassToggle.Text = "Включить обход";
                    btnBypassToggle.Enabled = false;
                    break;
                case BypassState.Enabled:
                    lblBypassStatus.Text = "WinDivert активен: фильтрация RST, фрагментация TLS и переадресация Star Citizen включены.";
                    lblBypassStatus.ForeColor = Color.ForestGreen;
                    btnBypassToggle.Text = "Выключить обход";
                    btnBypassToggle.Enabled = true;
                    break;
                case BypassState.Disabling:
                    lblBypassStatus.Text = "WinDivert останавливается…";
                    lblBypassStatus.ForeColor = Color.DodgerBlue;
                    btnBypassToggle.Text = "Выключить обход";
                    btnBypassToggle.Enabled = false;
                    break;
                case BypassState.Faulted:
                    var err = _bypassManager.LastError?.Message ?? "Неизвестная ошибка.";
                    lblBypassStatus.Text = "Ошибка WinDivert: " + err;
                    lblBypassStatus.ForeColor = Color.Crimson;
                    btnBypassToggle.Text = "Включить обход";
                    btnBypassToggle.Enabled = _bypassActivationAllowed;
                    break;
            }
        }

        private void LoadTargetsToListView()
        {
            lvTargets.Items.Clear();
            foreach (var kv in Program.Targets)
            {
                lvTargets.Items.Add(new ListViewItem(new[] { kv.Key, kv.Value.Host, kv.Value.Service }));
            }
        }

        private Panel BuildBypassPanel()
        {
            var textLayout = new TableLayoutPanel
            {
                ColumnCount = 1,
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink
            };
            textLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            textLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            textLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            textLayout.Controls.Add(lblBypassTitle, 0, 0);
            textLayout.Controls.Add(lblBypassHint, 0, 1);
            textLayout.Controls.Add(lblBypassStatus, 0, 2);

            var buttonsLayout = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(0, 4, 0, 0)
            };
            buttonsLayout.Controls.Add(btnBypassToggle);

            var layout = new TableLayoutPanel
            {
                ColumnCount = 2,
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 75));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            layout.Controls.Add(textLayout, 0, 0);
            layout.Controls.Add(buttonsLayout, 1, 0);

            var panel = new Panel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(12, 6, 12, 6),
                BackColor = Color.FromArgb(248, 250, 252)
            };
            panel.Controls.Add(layout);

            return panel;
        }

        private void SaveListViewToProgramTargets()
        {
            Program.Targets.Clear();
            foreach (ListViewItem it in lvTargets.Items)
            {
                var name = it.SubItems[0].Text;
                var host = it.SubItems[1].Text;
                var service = it.SubItems.Count > 2 ? it.SubItems[2].Text : string.Empty;
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(host)) continue;
                var def = new TargetDefinition
                {
                    Name = name,
                    Host = host,
                    Service = string.IsNullOrWhiteSpace(service) ? "Прочее" : service
                };
                Program.Targets[name] = def;
            }
        }

        private GuiProfileData BuildProfileData(List<int> ports, int timeoutSeconds)
        {
            var profile = new GuiProfileData
            {
                Ports = new List<int>(ports),
                TimeoutSeconds = timeoutSeconds,
                EnableDns = chkDns.Checked,
                EnableTcp = chkTcp.Checked,
                EnableHttp = chkHttp.Checked,
                EnableTrace = chkTrace.Checked,
                EnableUdp = chkUdp.Checked,
                EnableRst = chkRst.Checked
            };

            foreach (ListViewItem it in lvTargets.Items)
            {
                if (it.SubItems.Count < 2) continue;
                var name = it.SubItems[0].Text?.Trim() ?? string.Empty;
                var host = it.SubItems[1].Text?.Trim() ?? string.Empty;
                var service = it.SubItems.Count > 2 ? it.SubItems[2].Text?.Trim() ?? string.Empty : string.Empty;
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(host)) continue;
                profile.Targets.Add(new GuiProfileTarget
                {
                    Name = name,
                    Host = host,
                    Service = string.IsNullOrWhiteSpace(service) ? "Прочее" : service
                });
            }

            return profile;
        }

        private void ApplyProfile(GuiProfileData profile)
        {
            lvTargets.BeginUpdate();
            try
            {
                lvTargets.Items.Clear();
                foreach (var target in profile.Targets)
                {
                    if (string.IsNullOrWhiteSpace(target.Name) || string.IsNullOrWhiteSpace(target.Host)) continue;
                    var service = string.IsNullOrWhiteSpace(target.Service) ? "Прочее" : target.Service;
                    lvTargets.Items.Add(new ListViewItem(new[] { target.Name, target.Host, service }));
                }
                if (profile.Targets.Count == 0)
                {
                    foreach (var kv in TargetCatalog.CreateDefaultTargetMap())
                    {
                        lvTargets.Items.Add(new ListViewItem(new[] { kv.Key, kv.Value.Host, kv.Value.Service }));
                    }
                }
            }
            finally
            {
                lvTargets.EndUpdate();
            }

            chkDns.Checked = profile.EnableDns;
            chkTcp.Checked = profile.EnableTcp;
            chkHttp.Checked = profile.EnableHttp;
            chkTrace.Checked = profile.EnableTrace;
            chkUdp.Checked = profile.EnableUdp;
            chkRst.Checked = profile.EnableRst;

            if (profile.TimeoutSeconds > 0)
            {
                txtTimeout.Text = profile.TimeoutSeconds.ToString();
            }
            else
            {
                txtTimeout.Text = "12";
            }

            if (profile.Ports.Count > 0)
            {
                txtPorts.Text = Output.ReportWriter.FormatPortList(profile.Ports);
            }
            else
            {
                txtPorts.Text = Output.ReportWriter.FormatPortList(Config.Default().Ports);
            }

            SaveListViewToProgramTargets();
            _lastConfig = Config.Default();
            _lastConfig.TargetMap = Program.Targets.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.OrdinalIgnoreCase);
            _lastConfig.Targets = _lastConfig.TargetMap.Values.Select(t => t.Host).ToList();
            _lastConfig.EnableDns = profile.EnableDns;
            _lastConfig.EnableTcp = profile.EnableTcp;
            _lastConfig.EnableHttp = profile.EnableHttp;
            _lastConfig.EnableTrace = profile.EnableTrace;
            _lastConfig.EnableUdp = profile.EnableUdp;
            _lastConfig.EnableRst = profile.EnableRst;
            _lastConfig.Ports = profile.Ports.Count > 0 ? new List<int>(profile.Ports) : Config.Default().Ports;
            _lastConfig.HttpTimeoutSeconds = profile.TimeoutSeconds > 0 ? profile.TimeoutSeconds : 12;
            _lastConfig.TcpTimeoutSeconds = Math.Min(10, _lastConfig.HttpTimeoutSeconds);
            _lastConfig.UdpTimeoutSeconds = Math.Min(10, _lastConfig.HttpTimeoutSeconds);

            _summaryReady = false;
            _lastRun = null;
            _lastAdviceText = string.Empty;
            _lastSummaryPlainText = string.Empty;
            _lastSummaryCompactText = string.Empty;
            UpdateSummaryActionsState();
            UpdateBypassUi();
        }

        private bool TryGetPorts(out List<int> ports, bool showErrors)
        {
            ports = new List<int>();
            string text = txtPorts.Text.Trim();
            if (string.IsNullOrWhiteSpace(text))
            {
                ports = Config.Default().Ports;
                txtPorts.Text = Output.ReportWriter.FormatPortList(ports);
                return true;
            }

            var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var result = new SortedSet<int>();

            foreach (var part in parts)
            {
                if (part.Contains('-', StringComparison.Ordinal))
                {
                    var range = part.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (range.Length != 2 || !int.TryParse(range[0], out int start) || !int.TryParse(range[1], out int end) || start <= 0 || end > 65535 || end < start)
                    {
                        if (showErrors)
                            MessageBox.Show(this, "Неверный диапазон портов: " + part, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return false;
                    }
                    for (int p = start; p <= end; p++)
                    {
                        result.Add(p);
                    }
                }
                else if (int.TryParse(part, out int single) && single > 0 && single <= 65535)
                {
                    result.Add(single);
                }
                else
                {
                    if (showErrors)
                        MessageBox.Show(this, "Неверный порт: " + part, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
            }

            if (result.Count == 0)
            {
                if (showErrors)
                    MessageBox.Show(this, "Не указано ни одного порта.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            ports = result.ToList();
            var normalized = Output.ReportWriter.FormatPortList(ports);
            if (!string.Equals(normalized, txtPorts.Text.Trim(), StringComparison.Ordinal))
            {
                txtPorts.Text = normalized;
            }
            return true;
        }

        private int GetTimeoutSeconds()
        {
            return int.TryParse(txtTimeout.Text.Trim(), out int seconds) && seconds > 0 ? seconds : 12;
        }

        private async void BtnRun_Click(object? sender, EventArgs e)
        {
            if (!TryGetPorts(out var selectedPorts, true))
            {
                return;
            }

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
            _lastSummaryCompactText = string.Empty;
            _lastRun = null;
            _summaryReady = false;
            UpdateSummaryActionsState();
            CloseSummaryPopup();
            _bypassActivationAllowed = false;
            UpdateBypassUi();

            SaveListViewToProgramTargets();

            try
            {
                var cfg = Config.Default();
                cfg.TargetMap = Program.Targets.ToDictionary(kv => kv.Key, kv => kv.Value.Copy(), StringComparer.OrdinalIgnoreCase);
                cfg.Targets = cfg.TargetMap.Values.Select(t => t.Host).ToList();
                cfg.NoTrace = !chkTrace.Checked;
                cfg.EnableDns = chkDns.Checked;
                cfg.EnableTcp = chkTcp.Checked;
                cfg.EnableHttp = chkHttp.Checked;
                cfg.EnableTrace = chkTrace.Checked;
                cfg.EnableUdp = chkUdp.Checked;
                cfg.EnableRst = chkRst.Checked;
                cfg.Ports = selectedPorts;
                if (int.TryParse(txtTimeout.Text.Trim(), out int t) && t > 0)
                {
                    cfg.HttpTimeoutSeconds = t;
                    cfg.TcpTimeoutSeconds = Math.Min(10, t);
                    cfg.UdpTimeoutSeconds = Math.Min(10, t);
                }

                var resolvedTargets = cfg.ResolveTargets();
                var usage = ServiceTestMatrix.CalculateUsage(resolvedTargets, cfg);
                InitSteps(cfg, usage);
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
                UpdateBypassUi();
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
                UpdateBypassUi();
            }
            finally
            {
                pbOverall.Style = ProgressBarStyle.Blocks;
                lblStatus.Text = "Готово";
                btnRun.Enabled = true;
                btnCancel.Enabled = false;
                btnCancel.Visible = chkAdvanced.Checked;
                UpdateBypassUi();
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

        private async void BtnExportReport_Click(object? sender, EventArgs e)
        {
            if (_lastRun == null)
            {
                MessageBox.Show(this, "Сначала выполните проверку.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using var sfd = new SaveFileDialog
            {
                Filter = "HTML (*.html)|*.html|PDF (*.pdf)|*.pdf",
                FileName = "isp_report.html"
            };

            if (sfd.ShowDialog(this) == DialogResult.OK)
            {
                try
                {
                    UseWaitCursor = true;
                    btnExportReport.Enabled = false;
                    var ext = Path.GetExtension(sfd.FileName).ToLowerInvariant();
                    if (ext == ".pdf")
                    {
                        await Output.ReportWriter.SavePdfReportAsync(_lastRun, _lastConfig, sfd.FileName).ConfigureAwait(true);
                    }
                    else
                    {
                        await Output.ReportWriter.SaveHtmlReportAsync(_lastRun, _lastConfig, sfd.FileName).ConfigureAwait(true);
                    }

                    var dialogResult = MessageBox.Show(this, "Отчёт сохранён:\r\n" + sfd.FileName + "\r\n\r\nОткрыть файл сейчас?", "ISP Audit", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                    if (dialogResult == DialogResult.Yes)
                    {
                        try
                        {
                            Process.Start(new ProcessStartInfo { FileName = sfd.FileName, UseShellExecute = true });
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(this, "Не удалось открыть файл:\r\n" + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Не удалось экспортировать отчёт:\r\n" + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally
                {
                    UseWaitCursor = false;
                    btnExportReport.Enabled = _lastRun != null;
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

        private void BtnCopySummary_Click(object? sender, EventArgs e)
        {
            if (!_summaryReady || string.IsNullOrWhiteSpace(_lastSummaryCompactText))
            {
                MessageBox.Show(this, "Итог появится после завершения проверки.", "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                Clipboard.SetText(_lastSummaryCompactText);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Не удалось скопировать итог: " + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
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
            bool dnsExecuted = run.targets.Values.Any(t => t.dns_enabled);
            bool tcpExecuted = run.targets.Values.Any(t => t.tcp_enabled);
            bool httpExecuted = run.targets.Values.Any(t => t.http_enabled);
            string dnsOverall = dnsExecuted ? FormatStatus(run.summary.dns) : "не проверялось";
            string tcpOverall = tcpExecuted ? FormatStatus(run.summary.tcp) : "не проверялось";
            string tlsOverall = httpExecuted ? FormatStatus(run.summary.tls) : "не проверялось";
            sb.AppendLine($"DNS: {dnsOverall}");
            sb.AppendLine($"TCP: {tcpOverall}");
            sb.AppendLine($"UDP: {FormatStatus(run.summary.udp)}");
            sb.AppendLine($"TLS: {tlsOverall}");
            if (!string.Equals(run.summary.rst_inject, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"RST: {FormatStatus(run.summary.rst_inject)}");
            }
            sb.AppendLine();
            foreach (var kv in run.targets)
            {
                var t = kv.Value;
                bool anyOpen = t.tcp.Exists(r => r.open);
                bool httpOk = t.http.Exists(h => h.success && h.status is >= 200 and < 400);
                string dnsText = t.dns_enabled ? FormatStatus(t.dns_status) : "не проверялось";
                string tcpText = t.tcp_enabled ? (anyOpen ? "доступны" : "закрыты") : "не проверялись";
                string httpText = t.http_enabled ? (httpOk ? "отвечает" : "не отвечает") : "не проверялся";
                sb.AppendLine($"— {kv.Key}: DNS {dnsText}, порты {tcpText}, HTTPS {httpText}");
            }
            if (!string.Equals(run.summary.udp, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine();
                var udpStatus = string.Equals(run.summary.udp, "OK", StringComparison.OrdinalIgnoreCase)
                    ? "есть ответ"
                    : (string.Equals(run.summary.udp, "FAIL", StringComparison.OrdinalIgnoreCase) ? "нет ответа" : FormatStatus(run.summary.udp));
                sb.AppendLine($"UDP DNS 1.1.1.1: {udpStatus}");
            }
            return sb.ToString();
        }

        private void InitSteps(Config cfg, TestUsage usage)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => InitSteps(cfg, usage))); return; }
            lvSteps.Items.Clear();
            if (cfg.EnableDns)
                AddStepRow("DNS", usage.Dns ? "в очереди" : "не требуется", usage.Dns);
            if (cfg.EnableTcp)
                AddStepRow("TCP", usage.Tcp ? "в очереди" : "не требуется", usage.Tcp);
            if (cfg.EnableHttp)
                AddStepRow("HTTP", usage.Http ? "в очереди" : "не требуется", usage.Http);
            if (cfg.EnableTrace && !cfg.NoTrace)
                AddStepRow("Traceroute", usage.Trace ? "в очереди" : "не требуется", usage.Trace);
            if (cfg.EnableUdp && cfg.UdpProbes.Count > 0)
                AddStepRow("UDP", usage.Udp ? "в очереди" : "не требуется", usage.Udp);
            if (cfg.EnableRst)
                AddStepRow("RST", usage.Rst ? "в очереди" : "не требуется", usage.Rst);
        }

        private void AddStepRow(string name, string status, bool active)
        {
            var it = new ListViewItem(new[] { name, status, string.Empty }) { Tag = active };
            if (!active)
            {
                it.ForeColor = System.Drawing.Color.Gray;
            }
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
                    if (it.Tag is bool active && !active)
                    {
                        if (!string.IsNullOrEmpty(p.Message))
                        {
                            it.SubItems[1].Text = p.Message;
                            it.SubItems[2].Text = p.Message;
                        }
                        else if (p.Success.HasValue)
                        {
                            it.SubItems[1].Text = p.Success.Value ? "не требуется" : "ошибка";
                        }
                        lblStatus.Text = $"{name}: {p.Message ?? "не требуется"}";
                        it.ForeColor = System.Drawing.Color.Gray;
                        return;
                    }
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
            _lastSummaryCompactText = Output.ReportWriter.BuildCompactSummaryText(run, advice);
            _summaryReady = true;
            _bypassActivationAllowed = hasIssues;
            UpdateSummaryActionsState();
            UpdateBypassUi();
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

            var dnsBogus = run.targets.Where(kv => kv.Value.dns_enabled && kv.Value.dns_status == nameof(Tests.DnsStatus.DNS_BOGUS)).Select(kv => kv.Key).ToList();
            if (dnsBogus.Count > 0)
                AddIssue($"DNS: недействительные ответы для {string.Join(", ", dnsBogus)}.");

            var dnsFiltered = run.targets.Where(kv => kv.Value.dns_enabled && kv.Value.dns_status == nameof(Tests.DnsStatus.DNS_FILTERED)).Select(kv => kv.Key).ToList();
            if (dnsFiltered.Count > 0)
                AddIssue($"DNS: подозрение на фильтрацию ({string.Join(", ", dnsFiltered)}).");

            var dnsWarn = run.targets.Where(kv => kv.Value.dns_enabled && kv.Value.dns_status == nameof(Tests.DnsStatus.WARN)).Select(kv => kv.Key).ToList();
            if (dnsWarn.Count > 0)
                AddIssue($"DNS: системный и DoH ответы различаются ({string.Join(", ", dnsWarn)}).");

            var tcpFails = run.targets.Where(kv => kv.Value.tcp_enabled && !kv.Value.tcp.Any(r => r.open)).Select(kv => kv.Key).ToList();
            if (tcpFails.Count > 0)
                AddIssue($"TCP: порты не открылись для {string.Join(", ", tcpFails)}.");

            if (run.summary.udp == "FAIL")
                AddIssue("UDP: нет ответа на запрос к 1.1.1.1:53.");

            var tlsFails = run.targets.Where(kv => kv.Value.http_enabled && !kv.Value.http.Any(h => h.success && h.status is >= 200 and < 400)).Select(kv => kv.Key).ToList();
            if (tlsFails.Count > 0)
                AddIssue($"HTTPS: нет ответа от {string.Join(", ", tlsFails)}.");
            else if (run.summary.tls == "SUSPECT")
                AddIssue("HTTPS: есть подозрение на блокировку по SNI.");

            if (!run.targets.Values.Any(t => t.http_enabled))
                AddIssue("HTTPS-проверка не выполнялась (для выбранных целей не требуется).");

            if (issues.Length == 0)
                issues.Append("Явных проблем не найдено.");

            return issues.ToString();
        }

        private static string FormatStatus(string status) => Output.ReportWriter.GetReadableStatus(status);

        private void UpdateSummaryActionsState()
        {
            btnSummaryActions.Enabled = _summaryReady;
            btnCopySummary.Enabled = _summaryReady;
            btnCopyReport.Enabled = _summaryReady;
            btnExportReport.Enabled = _lastRun != null;
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            base.OnFormClosed(e);
            _bypassManager.StateChanged -= BypassManager_StateChanged;
            try
            {
                _bypassManager.Dispose();
            }
            catch
            {
            }
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

            var btnCopyCompact = new Button { Text = "Скопировать итог", AutoSize = true };
            btnCopyCompact.Click += (_, _) =>
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(_lastSummaryCompactText))
                        Clipboard.SetText(_lastSummaryCompactText);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(popup, "Не удалось скопировать итог: " + ex.Message, "ISP Audit", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            var btnCopyFull = new Button { Text = "Скопировать отчёт", AutoSize = true };
            btnCopyFull.Click += (_, _) =>
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(_lastSummaryPlainText))
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
            buttonsPanel.Controls.Add(btnCopyFull);
            buttonsPanel.Controls.Add(btnCopyCompact);
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
