using System;
using System.Net;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        private sealed class TestResultsManagerPipelineContext : IPipelineMessageParserContext
        {
            private readonly TestResultsManager _m;

            public TestResultsManagerPipelineContext(TestResultsManager manager)
            {
                _m = manager;
            }

            public System.Collections.ObjectModel.ObservableCollection<IspAudit.Models.TestResult> TestResults => _m.TestResults;

            public string? LastUpdatedHost => _m._lastUpdatedHost;
            public string? LastUserFacingHost => _m._lastUserFacingHost;

            public string NormalizeHost(string host) => _m.NormalizeHost(host);
            public string SelectUiKey(string hostFromLine, string msg) => _m.SelectUiKey(hostFromLine, msg);

            public void SetLastUpdatedHost(string hostKey)
            {
                _m._lastUpdatedHost = hostKey;

                if (string.IsNullOrWhiteSpace(hostKey))
                {
                    return;
                }

                // Мы хотим стабильно цеплять рекомендации/кнопки к "пользовательскому" ключу.
                // Поэтому шумовые домены НЕ должны затмевать последнюю «нормальную» цель.
                if (IPAddress.TryParse(hostKey, out _))
                {
                    _m._lastUserFacingHost = hostKey;
                    return;
                }

                if (!IspAudit.Utils.NoiseHostFilter.Instance.IsNoiseHost(hostKey))
                {
                    _m._lastUserFacingHost = hostKey;
                }
            }

            public void TryMigrateIpCardToNameKey(string ip, string nameKey) => _m.TryMigrateIpCardToNameKey(ip, nameKey);

            public void UpdateTestResult(string host, IspAudit.Models.TestStatus status, string details, string? fallbackIp) =>
                _m.UpdateTestResult(host, status, details, fallbackIp);

            public void UpdateTestResult(string host, IspAudit.Models.TestStatus status, string details) =>
                _m.UpdateTestResult(host, status, details);

            public (IspAudit.Models.TestStatus status, string note) AnalyzeHeuristicSeverity(string host) => _m.AnalyzeHeuristicSeverity(host);
            public bool AreHostsRelated(IspAudit.Models.Target passingTarget, string failingHost) => _m.AreHostsRelated(passingTarget, failingHost);

            public void Log(string message) => _m.Log(message);
            public void NotifyCountersChanged() => _m.NotifyCountersChanged();

            public bool IsNoiseHost(string host) => IspAudit.Utils.NoiseHostFilter.Instance.IsNoiseHost(host);

            public string StripNameTokens(string msg) => TestResultsManager.StripNameTokens(msg);
            public string? ExtractToken(string msg, string token) => TestResultsManager.ExtractToken(msg, token);

            public bool TryGetIpToUiKey(string ip, out string? uiKey)
            {
                if (_m._ipToUiKey.TryGetValue(ip, out var v))
                {
                    uiKey = v;
                    return true;
                }

                uiKey = null;
                return false;
            }

            public void SetIpToUiKeyIfEmptyOrIp(string ip, string uiKey)
            {
                if (!_m._ipToUiKey.TryGetValue(ip, out var existingKey) || string.IsNullOrWhiteSpace(existingKey) || IPAddress.TryParse(existingKey, out _))
                {
                    _m._ipToUiKey[ip] = uiKey;
                }
            }

            public bool ContainsIpToUiKey(string ip) => _m._ipToUiKey.ContainsKey(ip);
            public void SetIpToUiKey(string ip, string uiKey) => _m._ipToUiKey[ip] = uiKey;
        }

        private PipelineMessageParser? _pipelineMessageParser;

        private PipelineMessageParser PipelineParser => _pipelineMessageParser ??= new PipelineMessageParser(new TestResultsManagerPipelineContext(this));
    }
}
