using System;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;

namespace IspAudit.Utils
{
    public interface ILiveTestingPipelineFactory
    {
        LiveTestingPipeline Create(
            PipelineConfig config,
            ITrafficFilter filter,
            IProgress<string>? progress,
            TrafficEngine? trafficEngine,
            DnsParserService? dnsParser,
            IBlockageStateStore? stateStore,
            AutoHostlistService? autoHostlist,
            IHostTester? testerOverride = null);
    }
}
