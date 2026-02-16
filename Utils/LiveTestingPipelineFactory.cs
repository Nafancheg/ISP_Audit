using System;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Core.Modules;
using IspAudit.Core.Traffic;

namespace IspAudit.Utils
{
    public sealed class LiveTestingPipelineFactory : ILiveTestingPipelineFactory
    {
        private readonly IHostTesterFactory _testerFactory;
        private readonly IBlockageStateStoreFactory _stateStoreFactory;

        public LiveTestingPipelineFactory(IHostTesterFactory testerFactory, IBlockageStateStoreFactory stateStoreFactory)
        {
            _testerFactory = testerFactory ?? throw new ArgumentNullException(nameof(testerFactory));
            _stateStoreFactory = stateStoreFactory ?? throw new ArgumentNullException(nameof(stateStoreFactory));
        }

        public LiveTestingPipeline Create(
            PipelineConfig config,
            ITrafficFilter filter,
            IProgress<string>? progress,
            TrafficEngine? trafficEngine,
            DnsParserService? dnsParser,
            IBlockageStateStore? stateStore,
            AutoHostlistService? autoHostlist,
            IHostTester? testerOverride = null)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
            if (filter == null) throw new ArgumentNullException(nameof(filter));

            var tester = testerOverride
                ?? _testerFactory.CreateStandard(progress, dnsParser?.DnsCache, config.TestTimeout);

            var effectiveStateStore = stateStore ?? _stateStoreFactory.CreateDefault();

            // P1.5: «быстрый» тестер для деградации очереди low (timeout/2). Используем только для стандартного тестера.
            StandardHostTester? degraded = null;
            if (tester is StandardHostTester)
            {
                var half = TimeSpan.FromMilliseconds(Math.Max(250, config.TestTimeout.TotalMilliseconds / 2.0));
                degraded = _testerFactory.CreateStandard(progress, dnsParser?.DnsCache, half);
            }

            return new LiveTestingPipeline(
                config,
                filter,
                progress: progress,
                trafficEngine: trafficEngine,
                dnsParser: dnsParser,
                stateStore: effectiveStateStore,
                autoHostlist: autoHostlist,
                tester: tester,
                degradedTester: degraded);
        }
    }
}
