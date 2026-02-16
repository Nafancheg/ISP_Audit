using System;
using System.Collections.Generic;
using IspAudit.Core.Interfaces;

namespace IspAudit.Core.Modules
{
    public sealed class StandardHostTesterFactory : IHostTesterFactory
    {
        private readonly IStandardHostTesterProbeService _probes;

        public StandardHostTesterFactory(IStandardHostTesterProbeService probes)
        {
            _probes = probes ?? throw new ArgumentNullException(nameof(probes));
        }

        public StandardHostTester CreateStandard(
            IProgress<string>? progress,
            IReadOnlyDictionary<string, string>? dnsCache,
            TimeSpan testTimeout)
        {
            return new StandardHostTester(_probes, progress, dnsCache, testTimeout);
        }
    }
}
