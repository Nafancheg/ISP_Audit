using System;
using System.Collections.Generic;
using IspAudit.Core.Interfaces;

namespace IspAudit.Core.Modules
{
    public sealed class StandardHostTesterFactory : IHostTesterFactory
    {
        public StandardHostTester CreateStandard(
            IProgress<string>? progress,
            IReadOnlyDictionary<string, string>? dnsCache,
            TimeSpan testTimeout)
        {
            return new StandardHostTester(progress, dnsCache, testTimeout);
        }
    }
}
