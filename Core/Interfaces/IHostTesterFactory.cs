using System;
using System.Collections.Generic;
using IspAudit.Core.Modules;

namespace IspAudit.Core.Interfaces
{
    public interface IHostTesterFactory
    {
        StandardHostTester CreateStandard(
            IProgress<string>? progress,
            IReadOnlyDictionary<string, string>? dnsCache,
            TimeSpan testTimeout);
    }
}
