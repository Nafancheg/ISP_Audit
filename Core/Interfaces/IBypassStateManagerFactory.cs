using System;
using IspAudit.Bypass;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Interfaces
{
    public interface IBypassStateManagerFactory
    {
        BypassStateManager GetOrCreate(
            TrafficEngine trafficEngine,
            BypassProfile? baseProfile = null,
            Action<string>? log = null);
    }
}
