using System;
using IspAudit.Bypass;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Core.Traffic;

namespace IspAudit.Core.Modules
{
    public sealed class BypassStateManagerFactory : IBypassStateManagerFactory
    {
        public BypassStateManager GetOrCreate(
            TrafficEngine trafficEngine,
            BypassProfile? baseProfile = null,
            Action<string>? log = null)
        {
            return BypassStateManager.GetOrCreate(
                trafficEngine,
                baseProfile: baseProfile,
                log: log);
        }
    }
}
