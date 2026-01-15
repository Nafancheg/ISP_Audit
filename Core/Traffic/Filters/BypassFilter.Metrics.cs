using System.Threading;

namespace IspAudit.Core.Traffic.Filters
{
    public partial class BypassFilter
    {
        private long _packetsProcessed;
        private long _rstDropped;
        private long _rstDroppedRelevant;
        private long _clientHellosFragmented;
        private long _tlsHandled;
        private string _lastFragmentPlan = string.Empty;
        private long _tlsClientHellosObserved;
        private long _tlsClientHellosShort;
        private long _tlsClientHellosNon443;
        private long _tlsClientHellosNoSni;
        private long _udp443Dropped;

        public BypassMetricsSnapshot GetMetrics()
        {
            return new BypassMetricsSnapshot
            {
                PacketsProcessed = Interlocked.Read(ref _packetsProcessed),
                RstDropped = Interlocked.Read(ref _rstDropped),
                RstDroppedRelevant = Interlocked.Read(ref _rstDroppedRelevant),
                ClientHellosFragmented = Interlocked.Read(ref _clientHellosFragmented),
                TlsHandled = Interlocked.Read(ref _tlsHandled),
                LastFragmentPlan = _lastFragmentPlan,
                ClientHellosObserved = Interlocked.Read(ref _tlsClientHellosObserved),
                ClientHellosShort = Interlocked.Read(ref _tlsClientHellosShort),
                ClientHellosNon443 = Interlocked.Read(ref _tlsClientHellosNon443),
                ClientHellosNoSni = Interlocked.Read(ref _tlsClientHellosNoSni),
                Udp443Dropped = Interlocked.Read(ref _udp443Dropped)
            };
        }

        public readonly struct BypassMetricsSnapshot
        {
            public long PacketsProcessed { get; init; }
            public long RstDropped { get; init; }
            public long RstDroppedRelevant { get; init; }
            public long ClientHellosFragmented { get; init; }
            public long TlsHandled { get; init; }
            public string LastFragmentPlan { get; init; }
            public long ClientHellosObserved { get; init; }
            public long ClientHellosShort { get; init; }
            public long ClientHellosNon443 { get; init; }
            public long ClientHellosNoSni { get; init; }
            public long Udp443Dropped { get; init; }
        }
    }
}
