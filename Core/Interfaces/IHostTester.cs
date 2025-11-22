using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Models;

namespace IspAudit.Core.Interfaces
{
    public interface IHostTester
    {
        Task<HostTested> TestHostAsync(HostDiscovered host, CancellationToken ct);
    }
}