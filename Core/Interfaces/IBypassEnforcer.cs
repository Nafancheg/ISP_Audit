using System.Threading;
using System.Threading.Tasks;
using IspAudit.Core.Models;

namespace IspAudit.Core.Interfaces
{
    public interface IBypassEnforcer
    {
        Task ApplyBypassAsync(HostBlocked blocked, CancellationToken ct);
    }
}