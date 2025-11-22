using IspAudit.Core.Models;

namespace IspAudit.Core.Interfaces
{
    public interface IBlockageClassifier
    {
        HostBlocked ClassifyBlockage(HostTested tested);
    }
}