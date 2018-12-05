using Rhetos.Utilities;

namespace Rhetos.WindowsAuthImpersonation.Abstractions
{
    public interface IImpersonationUserInfo : IUserInfo
    {
        string ImpersonatedBy { get; }
    }
}
