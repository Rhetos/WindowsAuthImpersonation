namespace Rhetos.WindowsAuthImpersonation.Abstractions
{
    public interface IImpersonationProvider
    {
        string GetImpersonatedUserName();
        string GetActualUserName();
        void CheckImpersonatedUserPermissions(string impersonatedUser);
        void SetImpersonatedUser(string impersonatedUser);
    }
}