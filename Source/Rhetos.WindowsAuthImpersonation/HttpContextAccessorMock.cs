using System.Web.Security;
using Rhetos.WindowsAuthImpersonation.Abstractions;

namespace Rhetos.WindowsAuthImpersonation
{
    public class HttpContextAccessorMock : IHttpContextAccessor
    {
        private FormsAuthenticationTicket _ticket;

        public bool? IsUserAuthenticated => true;
        public string UserName => System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        public string AuthenticationType => "Windows";

        public FormsAuthenticationTicket GetAuthenticationTicket()
        {
            return _ticket;
        }

        public void AddTicketToResponse(FormsAuthenticationTicket authenticationTicket)
        {
            _ticket = authenticationTicket;
        }
    }
}