using Rhetos.Dom.DefaultConcepts;
using Rhetos.Logging;
using Rhetos.Security;
using Rhetos.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Security;

namespace Rhetos.WindowsAuthImpersonation
{
    #region Service parameters

    public class ImpersonateParameters
    {
        public string ImpersonatedUser { get; set; }

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(ImpersonatedUser))
                throw new UserException("Empty ImpersonatedUser is not allowed.");
        }
    }

    #endregion

    public class ImpersonationService
    {
        private readonly ILogger _logger;
        private readonly Lazy<IAuthorizationManager> _authorizationManager;
        private readonly Lazy<GenericRepository<IPrincipal>> _principals;
        private readonly Lazy<GenericRepository<IRolePermission>> _permissions;
        private readonly Lazy<GenericRepository<ICommonClaim>> _claims;
        private readonly Lazy<IAuthorizationProvider> _authorizationProvider;
        private readonly IUserInfo _userInfo;

        public ImpersonationService(
            ILogProvider logProvider,
            Lazy<IAuthorizationManager> authorizationManager,
            Lazy<GenericRepository<IPrincipal>> principals,
            Lazy<GenericRepository<IRolePermission>> permissions,
            Lazy<GenericRepository<ICommonClaim>> claims,
            Lazy<IAuthorizationProvider> authorizationProvider,
            IUserInfo userInfo)
        {
            _logger = logProvider.GetLogger(GetType().Name);
            _authorizationManager = authorizationManager;
            _principals = principals;
            _permissions = permissions;
            _claims = claims;
            _authorizationProvider = authorizationProvider;
            _userInfo = userInfo;
        }

        public void Impersonate(ImpersonateParameters parameters)
        {
            if (parameters == null)
                throw new ClientException("It is not allowed to call this service method with no parameters provided.");
            _logger.Trace(() => "Impersonate: " + HttpContext.Current.User.Identity.Name + " as " + parameters.ImpersonatedUser);
            parameters.Validate();

            // Update the existing security cookie (from Request).
            var authenticationCookie = HttpContext.Current.Request.Cookies[FormsAuthentication.FormsCookieName];
            ActivateImpersonation(parameters.ImpersonatedUser, authenticationCookie, limitImpersonationToSingleSession: true);
            HttpContext.Current.Response.Cookies.Add(authenticationCookie);
        }

        /// <summary>
        /// Checks the user's permissions, and sets the impersonation info in the authentication cookie.
        /// </summary>
        private void ActivateImpersonation(string impersonatedUser, HttpCookie authenticationCookie, bool limitImpersonationToSingleSession)
        {
            CheckImperionatedUserPermissions(impersonatedUser);
            UpdateAuthTicketToImpersonate(authenticationCookie, impersonatedUser, limitImpersonationToSingleSession);
        }

        class TempUserInfo : IUserInfo
        {
            public string UserName { get; set; }
            public string Workstation { get; set; }
            public bool IsUserRecognized { get { return true; } }
            public string Report() { return UserName; }
        }

        /// <summary>
        /// A user with this claim is allowed to impersonate another user that has more permissions.
        /// </summary>
        public static readonly Claim IncreasePermissionsClaim = new Claim("WindowsAuthImpersonation.Impersonate", "IncreasePermissions");

        private void CheckImperionatedUserPermissions(string impersonatedUser)
        {
            Guid impersonatedPrincipalId = _principals.Value
                .Query(p => p.Name == impersonatedUser)
                .Select(p => p.ID).SingleOrDefault();

            // This function must be called after the user is authenticated and authorized (see CheckCurrentUserClaim),
            // otherwise the provided error information would be a security issue.
            if (impersonatedPrincipalId == default(Guid))
                throw new UserException("User '{0}' is not registered.",
                    new[] { impersonatedUser }, null, null);

            var allowIncreasePermissions = _authorizationManager.Value.GetAuthorizations(new[] { IncreasePermissionsClaim }).Single();
            if (!allowIncreasePermissions)
            {
                // The impersonatedUser must have subset of permissions of the impersonating user.
                // It is not allowed to impersonate a user with more permissions then the impersonating user.

                var allClaims = _claims.Value.Query().Where(c => c.Active.Value)
                    .Select(c => new { c.ClaimResource, c.ClaimRight }).ToList()
                    .Select(c => new Claim(c.ClaimResource, c.ClaimRight)).ToList();

                var impersonatedUserInfo = new TempUserInfo { UserName = impersonatedUser, Workstation = _userInfo.Workstation };
                var impersonatedUserClaims = _authorizationProvider.Value.GetAuthorizations(impersonatedUserInfo, allClaims)
                    .Zip(allClaims, (hasClaim, claim) => new { hasClaim, claim })
                    .Where(c => c.hasClaim).Select(c => c.claim).ToList();

                var surplusImpersonatedClaims = _authorizationProvider.Value.GetAuthorizations(_userInfo, impersonatedUserClaims)
                    .Zip(impersonatedUserClaims, (hasClaim, claim) => new { hasClaim, claim })
                    .Where(c => !c.hasClaim).Select(c => c.claim).ToList();

                if (surplusImpersonatedClaims.Count() > 0)
                {
                    _logger.Info(
                        "User '{0}' is not allowed to impersonate '{1}' because the impersonated user has {2} more security claims (for example '{3}'). Increase the user's permissions or add '{4}' security claim.",
                        _userInfo.UserName,
                        impersonatedUser,
                        surplusImpersonatedClaims.Count(),
                        surplusImpersonatedClaims.First().FullName,
                        IncreasePermissionsClaim.FullName);

                    throw new UserException("You are not allowed to impersonate user '{0}'.",
                        new[] { impersonatedUser }, "See server log for more information.", null);
                }
            }
        }

        public const string ImpersonatingUserInfoPrefix = "Impersonating:";

        /// <summary>
        /// This function is updating previously generated security, instead of creating a new one,
        /// to make sure that the proper ticket and cookie settings are used (Expiration, HttpOnly, ...).
        /// </summary>
        private void UpdateAuthTicketToImpersonate(HttpCookie authenticationCookie, string impersonatedUser, bool limitImpersonationToSingleSession)
        {
            if (authenticationCookie.Value == null)
                throw new FrameworkException("There is no authentication cookie created.");

            var authenticationTicket = FormsAuthentication.Decrypt(authenticationCookie.Value);

            if (!string.IsNullOrEmpty(authenticationTicket.UserData) && !authenticationTicket.UserData.StartsWith(ImpersonatingUserInfoPrefix))
                throw new FrameworkException("Login impersonation plugin is not supported (" + GetType().FullName + "). The authentication ticket already has the UserData property set.");

            var newTicket = new FormsAuthenticationTicket(
                authenticationTicket.Version,
                authenticationTicket.Name,
                authenticationTicket.IssueDate,
                authenticationTicket.Expiration,
                limitImpersonationToSingleSession ? false : authenticationTicket.IsPersistent,
                ImpersonatingUserInfoPrefix + impersonatedUser,
                authenticationTicket.CookiePath);

            authenticationCookie.Value = FormsAuthentication.Encrypt(newTicket);

            if (limitImpersonationToSingleSession)
                authenticationCookie.Expires = default(DateTime);
        }

        public void StopImpersonating()
        {
            _logger.Trace(() => "StopImpersonating: " + HttpContext.Current.User.Identity.Name);

            var authenticationCookie = HttpContext.Current.Request.Cookies[FormsAuthentication.FormsCookieName];
            UpdateAuthTicketToStopImpersonating(authenticationCookie);
            HttpContext.Current.Response.Cookies.Add(authenticationCookie);
        }

        private void UpdateAuthTicketToStopImpersonating(HttpCookie authenticationCookie)
        {
            if (authenticationCookie.Value == null)
                return; // Ignore if not logged-in.

            var authenticationTicket = FormsAuthentication.Decrypt(authenticationCookie.Value);

            if (string.IsNullOrEmpty(authenticationTicket.UserData) || !authenticationTicket.UserData.StartsWith(ImpersonatingUserInfoPrefix))
                return; // Ignore if not impersonating.

            string userData = "";

            var newTicket = new FormsAuthenticationTicket(
                authenticationTicket.Version,
                authenticationTicket.Name,
                authenticationTicket.IssueDate,
                authenticationTicket.Expiration,
                authenticationTicket.IsPersistent,
                userData,
                authenticationTicket.CookiePath);

            authenticationCookie.Value = FormsAuthentication.Encrypt(newTicket);
        }
    }
}
