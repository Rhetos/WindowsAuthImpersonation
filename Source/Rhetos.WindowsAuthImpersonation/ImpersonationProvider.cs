/*
    Copyright (C) 2014 Omega software d.o.o.

    This file is part of Rhetos.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Linq;
using System.Web.Security;
using Rhetos.Dom.DefaultConcepts;
using Rhetos.Logging;
using Rhetos.Security;
using Rhetos.Utilities;
using Rhetos.WindowsAuthImpersonation.Abstractions;

namespace Rhetos.WindowsAuthImpersonation
{
    public class ImpersonationProvider : IImpersonationProvider
    {
        private readonly ILogger _logger;
        private readonly Lazy<IAuthorizationManager> _authorizationManager;
        private readonly Lazy<GenericRepository<IPrincipal>> _principals;
        private readonly Lazy<GenericRepository<ICommonClaim>> _claims;
        private readonly Lazy<IAuthorizationProvider> _authorizationProvider;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public static readonly string ImpersonatingUserInfoPrefix = "Impersonating:";
        public static readonly Claim IncreasePermissionsClaim = new Claim("WindowsAuthImpersonation.Impersonate", "IncreasePermissions");
        public static readonly Claim AllowImpersonationsClaim = new Claim("WindowsAuthImpersonation.Impersonate", "AllowImpersonation");
        public static readonly string[] SupportedAuthenticationTypes = { "Negotiate", "Windows", "Kerberos", "NTLM" };

        public ImpersonationProvider(
            ILogProvider logProvider,
            Lazy<IAuthorizationManager> authorizationManager,
            Lazy<GenericRepository<IPrincipal>> principals,
            Lazy<GenericRepository<ICommonClaim>> claims,
            Lazy<IAuthorizationProvider> authorizationProvider,
            IHttpContextAccessor httpContextAccessor)
        {
            _logger = logProvider.GetLogger(GetType().Name);
            _authorizationManager = authorizationManager;
            _principals = principals;
            _claims = claims;
            _authorizationProvider = authorizationProvider;
            _httpContextAccessor = httpContextAccessor;
        }

        public virtual string GetImpersonatedUserName()
        {
            var userData = GetOrCreateTicket().UserData;

            if (!String.IsNullOrEmpty(userData) && !userData.StartsWith(ImpersonatingUserInfoPrefix))
                throw new FrameworkException("Login impersonation plugin is not supported (" + GetType().FullName + "). The authentication ticket already has the UserData property set.");

            return String.IsNullOrEmpty(userData) ? null : userData.Substring(ImpersonatingUserInfoPrefix.Length);
        }

        public virtual string GetActualUserName()
        {
            if (_httpContextAccessor.IsUserAuthenticated != true || String.IsNullOrEmpty(_httpContextAccessor.UserName))
                throw new FrameworkException("WindowsAuthImpersonation plugin does not support unauthenticated requests.");

            var type = _httpContextAccessor.AuthenticationType;
            if (!SupportedAuthenticationTypes.Contains(type))
                throw new FrameworkException($"WindowsAuthImpersonation plugin does not support AuthenticationType '{type}'.");

            return _httpContextAccessor.UserName;
        }

        class TempUserInfo : IUserInfo
        {
            public string UserName { get; set; }
            public string Workstation { get; set; }
            public bool IsUserRecognized => true;
            public string Report() { return UserName; }
        }
        /// <summary>
        /// A user with this claim is allowed to impersonate another user that has more permissions.
        /// </summary>
        public virtual void CheckImpersonatedUserPermissions(string impersonatedUser)
        {
            var impersonatedPrincipalId = _principals.Value
                .Query(p => p.Name == impersonatedUser)
                .Select(p => p.ID).SingleOrDefault();

            // This function must be called after the user is authenticated and authorized (see CheckCurrentUserClaim),
            // otherwise the provided error information would be a security issue.
            if (impersonatedPrincipalId == default(Guid))
                throw new UserException("User '{0}' is not registered.", new[] { impersonatedUser }, null, null);

            var allowImpersonationPermissions = _authorizationManager.Value.GetAuthorizations(new[] {AllowImpersonationsClaim }).Single();
            if (!allowImpersonationPermissions)
                throw new UserException(
                    $"User '{GetActualUserName()}' doesn't have permission to impersonate other users. Claim '{AllowImpersonationsClaim.FullName}' is required.");

            var allowIncreasePermissions = _authorizationManager.Value.GetAuthorizations(new[] { IncreasePermissionsClaim }).Single();
            if (allowIncreasePermissions) return;

            // The impersonatedUser must have subset of permissions of the impersonating user.
            // It is not allowed to impersonate a user with more permissions then the impersonating user.
            var allClaims = _claims.Value.Query().Where(c => c.Active.Value)
                .Select(c => new { c.ClaimResource, c.ClaimRight }).ToList()
                .Select(c => new Claim(c.ClaimResource, c.ClaimRight)).ToList();

            var impersonatedUserInfo = new TempUserInfo { UserName = impersonatedUser };
            var impersonatedUserClaims = _authorizationProvider.Value.GetAuthorizations(impersonatedUserInfo, allClaims)
                .Zip(allClaims, (hasClaim, claim) => new { hasClaim, claim })
                .Where(c => c.hasClaim).Select(c => c.claim).ToList();

            var actualUserInfo = new TempUserInfo() { UserName = GetActualUserName() };
            var surplusImpersonatedClaims = _authorizationProvider.Value.GetAuthorizations(actualUserInfo, impersonatedUserClaims)
                .Zip(impersonatedUserClaims, (hasClaim, claim) => new { hasClaim, claim })
                .Where(c => !c.hasClaim).Select(c => c.claim).ToList();

            if (!surplusImpersonatedClaims.Any()) return;

            _logger.Info(
                "User '{0}' is not allowed to impersonate '{1}' because the impersonated user has {2} more security claims (for example '{3}'). Increase the user's permissions or add '{4}' security claim.",
                GetActualUserName(),
                impersonatedUser,
                surplusImpersonatedClaims.Count,
                surplusImpersonatedClaims.First().FullName,
                IncreasePermissionsClaim.FullName);

            throw new UserException("You are not allowed to impersonate user '{0}'.",
                new[] { impersonatedUser }, "See server log for more information.", null);
        }

        #region Cookies and Tickets

        private FormsAuthenticationTicket GetOrCreateTicket()
        {
            var existingTicket = _httpContextAccessor.GetAuthenticationTicket();
            if (existingTicket != null && IsTicketValid(existingTicket))
                return existingTicket;

            // ticket not found or not valid, we will create a fresh one
            var actualUserName = GetActualUserName();
            return new FormsAuthenticationTicket(2, actualUserName, DateTime.Now, DateTime.Now + TicketUtility.TicketTimeout.Value, false, null);
        }

        private bool IsTicketValid(FormsAuthenticationTicket authenticationTicket)
        {
            return !authenticationTicket.Expired
                   && authenticationTicket.Name == GetActualUserName();
        }

        public virtual void SetImpersonatedUser(string impersonatedUser)
        {
            if (String.IsNullOrEmpty(impersonatedUser))
            {
                _httpContextAccessor.AddTicketToResponse(null);
                return;
            }

            var ticket = GetOrCreateTicket();
            var newTicket = new FormsAuthenticationTicket(
                ticket.Version,
                ticket.Name,
                ticket.IssueDate,
                ticket.Expiration,
                false,
                impersonatedUser == null ? "" : ImpersonatingUserInfoPrefix + impersonatedUser,
                ticket.CookiePath);

            _httpContextAccessor.AddTicketToResponse(newTicket);
        }

        #endregion
    }
}