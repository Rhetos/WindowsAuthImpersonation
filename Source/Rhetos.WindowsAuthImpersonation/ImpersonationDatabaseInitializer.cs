using Rhetos.Dom.DefaultConcepts;
using Rhetos.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Text;

namespace Rhetos.WindowsAuthImpersonation
{
    // Executes at deployment-time.
    [Export(typeof(Rhetos.Extensibility.IServerInitializer))]
    public class ImpersonationDatabaseInitializer : Rhetos.Extensibility.IServerInitializer
    {
        private readonly GenericRepositories _repositories;

        public ImpersonationDatabaseInitializer(
            GenericRepositories repositories,
            ILogProvider logProvider)
        {
            _repositories = repositories;
        }

        public void Initialize()
        {
            // Admin role should already be created in AuthenticationDatabaseInitializer, see Dependencies property.
            var adminRole = _repositories.Load<IRole>(role => role.Name == AuthenticationDatabaseInitializer.AdminRoleName).Single();

            foreach (var securityClaim in ImpersonationServiceClaims.GetDefaultAdminClaims())
            {
                var commonClaim = _repositories.CreateInstance<ICommonClaim>();
                commonClaim.ClaimResource = securityClaim.Resource;
                commonClaim.ClaimRight = securityClaim.Right;
                _repositories.InsertOrReadId(commonClaim, item => new { item.ClaimResource, item.ClaimRight });

                var permission = _repositories.CreateInstance<IRolePermission>();
                permission.RoleID = adminRole.ID;
                permission.ClaimID = commonClaim.ID;
                permission.IsAuthorized = true;
                _repositories.InsertOrUpdateReadId(permission, item => new { item.RoleID, item.ClaimID }, item => item.IsAuthorized);
            }
        }

        public IEnumerable<string> Dependencies
        {
            get { return new[] { typeof(AuthenticationDatabaseInitializer).FullName }; }
        }
    }
}
