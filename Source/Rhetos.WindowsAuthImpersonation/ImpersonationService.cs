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

using Rhetos.Logging;
using Rhetos.Security;
using System;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Web;
using Rhetos.WindowsAuthImpersonation.Abstractions;

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

    [ServiceContract]
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Required)]
    public class ImpersonationService
    {
        private readonly Lazy<IImpersonationProvider> _impersonationProvider;
        private readonly ILogger _logger;

        public ImpersonationService(ILogProvider logProvider, Lazy<IImpersonationProvider> impersonationProvider)
        {
            _impersonationProvider = impersonationProvider;
            _logger = logProvider.GetLogger(GetType().Name);

            _logger.Trace(() => "New instance of ImpersonationService created.");

        }

        #region Service HttpMethods


        [OperationContract]
        [WebInvoke(Method = "POST", UriTemplate = "/Impersonate", BodyStyle = WebMessageBodyStyle.Bare, RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
        public void Impersonate(ImpersonateParameters parameters)
        {
            if (parameters == null)
                throw new ClientException("It is not allowed to call this service method with no parameters provided.");

            _logger.Trace(() => $"Impersonate: {_impersonationProvider.Value.GetActualUserName()} as {parameters.ImpersonatedUser}.");
            parameters.Validate();

            var impersonatedUserName = _impersonationProvider.Value.GetImpersonatedUserName();
            if (impersonatedUserName != null)
                throw new ClientException($"Unable to start impersonation. Already impersonating user '{impersonatedUserName}'. Stop impersonation first.");

            _impersonationProvider.Value.CheckImpersonatedUserPermissions(parameters.ImpersonatedUser);
            _impersonationProvider.Value.SetImpersonatedUser(parameters.ImpersonatedUser);
        }

        [OperationContract]
        [WebInvoke(Method = "POST", UriTemplate = "/StopImpersonating", BodyStyle = WebMessageBodyStyle.Bare, RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json)]
        public void StopImpersonating()
        {
            var impersonatedUser = _impersonationProvider.Value.GetImpersonatedUserName();
            _logger.Trace(() => $"StopImpersonating: {_impersonationProvider.Value.GetActualUserName()} as {impersonatedUser}.");

            if (string.IsNullOrEmpty(impersonatedUser)) return;
            _impersonationProvider.Value.SetImpersonatedUser(null);
        }
        #endregion


    }
}
