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

using Rhetos.Security;
using Rhetos.Utilities;
using System;
using System.ComponentModel.Composition;
using Rhetos.WindowsAuthImpersonation.Abstractions;

namespace Rhetos.WindowsAuthImpersonation
{
    [Export(typeof(IUserInfo))]
    public class ImpersonationUserInfo : IImpersonationUserInfo
    {
        private readonly IImpersonationProvider _impersonationProvider;

        public ImpersonationUserInfo(IImpersonationProvider impersonationProvider, IWindowsSecurity windowsSecurity)
        {
            _impersonationProvider = impersonationProvider;
            _workstation = new Lazy<string>(windowsSecurity.GetClientWorkstation);
        }

        #region IUserInfo implementation

        public bool IsUserRecognized => !string.IsNullOrWhiteSpace(_impersonationProvider.GetActualUserName());
        public string UserName
        {
            get
            {
                CheckIfUserRecognized();
                return _impersonationProvider.GetImpersonatedUserName() ?? _impersonationProvider.GetActualUserName();
            }
        }
        public string Workstation { get { CheckIfUserRecognized(); return _workstation.Value; } }

        private void CheckIfUserRecognized()
        {
            if (!IsUserRecognized)
                throw new ClientException("User is not authenticated.");
        }

        public string Report()
        {
            var impersonatedUserName = _impersonationProvider.GetImpersonatedUserName();
            var actualUserName = _impersonationProvider.GetActualUserName();

            return impersonatedUserName != null 
                ? $"{actualUserName} as {impersonatedUserName},{_workstation.Value}"
                : $"{actualUserName},{_workstation.Value}";
        }

        #endregion

        /// <summary>
        /// Returns null if there is no impersonation.
        /// If the current user is impersonating another, this property returns the actual (not impersonated) user that is logged in.
        /// </summary>
        public string ImpersonatedBy => _impersonationProvider.GetImpersonatedUserName() != null ? _impersonationProvider.GetActualUserName() : null;

        private readonly Lazy<string> _workstation;
    }
}
