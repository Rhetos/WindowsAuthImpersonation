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
        private readonly ImpersonationService _impersonationService;

        #region IUserInfo implementation

        public bool IsUserRecognized => _impersonationService.GetActualUserName() != null;
        public string UserName => _impersonationService.GetImpersonatedUserName() ?? _impersonationService.GetActualUserName();
        public string Workstation => IsUserRecognized ? _workstation.Value : null;
        public string Report()
        {
            var impersonatedUserName = _impersonationService.GetImpersonatedUserName();
            var actualUserName = _impersonationService.GetActualUserName();

            return impersonatedUserName != null 
                ? $"{actualUserName} as {impersonatedUserName},{_workstation.Value}"
                : $"{actualUserName},{_workstation.Value}";
        }

        #endregion

        /// <summary>
        /// Returns null if there is no impersonation.
        /// If the current user is impersonating another, this property returns the actual (not impersonated) user that is logged in.
        /// </summary>
        public string ImpersonatedBy => _impersonationService.GetImpersonatedUserName() != null ? _impersonationService.GetActualUserName() : null;

        private readonly Lazy<string> _workstation;


        public ImpersonationUserInfo(ImpersonationService impersonationService, IWindowsSecurity windowsSecurity)
        {
            _impersonationService = impersonationService;
            _workstation = new Lazy<string>(windowsSecurity.GetClientWorkstation);
        }
    }
}
