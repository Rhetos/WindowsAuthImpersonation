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
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Security;
using Rhetos.Logging;

namespace Rhetos.WindowsAuthImpersonation
{
    [Export(typeof(IUserInfo))]
    public class ImpersonationUserInfo : IUserInfo
    {
        #region IUserInfo implementation

        public bool IsUserRecognized => _isUserRecognized.Value;
        public string UserName => _impersonatedUser.Value ?? _actualUser.Value;
        public string Workstation => IsUserRecognized ? _workstation.Value : null;
        public string Report() => _impersonatedUser.Value != null
                ? (_actualUser.Value + " as " + _impersonatedUser.Value + "," + _workstation.Value)
                : _actualUser.Value + "," + _workstation.Value;

        #endregion

        /// <summary>
        /// Returns null if there is no impersonation.
        /// If the current user is impersonating another, this property returns the actual (not impersonated) user that is logged in.
        /// </summary>
        public string ImpersonatedBy => _impersonatedUser.Value != null ? _actualUser.Value : null;

        private readonly Lazy<bool> _isUserRecognized;

        private readonly Lazy<string> _workstation;

        /// <summary>
        /// The actual (not impersonated) user that is logged in.
        /// </summary>
        private readonly Lazy<string> _actualUser;

        /// <summary>
        /// The impersonated user whose context (including security permissions) is in effect.
        /// Null if there is no impersonation.
        /// </summary>
        private readonly Lazy<string> _impersonatedUser;

        public ImpersonationUserInfo(ImpersonationService impersonationService, IWindowsSecurity windowsSecurity)
        {
            _isUserRecognized = new Lazy<bool>(() => !string.IsNullOrEmpty(impersonationService.GetActualUserName()));
            _actualUser = new Lazy<string>(impersonationService.GetActualUserName);
            _impersonatedUser = new Lazy<string>(impersonationService.GetImpersonatedUserName);
            _workstation = new Lazy<string>(windowsSecurity.GetClientWorkstation);
        }
    }
}
